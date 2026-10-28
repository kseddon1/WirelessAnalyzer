"""Structured events and output sinks for automation.

Every event is a flat JSON object. The keys `alert`, `ssid`, `bssid` and
`sensor` sit at the top level so Event-Driven Ansible rules can match on
`event.payload.alert` etc. without digging into `details`.
"""

import json
import logging
import os
import queue
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from datetime import datetime, timezone

log = logging.getLogger(__name__)

SEVERITY = {"debug": 0, "info": 1, "warning": 2, "critical": 3}


def sev_value(s):
    return SEVERITY.get(str(s).lower(), 1)


class EventBus:
    def __init__(self, sensor_id, cooldown=300.0, clock=time.time):
        self.sensor_id = sensor_id
        self.cooldown = cooldown
        self.clock = clock
        self.sinks = []
        self.recent = deque(maxlen=2000)
        self._last = {}            # cooldown key -> (time, severity)
        self.counts = {k: 0 for k in SEVERITY}
        self.suppressed = 0
        self.seq = 0
        self._lock = threading.Lock()
        self.listeners = []        # callables(event) e.g. TUI status line

    def add_sink(self, sink):
        self.sinks.append(sink)

    def emit(self, alert, severity, category, message, *, ssid=None, bssid=None,
             client=None, channel=None, band=None, rssi=None, state="observed",
             details=None, key=None, cooldown=None, clients=None, bssids=None):
        now = self.clock()
        ck = key or (alert, bssid, client, state)
        cd = self.cooldown if cooldown is None else cooldown
        sv = sev_value(severity)
        with self._lock:
            prev = self._last.get(ck)
            if prev and now - prev[0] < cd and sv <= prev[1]:
                self.suppressed += 1
                return None
            self._last[ck] = (now, sv)
            if len(self._last) > 20000:
                cutoff = now - max(cd, 3600)
                self._last = {k: v for k, v in self._last.items() if v[0] > cutoff}
            self.seq += 1
            ev = {
                "event_id": str(uuid.uuid4()),
                "seq": self.seq,
                "ts": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="milliseconds"),
                "epoch": round(now, 3),
                "sensor": self.sensor_id,
                "alert": alert,
                "state": state,
                "severity": severity,
                "category": category,
                "ssid": ssid,
                "bssid": bssid,
                "client": client,
                "channel": channel,
                "band": band,
                "rssi": None if rssi is None else round(rssi, 1),
                "message": message,
                "details": details or {},
                "clients": clients or [],
                "bssids": bssids or [],
            }
            self.counts[severity] = self.counts.get(severity, 0) + 1
            self.recent.append(ev)
        for s in self.sinks:
            if sv >= s.min_sev:
                try:
                    s.send(ev)
                except Exception as e:          # a broken sink must not stop capture
                    log.warning("event sink %s failed: %s", s.name, e)
        for cb in self.listeners:
            try:
                cb(ev)
            except Exception:
                pass
        return ev

    def reset_cooldown(self, key_prefix):
        """Allow an alert to fire again (e.g. after it cleared)."""
        with self._lock:
            for k in [k for k in self._last if k[:len(key_prefix)] == key_prefix]:
                del self._last[k]

    def close(self):
        for s in self.sinks:
            try:
                s.close()
            except Exception:
                pass


class Sink:
    name = "sink"

    def __init__(self, min_severity="info"):
        self.min_sev = sev_value(min_severity)

    def send(self, ev):
        raise NotImplementedError

    def close(self):
        pass


class StreamSink(Sink):
    name = "stdout"

    def __init__(self, stream=None, min_severity="info"):
        super().__init__(min_severity)
        self.stream = stream or sys.stdout
        self._lock = threading.Lock()

    def send(self, ev):
        with self._lock:
            self.stream.write(json.dumps(ev, default=str) + "\n")
            self.stream.flush()


class FileSink(Sink):
    """Append JSON lines, rotating at max_mb keeping `keep` old files."""
    name = "file"

    def __init__(self, path, max_mb=50.0, keep=5, min_severity="info"):
        super().__init__(min_severity)
        self.path = path
        self.max_bytes = int(max_mb * 1024 * 1024)
        self.keep = keep
        self._lock = threading.Lock()
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self.fh = open(path, "a", encoding="utf-8")

    def _rotate(self):
        self.fh.close()
        for i in range(self.keep - 1, 0, -1):
            src = f"{self.path}.{i}"
            if os.path.exists(src):
                os.replace(src, f"{self.path}.{i + 1}")
        os.replace(self.path, f"{self.path}.1")
        self.fh = open(self.path, "a", encoding="utf-8")

    def send(self, ev):
        line = json.dumps(ev, default=str) + "\n"
        with self._lock:
            if self.max_bytes and self.fh.tell() + len(line) > self.max_bytes:
                self._rotate()
            self.fh.write(line)
            self.fh.flush()

    def close(self):
        self.fh.close()


class WebhookSink(Sink):
    """POST each event as JSON (Bearer token) from a background thread.

    Compatible with the ansible.eda.webhook source. The queue is bounded; if
    the receiver is down the oldest events are dropped rather than blocking.
    """
    name = "webhook"

    def __init__(self, url, token=None, min_severity="warning", timeout=10):
        super().__init__(min_severity)
        self.url = url
        self.token = token
        self.timeout = timeout
        self.q = queue.Queue(maxsize=1000)
        self.sent = self.failed = self.dropped = 0
        self.last_error = None
        self._stop = threading.Event()
        self.t = threading.Thread(target=self._run, name="webhook", daemon=True)
        self.t.start()

    def send(self, ev):
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            try:
                self.q.get_nowait()
                self.dropped += 1
            except queue.Empty:
                pass
            self.q.put_nowait(ev)

    def _post(self, ev):
        headers = {"Content-Type": "application/json", "User-Agent": "wlanscope"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.url, data=json.dumps(ev, default=str).encode(),
                                     headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            r.read()

    def _run(self):
        while not self._stop.is_set():
            try:
                ev = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            for attempt in range(3):
                try:
                    self._post(ev)
                    self.sent += 1
                    break
                except (urllib.error.URLError, OSError, ValueError) as e:
                    self.last_error = str(e)
                    if attempt == 2:
                        self.failed += 1
                        log.warning("webhook POST failed for %s: %s", ev["alert"], e)
                    else:
                        self._stop.wait(2 ** attempt)

    def close(self):
        deadline = time.time() + 3
        while not self.q.empty() and time.time() < deadline:
            time.sleep(0.1)
        self._stop.set()


class SyslogSink(Sink):
    """RFC 5424 over UDP, JSON as the message body (facility local0)."""
    name = "syslog"
    _SEV = {"critical": 2, "warning": 4, "info": 6, "debug": 7}

    def __init__(self, target, min_severity="warning"):
        super().__init__(min_severity)
        host, _, port = target.rpartition(":")
        if not host:
            host, port = target, "514"
        self.addr = (host, int(port))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.host = socket.gethostname()

    def send(self, ev):
        pri = 16 * 8 + self._SEV.get(ev["severity"], 6)
        msg = f"<{pri}>1 {ev['ts']} {self.host} wlanscope - {ev['alert']} - {json.dumps(ev, default=str)}"
        self.sock.sendto(msg.encode()[:8000], self.addr)

    def close(self):
        self.sock.close()
