"""Small read-mostly HTTP/JSON API so automation (or an aggregator for a
sensor cluster) can query live state.

GET  /health                 sensor liveness and throughput
GET  /state[?full=1]         every WLAN, BSS, client and channel
GET  /wlans                  BSSs grouped by SSID
GET  /bss/<bssid>            one BSS with its clients (full detail)
GET  /client/<mac>           one client (full detail)
GET  /events?since=<seq>&min_severity=warning&limit=500
POST /lock   {"bssid": ".."} or {"band": "5g", "channel": 36}   focus the radio
POST /unlock                 resume hopping
"""

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .events import sev_value

log = logging.getLogger(__name__)


def lock_to_bss(engine, bssid):
    """Lock every hopper to the BSS's channel and width. Returns message."""
    with engine.lock:
        ap = engine.aps.get(bssid)
        if ap is None or not ap.channel:
            return False, f"unknown BSS or channel for {bssid}"
        band, ch, width, center = ap.band or "2g", ap.channel, ap.width, ap.center_freq
    if not engine.hoppers:
        return False, "no live radio to tune"
    for h in engine.hoppers:
        h.lock(band, ch, width if width > 20 else None, center)
    return True, f"locked to {band} ch{ch}" + (f" {width}MHz" if width > 20 else "")


class _Handler(BaseHTTPRequestHandler):
    server_version = "wlanscope"

    def log_message(self, fmt, *args):
        log.debug("api: " + fmt, *args)

    def _auth(self):
        token = self.server.token
        if not token:
            return True
        if self.headers.get("Authorization", "") == f"Bearer {token}":
            return True
        self._send(401, {"error": "unauthorized"})
        return False

    def _send(self, code, obj):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth():
            return
        eng = self.server.engine
        u = urlparse(self.path)
        q = parse_qs(u.query)
        parts = [p for p in u.path.split("/") if p]
        nf = eng.th.noise_floor
        try:
            if u.path in ("/", "/health"):
                with eng.lock:
                    now = eng.now()
                    self._send(200, {"status": "ok", "sensor": eng.cfg.sensor_id,
                                     "uptime": round(now - (eng.start or now), 1),
                                     "radios": [h.describe() for h in eng.hoppers],
                                     "stats": eng.stats(now)})
            elif parts == ["state"]:
                self._send(200, eng.snapshot(brief=q.get("full", ["0"])[0] != "1"))
            elif parts == ["wlans"]:
                with eng.lock:
                    wl = eng.wlans()
                    for w in wl:
                        w.pop("aps")
                self._send(200, wl)
            elif len(parts) == 2 and parts[0] == "bss":
                b = parts[1].lower()
                with eng.lock:
                    now = eng.now()
                    ap = eng.aps.get(b)
                    if ap is None:
                        return self._send(404, {"error": "unknown bssid"})
                    d = ap.as_dict(nf, now)
                    d["clients_detail"] = [eng.clients[m].as_dict(nf, now)
                                           for m in sorted(ap.clients) if m in eng.clients]
                self._send(200, d)
            elif len(parts) == 2 and parts[0] == "client":
                with eng.lock:
                    cl = eng.clients.get(parts[1].lower())
                    if cl is None:
                        return self._send(404, {"error": "unknown client"})
                    d = cl.as_dict(nf, eng.now())
                self._send(200, d)
            elif parts == ["events"]:
                since = int(q.get("since", ["0"])[0])
                minsev = sev_value(q.get("min_severity", ["info"])[0])
                limit = int(q.get("limit", ["500"])[0])
                evs = [e for e in list(eng.bus.recent)
                       if e["seq"] > since and sev_value(e["severity"]) >= minsev]
                self._send(200, evs[-limit:])
            else:
                self._send(404, {"error": "not found"})
        except (ValueError, KeyError) as e:
            self._send(400, {"error": str(e)})

    def do_POST(self):
        if not self._auth():
            return
        eng = self.server.engine
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid JSON"})
        if self.path == "/lock":
            if "bssid" in body:
                ok, msg = lock_to_bss(eng, body["bssid"].lower())
            elif "channel" in body and eng.hoppers:
                for h in eng.hoppers:
                    h.lock(body.get("band", "5g" if body["channel"] > 14 else "2g"),
                           int(body["channel"]))
                ok, msg = True, f"locked to ch{body['channel']}"
            else:
                ok, msg = False, "need bssid or channel (and a live radio)"
            self._send(200 if ok else 400, {"ok": ok, "message": msg})
        elif self.path == "/unlock":
            for h in eng.hoppers:
                h.unlock()
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})


def start_api(engine, listen, token=None):
    host, _, port = listen.rpartition(":")
    srv = ThreadingHTTPServer((host or "127.0.0.1", int(port)), _Handler)
    srv.daemon_threads = True
    srv.engine = engine
    srv.token = token
    t = threading.Thread(target=srv.serve_forever, name="api", daemon=True)
    t.start()
    log.info("API listening on %s:%s", host or "127.0.0.1", port)
    return srv
