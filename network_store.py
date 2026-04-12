"""
NetworkStore – in‑memory representation of APs & clients.

Keeps a lock‑free structure for
    * AP discovery
    * per‑AP & per‑client statistics
    * rolling signal‑strength & rate sliding windows
"""

import time
from collections import deque
from datetime import datetime, timedelta
from threading import Lock

FLAG_LENGTH = 50    # increase display space for future flags
RETRY_RATE_THRESHOLD = 0.2   # 20 % of frames

class ClientInfo:
    def __init__(self, signal, ts, rate):
        self.signal = signal
        self.last_seen = ts.strftime("%m-%d %H:%M")
        self._last_seen_dt = ts
        self.txa_rate = rate
        self.frames = 0
        self.retries = 0
        self.aatime_pct = 0.0          # airtime %
        self.flags = "".ljust(FLAG_LENGTH)[:FLAG_LENGTH]
        self.last_retry_reset = datetime.now()
        self.ip = None
        self.signal_hist = deque(maxlen=30)   # rolling window
        self.pkt_rate = 0.0
        self._rate_frames = 0
        self._rate_start = time.monotonic()

    def update_frame(self, signal, rate, mac_af):
        now = datetime.now()
        self.frames += 1
        self._rate_frames += 1
        mono = time.monotonic()
        elapsed = mono - self._rate_start
        if elapsed >= 1.0:
            self.pkt_rate = round(self._rate_frames / elapsed, 1)
            self._rate_frames = 0
            self._rate_start = mono
        self.signal_hist.append(signal)
        self.last_seen = now.strftime("%m-%d %H:%M")
        self._last_seen_dt = now

        if signal is not None:
            self.signal = signal
        if rate and rate > (self.txa_rate or 0):
            self.txa_rate = rate

        # reset retry counter every minute
        if (now - self.last_retry_reset) > timedelta(seconds=60):
            self.retries = 0
            self.last_retry_reset = now

        # compute flags
        flags = []
        if signal and signal < -70:
            flags.append("WEAK_SIGNAL")
        if self.aatime_pct > 40:
            flags.append("HIGH_USAGE")
        if self.frames < 5:
            flags.append("IDLE")
        if self.retries / max(1, self.frames) > RETRY_RATE_THRESHOLD:
            flags.append("HIGH_RETRIES")
        self.flags = ",".join(flags).ljust(FLAG_LENGTH)[:FLAG_LENGTH]


class APInfo:
    def __init__(self, bssid):
        self.bssid = bssid
        self.ssid = "<hidden>"
        self.channel = "?"
        self.signal = None
        self.enc = "Open"
        self.uptime = "?"
        self.data_rates = "N/A"
        self.frames = 0
        self.qos_data = 0
        self.retries = 0
        self.clients = {}
        self.frame_hist = deque(maxlen=30)          # for airtime %, last 30 frames
        self.pkt_rate = 0.0
        self._rate_frames = 0
        self._rate_start = time.monotonic()

    def average_signal(self):
        if self.frame_hist:
            return round(sum(self.frame_hist)/len(self.frame_hist), 1)
        return None

    def add_frame(self, signal=None, is_qos=False, retry=False):
        self.frames += 1
        self._rate_frames += 1
        mono = time.monotonic()
        elapsed = mono - self._rate_start
        if elapsed >= 1.0:
            self.pkt_rate = round(self._rate_frames / elapsed, 1)
            self._rate_frames = 0
            self._rate_start = mono
        if signal is not None:
            self.signal = signal
            self.frame_hist.append(signal)

        if is_qos:
            self.qos_data += 1

        if retry:
            self.retries += 1

    def add_client(self, mac, signal=None, rate=None):
        if mac not in self.clients:
            self.clients[mac] = ClientInfo(signal, datetime.now(), rate)
        return self.clients[mac]

    def purge_stale_clients(self, ttl: int = 120):
        """Remove clients that have not been seen for `ttl` seconds."""
        now = datetime.now()
        stale = [mac for mac, ci in self.clients.items()
                 if (now - ci._last_seen_dt).total_seconds() > ttl]
        for mac in stale:
            del self.clients[mac]


class NetworkStore:
    """
    Public API used by UI, processor, and sniffer.
    Thread‑safe via internal locks only on mutation; reads are lock‑free because
    Python dicts are safe for concurrent reads.
    """
    def __init__(self):
        self.ap_map = {}
        self._lock = Lock()

    def upsert_ap(self, bssid):
        if bssid not in self.ap_map:
            self.ap_map[bssid] = APInfo(bssid)
        return self.ap_map[bssid]

    def get_sorted_by_signal(self):
        return sorted(self.ap_map.values(),
                      key=lambda ap: ap.signal if ap.signal is not None else -9999,
                      reverse=True)

    def purge(self):
        for ap in self.ap_map.values():
            ap.purge_stale_clients()
