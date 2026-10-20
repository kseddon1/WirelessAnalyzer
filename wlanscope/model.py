"""In-memory model of observed BSSs, clients and their statistics."""

from collections import deque

COUNTER_FIELDS = (
    "frames", "bytes", "mgmt", "ctrl", "data", "null", "data_bytes", "beacons",
    "probe_req", "probe_resp", "auth", "assoc", "reassoc", "deauth", "disassoc",
    "action", "eapol", "retries", "data_retries", "protected", "rts", "cts",
    "ack", "ba", "ps_poll",
)
COUNTER_INDEX = {f: i for i, f in enumerate(COUNTER_FIELDS)}


class Counters:
    __slots__ = COUNTER_FIELDS

    def __init__(self):
        for f in COUNTER_FIELDS:
            setattr(self, f, 0)

    def snapshot(self):
        return tuple(getattr(self, f) for f in COUNTER_FIELDS)

    def as_dict(self):
        return {f: getattr(self, f) for f in COUNTER_FIELDS}


class History:
    """Per-second samples of a Counters object for delta and rate math.

    Each sample is (wall_time, observed_seconds, snapshot). observed_seconds is
    the cumulative time the sensor spent on the entity's channel so that rates
    reflect activity while listening rather than being diluted by hopping.
    """

    __slots__ = ("samples",)

    def __init__(self, maxlen=62):
        self.samples = deque(maxlen=maxlen)

    def add(self, t, obs, snap):
        self.samples.append((t, obs, snap))

    def delta(self, fld):
        """Increment over the most recent tick."""
        s = self.samples
        if len(s) < 2:
            return s[-1][2][COUNTER_INDEX[fld]] if s else 0
        i = COUNTER_INDEX[fld]
        return s[-1][2][i] - s[-2][2][i]

    def window(self, fld, seconds):
        """(count delta, observed seconds) over roughly the last `seconds`."""
        s = self.samples
        if not s:
            return 0, 0.0
        i = COUNTER_INDEX[fld]
        last = s[-1]
        first = s[0]
        for smp in reversed(s):
            first = smp
            if last[0] - smp[0] >= seconds:
                break
        return last[2][i] - first[2][i], last[1] - first[1]

    def rate(self, fld, seconds=10.0):
        n, obs = self.window(fld, seconds)
        if obs <= 0.05:
            return 0.0
        return n / obs


class Signal:
    __slots__ = ("last", "avg", "min", "max", "n", "noise", "history", "_acc", "_cnt")

    def __init__(self):
        self.last = self.avg = self.min = self.max = self.noise = None
        self.n = 0
        self.history = deque(maxlen=120)
        self._acc = 0.0
        self._cnt = 0

    def update(self, dbm, noise=None):
        if dbm is None or dbm >= 0 or dbm < -120:
            return
        self.last = dbm
        self.n += 1
        self.avg = dbm if self.avg is None else self.avg * 0.8 + dbm * 0.2
        self.min = dbm if self.min is None else min(self.min, dbm)
        self.max = dbm if self.max is None else max(self.max, dbm)
        if noise is not None and -120 < noise < 0:
            self.noise = noise if self.noise is None else self.noise * 0.9 + noise * 0.1
        self._acc += dbm
        self._cnt += 1

    def tick(self):
        """Close a one-second bucket for the sparkline history."""
        if self._cnt:
            self.history.append(self._acc / self._cnt)
        else:
            self.history.append(None)
        self._acc = 0.0
        self._cnt = 0

    def snr(self, noise_floor):
        """Return (snr_db, estimated?)."""
        if self.avg is None:
            return None, False
        if self.noise is not None:
            return self.avg - self.noise, False
        return self.avg - noise_floor, True

    def as_dict(self, noise_floor):
        snr, est = self.snr(noise_floor)
        r = lambda v: None if v is None else round(v, 1)
        return {"rssi": r(self.last), "rssi_avg": r(self.avg), "rssi_min": self.min,
                "rssi_max": self.max, "noise": r(self.noise), "snr": r(snr),
                "snr_estimated": est, "samples": self.n}


class AccessPoint:
    def __init__(self, bssid, now):
        self.bssid = bssid
        self.ssid = None              # None = never learned
        self.hidden = False
        self.ssid_revealed = False
        self.vendor = ""
        self.ap_name = None
        self.first_seen = now
        self.last_seen = now
        self.last_beacon = None
        self.beacon_seen = False      # True once beacon/probe-resp received
        self.channel = None           # channel claimed by the AP (DS/HT op)
        self.band = None
        self.radio_channel = None     # channel the sensor heard it on
        self.width = 20
        self.center_freq = None
        self.beacon_interval = None
        self.dtim_period = None
        self.capability = 0
        self.ies = None               # latest IEInfo
        self.ie_parsed_at = 0.0
        self.ie_body_len = -1
        self.security = None
        self.security_class = None
        self.pairwise = []
        self.group_cipher = None
        self.akms = []
        self.mfp = "none"             # none | capable | required
        self.generation = None
        self.nss = None
        self.max_rate = None
        self.country = None
        self.bss_load = None
        self.wps = None
        self.vendor_ies = ()
        self.fingerprint = None
        self.fingerprint_changes = deque(maxlen=20)
        self.tsf = None
        self.tsf_at = None
        self.tsf_regressions = deque(maxlen=50)
        self.uptime = None
        self.claimed_channels = deque(maxlen=50)   # (t, channel) on change
        self.probe_resp_ssids = {}                 # ssid -> last time
        self.csa = None
        self.counters = Counters()
        self.history = History()
        self.signal = Signal()
        self.clients = set()
        self.data_up = 0
        self.data_down = 0
        self.data_mcast = 0
        self.deauth_times = deque(maxlen=500)
        self.wds_peers = set()
        self.alerts = {}              # code -> {severity, message, since, last_true, details}
        self.flags = set()            # informational characteristics (HIDDEN, WPS, ...)
        self.lost = False

    @property
    def display_ssid(self):
        if self.ssid:
            return self.ssid
        if self.hidden or self.ssid == "":
            return "<hidden>"
        return "<unknown>"

    def as_dict(self, noise_floor, now, brief=False):
        ies = self.ies
        d = {
            "bssid": self.bssid, "ssid": self.ssid, "hidden": self.hidden,
            "vendor": self.vendor, "ap_name": self.ap_name, "channel": self.channel,
            "band": self.band, "width": self.width, "security": self.security,
            "generation": self.generation, "clients": len(self.clients),
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "age": round(now - self.last_seen, 1),
            "alerts": sorted(self.alerts), "flags": sorted(self.flags),
        }
        d.update(self.signal.as_dict(noise_floor))
        if brief:
            return d
        d.update({
            "radio_channel": self.radio_channel, "center_freq": self.center_freq,
            "beacon_interval": self.beacon_interval, "dtim_period": self.dtim_period,
            "capability": f"0x{self.capability:04x}", "pairwise": self.pairwise,
            "group_cipher": self.group_cipher, "akms": self.akms, "mfp": self.mfp,
            "nss": self.nss, "country": self.country, "bss_load": self.bss_load,
            "wps": self.wps, "uptime_s": self.uptime,
            "dot11k": bool(ies and ies.dot11k), "dot11v": bool(ies and ies.btm),
            "dot11r": bool(ies and ies.dot11r), "dot11u": bool(ies and ies.dot11u),
            "rates": ies.rates if ies else [], "basic_rates": ies.basic_rates if ies else [],
            "vendor_ies": list(self.vendor_ies),
            "counters": self.counters.as_dict(),
            "rates_per_s": {f: round(self.history.rate(f), 2)
                            for f in ("frames", "data", "mgmt", "beacons", "retries")},
            "data_up": self.data_up, "data_down": self.data_down,
            "data_mcast": self.data_mcast,
            "client_macs": sorted(self.clients),
            "alert_details": self.alerts,
        })
        return d


class Client:
    def __init__(self, mac, now):
        self.mac = mac
        self.vendor = ""
        self.randomized = False
        self.bssid = None
        self.last_bssid = None
        self.state = "seen"            # seen|probing|authenticating|associating|associated|disconnected
        self.state_since = now
        self.first_seen = now
        self.last_seen = now
        self.last_data = None
        self.last_uplink = None
        self.aid = None
        self.listen_interval = None
        self.power_save = False
        self.ps_since = None
        self.probed_ssids = {}         # ssid -> last time
        self.caps = None               # IEInfo from (re)assoc request
        self.probe_caps = None         # IEInfo from probe request
        self.client_security = None    # AKM/cipher chosen in assoc req
        self.signal = Signal()
        self.counters = Counters()     # everything to/from the client
        self.history = History()
        self.tx_frames = 0
        self.tx_retries = 0
        self.rx_frames = 0
        self.rx_retries = 0
        self.data_up = 0
        self.data_down = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.tx_rate = None            # last uplink PHY rate
        self.rx_rate = None            # last downlink PHY rate
        self.tx_phy = None
        self.rates_up = deque(maxlen=50)
        self.rates_down = deque(maxlen=50)
        self.deauth_times = deque(maxlen=100)
        self.last_disconnect = None    # dict(kind, reason, by, t)
        self.auth_failures = deque(maxlen=50)   # (t, kind, detail)
        self.assoc_times = deque(maxlen=50)
        self.roams = deque(maxlen=50)           # (t, from, to)
        self.hs = {"state": None, "t": None, "last_msg": None, "started": None}
        self.hs_failures = deque(maxlen=20)
        self.hs_complete = 0
        self.eap_method = None
        self.eap_result = None
        self.btm = deque(maxlen=10)
        self.status = "SEEN"
        self.status_since = now
        self.flags = set()
        self.issues = {}               # status code -> {detail, severity, since, last_true}
        self.chan_key = None           # (band, channel) the client was last heard on

    @property
    def tx_retry_pct(self):
        return 100.0 * self.tx_retries / self.tx_frames if self.tx_frames else 0.0

    @property
    def rx_retry_pct(self):
        return 100.0 * self.rx_retries / self.rx_frames if self.rx_frames else 0.0

    def as_dict(self, noise_floor, now, brief=False):
        d = {
            "mac": self.mac, "vendor": self.vendor, "randomized": self.randomized,
            "bssid": self.bssid, "state": self.state, "status": self.status,
            "issues": {k: v["detail"] for k, v in self.issues.items()},
            "flags": sorted(self.flags),
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "age": round(now - self.last_seen, 1),
            "tx_rate": self.tx_rate, "rx_rate": self.rx_rate,
        }
        d.update(self.signal.as_dict(noise_floor))
        if brief:
            return d
        caps = self.caps or self.probe_caps
        d.update({
            "last_bssid": self.last_bssid, "aid": self.aid,
            "power_save": self.power_save, "listen_interval": self.listen_interval,
            "probed_ssids": sorted(self.probed_ssids),
            "generation": caps.generation if caps else None,
            "nss": caps.nss if caps else None,
            "dot11k": bool(caps and caps.dot11k), "dot11v": bool(caps and caps.btm),
            "dot11r": bool(self.caps and self.caps.dot11r),
            "client_security": self.client_security,
            "counters": self.counters.as_dict(),
            "data_up": self.data_up, "data_down": self.data_down,
            "bytes_up": self.bytes_up, "bytes_down": self.bytes_down,
            "tx_retry_pct": round(self.tx_retry_pct, 1),
            "rx_retry_pct": round(self.rx_retry_pct, 1),
            "rates_per_s": {f: round(self.history.rate(f), 2)
                            for f in ("frames", "data", "mgmt", "retries")},
            "last_disconnect": self.last_disconnect,
            "roams": [list(r) for r in self.roams][-10:],
            "handshake": dict(self.hs, complete=self.hs_complete,
                              failures=len(self.hs_failures)),
            "eap_method": self.eap_method, "eap_result": self.eap_result,
        })
        return d
