"""Observation model: raw, categorized facts seen on the 802.11 wire.

Observations are OBSERVATIONS, not diagnoses. Each one records a single
discrete fact (a client roamed, RSSI dropped, retries spiked, a deauth
frame was seen) without interpreting why it happened.  The four categories
map to the symptom areas an operator cares about:

  1. connectivity   -- roams, disconnects, reassociations, auth failures,
                        BSSID changes
  2. radio          -- RSSI/SNR, retries, channel utilisation, noise,
                        PHY-rate changes, 2.4/5/6 GHz band differences
  3. performance    -- throughput drops, latency, packet loss, associated
                        but passing little or no data (healthy RF vs broken
                        upper layers)
  4. protocol       -- deauth/disassoc floods, unusual management-frame
                        patterns, 4-way handshake / EAP failures

Each observation is emitted once (state="observed") on the EventBus and is
also kept in the engine's observation ring buffer so the heuristics layer
can aggregate them over time windows.
"""

from dataclasses import dataclass, field
from typing import Optional

# ----------------------------------------------------------------- categories

CONNECTIVITY = "connectivity"
RADIO = "radio"
PERFORMANCE = "performance"
PROTOCOL = "protocol"

CATEGORY_LABELS = {
    CONNECTIVITY: "Connectivity & Roaming",
    RADIO: "Radio Quality & Interference",
    PERFORMANCE: "Performance Degradation",
    PROTOCOL: "Protocol & Security Anomalies",
}

# Discrete observation types within each category.  These are the keys used
# in `details["obs_type"]` and in the `type` field of an observation event.
OBS_ASSOC = "assoc"            # client associated to a BSS
OBS_REASSOC = "reassoc"        # client reassociated
OBS_DISCONNECT = "disconnect"  # client disconnected (deauth/disassoc)
OBS_ROAM = "roam"              # client roamed between BSSIDs
OBS_AUTH_FAIL = "auth_fail"    # authentication rejected
OBS_ASSOC_FAIL = "assoc_fail"  # association rejected
OBS_BSSID_CHANGE = "bssid_change"  # BSSID changed for an SSID

OBS_RSSI_DROP = "rssi_drop"            # RSSI deteriorated below a threshold
OBS_SNR_DROP = "snr_drop"              # SNR deteriorated below a threshold
OBS_RETRY_SPIKE = "retry_spike"        # retry rate increased
OBS_CHANNEL_UTIL = "channel_util"      # channel utilisation high (BSS load)
OBS_RATE_CHANGE = "rate_change"        # PHY rate changed materially
OBS_BAND_DIFF = "band_diff"            # 2.4/5/6 GHz behaviour difference

OBS_THROUGHPUT_DROP = "throughput_drop"    # sustained throughput below expected
OBS_LATENCY_SPIKE = "latency_spike"        # latency inferred from retries/ACK gaps
OBS_PACKET_LOSS = "packet_loss"            # retries without corresponding ACK
OBS_CONNECTED_IDLE = "connected_idle"      # associated but passing little/no data

OBS_DEAUTH = "deauth"            # deauthentication frame
OBS_DISASSOC = "disassoc"        # disassociation frame
OBS_HANDSHAKE_FAIL = "handshake_fail"    # 4-way handshake failed
OBS_EAP_FAILURE = "eap_failure"  # EAP authentication failed
OBS_MGMT_ANOMALY = "mgmt_anomaly"        # unusual management-frame pattern

OBSERVATION_TYPES = {
    # connectivity
    OBS_ASSOC: "client associated",
    OBS_REASSOC: "client reassociated",
    OBS_DISCONNECT: "client disconnected",
    OBS_ROAM: "client roamed between BSSIDs",
    OBS_AUTH_FAIL: "authentication rejected",
    OBS_ASSOC_FAIL: "association rejected",
    OBS_BSSID_CHANGE: "BSSID changed for SSID",
    # radio
    OBS_RSSI_DROP: "RSSI deteriorated",
    OBS_SNR_DROP: "SNR deteriorated",
    OBS_RETRY_SPIKE: "retry rate increased",
    OBS_CHANNEL_UTIL: "channel utilisation high",
    OBS_RATE_CHANGE: "PHY rate changed",
    OBS_BAND_DIFF: "band behaviour difference",
    # performance
    OBS_THROUGHPUT_DROP: "throughput dropped",
    OBS_LATENCY_SPIKE: "latency increased",
    OBS_PACKET_LOSS: "packet loss (retries without ACK)",
    OBS_CONNECTED_IDLE: "associated but passing little or no data",
    # protocol
    OBS_DEAUTH: "deauthentication frame",
    OBS_DISASSOC: "disassociation frame",
    OBS_HANDSHAKE_FAIL: "4-way handshake failed",
    OBS_EAP_FAILURE: "EAP authentication failed",
    OBS_MGMT_ANOMALY: "unusual management-frame pattern",
}


@dataclass
class Observation:
    """A single observed fact on the wire.

    `category` is one of CONNECTIVITY / RADIO / PERFORMANCE / PROTOCOL.
    `obs_type` is one of the OBS_* constants above.  All other fields are
    optional context captured at observation time.
    """

    category: str
    obs_type: str
    ts: float
    client: Optional[str] = None
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    channel: Optional[int] = None
    band: Optional[str] = None
    rssi: Optional[float] = None
    snr: Optional[float] = None
    message: str = ""
    details: dict = field(default_factory=dict)

    def as_event(self, sensor_id: str, seq: int) -> dict:
        """Convert to an EventBus-compatible event dict (state='observed')."""
        return {
            "event_id": f"obs-{seq}",
            "seq": seq,
            "ts": self.ts,
            "epoch": round(self.ts, 3),
            "sensor": sensor_id,
            "alert": f"OBS_{self.obs_type.upper()}",
            "state": "observed",
            "severity": "info",
            "category": self.category,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "client": self.client,
            "channel": self.channel,
            "band": self.band,
            "rssi": None if self.rssi is None else round(self.rssi, 1),
            "message": self.message,
            "details": dict(self.details),
        }


class ObservationStore:
    """Ring buffer of recent observations, keyed for heuristic lookups.

    Keeps the most recent `maxlen` observations and provides time-windowed
    queries so heuristics can aggregate over, e.g., "the last 30 seconds".
    """

    def __init__(self, maxlen: int = 5000):
        self.maxlen = maxlen
        from collections import deque
        self._buf: deque = deque(maxlen=maxlen)

    def add(self, obs: Observation) -> None:
        self._buf.append(obs)

    def __iter__(self):
        return iter(self._buf)

    def __len__(self):
        return len(self._buf)

    # --------------------------------------------------------------- queries

    def window(self, seconds: float, now: Optional[float] = None):
        """Observations within the last `seconds` seconds of `now`."""
        if now is None:
            import time
            now = time.time()
        cutoff = now - seconds
        return [o for o in self._buf if o.ts >= cutoff]

    def by_type(self, obs_type: str, seconds: Optional[float] = None,
                now: Optional[float] = None):
        """Observations of a given type, optionally time-limited."""
        obs = self.window(seconds, now) if seconds is not None else list(self._buf)
        return [o for o in obs if o.obs_type == obs_type]

    def by_client(self, client: str, seconds: Optional[float] = None,
                  now: Optional[float] = None):
        obs = self.window(seconds, now) if seconds is not None else list(self._buf)
        return [o for o in obs if o.client == client]

    def by_bssid(self, bssid: str, seconds: Optional[float] = None,
                 now: Optional[float] = None):
        obs = self.window(seconds, now) if seconds is not None else list(self._buf)
        return [o for o in obs if o.bssid == bssid]

    def by_category(self, category: str, seconds: Optional[float] = None,
                    now: Optional[float] = None):
        obs = self.window(seconds, now) if seconds is not None else list(self._buf)
        return [o for o in obs if o.category == category]

    def count(self, obs_type: str, seconds: float,
              now: Optional[float] = None) -> int:
        return len(self.by_type(obs_type, seconds, now))
