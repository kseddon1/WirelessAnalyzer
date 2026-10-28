"""Configuration: defaults, TOML loading and detection thresholds."""

import dataclasses
import os
import socket
from dataclasses import dataclass, field

try:
    import tomllib
except ImportError:          # Python < 3.11
    tomllib = None


@dataclass
class Thresholds:
    # client activity
    active_window: float = 10.0          # s: data in this window => ACTIVE
    idle_after: float = 30.0             # s without data => IDLE
    client_timeout: float = 300.0        # s unseen => GONE
    ap_timeout: float = 180.0            # s unseen => AP_LOST event
    forget_after: float = 3600.0         # s unseen => purge from memory
    # utilisation (frames are normalised by channel observation time)
    high_util_fps: float = 200.0         # data frames/s from+to a client
    high_util_kbps: float = 5000.0       # observed airtime-independent throughput
    high_util_share: float = 0.6         # share of BSS data frames
    high_util_min_bss_fps: float = 50.0  # ...when the BSS carries at least this
    # link quality
    retry_pct: float = 10.0
    retry_min_frames: int = 50
    low_rssi: float = -80.0
    low_snr: float = 19.0
    low_rate_mbps: float = 12.0
    sticky_rssi: float = -75.0
    # AP
    high_channel_util_pct: float = 70.0
    bss_retry_pct: float = 25.0
    # attacks / failures
    deauth_window: float = 10.0
    deauth_flood_count: int = 20         # per BSS per window
    client_deauth_count: int = 5         # per client per window
    auth_fail_window: float = 120.0
    auth_fail_count: int = 2
    handshake_timeout: float = 5.0
    handshake_fail_count: int = 2
    roam_window: float = 60.0
    roam_storm_count: int = 4
    tsf_regression_count: int = 3
    tsf_window: float = 60.0
    channel_flap_count: int = 3
    karma_ssid_count: int = 3
    beacon_flood_new_bss: int = 50       # new BSSIDs per minute
    evil_twin_score: int = 3
    learning_period: float = 15.0        # suppress "new" events at startup
    noise_floor: float = -95.0           # SNR estimate when driver lacks noise
    # ---- observation / heuristic thresholds (four symptom categories) ----
    # (A) weak / deteriorating link
    obs_rssi_weak: float = -70.0         # RSSI below this = weak link
    obs_rssi_drop_db: float = 10.0       # RSSI drop of this much = deterioration
    obs_retry_pct: float = 30.0          # retry rate above this = retry spike
    obs_retry_min_frames: int = 20       # min frames before judging retry rate
    obs_rate_drop_pct: float = 30.0      # PHY rate drop of this much = rate change
    obs_rate_min_samples: int = 5        # min rate samples before judging
    # radio / channel
    obs_channel_util_pct: float = 70.0   # BSS-load utilisation above this = high
    obs_noise_rise_db: float = 5.0       # noise floor rise of this much = interference
    # (B) sticky client
    obs_sticky_rssi: float = -75.0        # client RSSI below this = weak on current AP
    obs_sticky_neighbor_db: float = 10.0  # neighbor AP must be this much stronger
    obs_sticky_min_assoc_s: float = 60.0  # associated this long before sticky applies
    obs_sticky_roam_lookback_s: float = 300.0  # roam lookback for stickiness
    # (C) roaming disruption
    obs_roam_disruption_window_s: float = 30.0  # window after a roam to check loss
    obs_roam_disruption_loss_pct: float = 20.0  # packet-loss share after roam
    obs_roam_latency_multiplier: float = 3.0    # latency multiplier after roam
    # (D) connected-but-broken
    obs_connected_idle_s: float = 60.0   # associated but idle this long = connected_idle
    obs_throughput_drop_pct: float = 50.0  # throughput drop vs baseline = degradation
    obs_min_baseline_frames: int = 100   # frames needed for a throughput baseline


@dataclass
class ManagedSSID:
    """A network you own. Anything advertising it outside policy is a rogue."""
    ssid: str
    security: list = field(default_factory=list)     # e.g. ["WPA2-Enterprise"]
    allowed_bssids: list = field(default_factory=list)   # full MACs or prefixes
    allowed_ouis: list = field(default_factory=list)
    bands: list = field(default_factory=list)        # e.g. ["2g","5g"]


@dataclass
class Config:
    sensor_id: str = field(default_factory=lambda: os.environ.get("WA_SENSOR", socket.gethostname()))
    interfaces: list = field(default_factory=list)
    pcap: str = None
    channels: str = "default"
    dwell: float = 0.25
    hop: bool = True
    replay_speed: float = None         # None: as fast as possible headless, real time in the UI
    split_channels: bool = True        # split the channel list across several interfaces
    write_pcap: str = None
    oui_file: str = None
    # events
    events_file: str = None
    events_max_mb: float = 50.0
    events_keep: int = 5
    stdout_events: bool = None
    webhook_url: str = field(default_factory=lambda: os.environ.get("WA_EDA_URL"))
    webhook_token: str = field(default_factory=lambda: os.environ.get("WA_EDA_TOKEN"))
    webhook_min_severity: str = "warning"
    syslog: str = None
    syslog_min_severity: str = "warning"
    min_severity: str = "info"
    event_cooldown: float = 300.0
    heartbeat_interval: float = 60.0
    state_file: str = None
    state_interval: float = 10.0
    api: str = None
    api_token: str = None
    managed: list = field(default_factory=list)
    thresholds: Thresholds = field(default_factory=Thresholds)


def _merge(dc, values, path=""):
    names = {f.name for f in dataclasses.fields(dc)}
    for k, v in values.items():
        k2 = k.replace("-", "_")
        if k2 not in names:
            raise ValueError(f"unknown config key '{path}{k}'")
        setattr(dc, k2, v)


def load(path):
    """Load a TOML file into a Config."""
    if tomllib is None:
        raise RuntimeError("TOML config needs Python 3.11+")
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    cfg = Config()
    for section in ("sensor", "capture", "events", "outputs"):
        if section in data:
            _merge(cfg, data[section], f"{section}.")
    if "thresholds" in data:
        _merge(cfg.thresholds, data["thresholds"], "thresholds.")
    for m in data.get("managed_ssid", []):
        cfg.managed.append(ManagedSSID(**{k.replace("-", "_"): v for k, v in m.items()}))
    return cfg
