"""
alerts – evaluates APInfo / ClientInfo objects and returns a list of insight strings.
"""

RETRY_RATE_THRESHOLD = 0.2    # 20% of frames
WEAK_SIGNAL_DBM = -70
HIGH_AIRTIME_PCT = 40
MIN_FRAMES_ACTIVE = 5
SIGNAL_INSTABILITY_THRESHOLD = 10   # dBm standard deviation


def _std(values):
    if len(values) < 2:
        return 0.0
    n = len(values)
    mean = sum(values) / n
    return (sum((x - mean) ** 2 for x in values) / n) ** 0.5


def _evaluate_client(client) -> list:
    alerts = []

    if client.signal is not None and client.signal < WEAK_SIGNAL_DBM:
        alerts.append("WEAK_SIGNAL")

    if client.retries / max(1, client.frames) > RETRY_RATE_THRESHOLD:
        alerts.append("HIGH_RETRIES")

    if client.aatime_pct > HIGH_AIRTIME_PCT:
        alerts.append("HIGH_USAGE")

    if client.frames < MIN_FRAMES_ACTIVE:
        alerts.append("IDLE")

    hist = list(client.signal_hist)

    # Detect sustained signal degradation (compare oldest 3 vs newest 3 samples)
    if len(hist) >= 6:
        recent = sum(hist[-3:]) / 3
        older = sum(hist[:3]) / 3
        if recent - older < -8:
            alerts.append("SIGNAL_DEGRADING")

    # Detect erratic signal (high variance)
    if len(hist) >= 5 and _std(hist) > SIGNAL_INSTABILITY_THRESHOLD:
        alerts.append("SIGNAL_UNSTABLE")

    return alerts


def _evaluate_ap(ap) -> list:
    alerts = []

    if ap.retries / max(1, ap.frames) > RETRY_RATE_THRESHOLD:
        alerts.append("HIGH_RETRIES")

    if ap.enc and ap.enc.lower() == "open":
        alerts.append("OPEN_NETWORK")

    clients = list(ap.clients.values())
    if clients:
        weak = sum(1 for c in clients if c.signal is not None and c.signal < WEAK_SIGNAL_DBM)
        if weak / len(clients) > 0.5:
            alerts.append("MANY_WEAK_CLIENTS")

    hist = list(ap.frame_hist)
    if len(hist) >= 5 and _std(hist) > SIGNAL_INSTABILITY_THRESHOLD:
        alerts.append("SIGNAL_UNSTABLE")

    return alerts


def evaluate(entity) -> list:
    """
    Return a list of alert strings for an APInfo or ClientInfo.
    Returns an empty list when no issues are detected.
    """
    # Lazy import avoids circular dependency at module load time
    from network_store import APInfo, ClientInfo

    if isinstance(entity, APInfo):
        return _evaluate_ap(entity)
    if isinstance(entity, ClientInfo):
        return _evaluate_client(entity)
    return []
