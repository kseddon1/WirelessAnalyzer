"""Explainable heuristics layer: observations -> diagnoses.

Turns the raw OBS_* observations produced by the engine (see observations.py)
into actionable, explainable diagnoses.  Each heuristic is a pure function of
the current state + the observation ring buffer, so it is deterministic,
testable, and trivially reviewed before any LLM interpretation is added.

Heuristics intentionally do NOT fire events themselves -- they return
Diagnosis objects.  Callers (the detector, the TUI, the API, an LLM
interpreter, an EDA webhook) decide what to do with them.

Four observation categories are covered:

  connectivity   roams, disconnects, reassocs, auth failures, BSSID changes
  radio          RSSI/SNR, retries, channel utilisation, noise, PHY rates,
                 band differences
  performance    throughput drops, latency, packet loss, connected-but-idle
  protocol       deauth/disassoc, handshake/EAP failures, mgmt anomalies

Five starter heuristics (A-E) correspond to the documented symptom areas:

  A  Weak / deteriorating link              -- coverage / link-quality problem
  B  Sticky client                          -- client won't roam to a better AP
  C  Roaming disruption                     -- roam followed by loss/latency burst
  D  Connected but broken                   -- healthy RF association, nothing passes
  E  Client-specific incompatibility        -- failures cluster on one client type

Every numeric threshold comes from config.Thresholds (the obs_* fields) and is
an initial investigation value, not a universal Wi-Fi standard.  Citations
point to Cisco Meraki Documentation and Microsoft Learn where applicable.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import Engine

from .model import Client
from .observations import (ObservationStore,
                           CONNECTIVITY, RADIO, PERFORMANCE, PROTOCOL,
                           OBS_ROAM, OBS_DISCONNECT, OBS_ASSOC_FAIL,
                           OBS_AUTH_FAIL, OBS_RETRY_SPIKE, OBS_RSSI_DROP,
                           OBS_CHANNEL_UTIL, OBS_DEAUTH, OBS_DISASSOC,
                           OBS_HANDSHAKE_FAIL, OBS_EAP_FAILURE,
                           OBS_THROUGHPUT_DROP, OBS_PACKET_LOSS,
                           OBS_CONNECTED_IDLE, OBS_RATE_CHANGE,
                           OBS_LATENCY_SPIKE)


@dataclass
class Diagnosis:
    """One explainable diagnosis with its supporting evidence."""

    code: str                  # HEUR_A .. HEUR_E
    name: str                  # human-readable name
    confidence: float          # 0.0 -> 1.0
    severity: str              # info | warning | critical
    summary: str               # one-line claim
    explanation: str           # plain-English "why" (observation-based)
    evidence: list = field(default_factory=list)   # observation dicts
    clients: list = field(default_factory=list)    # client MACs implicated
    bssids: list = field(default_factory=list)     # BSSIDs implicated
    recommended: str = ""      # suggested next step
    citation: str = ""         # source URL for the underlying concept

    def as_dict(self):
        return {
            "code": self.code, "name": self.name, "confidence": self.confidence,
            "severity": self.severity, "summary": self.summary,
            "explanation": self.explanation, "evidence": self.evidence,
            "clients": self.clients, "bssids": self.bssids,
            "recommended": self.recommended, "citation": self.citation,
        }


def _recent(store, seconds, now=None):
    return store.window(seconds, now)


def _client_roams(store, client, window, now=None):
    return [o for o in store.by_client(client, window, now) if o.obs_type == OBS_ROAM]


def _client_disconnects(store, client, window, now=None):
    return [o for o in store.by_client(client, window, now) if o.obs_type == OBS_DISCONNECT]


def _client_rssi_drops(store, client, window, now=None):
    return [o for o in store.by_client(client, window, now) if o.obs_type == OBS_RSSI_DROP]


def _client_retries(store, client, window, now=None):
    return [o for o in store.by_client(client, window, now) if o.obs_type == OBS_RETRY_SPIKE]


def _bssid_deauths(store, bssid, window, now=None):
    return [o for o in store.by_bssid(bssid, window, now)
            if o.obs_type in (OBS_DEAUTH, OBS_DISASSOC)]


# ------------------------------------------------------------------- heuristic A

def heuristic_a_weak_link(eng: Engine, now: Optional[float] = None) -> list[Diagnosis]:
    """(A) Weak / deteriorating link.

    RSSI below the weak threshold (default −70 dBm) combined with a sustained
    retry rate above obs_retry_pct, over obs_active_window seconds, indicates a
    coverage / link-quality problem rather than an upper-layer fault.

    Citations: Cisco Meraki docs on RSSI and retry rates as link-quality
    indicators; Microsoft Learn Wi-Fi troubleshooting (signal strength / retry
    rate as primary RF health metrics).
    """
    th = eng.th
    out = []
    window = th.active_window
    for cl in eng.clients.values():
        if cl.bssid is None:
            continue
        ap = eng.aps.get(cl.bssid)
        if ap is None:
            continue
        if cl.signal.avg is None:
            continue
        # RSSI must be weak AND retries elevated over the window.
        weak_rssi = cl.signal.avg < th.obs_rssi_weak
        rssi_drops = _client_rssi_drops(eng.observations, cl.mac, window, now)
        d, _ = cl.history.window("data", window)
        rr, _ = cl.history.window("data_retries", window)
        retry_pct = 100.0 * rr / d if d else 0.0
        retries_high = d >= th.obs_retry_min_frames and retry_pct >= th.obs_retry_pct

        if not (weak_rssi or rssi_drops) or not retries_high:
            continue

        parts = []
        if weak_rssi:
            parts.append(f"RSSI {cl.signal.avg:.0f} dBm (< {th.obs_rssi_weak:.0f})")
        if rssi_drops:
            parts.append(f"{len(rssi_drops)} RSSI-drop observations in {window:.0f}s")
        parts.append(f"{retry_pct:.0f}% retries over {d} frames (>{th.obs_retry_pct:.0f}%)")

        conf = 0.6
        if weak_rssi and retries_high:
            conf = 0.8
        if rssi_drops and retries_high:
            conf = 0.85

        out.append(Diagnosis(
            code="HEUR_A", name="Weak / deteriorating link",
            confidence=conf, severity="warning",
            summary=(f"{cl.mac} has a weak/deteriorating link to {ap.bssid}: "
                     f"{'; '.join(parts)}"),
            explanation=("The client's signal is weak and/or falling while retries "
                         "are sustained, which is the classic signature of a "
                         "coverage or link-quality problem at the RF layer."),
            evidence=[o.as_event(eng.cfg.sensor_id, i)
                      for i, o in enumerate(
                          rssi_drops + _client_retries(eng.observations, cl.mac,
                                                       window, now))],
            clients=[cl.mac], bssids=[ap.bssid],
            recommended=(f"Check AP {ap.bssid} placement/power toward {cl.mac}, or "
                         f"steer the client to a closer/stronger AP of SSID "
                         f"{ap.display_ssid or ap.bssid}."),
            citation="https://documentation.meraki.com/MR/Monitoring_and_Reporting/"
                     "Monitor_Client_Connectivity_Details"))
    return out


# ------------------------------------------------------------------- heuristic B

def heuristic_b_sticky_client(eng: Engine, now: Optional[float] = None) -> list[Diagnosis]:
    """(B) Sticky client.

    A client is weakly associated to its current AP while a materially stronger
    neighbor (same SSID) is audible, and the client has been associated long
    enough that it should have considered roaming.  Roaming is a client
    decision, so this flags the possibility without blaming the AP.

    Citations: Cisco Meraki / 802.11k/v roaming guidance; Microsoft Learn on
    client-driven roam decisions and sticky-client symptoms.
    """
    th = eng.th
    out = []
    min_assoc = th.obs_sticky_min_assoc_s
    neigh_db = th.obs_sticky_neighbor_db
    lookback = th.obs_sticky_roam_lookback_s
    for cl in eng.clients.values():
        if cl.bssid is None or cl.state != "associated":
            continue
        ap = eng.aps.get(cl.bssid)
        if ap is None or ap.signal.avg is None:
            continue
        # Must be weak on the current link.
        if cl.signal.avg is None or cl.signal.avg >= th.obs_sticky_rssi:
            continue
        # Associated long enough that roaming should have been considered.
        assoc_for = now - cl.state_since if cl.state_since else 0
        if assoc_for < min_assoc:
            continue
        # Hasn't roamed recently (otherwise it's actively roaming, not stuck).
        recent_roams = _client_roams(eng.observations, cl.mac, lookback, now)
        if recent_roams:
            continue
        # Find a stronger neighbor on the same SSID.
        better = [a for a in eng.aps.values()
                  if a is not ap and a.ssid == ap.ssid and not a.lost
                  and a.signal.avg is not None and now - a.last_seen < 60
                  and a.signal.avg - ap.signal.avg >= neigh_db]
        if not better:
            continue
        b = max(better, key=lambda a: a.signal.avg)
        conf = min(0.9, 0.5 + (b.signal.avg - ap.signal.avg) / 40.0)
        out.append(Diagnosis(
            code="HEUR_B", name="Sticky client",
            confidence=conf, severity="info",
            summary=(f"{cl.mac} stays on {ap.bssid} (client RSSI "
                     f"{cl.signal.avg:.0f} dBm) while {b.bssid} is "
                     f"{b.signal.avg - ap.signal.avg:.0f} dB stronger "
                     f"on the same SSID ({ap.display_ssid}) after "
                     f"{assoc_for:.0f}s associated"),
            explanation=("Roaming is a client decision: a client can remain on a "
                         "weak AP even when a stronger neighbor of the same SSID "
                         "is audible. This is a possible sticky client, not an AP "
                         "fault. Consider 802.11k/v BSS Transition Management to "
                         "encourage the roam."),
            evidence=[{"type": "rssi", "client": cl.mac, "bssid": ap.bssid,
                       "rssi": cl.signal.avg},
                      {"type": "neighbor", "bssid": b.bssid, "rssi": b.signal.avg,
                       "advantage_db": round(b.signal.avg - ap.signal.avg, 1)}],
            clients=[cl.mac], bssids=[ap.bssid, b.bssid],
            recommended=(f"Consider sending an 802.11v BTM request to {cl.mac} "
                         f"steering it toward {b.bssid} (SSID {ap.display_ssid})."),
            citation="https://documentation.meraki.com/MR/Monitoring_and_Reporting/"
                     "Monitor_Client_Connectivity_Details"))
    return out


# ------------------------------------------------------------------- heuristic C

def heuristic_c_roaming_disruption(eng: Engine, now: Optional[float] = None
                                   ) -> list[Diagnosis]:
    """(C) Roaming disruption.

    A roam is followed within a short window by a burst of packet loss or
    latency, indicating a roaming-performance issue (the roam itself, or the
    new AP, is causing user-visible disruption rather than fixing it).

    Citations: Microsoft Learn Wi-Fi roaming troubleshooting; Cisco Meraki
    docs on roam time and post-roam client experience.
    """
    th = eng.th
    out = []
    window = th.obs_roam_disruption_window_s
    for cl in eng.clients.values():
        roams = _client_roams(eng.observations, cl.mac, window * 2, now)
        for roam in roams:
            r_t = roam.ts
            if r_t < now - window * 2:
                continue
            # Look at the window right after the roam for loss/latency.
            loss = [o for o in eng.observations.by_client(cl.mac, window, now)
                    if o.obs_type in (OBS_PACKET_LOSS, OBS_LATENCY_SPIKE)
                    and r_t <= o.ts <= r_t + window]
            disc = _client_disconnects(eng.observations, cl.mac, window, now)
            disc = [d for d in disc if r_t <= d.ts <= r_t + window]
            if not loss and not disc:
                continue
            ap = eng.aps.get(cl.bssid) if cl.bssid else None
            to_bssid = roam.details.get("to_bssid") if roam.details else None
            conf = 0.7 if loss else 0.55
            out.append(Diagnosis(
                code="HEUR_C", name="Roaming disruption",
                confidence=conf, severity="warning",
                summary=(f"{cl.mac} roamed to {to_bssid or cl.bssid} at "
                         f"{r_t:.0f} and saw {len(loss)} loss/latency "
                         f"observation(s) plus {len(disc)} disconnect(s) in "
                         f"the next {window:.0f}s"),
                explanation=("A roam should improve or preserve the client's "
                             "experience; a burst of loss/latency or disconnects "
                             "immediately after means the roam (or the target AP) "
                             "is causing user-visible disruption."),
                evidence=[o.as_event(eng.cfg.sensor_id, i) for i, o in enumerate(loss + disc)],
                clients=[cl.mac],
                bssids=[roam.details.get("from_bssid")] if roam.details else [],
                recommended=(f"Inspect the target AP ({to_bssid}) and the "
                             f"roam decision (802.11k/v/r state) for {cl.mac}."),
                citation="https://learn.microsoft.com/en-us/training/modules/"
                         "troubleshoot-wi-fi-connections/"))
    return out


# ------------------------------------------------------------------- heuristic D

def heuristic_d_connected_but_broken(eng: Engine, now: Optional[float] = None
                                     ) -> list[Diagnosis]:
    """(D) Connected but broken.

    The client has a healthy association (good RSSI, low retries) yet passes
    little or no data, suggesting the problem is above the RF layer -- DHCP,
    DNS, gateway, captive portal, or the upstream internet rather than Wi-Fi.

    Citations: Microsoft Learn "healthy Wi-Fi link vs healthy internet
    connection" distinction; Cisco Meraki DNS/DHCP troubleshooting.
    """
    th = eng.th
    out = []
    idle_s = th.obs_connected_idle_s
    for cl in eng.clients.values():
        if cl.bssid is None or cl.state != "associated":
            continue
        ap = eng.aps.get(cl.bssid)
        if ap is None:
            continue
        # Can't claim healthy RF without a signal sample.
        if cl.signal.avg is None:
            continue
        # Healthy RF: not weak, retries low.
        if cl.signal.avg < th.low_rssi:
            continue
        d, _ = cl.history.window("data", 10)
        rr, _ = cl.history.window("data_retries", 10)
        if d >= th.retry_min_frames and 100.0 * rr / d >= th.retry_pct:
            continue
        # Passing little or no data recently.
        if cl.last_data is not None and now - cl.last_data < idle_s:
            continue
        # Has been associated long enough to expect traffic if it were useful.
        assoc_for = now - cl.state_since if cl.state_since else 0
        if assoc_for < idle_s:
            continue
        conf = 0.75
        out.append(Diagnosis(
            code="HEUR_D", name="Connected but broken",
            confidence=conf, severity="warning",
            summary=(f"{cl.mac} is associated to {ap.bssid} with good RF "
                     f"(RSSI {cl.signal.avg:.0f} dBm, retries low) but has passed "
                     f"little/no data for {idle_s:.0f}s -- the fault is likely "
                     f"above the RF layer"),
            explanation=("A strong, clean association that carries no traffic "
                         "means Wi-Fi is probably not the root cause. Check DHCP "
                         "lease, DNS resolution, gateway reachability, captive "
                         "portal state, and the upstream internet path."),
            evidence=[{"type": "rssi", "client": cl.mac, "bssid": ap.bssid,
                       "rssi": cl.signal.avg},
                      {"type": "idle_s", "client": cl.mac,
                       "seconds_since_data": None if cl.last_data is None
                       else round(now - cl.last_data, 1)}],
            clients=[cl.mac], bssids=[ap.bssid],
            recommended=(f"Ping the gateway and a public DNS resolver from "
                         f"{cl.mac}'s VLAN; check DHCP/DNS/captive-portal state "
                         f"for SSID {ap.display_ssid or ap.bssid}."),
            citation="https://learn.microsoft.com/en-us/training/modules/"
                     "troubleshoot-wi-fi-connections/"))
    return out


# ------------------------------------------------------------------- heuristic E

def heuristic_e_client_specific(eng: Engine, now: Optional[float] = None
                                ) -> list[Diagnosis]:
    """(E) Client-specific incompatibility.

    Failures cluster on one client model / driver / security-mode / feature
    combination, pointing at a client-specific cause rather than a network-wide
    fault.  Clustering is detected by grouping failure observations by client
    vendor/randomized status and by the AP security they were failing against.

    Citations: Cisco Meraki client-specific troubleshooting; Microsoft Learn on
    isolating client-driver incompatibilities.
    """
    th = eng.th
    out = []
    window = th.auth_fail_window
    # Group protocol/auth failures by client.
    by_client = {}
    for cl in eng.clients.values():
        fails = [o for o in eng.observations.by_client(cl.mac, window, now)
                 if o.obs_type in (OBS_AUTH_FAIL, OBS_ASSOC_FAIL,
                                   OBS_HANDSHAKE_FAIL, OBS_EAP_FAILURE)]
        disc = _client_disconnects(eng.observations, cl.mac, window, now)
        total = len(fails) + len(disc)
        if total < 2:
            continue
        by_client[cl.mac] = (cl, fails, disc, total)

    if len(by_client) < 2:
        return out   # no cross-client clustering signal

    # Look for a common denominator: same security/AP class failing only some
    # clients, or one client failing across many APs (client-side issue).
    # Signal: a client with a high failure rate while peers on the same AP do not.
    for ap in eng.aps.values():
        members = [(m, cl, fails, disc, t) for m, (cl, f, d, t) in by_client.items()
                   if cl.bssid == ap.bssid]
        if len(members) < 2:
            continue
        total_fail = sum(t for _, _, _, _, t in members)
        if total_fail < 3:
            continue
        # Find clients failing disproportionately vs peers on this AP.
        for m2, cl2, f2, d2, t2 in members:
            peers = [t3 for _, _, _, _, t3 in members if _ != m2]
            if not peers:
                continue
            peer_avg = sum(peers) / len(peers)
            if peer_avg == 0:
                continue
            ratio = t2 / peer_avg
            if ratio >= 2.0 and t2 >= 3:
                ap_sec = ap.security or "unknown"
                conf = min(0.9, 0.55 + ratio / 10.0)
                out.append(Diagnosis(
                    code="HEUR_E", name="Client-specific incompatibility",
                    confidence=conf, severity="warning",
                    summary=(f"{cl2.mac} ({cl2.vendor or 'unknown vendor'}, "
                             f"{'randomized' if cl2.randomized else 'fixed MAC'}) "
                             f"has {t2} failures on {ap.bssid} ({ap_sec}) vs a "
                             f"peer average of {peer_avg:.1f} -- a "
                             f"client/driver/security-mode incompatibility"),
                    explanation=("Failures concentrate on one client type while "
                                 "peers on the same AP are fine, which points at "
                                 "the client (driver, firmware, security-mode "
                                 "support, PMF/802.11w) rather than the network."),
                    evidence=[o.as_event(eng.cfg.sensor_id, i)
                              for i, o in enumerate(f2 + d2)],
                    clients=[cl2.mac], bssids=[ap.bssid],
                    recommended=(f"Update {cl2.mac}'s driver/firmware, or test "
                                 f"with PMF/802.11w and the security mode of "
                                 f"{ap.display_ssid or ap.bssid} ({ap_sec}) "
                                 f"disabled to isolate the incompatibility."),
                    citation="https://documentation.meraki.com/MR/Monitoring_and_Reporting/"
                             "Monitor_Client_Connectivity_Details"))
    return out


# ------------------------------------------------------------------- registry

HEURISTICS = {
    "A": heuristic_a_weak_link,
    "B": heuristic_b_sticky_client,
    "C": heuristic_c_roaming_disruption,
    "D": heuristic_d_connected_but_broken,
    "E": heuristic_e_client_specific,
}

HEURISTIC_NAMES = {
    "A": "Weak / deteriorating link",
    "B": "Sticky client",
    "C": "Roaming disruption",
    "D": "Connected but broken",
    "E": "Client-specific incompatibility",
}


def run_heuristics(eng: Engine, codes: Optional[str] = None,
                   now: Optional[float] = None) -> list[Diagnosis]:
    """Run the requested heuristics (default: all A-E).

    `codes` is a string like "ABC" or "AE". Returns a flat list of Diagnosis
    objects sorted by confidence descending.
    """
    want = set(codes) if codes else set(HEURISTICS)
    results = []
    for code, fn in HEURISTICS.items():
        if code not in want:
            continue
        try:
            results.extend(fn(eng, now))
        except Exception as e:  # one broken heuristic must not kill the rest
            import logging
            log = logging.getLogger("wlanscope.heuristics")
            log.warning("heuristic %s failed: %s", code, e)
    results.sort(key=lambda d: d.confidence, reverse=True)
    return results
