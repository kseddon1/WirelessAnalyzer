"""Detectors: AP alerts, evil-twin scoring and per-client status.

Runs once per engine tick with the engine lock held. Alerts are stateful:
an event with state "raised" fires when a condition starts, and an
"<ALERT>_CLEARED" event fires once it has been false for the hold time.
"""

import statistics
from collections import Counter

from .constants import SECURITY_RANK

# client issue -> (severity, short label for the UI)
CLIENT_ISSUES = {
    "EVIL_TWIN": ("critical", "EVIL-TWIN"),
    "DEAUTH_ATTACK": ("critical", "DEAUTH-ATK"),
    "HANDSHAKE_FAIL": ("warning", "4WAY-FAIL"),
    "AUTH_FAILURE": ("warning", "AUTH-FAIL"),
    "ROAMING_STORM": ("warning", "ROAM-STORM"),
    "HIGH_RETRY": ("warning", "HIGH-RETRY"),
    "WEAK_SIGNAL": ("info", "WEAK-SIGNAL"),
    "LOW_RATE": ("info", "LOW-RATE"),
    "STICKY": ("info", "STICKY?"),
    "HIGH_UTIL": ("info", "HIGH-UTIL"),
}
ISSUE_PRIORITY = list(CLIENT_ISSUES)
ACTIVITY_LABEL = {"ACTIVE": "ACTIVE", "POWER_SAVE": "PWR-SAVE", "IDLE": "IDLE",
                  "PROBING": "PROBING", "CONNECTING": "CONNECTING",
                  "DISCONNECTED": "DISCONN", "SEEN": "SEEN", "GONE": "GONE"}

TWIN_ALERTS = ("EVIL_TWIN", "SPOOFED_BSSID", "KARMA")
LATCHED = {"SECURITY_DOWNGRADE": 600, "SECURITY_CHANGED": 600}
ISSUE_HOLD = 30.0


def status_label(code):
    if code in CLIENT_ISSUES:
        return CLIENT_ISSUES[code][1]
    return ACTIVITY_LABEL.get(code, code)


class Detector:
    def __init__(self, engine):
        self.e = engine

    @property
    def th(self):
        return self.e.th

    @property
    def bus(self):
        return self.e.bus

    # ----------------------------------------------------------- AP alerts
    def _alert(self, ap, code, active, sev, msg, now, details=None, hold=30.0,
               category="security"):
        cur = ap.alerts.get(code)
        if active:
            if cur is None:
                ap.alerts[code] = {"severity": sev, "message": msg, "since": now,
                                   "last_true": now, "details": details or {}, "hold": hold}
                self.bus.emit(code, sev, category, msg, ssid=ap.ssid, bssid=ap.bssid,
                              channel=ap.channel, band=ap.band, rssi=ap.signal.avg,
                              state="raised", details=details)
            else:
                escalated = _sev(sev) > _sev(cur["severity"])
                cur.update(message=msg, last_true=now, details=details or {})
                if escalated:
                    cur["severity"] = sev
                    self.bus.emit(code, sev, category, msg, ssid=ap.ssid, bssid=ap.bssid,
                                  channel=ap.channel, band=ap.band, rssi=ap.signal.avg,
                                  state="raised", details=details)
        elif cur is not None and now - cur["last_true"] >= cur.get("hold", hold):
            del ap.alerts[code]
            self.bus.emit(f"{code}_CLEARED", "info", category,
                          f"{code} cleared on {ap.bssid} ({ap.display_ssid})",
                          ssid=ap.ssid, bssid=ap.bssid, channel=ap.channel,
                          band=ap.band, state="cleared",
                          details={"active_for_s": round(now - cur["since"], 1)})
            self.bus.reset_cooldown((code, ap.bssid))

    def new_ap(self, ap, now):
        if self.e.learning:
            return
        self.bus.emit("AP_NEW", "info", "ap",
                      f"new BSS {ap.bssid} '{ap.display_ssid}' ch{ap.channel} {ap.security}",
                      ssid=ap.ssid, bssid=ap.bssid, channel=ap.channel, band=ap.band,
                      rssi=ap.signal.avg,
                      details={"vendor": ap.vendor, "security": ap.security,
                               "generation": ap.generation, "width": ap.width})

    def broadcast_deauth(self, ap, kind, reason, now):
        from .constants import reason_text
        self.bus.emit("BROADCAST_DEAUTH", "warning", "security",
                      f"broadcast {kind} from {ap.bssid} ({ap.display_ssid}): {reason_text(reason)}",
                      ssid=ap.ssid, bssid=ap.bssid, channel=ap.channel, band=ap.band,
                      rssi=ap.signal.avg, details={"kind": kind, "reason": reason,
                                                   "clients": len(ap.clients)},
                      cooldown=60)

    def security_changed(self, ap, old, old_class, new, new_class, now):
        down = SECURITY_RANK.get(new_class, 0) < SECURITY_RANK.get(old_class, 0)
        code = "SECURITY_DOWNGRADE" if down else "SECURITY_CHANGED"
        self._alert(ap, code, True, "critical" if down else "warning",
                    f"{ap.bssid} ({ap.display_ssid}) security changed {old} -> {new}",
                    now, {"old": old, "new": new}, hold=LATCHED[code])

    def run(self, now):
        th = self.th
        e = self.e
        recent_aps = []
        for ap in list(e.aps.values()):
            if not ap.beacon_seen:
                if ap.deauth_times:          # floods matter even if we never heard a beacon
                    self._deauth_check(ap, now)
                continue
            if now - ap.last_seen > th.ap_timeout:
                if not ap.lost:
                    ap.lost = True
                    if ap.counters.beacons >= 10 and ap.last_seen - ap.first_seen >= 60:
                        managed = self._managed(ap.ssid) is not None
                        self.bus.emit("AP_LOST", "warning" if managed else "info", "ap",
                                      f"BSS {ap.bssid} ({ap.display_ssid}) not heard for "
                                      f"{int(now - ap.last_seen)}s",
                                      ssid=ap.ssid, bssid=ap.bssid, channel=ap.channel,
                                      band=ap.band, state="raised",
                                      details={"last_seen": ap.last_seen,
                                               "last_rssi": ap.signal.avg})
                    ap.alerts.clear()
                continue
            if ap.lost:
                ap.lost = False
                self.bus.emit("AP_LOST_CLEARED", "info", "ap",
                              f"BSS {ap.bssid} ({ap.display_ssid}) is back",
                              ssid=ap.ssid, bssid=ap.bssid, channel=ap.channel,
                              band=ap.band, state="cleared")
                self.bus.reset_cooldown(("AP_LOST", ap.bssid))
            recent_aps.append(ap)
            self._ap_checks(ap, now)

        self._evil_twins(recent_aps, now)

        new = sum(1 for t in e.new_bss_times if now - t < 60)
        if new >= th.beacon_flood_new_bss and not e.learning:
            self.bus.emit("BEACON_FLOOD", "warning", "security",
                          f"{new} new BSSIDs appeared in the last minute",
                          details={"new_bss_per_min": new}, cooldown=300)

        for cl in list(e.clients.values()):
            self._client(cl, now)

    def _ap_checks(self, ap, now):
        th = self.th
        sc = ap.security_class
        flags = set()
        if ap.hidden:
            flags.add("HIDDEN")
        if ap.wps and ap.wps.get("state") == "configured" and not ap.wps.get("locked"):
            flags.add("WPS")
        if sc == "WPA2" and ap.mfp == "none":
            flags.add("NO_PMF")
        if ap.security and "WPA2/WPA3" in ap.security:
            flags.add("WPA3_TRANSITION")
        if ap.generation in ("b", "g/a"):
            flags.add("LEGACY")
        if ap.wds_peers:
            flags.add("WDS/MESH")
        ap.flags = flags

        self._alert(ap, "OPEN_NETWORK", sc == "OPEN",
                    "warning" if self._managed(ap.ssid) else "info",
                    f"open (unencrypted) network '{ap.display_ssid}' on {ap.bssid}", now,
                    {"security": ap.security}, hold=0)
        weak = sc in ("WEP", "WPA") or "TKIP" in ap.pairwise
        self._alert(ap, "WEAK_SECURITY", weak, "warning",
                    f"weak security {ap.security} {'/'.join(ap.pairwise)} on {ap.bssid}",
                    now, {"security": ap.security, "pairwise": ap.pairwise}, hold=0)

        self._deauth_check(ap, now)

        regs = [x for x in ap.tsf_regressions if now - x[0] < th.tsf_window]
        flaps = [x for x in ap.claimed_channels if now - x[0] < th.tsf_window]
        reasons = []
        if len(regs) >= th.tsf_regression_count:
            reasons.append(f"{len(regs)} beacon TSF discontinuities in {th.tsf_window:.0f}s "
                           "(two transmitters using one BSSID)")
        if len(flaps) >= th.channel_flap_count:
            chans = sorted({c for x in flaps for c in x[1:]})
            reasons.append(f"beacons claim alternating channels {chans}")
        self._alert(ap, "SPOOFED_BSSID", bool(reasons), "critical",
                    f"BSSID {ap.bssid} ({ap.display_ssid}) appears cloned: " + "; ".join(reasons),
                    now, {"reasons": reasons}, hold=120)

        others = [s for s, t in ap.probe_resp_ssids.items()
                  if now - t < 300 and s != ap.ssid]
        self._alert(ap, "KARMA", len(others) >= th.karma_ssid_count, "critical",
                    f"{ap.bssid} answers probes for {len(others)} different SSIDs "
                    "(Karma/MANA rogue AP)", now, {"ssids": sorted(others)[:20]}, hold=300)

        util = (ap.bss_load or {}).get("util_pct")
        self._alert(ap, "HIGH_CHANNEL_UTIL", util is not None and util >= th.high_channel_util_pct,
                    "warning", f"{ap.bssid} reports {util}% channel utilisation", now,
                    {"util_pct": util, "stations": (ap.bss_load or {}).get("stations")},
                    hold=60, category="rf")

        d, _ = ap.history.window("data", 10)
        rr, _ = ap.history.window("data_retries", 10)
        pct = 100.0 * rr / d if d else 0.0
        self._alert(ap, "HIGH_RETRY", d >= 2 * th.retry_min_frames and pct >= th.bss_retry_pct,
                    "warning", f"{pct:.0f}% of data frames on {ap.bssid} are retries", now,
                    {"retry_pct": round(pct, 1), "data_frames": d}, hold=60, category="rf")

        for code, hold in LATCHED.items():
            if code in ap.alerts:
                self._alert(ap, code, False, "info", "", now, hold=hold)

    def _deauth_check(self, ap, now):
        th = self.th
        n = sum(1 for t in ap.deauth_times if now - t < th.deauth_window)
        self._alert(ap, "DEAUTH_FLOOD", n >= th.deauth_flood_count, "critical",
                    f"{n} deauth/disassoc frames in {th.deauth_window:.0f}s on {ap.bssid}",
                    now, {"count": n, "window_s": th.deauth_window})

    def _managed(self, ssid):
        for m in self.e.cfg.managed:
            if m.ssid == ssid:
                return m
        return None

    def _evil_twins(self, aps, now):
        th = self.th
        groups = {}
        for ap in aps:
            if ap.ssid:
                groups.setdefault(ap.ssid, []).append(ap)
        for ssid, group in groups.items():
            m = self._managed(ssid)
            classes = Counter(a.security_class for a in group)
            vies = Counter(a.vendor_ies for a in group)
            intervals = Counter(a.beacon_interval for a in group)
            countries = Counter(a.country for a in group if a.country)
            for ap in group:
                score, reasons = 0, []
                if m is not None:
                    if m.security and not any(p.lower() in (ap.security or "").lower()
                                              for p in m.security):
                        score += 5
                        reasons.append(f"security '{ap.security}' violates policy {m.security}")
                    if m.allowed_bssids and not any(ap.bssid.startswith(p.lower())
                                                    for p in m.allowed_bssids):
                        score += 3
                        reasons.append("BSSID not in allowed_bssids")
                    if m.allowed_ouis and ap.bssid[:8] not in [o.lower() for o in m.allowed_ouis]:
                        score += 3
                        reasons.append(f"OUI {ap.bssid[:8]} not in allowed_ouis")
                    if m.bands and ap.band not in m.bands:
                        score += 1
                        reasons.append(f"band {ap.band} not expected")
                others = len(group) - 1
                if others >= 1:
                    maj, maj_n = classes.most_common(1)[0]
                    mine = classes[ap.security_class]
                    if ap.security_class != maj and maj_n > mine:
                        score += 3
                        reasons.append(f"security {ap.security} differs from {maj_n} "
                                       f"other BSSIDs using {maj}")
                    elif mine == maj_n and len(classes) > 1:
                        best = max(classes, key=lambda c: SECURITY_RANK.get(c, 0))
                        if SECURITY_RANK.get(ap.security_class, 0) < SECURITY_RANK.get(best, 0):
                            score += 3
                            reasons.append(f"weaker security ({ap.security}) than other "
                                           f"BSSIDs of this SSID ({best})")
                if others >= 2:
                    v, vn = vies.most_common(1)[0]
                    if ap.vendor_ies != v and vn >= 2 and vn >= 2 * vies[ap.vendor_ies]:
                        score += 2
                        reasons.append("vendor-specific IE fingerprint differs from the "
                                       f"other {vn} BSSIDs")
                    bi, bn = intervals.most_common(1)[0]
                    if ap.beacon_interval != bi and bn >= 2:
                        score += 1
                        reasons.append(f"beacon interval {ap.beacon_interval} vs {bi}")
                    if countries:
                        cc, cn = countries.most_common(1)[0]
                        if ap.country and ap.country != cc and cn >= 2:
                            score += 1
                            reasons.append(f"country {ap.country} vs {cc}")
                active = score >= th.evil_twin_score
                sev = "critical" if score >= 5 else "warning"
                self._alert(ap, "EVIL_TWIN", active, sev,
                            f"possible evil twin of '{ssid}' at {ap.bssid}: " + "; ".join(reasons),
                            now, {"score": score, "reasons": reasons,
                                  "ssid_bssids": [a.bssid for a in group],
                                  "managed": m is not None}, hold=120)

    # ----------------------------------------------------------- clients
    def _client(self, cl, now):
        th = self.th
        e = self.e
        age = now - cl.last_seen
        ap = e.aps.get(cl.bssid) if cl.bssid else None
        found = {}

        if age > th.client_timeout:
            activity = "GONE"
        else:
            if ap is not None:
                bad = [c for c in TWIN_ALERTS if c in ap.alerts]
                if bad:
                    found["EVIL_TWIN"] = f"associated to {ap.bssid} flagged {','.join(bad)}"
            dn = sum(1 for t in cl.deauth_times if now - t < th.deauth_window)
            target = e.aps.get(cl.bssid or cl.last_bssid or "")
            flood = target is not None and "DEAUTH_FLOOD" in target.alerts and dn
            if dn >= th.client_deauth_count or flood:
                found["DEAUTH_ATTACK"] = f"{dn} deauth/disassoc in {th.deauth_window:.0f}s"
            fails = [x for x in cl.auth_failures if now - x[0] < th.auth_fail_window]
            if len(fails) >= th.auth_fail_count or any(x[1] == "eap" for x in fails):
                found["AUTH_FAILURE"] = f"{len(fails)} failures, last: {fails[-1][2]}"
            hsf = [x for x in cl.hs_failures if now - x[0] < th.auth_fail_window]
            if len(hsf) >= th.handshake_fail_count or (hsf and cl.hs.get("state") == "failed"):
                found["HANDSHAKE_FAIL"] = hsf[-1][1]
            roams = sum(1 for x in cl.roams if now - x[0] < th.roam_window)
            assocs = sum(1 for t in cl.assoc_times if now - t < th.roam_window)
            if max(roams, assocs) >= th.roam_storm_count:
                found["ROAMING_STORM"] = f"{roams} roams / {assocs} associations in {th.roam_window:.0f}s"
            if cl.bssid:
                d, _ = cl.history.window("data", 10)
                rr, _ = cl.history.window("data_retries", 10)
                if d >= th.retry_min_frames and rr * 100.0 / d >= th.retry_pct:
                    found["HIGH_RETRY"] = f"{rr * 100.0 / d:.0f}% retries over {d} data frames"
            if cl.bssid and cl.last_uplink and now - cl.last_uplink < 60 \
                    and cl.signal.avg is not None:
                snr, est = cl.signal.snr(th.noise_floor)
                if cl.signal.avg < th.low_rssi:
                    found["WEAK_SIGNAL"] = f"RSSI {cl.signal.avg:.0f} dBm"
                elif snr is not None and snr < th.low_snr:
                    found["WEAK_SIGNAL"] = f"SNR {snr:.0f} dB{' (est)' if est else ''}"
            if cl.bssid and ap is not None and ap.generation not in (None, "b", "g/a"):
                rates = list(cl.rates_up) + list(cl.rates_down)
                if len(rates) >= 20:
                    med = statistics.median(rates)
                    if med <= th.low_rate_mbps:
                        found["LOW_RATE"] = f"median PHY rate {med:g} Mbps"
            if ap is not None and cl.signal.avg is not None and cl.signal.avg < th.sticky_rssi \
                    and ap.signal.avg is not None and ap.ssid:
                better = [a for a in e.aps.values()
                          if a is not ap and a.ssid == ap.ssid and not a.lost
                          and a.signal.avg is not None and now - a.last_seen < 60
                          and a.signal.avg - ap.signal.avg >= 10]
                if better:
                    b = max(better, key=lambda a: a.signal.avg)
                    found["STICKY"] = (f"weak link (client {cl.signal.avg:.0f} dBm) while "
                                       f"{b.bssid} is {b.signal.avg - ap.signal.avg:.0f} dB "
                                       "stronger at the sensor")
            if ap is not None:
                fps = cl.history.rate("data")
                kbps = cl.history.rate("data_bytes") * 8 / 1000
                ap_fps = ap.history.rate("data")
                share = fps / ap_fps if ap_fps else 0
                if fps >= th.high_util_fps or kbps >= th.high_util_kbps or (
                        ap_fps >= th.high_util_min_bss_fps and share >= th.high_util_share
                        and len(ap.clients) > 1):
                    found["HIGH_UTIL"] = (f"{fps:.0f} data frames/s, {kbps:.0f} kbps, "
                                          f"{share * 100:.0f}% of BSS data")

            if cl.state == "associated":
                if cl.last_data and now - cl.last_data < th.active_window:
                    activity = "ACTIVE"
                elif cl.power_save:
                    activity = "POWER_SAVE"
                elif cl.last_data is None or now - cl.last_data >= th.idle_after:
                    activity = "IDLE"
                else:
                    activity = "ACTIVE"
            elif cl.state == "probing":
                activity = "PROBING"
            elif cl.state in ("authenticating", "associating"):
                activity = "CONNECTING"
            elif cl.state == "disconnected":
                activity = "DISCONNECTED"
            else:
                activity = "SEEN"

        # flags
        caps = cl.caps or cl.probe_caps
        if caps is not None and not caps.ht and caps.rates:
            cl.flags.add("LEGACY_CLIENT")
        if cl.btm and now - cl.btm[-1][0] < 120:
            cl.flags.add("BTM_STEERED")
        else:
            cl.flags.discard("BTM_STEERED")
        if cl.power_save:
            cl.flags.add("PS")
        else:
            cl.flags.discard("PS")

        # raise / clear issues with hysteresis
        for code, detail in found.items():
            cur = cl.issues.get(code)
            if cur is None:
                sev = CLIENT_ISSUES[code][0]
                cl.issues[code] = {"detail": detail, "severity": sev, "since": now,
                                   "last_true": now}
                self._client_event(cl, ap, f"CLIENT_{code}", sev, detail, "raised")
            else:
                cur["detail"] = detail
                cur["last_true"] = now
        for code in [c for c in cl.issues if c not in found]:
            cur = cl.issues[code]
            if now - cur["last_true"] >= ISSUE_HOLD or activity == "GONE":
                del cl.issues[code]
                if activity != "GONE":
                    self._client_event(cl, ap, f"CLIENT_{code}_CLEARED", "info",
                                       f"{code} cleared", "cleared")
                self.bus.reset_cooldown((f"CLIENT_{code}", cl.bssid))

        status = activity
        if activity != "GONE":
            for code in ISSUE_PRIORITY:
                if code in cl.issues:
                    status = code
                    break
        if status != cl.status:
            cl.status = status
            cl.status_since = now

    def _client_event(self, cl, ap, alert, sev, detail, state):
        ap = ap or self.e.aps.get(cl.last_bssid or "")
        self.bus.emit(alert, sev, "client", f"{cl.mac}: {detail}",
                      ssid=ap.ssid if ap else None, bssid=ap.bssid if ap else cl.bssid,
                      client=cl.mac, channel=ap.channel if ap else None,
                      band=ap.band if ap else None, rssi=cl.signal.avg, state=state,
                      details={"detail": detail, "vendor": cl.vendor,
                               "client_state": cl.state},
                      cooldown=600 if sev == "info" else None)


def _sev(s):
    return {"info": 1, "warning": 2, "critical": 3}.get(s, 0)
