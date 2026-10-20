"""State engine: consumes parsed frames, maintains BSS/client state, ticks
statistics once per second and runs the detectors."""

import logging
import struct
import threading
import time
from collections import deque

from . import constants as C
from .channels import guess_band, he_rate, ht_rate, vht_rate
from .detect import Detector
from .dot11 import (bss_width, find_ie, is_local_admin, is_multicast,
                    llc_ethertype, parse_eapol, parse_ies, summarize_security)
from .model import AccessPoint, Client, Counters, History

log = logging.getLogger(__name__)

# disconnect reasons that indicate an authentication/key problem
AUTH_REASONS = {2, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 29, 45, 49}
HANDSHAKE_REASONS = {14, 15, 17}
# association/auth status codes that are part of normal operation
BENIGN_STATUS = {0, 30, 76, 82, 126}


class ChannelStats:
    __slots__ = ("band", "channel", "counters", "history", "last_seen")

    def __init__(self, band, channel):
        self.band = band
        self.channel = channel
        self.counters = Counters()
        self.history = History()
        self.last_seen = None


class Engine:
    def __init__(self, cfg, bus, oui, live=True):
        self.cfg = cfg
        self.th = cfg.thresholds
        self.bus = bus
        self.oui = oui
        self.live = live
        self.lock = threading.RLock()
        self.aps = {}
        self.clients = {}
        self.channels = {}
        self.obs_time = {}
        self.hoppers = []
        self.totals = Counters()
        self.totals_hist = History()
        self.bad_fcs = 0
        self.dropped = 0
        self.parse_errors = 0
        self.start = None
        self.clock = None              # timestamp of last frame (replay clock)
        self.last_tick = None
        self.new_bss_times = deque(maxlen=2000)
        self.detector = Detector(self)
        bus.clock = self.now

    # ------------------------------------------------------------ clock
    def now(self):
        if self.live or self.clock is None:
            return time.time()
        return self.clock

    @property
    def learning(self):
        return self.start is None or self.now() - self.start < self.th.learning_period

    def on_dwell(self, band, channel, seconds):
        with self.lock:
            k = (band, channel)
            self.obs_time[k] = self.obs_time.get(k, 0.0) + seconds

    def _hopping(self):
        return any(h.hop or h.locked for h in self.hoppers)

    def obs(self, key, now):
        if self._hopping():
            return self.obs_time.get(key, 0.0)
        return now - (self.start or now)

    # ------------------------------------------------------------ lookups
    def _ap(self, bssid, now, create=True):
        ap = self.aps.get(bssid)
        if ap is None and create:
            ap = AccessPoint(bssid, now)
            ap.vendor = self.oui.lookup(bssid)
            self.aps[bssid] = ap
        return ap

    def _client(self, m, now, create=True):
        cl = self.clients.get(m)
        if cl is None and create:
            ap = self.aps.get(m)
            if ap is not None and ap.beacon_seen:
                return None                # that address is an AP
            cl = Client(m, now)
            cl.vendor = self.oui.lookup(m)
            cl.randomized = is_local_admin(m)
            if cl.randomized:
                cl.flags.add("RANDOMIZED_MAC")
            self.clients[m] = cl
        return cl

    @staticmethod
    def _count(ctr, f):
        ctr.frames += 1
        ctr.bytes += f.length
        if f.retry:
            ctr.retries += 1
        if f.protected:
            ctr.protected += 1

    # ------------------------------------------------------------ ingest
    def ingest(self, f):
        with self.lock:
            now = f.ts
            if self.start is None:
                self.start = now
                self.last_tick = now
            if not self.live:
                self.clock = now
            r = f.radio
            if r is not None and r.bad_fcs:
                self.bad_fcs += 1
                return
            self._count(self.totals, f)
            if r is not None and r.channel is not None:
                key = (r.band, r.channel)
                cs = self.channels.get(key)
                if cs is None:
                    cs = self.channels[key] = ChannelStats(r.band, r.channel)
                self._count(cs.counters, f)
                cs.last_seen = now
                self._type_count(cs.counters, f)
            self._type_count(self.totals, f)
            try:
                if f.ftype == C.MGMT:
                    self._mgmt(f, now)
                elif f.ftype == C.DATA:
                    self._data(f, now)
                elif f.ftype == C.CTRL:
                    self._ctrl(f, now)
            except (struct.error, IndexError, ValueError) as e:
                self.parse_errors += 1
                log.debug("frame handling error: %s", e)
            if not self.live and now - self.last_tick >= 1.0:
                self.tick(now)

    @staticmethod
    def _type_count(ctr, f):
        if f.ftype == C.MGMT:
            ctr.mgmt += 1
            if f.subtype == C.BEACON:
                ctr.beacons += 1
        elif f.ftype == C.CTRL:
            ctr.ctrl += 1
        elif f.ftype == C.DATA:
            if f.is_null:
                ctr.null += 1
            else:
                ctr.data += 1
                if f.retry:
                    ctr.data_retries += 1

    # ------------------------------------------------------------ management
    def _mgmt(self, f, now):
        st = f.subtype
        r = f.radio
        sig = r.signal if r else None
        noise = r.noise if r else None
        body = f.body

        if st in (C.BEACON, C.PROBE_RESP):
            if len(body) < 12 or is_multicast(f.a3):
                return
            ap = self._ap(f.a3, now)
            c = ap.counters
            self._count(c, f)
            c.mgmt += 1
            if st == C.BEACON:
                c.beacons += 1
                ap.last_beacon = now
            else:
                c.probe_resp += 1
            ap.last_seen = now
            ap.signal.update(sig, noise)
            if r is not None:
                ap.radio_channel = r.channel
                if r.band:
                    ap.band = r.band
            tsf, bi, cap = struct.unpack_from("<QHH", body, 0)
            ap.beacon_interval = bi
            ap.capability = cap
            if st == C.BEACON:
                self._check_tsf(ap, tsf, now)
            if (st == C.PROBE_RESP or not ap.beacon_seen or now - ap.ie_parsed_at >= 2.0
                    or len(body) != ap.ie_body_len):
                self._apply_ies(ap, parse_ies(body, 12), st, len(body), now)
            else:
                v = find_ie(body, 3, 12)
                if v:
                    self._claim_channel(ap, v[0], now)
            if st == C.PROBE_RESP and not is_multicast(f.a1):
                cl = self.clients.get(f.a1)
                if cl is not None:
                    cl.counters.probe_resp += 1
            return

        if st == C.PROBE_REQ:
            if is_multicast(f.a2):
                return
            cl = self._client(f.a2, now)
            if cl is None:
                return
            self._from_client(cl, f, now)
            cl.counters.probe_req += 1
            info = parse_ies(body, 0)
            if info.ssid:
                cl.probed_ssids[info.ssid] = now
                if len(cl.probed_ssids) > 64:
                    oldest = min(cl.probed_ssids, key=cl.probed_ssids.get)
                    del cl.probed_ssids[oldest]
            if info.ht or info.vht or info.he or cl.probe_caps is None:
                cl.probe_caps = info
            if cl.state in ("seen", "disconnected"):
                self._set_state(cl, "probing", now)
            return

        bssid = f.a3
        if is_multicast(bssid):
            return
        from_ap = f.a2 == bssid
        sta = f.a1 if from_ap else f.a2

        if st == C.AUTH:
            if len(body) < 6:
                return
            algo, seq, status = struct.unpack_from("<HHH", body, 0)
            ap = self._ap(bssid, now)
            self._count(ap.counters, f)
            ap.counters.mgmt += 1
            ap.counters.auth += 1
            if is_multicast(sta):
                return
            cl = self._client(sta, now)
            if cl is None:
                return
            cl.counters.auth += 1
            if from_ap:
                self._from_ap(ap, f, now)
                self._to_client(cl, f)
                if status not in BENIGN_STATUS:
                    self._auth_failure(cl, ap, "auth", C.status_text(status), now,
                                       {"algorithm": C.AUTH_ALGOS.get(algo, algo),
                                        "status": status})
            else:
                self._from_client(cl, f, now)
                if cl.state != "associated" or cl.bssid != bssid:
                    self._set_state(cl, "authenticating", now)
            return

        if st in (C.ASSOC_REQ, C.REASSOC_REQ):
            if from_ap or is_multicast(sta):
                return
            ap = self._ap(bssid, now)
            self._count(ap.counters, f)
            ap.counters.mgmt += 1
            cl = self._client(sta, now)
            if cl is None:
                return
            self._from_client(cl, f, now)
            if st == C.ASSOC_REQ:
                ap.counters.assoc += 1
                cl.counters.assoc += 1
                off = 4
            else:
                ap.counters.reassoc += 1
                cl.counters.reassoc += 1
                off = 10
            if len(body) < off:
                return
            _cap, listen = struct.unpack_from("<HH", body, 0)
            cl.listen_interval = listen
            info = parse_ies(body, off)
            cl.caps = info
            if info.ssid and (ap.ssid is None or ap.hidden) and ap.ssid != info.ssid:
                if ap.hidden:
                    ap.ssid_revealed = True
                ap.ssid = info.ssid
            if info.rsn:
                cl.client_security = {"akm": info.rsn["akm_names"],
                                      "pairwise": info.rsn["pairwise"],
                                      "mfpc": info.rsn["mfpc"], "mfpr": info.rsn["mfpr"]}
            self._set_state(cl, "associating", now)
            return

        if st in (C.ASSOC_RESP, C.REASSOC_RESP):
            if not from_ap or is_multicast(sta) or len(body) < 6:
                return
            ap = self._ap(bssid, now)
            self._count(ap.counters, f)
            ap.counters.mgmt += 1
            self._from_ap(ap, f, now)
            cl = self._client(sta, now)
            if cl is None:
                return
            self._to_client(cl, f)
            _cap, status, aid = struct.unpack_from("<HHH", body, 0)
            if status == 0:
                cl.aid = aid & 0x3FFF
                cl.assoc_times.append(now)
                self._associate(cl, ap, now, "reassoc" if st == C.REASSOC_RESP else "assoc")
            elif status not in BENIGN_STATUS:
                self._auth_failure(cl, ap, "assoc", C.status_text(status), now,
                                   {"status": status})
            return

        if st in (C.DEAUTH, C.DISASSOC):
            reason = None
            if len(body) >= 2 and not f.protected:
                reason = struct.unpack_from("<H", body, 0)[0]
            kind = "deauth" if st == C.DEAUTH else "disassoc"
            ap = self._ap(bssid, now)
            self._count(ap.counters, f)
            ap.counters.mgmt += 1
            setattr(ap.counters, kind, getattr(ap.counters, kind) + 1)
            ap.deauth_times.append(now)
            if from_ap:
                self._from_ap(ap, f, now)
                if is_multicast(sta):
                    self.detector.broadcast_deauth(ap, kind, reason, now)
                    for m in list(ap.clients):
                        cl = self.clients.get(m)
                        if cl:
                            cl.deauth_times.append(now)
                            self._disconnect(cl, kind, reason, "ap(broadcast)", now, quiet=True)
                    return
                cl = self._client(sta, now)
                if cl is None:
                    return
                self._to_client(cl, f)
                cl.deauth_times.append(now)
                by = "ap"
            else:
                if is_multicast(sta):
                    return
                cl = self._client(sta, now)
                if cl is None:
                    return
                self._from_client(cl, f, now)
                by = "client"
            setattr(cl.counters, kind, getattr(cl.counters, kind) + 1)
            self._disconnect(cl, kind, reason, by, now)
            return

        if st in (C.ACTION, C.ACTION_NOACK):
            ap = self.aps.get(bssid)
            if ap is not None:
                self._count(ap.counters, f)
                ap.counters.mgmt += 1
                ap.counters.action += 1
            if is_multicast(sta):
                return
            cl = self.clients.get(sta) if ap is not None else None
            if cl is None:
                return
            cl.counters.action += 1
            if from_ap:
                self._to_client(cl, f)
            else:
                self._from_client(cl, f, now)
            if f.protected or len(body) < 2:
                return
            cat, act = body[0], body[1]
            if cat == 10 and act == 7 and from_ap:
                cl.btm.append((now, "request", None))
                self.bus.emit("BTM_REQUEST", "info", "client",
                              f"AP {bssid} sent BSS Transition request to {cl.mac}",
                              ssid=ap.ssid, bssid=bssid, client=cl.mac,
                              channel=ap.channel, band=ap.band, rssi=cl.signal.avg,
                              cooldown=60)
            elif cat == 10 and act == 8 and not from_ap and len(body) >= 4:
                status = body[3]
                cl.btm.append((now, "response", status))
                self.bus.emit("BTM_RESPONSE", "info", "client",
                              f"{cl.mac} answered BTM: {C.BTM_STATUS.get(status, status)}",
                              ssid=ap.ssid, bssid=bssid, client=cl.mac,
                              channel=ap.channel, band=ap.band,
                              details={"status": status}, cooldown=60)

    def _apply_ies(self, ap, info, st, body_len, now):
        first = not ap.beacon_seen
        if st == C.BEACON:
            ap.ie_parsed_at = now
            ap.ie_body_len = body_len
        if st == C.BEACON and info.ssid_present:
            if info.hidden:
                ap.hidden = True
                if ap.ssid is None:
                    ap.ssid = ""
            else:
                if ap.ssid and ap.ssid != info.ssid and not first and not ap.hidden:
                    self.bus.emit("SSID_CHANGED", "warning", "ap",
                                  f"{ap.bssid} changed SSID '{ap.ssid}' -> '{info.ssid}'",
                                  ssid=info.ssid, bssid=ap.bssid, channel=ap.channel,
                                  details={"old": ap.ssid, "new": info.ssid})
                ap.ssid = info.ssid
                ap.hidden = False
        elif st == C.PROBE_RESP and info.ssid:
            ap.probe_resp_ssids[info.ssid] = now
            if ap.ssid is None or (ap.hidden and not ap.ssid):
                ap.ssid = info.ssid
                ap.ssid_revealed = ap.hidden
        primary = (info.ds_channel or (info.ht_op or {}).get("primary")
                   or ((info.he_op or {}).get("6ghz") or {}).get("primary"))
        if primary:
            if ap.band is None:
                ap.band = guess_band(primary)
            self._claim_channel(ap, primary, now)
        ap.width, ap.center_freq = bss_width(info, ap.band)
        sec, klass = summarize_security(ap.capability & C.CAP_PRIVACY, info.rsn,
                                        info.wpa, info.owe_transition)
        rsn = info.rsn or info.wpa
        if st == C.BEACON and ap.security and ap.security != sec:
            self.detector.security_changed(ap, ap.security, ap.security_class, sec, klass, now)
        ap.security, ap.security_class = sec, klass
        if rsn:
            ap.pairwise = rsn["pairwise"]
            ap.group_cipher = rsn["group"]
            ap.akms = rsn["akm_names"]
            ap.mfp = "required" if rsn["mfpr"] else "capable" if rsn["mfpc"] else "none"
        else:
            ap.pairwise, ap.group_cipher, ap.akms, ap.mfp = [], None, [], "none"
        ap.generation = info.generation
        ap.nss = info.nss
        ap.max_rate = _max_rate(info, ap.width)
        ap.country = info.country or ap.country
        ap.bss_load = info.bss_load
        ap.wps = info.wps
        if info.dtim_period:
            ap.dtim_period = info.dtim_period
        if info.ap_name:
            ap.ap_name = info.ap_name
        if st == C.BEACON or ap.ies is None:
            ap.ies = info
        if info.csa:
            ap.csa = dict(info.csa, t=now)
            self.bus.emit("CHANNEL_SWITCH", "info", "rf",
                          f"{ap.bssid} announced channel switch to {info.csa['new_channel']}",
                          ssid=ap.ssid, bssid=ap.bssid, channel=ap.channel, band=ap.band,
                          details=info.csa, cooldown=120)
        if st == C.BEACON:
            ap.vendor_ies = tuple(sorted(set(info.vendor_ouis)))
            fp = (sec, tuple(ap.pairwise), tuple(ap.akms), ap.mfp, ap.beacon_interval,
                  ap.vendor_ies, ap.generation)
            if ap.fingerprint is not None and fp != ap.fingerprint:
                ap.fingerprint_changes.append((now, ap.fingerprint, fp))
            ap.fingerprint = fp
        if first:
            ap.beacon_seen = True
            self.new_bss_times.append(now)
            self.detector.new_ap(ap, now)

    def _claim_channel(self, ap, ch, now):
        if ap.channel != ch:
            if ap.channel is not None:
                ap.claimed_channels.append((now, ap.channel, ch))
            ap.channel = ch

    def _check_tsf(self, ap, tsf, now):
        if ap.tsf is not None:
            expected = ap.tsf + (now - ap.tsf_at) * 1e6
            if abs(tsf - expected) > 2e6:
                ap.tsf_regressions.append((now, int(expected), tsf))
        ap.tsf = tsf
        ap.tsf_at = now
        ap.uptime = int(tsf / 1e6)

    # ------------------------------------------------------------ helpers
    def _from_client(self, cl, f, now):
        """Frame transmitted by a client."""
        self._count(cl.counters, f)
        if f.ftype == C.MGMT:
            cl.counters.mgmt += 1
        r = f.radio
        if r is not None:
            cl.signal.update(r.signal, r.noise)
            if r.channel is not None:
                cl.chan_key = (r.band, r.channel)
        cl.last_seen = now
        cl.last_uplink = now
        cl.tx_frames += 1
        if f.retry:
            cl.tx_retries += 1

    def _to_client(self, cl, f):
        self._count(cl.counters, f)
        if f.ftype == C.MGMT:
            cl.counters.mgmt += 1
        cl.rx_frames += 1
        if f.retry:
            cl.rx_retries += 1

    def _from_ap(self, ap, f, now):
        r = f.radio
        if r is not None:
            ap.signal.update(r.signal, r.noise)
        ap.last_seen = now

    def _set_state(self, cl, state, now):
        if cl.state != state:
            cl.state = state
            cl.state_since = now

    def _associate(self, cl, ap, now, how):
        prev = cl.bssid
        if prev and prev != ap.bssid:
            old = self.aps.get(prev)
            if old is not None:
                old.clients.discard(cl.mac)
            cl.roams.append((now, prev, ap.bssid))
            same_ess = bool(old is not None and old.ssid and old.ssid == ap.ssid)
            self.bus.emit("CLIENT_ROAMED", "info", "client",
                          f"{cl.mac} roamed {prev} -> {ap.bssid} ({how})",
                          ssid=ap.ssid, bssid=ap.bssid, client=cl.mac,
                          channel=ap.channel, band=ap.band, rssi=cl.signal.avg,
                          details={"from_bssid": prev, "to_bssid": ap.bssid, "how": how,
                                   "same_ess": same_ess,
                                   "from_channel": old.channel if old else None},
                          cooldown=5)
        elif how != "data" and (cl.state != "associated" or prev != ap.bssid):
            self.bus.emit("CLIENT_ASSOCIATED", "info", "client",
                          f"{cl.mac} associated to {ap.display_ssid} ({ap.bssid})",
                          ssid=ap.ssid, bssid=ap.bssid, client=cl.mac,
                          channel=ap.channel, band=ap.band, rssi=cl.signal.avg,
                          details={"how": how, "aid": cl.aid}, cooldown=30)
        elif how == "data" and prev is None and not self.learning \
                and cl.last_disconnect is None:
            self.bus.emit("CLIENT_NEW", "info", "client",
                          f"new client {cl.mac} on {ap.display_ssid} ({ap.bssid})",
                          ssid=ap.ssid, bssid=ap.bssid, client=cl.mac,
                          channel=ap.channel, band=ap.band, rssi=cl.signal.avg,
                          details={"vendor": cl.vendor, "randomized": cl.randomized})
        cl.bssid = ap.bssid
        cl.last_bssid = ap.bssid
        ap.clients.add(cl.mac)
        self._set_state(cl, "associated", now)

    def _disconnect(self, cl, kind, reason, by, now, quiet=False):
        ap = self.aps.get(cl.bssid or cl.last_bssid or "")
        cl.last_disconnect = {"kind": kind, "reason": reason, "reason_text": C.reason_text(reason),
                              "by": by, "t": now, "bssid": cl.bssid or cl.last_bssid}
        if cl.bssid:
            if ap is not None:
                ap.clients.discard(cl.mac)
            cl.last_bssid = cl.bssid
            cl.bssid = None
        self._set_state(cl, "disconnected", now)
        if reason in HANDSHAKE_REASONS:
            cl.hs_failures.append((now, C.reason_text(reason)))
            cl.hs["state"] = "failed"
        if reason in AUTH_REASONS:
            cl.auth_failures.append((now, kind, C.reason_text(reason)))
        if quiet:
            return
        sev = "warning" if reason in AUTH_REASONS else "info"
        self.bus.emit("CLIENT_DISCONNECTED", sev, "client",
                      f"{cl.mac} {kind} by {by}: {C.reason_text(reason)}",
                      ssid=ap.ssid if ap else None, bssid=cl.last_bssid, client=cl.mac,
                      channel=ap.channel if ap else None, band=ap.band if ap else None,
                      rssi=cl.signal.avg,
                      details={"kind": kind, "reason": reason, "by": by,
                               "reason_text": C.reason_text(reason)},
                      cooldown=30)

    def _auth_failure(self, cl, ap, kind, text, now, details=None):
        cl.auth_failures.append((now, kind, text))
        self.bus.emit(f"{kind.upper()}_REJECTED", "warning", "client",
                      f"{ap.bssid} rejected {kind} from {cl.mac}: {text}",
                      ssid=ap.ssid, bssid=ap.bssid, client=cl.mac, channel=ap.channel,
                      band=ap.band, rssi=cl.signal.avg, details=details, cooldown=60)

    # ------------------------------------------------------------ control
    def _ctrl(self, f, now):
        st = f.subtype
        r = f.radio
        if f.a2 is not None:
            ta = f.a2
            ent = self.clients.get(ta) or self.aps.get(ta)
            if ent is not None:
                ent.counters.frames += 1
                ent.counters.ctrl += 1
                ent.counters.bytes += f.length
                if r is not None:
                    ent.signal.update(r.signal, r.noise)
                if isinstance(ent, Client):
                    ent.last_seen = now
                    if st == C.CTRL_PSPOLL:
                        ent.power_save = True
                        ent.counters.ps_poll += 1
                else:
                    ent.last_seen = now
                if st == C.CTRL_RTS:
                    ent.counters.rts += 1
                elif st in (C.CTRL_BA, C.CTRL_BAR):
                    ent.counters.ba += 1
        elif st in (C.CTRL_ACK, C.CTRL_CTS):
            ent = self.clients.get(f.a1) or self.aps.get(f.a1)
            if ent is not None:
                ent.counters.ctrl += 1
                if st == C.CTRL_ACK:
                    ent.counters.ack += 1
                else:
                    ent.counters.cts += 1

    # ------------------------------------------------------------ data
    def _data(self, f, now):
        to, frm = f.to_ds, f.from_ds
        r = f.radio
        if to and frm:
            ap = self.aps.get(f.a2) or self.aps.get(f.a1)
            if ap is not None:
                self._count(ap.counters, f)
                ap.counters.data += 0 if f.is_null else 1
                ap.wds_peers.add(f.a1 if ap.bssid == f.a2 else f.a2)
            return
        if not to and not frm:
            ap = self.aps.get(f.a3)
            if ap is not None:
                self._count(ap.counters, f)
            return
        if to:
            bssid, sta, up = f.a1, f.a2, True
        else:
            bssid, sta, up = f.a2, f.a1, False
        if is_multicast(bssid):
            return
        ap = self._ap(bssid, now)
        c = ap.counters
        self._count(c, f)
        null = f.is_null
        if null:
            c.null += 1
        else:
            c.data += 1
            c.data_bytes += f.length
            if f.retry:
                c.data_retries += 1
        if not up:
            self._from_ap(ap, f, now)
            if r is not None and r.band and ap.band is None:
                ap.band = r.band
            if is_multicast(sta):
                ap.data_mcast += 1
                return
            ap.data_down += 0 if null else 1
        else:
            ap.last_seen = max(ap.last_seen, now)
            ap.data_up += 0 if null else 1
            if is_multicast(sta):
                return
        if sta == bssid:
            return
        cl = self._client(sta, now)
        if cl is None:
            return
        cc = cl.counters
        eapol = None
        if not f.protected and not null and llc_ethertype(f.body) == 0x888E:
            eapol = parse_eapol(f.body[8:])
        # EAPOL and null frames go out at basic rates; keep them out of rate stats
        sample = r is not None and r.rate and not null and eapol is None
        if up:
            self._from_client(cl, f, now)
            cl.power_save = f.pwr_mgmt
            if sample:
                cl.tx_rate = r.rate
                cl.tx_phy = r.phy
                cl.rates_up.append(r.rate)
        else:
            self._to_client(cl, f)
            if sample:
                cl.rx_rate = r.rate
                cl.rates_down.append(r.rate)
        if null:
            cc.null += 1
        else:
            cc.data += 1
            cc.data_bytes += f.length
            if f.retry:
                cc.data_retries += 1
            cl.last_data = now
            if up:
                cl.data_up += 1
                cl.bytes_up += f.length
            else:
                cl.data_down += 1
                cl.bytes_down += f.length
        if cl.bssid != ap.bssid and (up or cl.bssid is None or now - cl.state_since > 2):
            self._associate(cl, ap, now, "data")
        elif cl.state != "associated":
            self._set_state(cl, "associated", now)
            ap.clients.add(cl.mac)
        if eapol:
            c.eapol += 1
            cc.eapol += 1
            self._eapol(cl, ap, eapol, up, now)

    def _eapol(self, cl, ap, e, up, now):
        kind = e["kind"]
        if kind == "key":
            msg = e["msg"]
            hs = cl.hs
            if msg == "M1":
                if hs["state"] == "M2" and hs["t"] and now - hs["t"] < 10:
                    self._handshake_failure(
                        cl, ap, now, "AP restarted the 4-way handshake after M2 "
                        "(MIC check failed - wrong passphrase?)")
                elif hs["state"] == "M1" and hs["t"] and now - hs["t"] < 10:
                    hs["m1_repeats"] = hs.get("m1_repeats", 0) + 1
                    if hs["m1_repeats"] == 3:
                        self._handshake_failure(cl, ap, now,
                                                "client is not answering 4-way handshake M1")
                    hs["t"] = now
                    return
                cl.hs = {"state": "M1", "t": now, "last_msg": "M1", "started": now,
                         "m1_repeats": 0}
            elif msg in ("M2", "M3"):
                hs.update(state=msg, t=now, last_msg=msg)
            elif msg == "M4":
                hs.update(state="complete", t=now, last_msg=msg)
                cl.hs_complete += 1
                self.bus.emit("HANDSHAKE_COMPLETE", "info", "client",
                              f"{cl.mac} completed the 4-way handshake with {ap.bssid}",
                              ssid=ap.ssid, bssid=ap.bssid, client=cl.mac,
                              channel=ap.channel, band=ap.band, rssi=cl.signal.avg,
                              cooldown=60)
            elif msg in ("G1", "G2"):
                hs["group_rekey"] = now
        elif kind == "eap":
            code = e.get("eap_code")
            if code == 2 and e.get("eap_type") not in (None, 1, 3):
                cl.eap_method = C.EAP_TYPES.get(e["eap_type"], f"type-{e['eap_type']}")
            elif code == 3:
                cl.eap_result = "success"
            elif code == 4:
                cl.eap_result = "failure"
                self._auth_failure(cl, ap, "eap", "EAP-Failure from authentication server",
                                   now, {"method": cl.eap_method})

    def _handshake_failure(self, cl, ap, now, why):
        cl.hs_failures.append((now, why))
        cl.hs["state"] = "failed"
        cl.hs["t"] = now
        self.bus.emit("HANDSHAKE_FAILED", "warning", "client",
                      f"{cl.mac} 4-way handshake failed with {ap.bssid}: {why}",
                      ssid=ap.ssid, bssid=ap.bssid, client=cl.mac, channel=ap.channel,
                      band=ap.band, rssi=cl.signal.avg, details={"why": why}, cooldown=60)

    # ------------------------------------------------------------ tick
    def tick_if_due(self, now=None):
        with self.lock:
            now = now or self.now()
            if self.last_tick is None or now - self.last_tick >= 1.0:
                self.tick(now)

    def tick(self, now):
        self.last_tick = now
        elapsed_obs = now - (self.start or now)
        self.totals_hist.add(now, elapsed_obs, self.totals.snapshot())
        for key, cs in self.channels.items():
            cs.history.add(now, self.obs(key, now), cs.counters.snapshot())
        for ap in self.aps.values():
            key = (ap.band, ap.channel) if ap.channel else (ap.band, ap.radio_channel)
            ap.history.add(now, self.obs(key, now), ap.counters.snapshot())
            ap.signal.tick()
        for cl in self.clients.values():
            ap = self.aps.get(cl.bssid) if cl.bssid else None
            if ap is not None and ap.channel:
                key = (ap.band, ap.channel)
            else:
                key = cl.chan_key
            cl.history.add(now, self.obs(key, now), cl.counters.snapshot())
            cl.signal.tick()
        self.detector.run(now)
        self._expire(now)

    def _expire(self, now):
        fa = self.th.forget_after
        for m in [m for m, c in self.clients.items() if now - c.last_seen > fa]:
            cl = self.clients.pop(m)
            ap = self.aps.get(cl.bssid or "")
            if ap is not None:
                ap.clients.discard(m)
        for b in [b for b, a in self.aps.items() if now - a.last_seen > fa]:
            del self.aps[b]

    # ------------------------------------------------------------ queries
    def visible_aps(self):
        return [a for a in self.aps.values()
                if a.beacon_seen or a.counters.frames >= 5]

    def wlans(self, now=None):
        """Group visible BSSs by SSID."""
        now = now or self.now()
        groups = {}
        for ap in self.visible_aps():
            groups.setdefault(ap.display_ssid, []).append(ap)
        out = []
        for ssid, aps in groups.items():
            rssis = [a.signal.avg for a in aps if a.signal.avg is not None]
            out.append({
                "ssid": ssid,
                "bssids": [a.bssid for a in aps],
                "aps": aps,
                "clients": sum(len(a.clients) for a in aps),
                "bands": sorted({a.band for a in aps if a.band}),
                "channels": sorted({a.channel for a in aps if a.channel}),
                "security": sorted({a.security for a in aps if a.security}),
                "best_rssi": max(rssis) if rssis else None,
                "alerts": sorted({k for a in aps for k in a.alerts}),
                "beacons": sum(a.counters.beacons for a in aps),
                "data_rate": sum(a.history.rate("data") for a in aps),
                "last_seen": max(a.last_seen for a in aps),
            })
        return out

    def snapshot(self, brief=True):
        with self.lock:
            now = self.now()
            nf = self.th.noise_floor
            wl = self.wlans(now)
            for w in wl:
                w.pop("aps")
            return {
                "sensor": self.cfg.sensor_id,
                "time": now,
                "uptime": round(now - (self.start or now), 1),
                "stats": self.stats(now),
                "radios": [h.describe() for h in self.hoppers],
                "wlans": wl,
                "aps": [a.as_dict(nf, now, brief) for a in self.visible_aps()],
                "clients": [c.as_dict(nf, now, brief) for c in self.clients.values()],
                "channels": self.channel_rows(now),
            }

    def stats(self, now=None):
        now = now or self.now()
        return {
            "frames": self.totals.frames, "mgmt": self.totals.mgmt,
            "ctrl": self.totals.ctrl, "data": self.totals.data, "null": self.totals.null,
            "beacons": self.totals.beacons, "retries": self.totals.retries,
            "bad_fcs": self.bad_fcs, "dropped": self.dropped,
            "parse_errors": self.parse_errors,
            "fps": round(self.totals_hist.rate("frames", 5), 1),
            "aps": len(self.visible_aps()), "clients": len(self.clients),
            "events": dict(self.bus.counts), "events_suppressed": self.bus.suppressed,
        }

    def channel_rows(self, now=None):
        now = now or self.now()
        by_ch = {}
        for ap in self.visible_aps():
            if ap.channel:
                by_ch.setdefault((ap.band, ap.channel), []).append(ap)
        hopping = self._hopping()
        total_obs = sum(self.obs_time.values()) or 0
        rows = []
        for key in sorted(set(self.channels) | set(by_ch), key=lambda k: (str(k[0]), k[1] or 0)):
            cs = self.channels.get(key)
            aps = by_ch.get(key, [])
            utils = [a.bss_load["util_pct"] for a in aps if a.bss_load]
            c = cs.counters if cs else Counters()
            rows.append({
                "band": key[0], "channel": key[1], "bss": len(aps),
                "clients": sum(len(a.clients) for a in aps),
                "frames": c.frames, "fps": round(cs.history.rate("frames"), 1) if cs else 0,
                "data_fps": round(cs.history.rate("data"), 1) if cs else 0,
                "retry_pct": round(100 * c.retries / c.frames, 1) if c.frames else 0,
                "bss_load_util": round(max(utils), 1) if utils else None,
                "observed_s": round(self.obs_time.get(key, 0.0), 1) if hopping else None,
                "observed_pct": round(100 * self.obs_time.get(key, 0.0) / total_obs, 1)
                if hopping and total_obs else None,
            })
        return rows


def _max_rate(info, width):
    nss = info.nss or 1
    if info.he:
        return he_rate(11, nss, width if width in (20, 40, 80, 160) else 20)
    if info.vht:
        sgi = bool(info.vht.get("sgi80"))
        return vht_rate(9 if width != 20 else 8, nss, width if width in (20, 40, 80, 160) else 80, sgi)
    if info.ht:
        w = 40 if width >= 40 else 20
        sgi = info.ht["sgi40"] if w == 40 else info.ht["sgi20"]
        return ht_rate(7 + 8 * (min(nss, 4) - 1), w, sgi)
    return max(info.rates) if info.rates else None
