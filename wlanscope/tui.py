"""Interactive curses interface.

Drill-down: WLANs (SSIDs) -> BSSIDs of an SSID -> BSS detail with its
clients -> client detail.  Side views: all clients, channels, events.
"""

import curses
import json
import locale
import os
import time

from . import __version__
from . import constants as C
from .api import lock_to_bss
from .detect import CLIENT_ISSUES, status_label
from .headless import write_state

SPARK_UTF = "▁▂▃▄▅▆▇█"
SPARK_ASCII = "_.-~=+*#"

# colour pair ids
P_HDR, P_GREEN, P_YELLOW, P_RED, P_CYAN, P_MAGENTA, P_BLUE, P_SEL, P_DIM = range(1, 10)


# ------------------------------------------------------------------ format

def f_rssi(v):
    return "" if v is None else f"{v:.0f}"


def f_num(n):
    if n is None:
        return ""
    if n >= 10_000_000:
        return f"{n / 1e6:.0f}M"
    if n >= 1_000_000:
        return f"{n / 1e6:.1f}M"
    if n >= 100_000:
        return f"{n / 1e3:.0f}k"
    if n >= 10_000:
        return f"{n / 1e3:.1f}k"
    return str(int(n))


def f_rate(v):
    if not v:
        return ""
    return f"{v:.1f}" if v < 10 else f"{v:.0f}"


def f_bytes(n):
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}T"


def f_age(sec):
    if sec is None:
        return ""
    if sec < 0:
        sec = 0
    if sec < 60:
        return f"{sec:.0f}s"
    if sec < 3600:
        return f"{sec / 60:.0f}m"
    if sec < 86400:
        return f"{sec / 3600:.1f}h"
    return f"{sec / 86400:.1f}d"


def f_uptime(sec):
    if sec is None:
        return ""
    d, r = divmod(int(sec), 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    return f"{d}d {h:02d}:{m:02d}:{s:02d}" if d else f"{h:02d}:{m:02d}:{s:02d}"


def f_mbps(v):
    return "" if v is None else (f"{v:.0f}" if v >= 10 else f"{v:g}")


def gen_label(g):
    return {"be": "be/7", "ax": "ax/6", "ac": "ac/5", "n": "n/4", "g/a": "a/g", "b": "b"}.get(g, g or "")


def band_label(b):
    return {"2g": "2.4", "5g": "5", "6g": "6"}.get(b, "?")


def yn(v):
    return "yes" if v else "no"


# ------------------------------------------------------------------ widgets

class Col:
    def __init__(self, title, width, get, fmt=str, align="<", color=None, sort=None):
        self.title, self.width, self.get, self.fmt = title, width, get, fmt
        self.align, self.color = align, color
        self.sort = sort if sort is not None else get


class Table:
    def __init__(self, cols, key, sort_col=0, reverse=True):
        self.cols = cols
        self.key = key
        self.rows = []
        self.view_rows = []
        self.sel = 0
        self.top = 0
        self.sel_key = None
        self.sort_col = sort_col
        self.reverse = reverse
        self.filter = ""

    def set_rows(self, rows):
        col = self.cols[self.sort_col]

        def sk(r):
            v = col.sort(r)
            if v is None:
                return (0, 0)
            return (1, v.lower() if isinstance(v, str) else v)
        try:
            rows = sorted(rows, key=sk, reverse=self.reverse)
        except TypeError:
            pass
        self.rows = rows
        if self.filter:
            f = self.filter.lower()
            rows = [r for r in rows
                    if f in " ".join(str(c.fmt(c.get(r))) for c in self.cols).lower()]
        self.view_rows = rows
        if self.sel_key is not None:
            for i, r in enumerate(rows):
                if self.key(r) == self.sel_key:
                    self.sel = i
                    break
        self.sel = max(0, min(self.sel, len(rows) - 1))

    def current(self):
        if 0 <= self.sel < len(self.view_rows):
            return self.view_rows[self.sel]
        return None

    def move(self, d):
        if not self.view_rows:
            return
        self.sel = max(0, min(len(self.view_rows) - 1, self.sel + d))
        self.sel_key = self.key(self.view_rows[self.sel])

    def cycle_sort(self):
        self.sort_col = (self.sort_col + 1) % len(self.cols)

    def draw(self, ui, y, x, h, w, focused=True):
        if h < 2:
            return
        hdr = ""
        for c in self.cols:
            hdr += _cell(c.title + ("▼" if c is self.cols[self.sort_col] and self.reverse else
                                    "▲" if c is self.cols[self.sort_col] else ""),
                         c.width, c.align) + " "
        ui.put(y, x, hdr[:w].ljust(w), ui.attr(P_BLUE) | curses.A_BOLD)
        body_h = h - 1
        if self.sel < self.top:
            self.top = self.sel
        if self.sel >= self.top + body_h:
            self.top = self.sel - body_h + 1
        self.top = max(0, min(self.top, max(0, len(self.view_rows) - body_h)))
        for i in range(body_h):
            idx = self.top + i
            if idx >= len(self.view_rows):
                break
            r = self.view_rows[idx]
            selected = focused and idx == self.sel
            cx = x
            for c in self.cols:
                try:
                    v = c.get(r)
                    txt = _cell(c.fmt(v), c.width, c.align)
                    attr = c.color(r, v) if c.color else 0
                except Exception:
                    txt, attr = _cell("?", c.width, c.align), 0
                if selected:
                    attr = ui.attr(P_SEL) | (attr & curses.A_BOLD)
                ui.put(y + 1 + i, cx, txt + " ", attr)
                cx += c.width + 1
                if cx >= x + w:
                    break
            if selected and cx < x + w:
                ui.put(y + 1 + i, cx, " " * (x + w - cx), ui.attr(P_SEL))
        if len(self.view_rows) > body_h:
            ui.put(y, x + w - 12, f" {self.sel + 1}/{len(self.view_rows)} ".rjust(12),
                   ui.attr(P_BLUE))


def _cell(s, width, align):
    s = str(s)
    if width <= 0:
        return s
    if len(s) > width:
        s = s[:max(1, width - 1)] + "…"
    return s.rjust(width) if align == ">" else s.ljust(width)


# ------------------------------------------------------------------ views

class View:
    title = ""
    hints = ""
    table = None

    def __init__(self, ui):
        self.ui = ui
        self.eng = ui.eng

    def refresh(self):
        pass

    def draw(self, y, h, w):
        if self.table:
            self.table.draw(self.ui, y, 0, h, w)

    def key(self, k):
        return False

    def open(self):
        return None


class WlanView(View):
    title = "WLANs"
    hints = "Enter:BSSIDs  c:clients  n:channels  e:events  s/r:sort  /:filter  p:pause  ?:help  q:quit"

    def __init__(self, ui):
        super().__init__(ui)
        u = ui
        self.table = Table([
            Col("SSID", 28, lambda r: r["ssid"], color=lambda r, v: u.attr(P_DIM) if v.startswith("<") else curses.A_BOLD),
            Col("BSS", 4, lambda r: len(r["bssids"]), align=">"),
            Col("CLI", 4, lambda r: r["clients"], align=">"),
            Col("BAND", 7, lambda r: ",".join(band_label(b) for b in r["bands"])),
            Col("CHANNELS", 14, lambda r: ",".join(str(c) for c in r["channels"])),
            Col("SECURITY", 24, lambda r: " | ".join(r["security"]),
                color=lambda r, v: u.attr(P_RED) if "OPEN" in v or "WEP" in v else 0),
            Col("RSSI", 5, lambda r: r["best_rssi"], f_rssi, ">", lambda r, v: u.rssi_attr(v)),
            Col("BEACONS", 8, lambda r: r["beacons"], f_num, ">"),
            Col("DATA/s", 7, lambda r: r["data_rate"], f_rate, ">"),
            Col("LAST", 5, lambda r: u.now - r["last_seen"], f_age, ">", sort=lambda r: r["last_seen"]),
            Col("ALERTS", 30, lambda r: " ".join(r["alerts"]),
                color=lambda r, v: u.attr(P_RED) | curses.A_BOLD if v else 0),
        ], key=lambda r: r["ssid"], sort_col=2)

    def refresh(self):
        with self.eng.lock:
            rows = self.eng.wlans(self.ui.now)
            for r in rows:
                r.pop("aps")
        self.table.set_rows(rows)

    def open(self):
        r = self.table.current()
        return BssListView(self.ui, r["ssid"]) if r else None


def _ap_row(ap, ui):
    nf = ui.eng.th.noise_floor
    snr, est = ap.signal.snr(nf)
    d = ap.counters.data
    return {
        "bssid": ap.bssid, "vendor": ap.ap_name or ap.vendor, "channel": ap.channel,
        "band": ap.band, "width": ap.width, "gen": ap.generation, "rssi": ap.signal.avg,
        "snr": snr, "snr_est": est, "clients": len(ap.clients), "beacons": ap.counters.beacons,
        "data": d, "data_rate": ap.history.rate("data"),
        "retry": 100.0 * ap.counters.data_retries / d if d else None,
        "util": (ap.bss_load or {}).get("util_pct"), "security": ap.security or "",
        "alerts": " ".join(sorted(ap.alerts)), "flags": " ".join(sorted(ap.flags)),
        "last": ap.last_seen, "ssid": ap.display_ssid,
        "sev": max((_sevn(a["severity"]) for a in ap.alerts.values()), default=0),
    }


def _sevn(s):
    return {"info": 1, "warning": 2, "critical": 3}.get(s, 0)


class BssListView(View):
    hints = "Enter:BSS detail  l:lock radio to BSS  u:unlock  s/r:sort  /:filter  Esc:back"

    def __init__(self, ui, ssid):
        super().__init__(ui)
        self.ssid = ssid
        self.title = ssid
        u = ui
        self.table = Table([
            Col("BSSID", 17, lambda r: r["bssid"], color=lambda r, v: u.sev_attr(r["sev"])),
            Col("VENDOR/NAME", 14, lambda r: r["vendor"]),
            Col("CH", 4, lambda r: r["channel"], lambda v: v or "", ">"),
            Col("BAND", 4, lambda r: band_label(r["band"])),
            Col("W", 3, lambda r: r["width"], align=">"),
            Col("PHY", 4, lambda r: gen_label(r["gen"])),
            Col("RSSI", 5, lambda r: r["rssi"], f_rssi, ">", lambda r, v: u.rssi_attr(v)),
            Col("SNR", 4, lambda r: r["snr"], lambda v: "" if v is None else f"{v:.0f}", ">",
                lambda r, v: u.snr_attr(v)),
            Col("CLI", 4, lambda r: r["clients"], align=">"),
            Col("BEACON", 7, lambda r: r["beacons"], f_num, ">"),
            Col("DATA", 7, lambda r: r["data"], f_num, ">"),
            Col("D/s", 6, lambda r: r["data_rate"], f_rate, ">"),
            Col("RTY%", 5, lambda r: r["retry"], lambda v: "" if v is None else f"{v:.0f}", ">",
                lambda r, v: u.attr(P_RED) if v and v > 20 else 0),
            Col("UTIL", 5, lambda r: r["util"], lambda v: "" if v is None else f"{v:.0f}%", ">",
                lambda r, v: u.attr(P_RED) if v and v > 70 else 0),
            Col("SECURITY", 22, lambda r: r["security"],
                color=lambda r, v: u.attr(P_RED) if v.startswith(("OPEN", "WEP")) else 0),
            Col("LAST", 5, lambda r: u.now - r["last"], f_age, ">", sort=lambda r: r["last"]),
            Col("ALERTS/FLAGS", 30, lambda r: (r["alerts"] + " " + r["flags"]).strip(),
                color=lambda r, v: u.sev_attr(r["sev"]) | (curses.A_BOLD if r["alerts"] else 0)),
        ], key=lambda r: r["bssid"], sort_col=6)

    def refresh(self):
        with self.eng.lock:
            rows = [_ap_row(ap, self.ui) for ap in self.eng.visible_aps()
                    if ap.display_ssid == self.ssid]
        self.table.set_rows(rows)

    def open(self):
        r = self.table.current()
        return BssDetailView(self.ui, r["bssid"]) if r else None

    def key(self, k):
        if k == ord("l"):
            r = self.table.current()
            if r:
                self.ui.lock_bss(r["bssid"])
            return True
        return False


def _client_row(cl, ui):
    nf = ui.eng.th.noise_floor
    snr, est = cl.signal.snr(nf)
    tf = cl.tx_frames + cl.rx_frames
    ap = ui.eng.aps.get(cl.bssid or cl.last_bssid or "")
    issues = cl.issues
    sev = max((_sevn(v["severity"]) for v in issues.values()), default=0)
    return {
        "mac": cl.mac, "vendor": cl.vendor, "rssi": cl.signal.avg, "snr": snr,
        "tx_rate": cl.tx_rate, "rx_rate": cl.rx_rate, "up": cl.data_up, "down": cl.data_down,
        "mgmt": cl.counters.mgmt, "retry": 100.0 * (cl.tx_retries + cl.rx_retries) / tf if tf else None,
        "ps": cl.power_save, "last": cl.last_seen, "status": cl.status,
        "flags": " ".join(sorted(f for f in cl.flags if f != "PS")),
        "issues": ",".join(status_label(c) for c in issues),
        "sev": sev, "ssid": ap.display_ssid if ap else "", "bssid": cl.bssid or "",
        "channel": ap.channel if ap else (cl.chan_key[1] if cl.chan_key else None),
        "data_rate": cl.history.rate("data"), "state": cl.state,
        "probes": ",".join(sorted(cl.probed_ssids))[:60],
    }


def client_cols(ui, wide=False):
    u = ui
    cols = [
        Col("CLIENT", 17, lambda r: r["mac"], color=lambda r, v: u.sev_attr(r["sev"])),
        Col("VENDOR", 11, lambda r: r["vendor"]),
    ]
    if wide:
        cols += [Col("SSID", 16, lambda r: r["ssid"]),
                 Col("CH", 4, lambda r: r["channel"], lambda v: v or "", ">")]
    cols += [
        Col("RSSI", 5, lambda r: r["rssi"], f_rssi, ">", lambda r, v: u.rssi_attr(v)),
        Col("SNR", 4, lambda r: r["snr"], lambda v: "" if v is None else f"{v:.0f}", ">",
            lambda r, v: u.snr_attr(v)),
        Col("TXRT", 5, lambda r: r["tx_rate"], f_mbps, ">"),
        Col("RXRT", 5, lambda r: r["rx_rate"], f_mbps, ">"),
        Col("DATA↑", 7, lambda r: r["up"], f_num, ">"),
        Col("DATA↓", 7, lambda r: r["down"], f_num, ">"),
        Col("D/s", 6, lambda r: r["data_rate"], f_rate, ">"),
        Col("MGMT", 5, lambda r: r["mgmt"], f_num, ">"),
        Col("RTY%", 5, lambda r: r["retry"], lambda v: "" if v is None else f"{v:.0f}", ">",
            lambda r, v: u.attr(P_RED) if v and v > 20 else 0),
        Col("PS", 2, lambda r: "z" if r["ps"] else ""),
        Col("LAST", 5, lambda r: u.now - r["last"], f_age, ">", sort=lambda r: r["last"]),
        Col("STATUS", 11, lambda r: r["status"], status_label, color=lambda r, v: u.status_attr(v),
            sort=lambda r: (r["sev"], r["status"])),
        Col("ISSUES/FLAGS", 34, lambda r: (r["issues"] + " " + r["flags"]).strip(),
            color=lambda r, v: u.sev_attr(r["sev"])),
    ]
    return cols


class BssDetailView(View):
    hints = "Enter:client  i:layout  l:lock radio to BSS  u:unlock  a:all/active  s/r:sort  Esc:back"
    LAYOUTS = ("split", "info", "clients")

    def __init__(self, ui, bssid):
        super().__init__(ui)
        self.bssid = bssid
        self.title = bssid
        self.table = Table(client_cols(ui), key=lambda r: r["mac"], sort_col=2)
        self.lines = []
        self.show_all = True
        self.layout = "split"
        self.scroll = 0

    def refresh(self):
        eng = self.eng
        now = self.ui.now
        with eng.lock:
            ap = eng.aps.get(self.bssid)
            if ap is None:
                self.lines = [[("BSS no longer tracked", self.ui.attr(P_RED))]]
                self.table.set_rows([])
                return
            members = set(ap.clients)
            if self.show_all:   # recently disconnected clients of this BSS too
                members |= {m for m, c in eng.clients.items()
                            if c.bssid is None and c.last_bssid == ap.bssid
                            and now - c.last_seen < 600}
            rows = [_client_row(eng.clients[m], self.ui) for m in members if m in eng.clients]
            if not self.show_all:
                rows = [r for r in rows if r["status"] not in ("GONE", "DISCONNECTED", "IDLE")]
            self.lines = self._info(ap, now)
        self.table.set_rows(rows)
        self.title = f"{ap.bssid}"

    def _info(self, ap, now):
        ui = self.ui
        nf = self.eng.th.noise_floor
        ies = ap.ies
        dim = ui.attr(P_DIM)
        kv = ui.kv
        snr, est = ap.signal.snr(nf)
        cap = ap.capability
        capnames = [n for bit, n in ((C.CAP_ESS, "ESS"), (C.CAP_IBSS, "IBSS"),
                                     (C.CAP_PRIVACY, "Privacy"), (C.CAP_SHORT_PREAMBLE, "ShortPre"),
                                     (C.CAP_SPECTRUM_MGMT, "SpecMgmt"), (C.CAP_QOS, "QoS"),
                                     (C.CAP_SHORT_SLOT, "ShortSlot"), (C.CAP_APSD, "APSD"),
                                     (C.CAP_RADIO_MEAS, "RadioMeas")) if cap & bit]
        a = [
            [("── BSS / RF ", ui.attr(P_CYAN) | curses.A_BOLD)],
            kv("SSID", ap.display_ssid + (" (revealed)" if ap.ssid_revealed else ""), curses.A_BOLD),
            kv("BSSID", ap.bssid + ("  [locally administered]" if int(ap.bssid[:2], 16) & 2 else "")),
            kv("Vendor", (ap.vendor or "?") + (f"  name: {ap.ap_name}" if ap.ap_name else "")),
            kv("Channel", f"{ap.channel} ({band_label(ap.band)} GHz)  {ap.width} MHz"
               + (f" ctr {ap.center_freq}" if ap.center_freq else "")
               + (f"  heard on ch{ap.radio_channel}" if ap.radio_channel and ap.radio_channel != ap.channel else "")),
            kv("PHY", f"802.11{ap.generation or '?'}  NSS {ap.nss or '?'}  max ~{f_mbps(ap.max_rate)} Mbps"),
            kv("RSSI", f"{f_rssi(ap.signal.last)} dBm  avg {f_rssi(ap.signal.avg)}  "
               f"min {f_rssi(ap.signal.min)}  max {f_rssi(ap.signal.max)}", ui.rssi_attr(ap.signal.avg)),
            kv("SNR", "" if snr is None else f"{'~' if est else ''}{snr:.0f} dB  noise "
               + (f"{ap.signal.noise:.0f} dBm" if ap.signal.noise is not None else f"~{nf:.0f} (est)"),
               ui.snr_attr(snr)),
            kv("Signal", ui.spark(ap.signal.history, 36), ui.attr(P_GREEN)),
            kv("Beacon", f"{ap.beacon_interval} TU  DTIM {ap.dtim_period or '?'}  "
               f"{ap.history.rate('beacons'):.1f}/s heard"),
            kv("BSS load", f"{ap.bss_load['stations']} sta, {ap.bss_load['util_pct']}% util"
               if ap.bss_load else "not advertised"),
            kv("Country", ap.country or "-"),
            kv("TSF uptime", f_uptime(ap.uptime)),
            kv("Seen", f"first {f_age(now - ap.first_seen)} ago, last {f_age(now - ap.last_seen)} ago"),
        ]
        rates = ""
        if ies:
            rates = " ".join(f"{r:g}{'*' if r in ies.basic_rates else ''}" for r in ies.rates)
        phy = []
        if ies and ies.ht:
            h = ies.ht
            phy.append("HT:" + " ".join(x for x, ok in (("40MHz", h["width40"]), ("SGI20", h["sgi20"]),
                                                       ("SGI40", h["sgi40"]), ("LDPC", h["ldpc"])) if ok)
                       + f" {h['nss']}SS")
        if ies and ies.vht:
            v = ies.vht
            phy.append("VHT:" + " ".join(x for x, ok in (("160", v["width160"]), ("SGI80", v["sgi80"]),
                                                        ("SU-BF", v["su_beamformer"]),
                                                        ("MU-BF", v["mu_beamformer"])) if ok)
                       + f" {v['nss']}SS")
        if ies and ies.he:
            color = (ies.he_op or {}).get("bss_color")
            phy.append(f"HE: {ies.he.get('nss') or '?'}SS" + (f" color {color}" if color is not None else ""))
        if ies and ies.eht:
            phy.append("EHT")
        wps = ap.wps
        b = [
            [("── Security / Capabilities ", ui.attr(P_CYAN) | curses.A_BOLD)],
            kv("Security", ap.security or "?", ui.attr(P_RED) if ap.security_class in ("OPEN", "WEP", "WPA") else ui.attr(P_GREEN)),
            kv("AKM", ", ".join(ap.akms) or "-"),
            kv("Ciphers", f"pairwise {'/'.join(ap.pairwise) or '-'}  group {ap.group_cipher or '-'}"),
            kv("PMF (11w)", ap.mfp, ui.attr(P_YELLOW) if ap.mfp == "none" and ap.security_class not in ("OPEN",) else 0),
            kv("WPS", "-" if not wps else f"{wps.get('state')}{' locked' if wps.get('locked') else ''}"
               + (f" {wps.get('manufacturer') or ''} {wps.get('model') or ''}".rstrip())),
            kv("Cap bits", " ".join(capnames)),
            kv("11k/v/r/u", "  ".join(f"{n}:{'✓' if ok else '-'}" for n, ok in (
                ("k", ies and ies.dot11k), ("v", ies and ies.btm), ("r", ies and ies.dot11r),
                ("u", ies and ies.dot11u))) + (f"  WMM:{'✓' if ies and ies.wmm else '-'}")),
            kv("Rates", rates[:60]),
            kv("PHY caps", "  ".join(phy)[:70]),
            kv("Vendor IEs", " ".join(o.split("/")[0] for o in ap.vendor_ies)[:70]),
            kv("Flags", " ".join(sorted(ap.flags)) or "-"),
            kv("Clients", f"{len(ap.clients)} associated  data up {f_num(ap.data_up)} "
               f"down {f_num(ap.data_down)} mcast {f_num(ap.data_mcast)}"),
        ]
        c = ui.counter_block(ap.counters, ap.history,
                             ("frames", "beacons", "probe_resp", "mgmt", "ctrl", "data", "null",
                              "auth", "assoc", "reassoc", "deauth", "disassoc", "action",
                              "eapol", "retries", "data_retries", "bytes"))
        blocks = ui.columns([a, b, c])
        if ap.alerts:
            blocks.append([("── Alerts ", ui.attr(P_RED) | curses.A_BOLD)])
            for code, al in sorted(ap.alerts.items(), key=lambda kv_: -_sevn(kv_[1]["severity"])):
                blocks.append([(f" {al['severity'].upper():8} ", ui.sev_attr(_sevn(al["severity"])) | curses.A_BOLD),
                               (f"{code}: ", curses.A_BOLD), (al["message"], 0)])
        return blocks

    def draw(self, y, h, w):
        if self.layout == "info":
            self.scroll = max(0, min(self.scroll, max(0, len(self.lines) - h)))
            self.ui.draw_lines(y, 0, w, self.lines[self.scroll:self.scroll + h])
            return
        n = 0 if self.layout == "clients" else min(len(self.lines), max(4, h - 8))
        self.ui.draw_lines(y, 0, w, self.lines[:n])
        ty = y + n
        self.ui.put(ty, 0, f"── Clients ({len(self.table.view_rows)}) {'all' if self.show_all else 'active'} "
                    .ljust(w, "─"), self.ui.attr(P_CYAN) | curses.A_BOLD)
        self.table.draw(self.ui, ty + 1, 0, h - n - 1, w)

    def open(self):
        r = self.table.current()
        return ClientDetailView(self.ui, r["mac"]) if r else None

    def key(self, k):
        if k == ord("i"):
            self.layout = self.LAYOUTS[(self.LAYOUTS.index(self.layout) + 1) % 3]
            self.ui.message(f"layout: {self.layout}" + ("  (↑↓ scroll)" if self.layout == "info" else ""))
            return True
        if self.layout == "info" and k in (curses.KEY_DOWN, ord("j"), curses.KEY_NPAGE):
            self.scroll += 10 if k == curses.KEY_NPAGE else 1
            return True
        if self.layout == "info" and k in (curses.KEY_UP, ord("k"), curses.KEY_PPAGE):
            self.scroll = max(0, self.scroll - (10 if k == curses.KEY_PPAGE else 1))
            return True
        if k == ord("l"):
            self.ui.lock_bss(self.bssid)
            return True
        if k == ord("a"):
            self.show_all = not self.show_all
            self.refresh()
            return True
        return False


class ClientDetailView(View):
    hints = "↑↓:scroll  l:lock radio to client's BSS  u:unlock  Esc:back"

    def __init__(self, ui, mac):
        super().__init__(ui)
        self.mac = mac
        self.title = mac
        self.lines = []
        self.scroll = 0

    def refresh(self):
        eng = self.eng
        with eng.lock:
            cl = eng.clients.get(self.mac)
            if cl is None:
                self.lines = [[("client no longer tracked", self.ui.attr(P_RED))]]
                return
            self.lines = self._info(cl, self.ui.now)

    def _info(self, cl, now):
        ui = self.ui
        kv = ui.kv
        eng = self.eng
        nf = eng.th.noise_floor
        ap = eng.aps.get(cl.bssid or cl.last_bssid or "")
        snr, est = cl.signal.snr(nf)
        caps = cl.caps or cl.probe_caps
        sec = cl.client_security or {}
        med = lambda xs: f_mbps(sorted(xs)[len(xs) // 2]) if xs else "-"
        a = [
            [("── Client ", ui.attr(P_CYAN) | curses.A_BOLD)],
            kv("MAC", cl.mac + ("  [randomized]" if cl.randomized else ""), curses.A_BOLD),
            kv("Vendor", cl.vendor or "?"),
            kv("Status", f"{status_label(cl.status)} for {f_age(now - cl.status_since)}",
               ui.status_attr(cl.status) | curses.A_BOLD),
            kv("State", f"{cl.state} for {f_age(now - cl.state_since)}"),
            kv("Network", f"{ap.display_ssid} {ap.bssid}" if ap else "-"),
            kv("Channel", f"{ap.channel} ({band_label(ap.band)} GHz) {ap.width} MHz" if ap else
               (f"heard on ch{cl.chan_key[1]}" if cl.chan_key else "-")),
            kv("AID", cl.aid if cl.aid is not None else "-"),
            kv("RSSI", f"{f_rssi(cl.signal.last)} dBm  avg {f_rssi(cl.signal.avg)}  "
               f"min {f_rssi(cl.signal.min)}  max {f_rssi(cl.signal.max)}", ui.rssi_attr(cl.signal.avg)),
            kv("SNR", "" if snr is None else f"{'~' if est else ''}{snr:.0f} dB", ui.snr_attr(snr)),
            kv("Signal", ui.spark(cl.signal.history, 36), ui.attr(P_GREEN)),
            kv("TX rate", f"{f_mbps(cl.tx_rate)} Mbps ({cl.tx_phy or '?'})  median {med(list(cl.rates_up))}"),
            kv("RX rate", f"{f_mbps(cl.rx_rate)} Mbps  median {med(list(cl.rates_down))}"),
            kv("Power save", f"{yn(cl.power_save)}  listen int {cl.listen_interval or '-'}"),
            kv("Seen", f"first {f_age(now - cl.first_seen)} ago, last {f_age(now - cl.last_seen)} ago"),
            kv("Last data", f"{f_age(now - cl.last_data)} ago" if cl.last_data else "never"),
        ]
        b = [
            [("── Capabilities / Security ", ui.attr(P_CYAN) | curses.A_BOLD)],
            kv("PHY", f"802.11{caps.generation or '?'}  NSS {caps.nss or '?'}" if caps else "unknown"),
            kv("Widths", " ".join(x for x, ok in (
                ("40", caps and caps.ht and caps.ht["width40"]),
                ("80", caps and caps.vht), ("160", caps and caps.vht and caps.vht["width160"])) if ok) or "20"),
            kv("11k/v/r", "  ".join(f"{n}:{'✓' if ok else '-'}" for n, ok in (
                ("k", caps and caps.dot11k), ("v", caps and caps.btm),
                ("r", cl.caps and cl.caps.dot11r)))),
            kv("AKM", ", ".join(sec.get("akm", [])) or "-"),
            kv("Pairwise", ", ".join(sec.get("pairwise", [])) or "-"),
            kv("PMF", "required" if sec.get("mfpr") else "capable" if sec.get("mfpc") else "-"),
            kv("Power cap", f"{cl.caps.power_cap[0]}..{cl.caps.power_cap[1]} dBm"
               if cl.caps and cl.caps.power_cap else "-"),
            kv("Channels", f"{len(cl.caps.supported_channels)} supported"
               if cl.caps and cl.caps.supported_channels else "-"),
            kv("4-way HS", f"{cl.hs.get('state') or '-'}  ok {cl.hs_complete}  failed {len(cl.hs_failures)}"),
            kv("EAP", f"{cl.eap_method or '-'} {cl.eap_result or ''}"),
            kv("Flags", " ".join(sorted(cl.flags)) or "-"),
            kv("Probes", ", ".join(sorted(cl.probed_ssids))[:70] or "-"),
        ]
        c = ui.counter_block(cl.counters, cl.history,
                             ("frames", "data", "null", "mgmt", "ctrl", "probe_req", "auth",
                              "assoc", "reassoc", "deauth", "disassoc", "action", "eapol",
                              "retries", "data_retries", "bytes"))
        c.append(kv("Data ↑/↓", f"{f_num(cl.data_up)} / {f_num(cl.data_down)}", lw=11))
        c.append(kv("Bytes ↑/↓", f"{f_bytes(cl.bytes_up)} / {f_bytes(cl.bytes_down)}", lw=11))
        c.append(kv("Retry ↑/↓", f"{cl.tx_retry_pct:.1f}% / {cl.rx_retry_pct:.1f}%", lw=11))
        lines = ui.columns([a, b, c])
        lines.append([("── Issues ", ui.attr(P_RED if cl.issues else P_CYAN) | curses.A_BOLD)])
        if not cl.issues:
            lines.append([(" none", ui.attr(P_GREEN))])
        for code, v in cl.issues.items():
            lines.append([(f" {status_label(code):12}", ui.sev_attr(_sevn(v["severity"])) | curses.A_BOLD),
                          (f" {v['detail']}  (since {f_age(now - v['since'])})", 0)])
        lines.append([("── History ", ui.attr(P_CYAN) | curses.A_BOLD)])
        if cl.last_disconnect:
            d = cl.last_disconnect
            lines.append([(f" last {d['kind']} by {d['by']} {f_age(now - d['t'])} ago: {d['reason_text']}", 0)])
        for t, frm, to in list(cl.roams)[-5:]:
            lines.append([(f" roam {f_age(now - t)} ago: {frm} -> {to}", 0)])
        for t, kind, text in list(cl.auth_failures)[-5:]:
            lines.append([(f" {kind} failure {f_age(now - t)} ago: {text}", ui.attr(P_YELLOW))])
        for t, why in list(cl.hs_failures)[-3:]:
            lines.append([(f" handshake failure {f_age(now - t)} ago: {why}", ui.attr(P_YELLOW))])
        for t, kind, st in list(cl.btm)[-3:]:
            lines.append([(f" BTM {kind} {f_age(now - t)} ago" + (f" status {C.BTM_STATUS.get(st, st)}"
                                                                    if st is not None else ""), 0)])
        lines.append([("── Recent events ", ui.attr(P_CYAN) | curses.A_BOLD)])
        evs = [e for e in reversed(eng.bus.recent) if e.get("client") == cl.mac][:15]
        for e in evs:
            lines.append([(time.strftime(" %H:%M:%S ", time.localtime(e["epoch"])), ui.attr(P_DIM)),
                          (f"{e['alert']:24} ", ui.sev_attr(_sevn(e["severity"]))), (e["message"], 0)])
        return lines

    def draw(self, y, h, w):
        self.scroll = max(0, min(self.scroll, max(0, len(self.lines) - h)))
        self.ui.draw_lines(y, 0, w, self.lines[self.scroll:self.scroll + h])

    def key(self, k):
        if k in (curses.KEY_DOWN, ord("j")):
            self.scroll += 1
        elif k in (curses.KEY_UP, ord("k")):
            self.scroll = max(0, self.scroll - 1)
        elif k == curses.KEY_NPAGE:
            self.scroll += 10
        elif k == curses.KEY_PPAGE:
            self.scroll = max(0, self.scroll - 10)
        elif k == ord("l"):
            cl = self.eng.clients.get(self.mac)
            if cl and (cl.bssid or cl.last_bssid):
                self.ui.lock_bss(cl.bssid or cl.last_bssid)
        else:
            return False
        return True


class ClientsView(View):
    title = "All clients"
    hints = "Enter:client  a:associated/all  s/r:sort  /:filter  Esc:back"

    def __init__(self, ui):
        super().__init__(ui)
        self.table = Table(client_cols(ui, wide=True), key=lambda r: r["mac"], sort_col=4)
        self.assoc_only = False

    def refresh(self):
        with self.eng.lock:
            rows = [_client_row(c, self.ui) for c in self.eng.clients.values()
                    if not self.assoc_only or c.bssid]
        self.title = "Associated clients" if self.assoc_only else "All clients"
        self.table.set_rows(rows)

    def open(self):
        r = self.table.current()
        return ClientDetailView(self.ui, r["mac"]) if r else None

    def key(self, k):
        if k == ord("a"):
            self.assoc_only = not self.assoc_only
            self.refresh()
            return True
        return False


class ChannelsView(View):
    title = "Channels"
    hints = "Enter/l:lock radio to channel  u:unlock  s/r:sort  Esc:back"

    def __init__(self, ui):
        super().__init__(ui)
        u = ui
        self.table = Table([
            Col("BAND", 4, lambda r: band_label(r["band"])),
            Col("CH", 4, lambda r: r["channel"], align=">"),
            Col("BSS", 4, lambda r: r["bss"], align=">"),
            Col("CLI", 4, lambda r: r["clients"], align=">"),
            Col("FRAMES", 8, lambda r: r["frames"], f_num, ">"),
            Col("F/s", 7, lambda r: r["fps"], f_rate, ">"),
            Col("DATA/s", 7, lambda r: r["data_fps"], f_rate, ">"),
            Col("RTY%", 5, lambda r: r["retry_pct"], lambda v: f"{v:.0f}", ">",
                lambda r, v: u.attr(P_RED) if v > 20 else 0),
            Col("BSSLOAD", 8, lambda r: r["bss_load_util"], lambda v: "" if v is None else f"{v:.0f}%", ">",
                lambda r, v: u.attr(P_RED) if v and v > 70 else 0),
            Col("OBSERVED", 9, lambda r: r["observed_s"], lambda v: "" if v is None else f"{v:.0f}s", ">"),
            Col("DWELL%", 7, lambda r: r["observed_pct"], lambda v: "" if v is None else f"{v:.1f}", ">"),
            Col("LOAD", 30, lambda r: r["fps"], lambda v: u.bar(v, u.max_fps, 30), color=lambda r, v: u.attr(P_GREEN)),
        ], key=lambda r: (r["band"], r["channel"]), sort_col=1, reverse=False)

    def refresh(self):
        with self.eng.lock:
            rows = self.eng.channel_rows(self.ui.now)
        self.ui.max_fps = max([r["fps"] for r in rows] + [1])
        self.table.set_rows(rows)

    def key(self, k):
        if k == ord("l"):
            self._lock()
            return True
        return False

    def _lock(self):
        r = self.table.current()
        if not r:
            return
        if not self.eng.hoppers:
            self.ui.message("no live radio to tune", P_YELLOW)
            return
        for h in self.eng.hoppers:
            h.lock(r["band"], r["channel"])
        self.ui.message(f"radio locked to {band_label(r['band'])} GHz ch{r['channel']} (u to resume hopping)", P_GREEN)

    def open(self):
        self._lock()
        return None


class EventsView(View):
    title = "Events"
    hints = "Enter:event JSON  f:min severity  s/r:sort  /:filter  Esc:back"

    def __init__(self, ui):
        super().__init__(ui)
        u = ui
        self.minsev = 1
        self.table = Table([
            Col("TIME", 8, lambda r: time.strftime("%H:%M:%S", time.localtime(r["epoch"])),
                sort=lambda r: r["seq"]),
            Col("SEV", 4, lambda r: r["severity"][:4].upper(), color=lambda r, v: u.sev_attr(_sevn(r["severity"]))),
            Col("ALERT", 30, lambda r: r["alert"], color=lambda r, v: u.sev_attr(_sevn(r["severity"])) | curses.A_BOLD),
            Col("SSID", 16, lambda r: r.get("ssid") or ""),
            Col("BSSID", 17, lambda r: r.get("bssid") or ""),
            Col("CLIENT", 17, lambda r: r.get("client") or ""),
            Col("MESSAGE", 80, lambda r: r["message"]),
        ], key=lambda r: r["seq"], sort_col=0)

    def refresh(self):
        sev = {"debug": 0, "info": 1, "warning": 2, "critical": 3}
        rows = [e for e in list(self.eng.bus.recent) if sev.get(e["severity"], 1) >= self.minsev]
        self.title = f"Events (>= {['debug', 'info', 'warning', 'critical'][self.minsev]})"
        self.table.set_rows(rows)

    def open(self):
        r = self.table.current()
        if not r:
            return None
        return TextView(self.ui, f"event {r['seq']}", json.dumps(r, indent=2, default=str).splitlines())

    def key(self, k):
        if k == ord("f"):
            self.minsev = 1 + self.minsev % 3
            self.refresh()
            return True
        return False


class TextView(View):
    hints = "↑↓/PgUp/PgDn:scroll  Esc:back"

    def __init__(self, ui, title, lines):
        super().__init__(ui)
        self.title = title
        self.text = lines
        self.scroll = 0

    def draw(self, y, h, w):
        self.scroll = max(0, min(self.scroll, max(0, len(self.text) - h)))
        for i, line in enumerate(self.text[self.scroll:self.scroll + h]):
            self.ui.put(y + i, 0, line[:w])

    def key(self, k):
        if k in (curses.KEY_DOWN, ord("j")):
            self.scroll += 1
        elif k in (curses.KEY_UP, ord("k")):
            self.scroll = max(0, self.scroll - 1)
        elif k == curses.KEY_NPAGE:
            self.scroll += 20
        elif k == curses.KEY_PPAGE:
            self.scroll = max(0, self.scroll - 20)
        else:
            return False
        return True


HELP = """\
wlanscope - keys

  Navigation
    Up/Down j/k  PgUp/PgDn  Home/End    move selection
    Enter / Right                        drill down (WLAN -> BSSIDs -> BSS -> client)
    Esc / Backspace / Left               back
    1 / w   WLAN list (home)             2 / c   all clients
    3 / n   channels                     4 / e   events

  Actions
    l       lock the radio(s) to the selected BSS's channel and width
            (needed to decode data frames of 40/80/160 MHz BSSs)
    u       unlock: resume channel hopping
    s / r   cycle sort column / reverse sort
    /       filter rows (substring, Esc clears)
    a       BSS detail: all vs active clients; clients view: associated only
    i       BSS detail: cycle layout split / info only (scrollable) / clients only
    f       events view: cycle minimum severity
    p       pause / resume screen updates
    S       save a full JSON snapshot to the current directory
    q       quit

  Columns
    RSSI    average received signal at this sensor (dBm)
    SNR     RSSI - noise; '~' means the driver reports no noise and the
            configured noise floor was used
    TXRT/RXRT  last PHY rate sent by / to the client (Mbps)
    D/s     data frames per second while the radio was on that channel
    RTY%    share of frames with the retry bit set
    PS      'z' = client is in power save
    +Δ      increase over the last second;  /s = 10 s rate (dwell-normalised)

  Client status (worst issue wins, otherwise activity)
    EVIL-TWIN   associated to a BSS flagged EVIL_TWIN / SPOOFED_BSSID / KARMA
    DEAUTH-ATK  receiving a burst of deauth/disassoc frames
    AUTH-FAIL   auth/assoc rejected, EAP failure, or auth-related disconnects
    4WAY-FAIL   4-way handshake failed (often a wrong passphrase)
    ROAM-STORM  roaming/re-associating repeatedly
    HIGH-RETRY  retry rate above threshold
    WEAK-SIGNAL low RSSI/SNR at the sensor
    LOW-RATE    median PHY rate very low
    STICKY?     weak link while a stronger BSS of the same SSID exists (heuristic)
    HIGH-UTIL   heavy data user (frames/s, kbps or share of BSS traffic)
    ACTIVE / PWR-SAVE / IDLE / PROBING / CONNECTING / DISCONN / GONE
"""


# ------------------------------------------------------------------ app

class TUI:
    def __init__(self, rt):
        self.rt = rt
        self.eng = rt.engine
        self.stack = []
        self.paused = False
        self.msg = ("", 0, 0.0)
        self.now = time.time()
        self.max_fps = 1
        self.utf = "utf" in (locale.getpreferredencoding(False) or "").lower()
        rt.bus.listeners.append(self._on_event)

    def _on_event(self, ev):
        if ev["severity"] == "critical" and ev.get("state") != "cleared":
            self.msg = (f"CRITICAL {ev['alert']}: {ev['message']}", P_RED, time.time() + 8)

    def message(self, text, pair=P_CYAN, secs=5):
        self.msg = (text, pair, time.time() + secs)

    # ---- drawing helpers
    def attr(self, pair):
        return curses.color_pair(pair) if self.colors else 0

    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w or x < 0:
            return
        text = str(text)[:w - x]
        if y == h - 1 and x + len(text) >= w:
            text = text[:w - x - 1]
        if not self.utf:
            text = text.encode("ascii", "replace").decode()
        try:
            self.scr.addstr(y, x, text, attr)
        except (curses.error, UnicodeEncodeError):
            pass

    def draw_lines(self, y, x, w, lines):
        for i, segs in enumerate(lines):
            cx = x
            for text, attr in segs:
                if cx >= x + w:
                    break
                self.put(y + i, cx, text[:x + w - cx], attr)
                cx += len(text)

    def kv(self, label, value, attr=0, lw=11):
        return [(f" {label:<{lw}}", self.attr(P_DIM)), (str(value), attr)]

    def columns(self, blocks):
        """Lay out blocks of lines side by side if wide enough, else stacked."""
        _, w = self.scr.getmaxyx()
        widths = [max((sum(len(t) for t, _ in l) for l in b), default=0) + 2 for b in blocks]
        if sum(widths) <= w:
            out = []
            for i in range(max(len(b) for b in blocks)):
                line, used = [], 0
                for b, bw in zip(blocks, widths):
                    segs = b[i] if i < len(b) else []
                    n = sum(len(t) for t, _ in segs)
                    line.extend(segs)
                    line.append((" " * (bw - n), 0))
                    used += bw
                out.append(line)
            return out
        if len(blocks) == 3 and widths[0] + widths[1] <= w:
            out = self.columns(blocks[:2])
            out.extend(blocks[2])
            return out
        return [l for b in blocks for l in b]

    def counter_block(self, ctr, hist, fields):
        lines = [[("── Counters ", self.attr(P_CYAN) | curses.A_BOLD),
                  ("      total     +Δ      /s", self.attr(P_DIM))]]
        for f in fields:
            total = getattr(ctr, f)
            delta = hist.delta(f)
            rate = hist.rate(f)
            fmt = f_bytes if f == "bytes" else f_num
            dattr = self.attr(P_GREEN) if delta else self.attr(P_DIM)
            if f in ("deauth", "disassoc", "retries", "data_retries") and delta:
                dattr = self.attr(P_YELLOW)
            lines.append([(f" {f.replace('_', ' '):<13}", self.attr(P_DIM)),
                          (f"{fmt(total):>9}", 0),
                          (f"{'+' + fmt(delta) if delta else '·':>7}", dattr),
                          (f"{rate:>8.1f}" if f != "bytes" else f"{f_bytes(rate):>8}", 0)])
        return lines

    def spark(self, hist, n):
        chars = SPARK_UTF if self.utf else SPARK_ASCII
        vals = list(hist)[-n:]
        nums = [v for v in vals if v is not None]
        if not nums:
            return "-"
        lo, hi = min(nums), max(nums)
        span = max(hi - lo, 6)
        out = "".join(" " if v is None else chars[min(len(chars) - 1, int((v - lo) / span * (len(chars) - 1)))]
                      for v in vals)
        return f"{out} {lo:.0f}..{hi:.0f}"

    def bar(self, v, vmax, width):
        n = int(width * (v or 0) / vmax) if vmax else 0
        return ("█" if self.utf else "#") * n

    def rssi_attr(self, v):
        if v is None:
            return self.attr(P_DIM)
        if v >= -60:
            return self.attr(P_GREEN)
        if v >= -72:
            return self.attr(P_YELLOW)
        return self.attr(P_RED)

    def snr_attr(self, v):
        if v is None:
            return self.attr(P_DIM)
        if v >= 25:
            return self.attr(P_GREEN)
        if v >= 15:
            return self.attr(P_YELLOW)
        return self.attr(P_RED)

    def sev_attr(self, n):
        return {3: self.attr(P_RED) | curses.A_BOLD, 2: self.attr(P_YELLOW),
                1: self.attr(P_CYAN)}.get(n, 0)

    def status_attr(self, code):
        if code in CLIENT_ISSUES:
            return self.sev_attr(_sevn(CLIENT_ISSUES[code][0]))
        return {"ACTIVE": self.attr(P_GREEN), "PROBING": self.attr(P_MAGENTA),
                "CONNECTING": self.attr(P_CYAN), "GONE": self.attr(P_DIM),
                "DISCONNECTED": self.attr(P_DIM)}.get(code, 0)

    # ---- actions
    def lock_bss(self, bssid):
        ok, msg = lock_to_bss(self.eng, bssid)
        self.message(msg + (" (u to resume hopping)" if ok else ""), P_GREEN if ok else P_YELLOW)

    def snapshot(self):
        path = os.path.abspath(time.strftime("wlanscope-snapshot-%Y%m%d-%H%M%S.json"))
        try:
            write_state(path, self.eng.snapshot(brief=False))
            self.message(f"snapshot written to {path}", P_GREEN, 8)
        except OSError as e:
            self.message(f"snapshot failed: {e}", P_RED)

    def prompt(self, label):
        h, w = self.scr.getmaxyx()
        buf = ""
        self.scr.timeout(-1)
        curses.curs_set(1)
        try:
            while True:
                self.put(h - 1, 0, (label + buf).ljust(w - 1), self.attr(P_SEL))
                self.scr.move(h - 1, min(w - 2, len(label) + len(buf)))
                k = self.scr.get_wch()
                if k in ("\n", "\r", curses.KEY_ENTER):
                    return buf
                if k == "\x1b":
                    return None
                if k in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                    buf = buf[:-1]
                elif isinstance(k, str) and k.isprintable():
                    buf += k
        finally:
            curses.curs_set(0)
            self.scr.timeout(250)

    # ---- main loop
    def run(self):
        os.environ.setdefault("ESCDELAY", "25")
        locale.setlocale(locale.LC_ALL, "")
        curses.wrapper(self._main)

    def _main(self, scr):
        self.scr = scr
        self.colors = curses.has_colors()
        if self.colors:
            curses.start_color()
            try:
                curses.use_default_colors()
                bg = -1
            except curses.error:
                bg = curses.COLOR_BLACK
            curses.init_pair(P_HDR, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(P_GREEN, curses.COLOR_GREEN, bg)
            curses.init_pair(P_YELLOW, curses.COLOR_YELLOW, bg)
            curses.init_pair(P_RED, curses.COLOR_RED, bg)
            curses.init_pair(P_CYAN, curses.COLOR_CYAN, bg)
            curses.init_pair(P_MAGENTA, curses.COLOR_MAGENTA, bg)
            curses.init_pair(P_BLUE, curses.COLOR_BLUE, bg)
            curses.init_pair(P_SEL, curses.COLOR_BLACK, curses.COLOR_WHITE)
            curses.init_pair(P_DIM, 8 if curses.COLORS > 8 else curses.COLOR_WHITE, bg)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        scr.keypad(True)
        scr.timeout(250)
        self.stack = [WlanView(self)]
        last_refresh = 0.0
        while not self.rt.stop.is_set():
            if self.eng.live:
                self.eng.tick_if_due()
            wall = time.time()
            if not self.paused and wall - last_refresh >= 1.0:
                self.now = self.eng.now()
                self.stack[-1].refresh()
                last_refresh = wall
            self._draw()
            k = scr.getch()
            if k == -1:
                continue
            if self._key(k) == "quit":
                break
            # instant feedback after navigation
            if not self.paused:
                self.now = self.eng.now()
                self.stack[-1].refresh()
                last_refresh = time.time()

    def _key(self, k):
        v = self.stack[-1]
        t = v.table
        if k in (ord("q"), ord("Q")):
            return "quit"
        if k == curses.KEY_RESIZE:
            curses.update_lines_cols()
            self.scr.clear()
            return None
        if v.key(k):
            return None
        if t is not None:
            if k in (curses.KEY_DOWN, ord("j")):
                t.move(1)
                return None
            if k in (curses.KEY_UP, ord("k")):
                t.move(-1)
                return None
            if k == curses.KEY_NPAGE:
                t.move(10)
                return None
            if k == curses.KEY_PPAGE:
                t.move(-10)
                return None
            if k == curses.KEY_HOME:
                t.move(-10 ** 6)
                return None
            if k == curses.KEY_END:
                t.move(10 ** 6)
                return None
            if k == ord("s"):
                t.cycle_sort()
                self.message(f"sorted by {t.cols[t.sort_col].title}")
                return None
            if k == ord("r"):
                t.reverse = not t.reverse
                return None
            if k == ord("/"):
                f = self.prompt("filter: ")
                t.filter = f or ""
                t.sel = 0
                return None
        if k in (10, 13, curses.KEY_ENTER, curses.KEY_RIGHT):
            nv = v.open()
            if nv is not None:
                self.stack.append(nv)
            return None
        if k in (27, curses.KEY_BACKSPACE, 127, 8, curses.KEY_LEFT, ord("b")):
            if t is not None and t.filter and k == 27:
                t.filter = ""
            elif len(self.stack) > 1:
                self.stack.pop()
            return None
        jump = {ord("1"): WlanView, ord("w"): WlanView, ord("2"): ClientsView, ord("c"): ClientsView,
                ord("3"): ChannelsView, ord("n"): ChannelsView, ord("4"): EventsView,
                ord("e"): EventsView}
        if k in jump:
            cls = jump[k]
            if cls is WlanView:
                self.stack = self.stack[:1]
            else:
                self.stack = [self.stack[0], cls(self)]
            return None
        if k == ord("u"):
            for h in self.eng.hoppers:
                h.unlock()
            self.message("channel hopping resumed" if self.eng.hoppers else "no live radio", P_GREEN)
            return None
        if k == ord("p"):
            self.paused = not self.paused
            return None
        if k == ord("S"):
            self.snapshot()
            return None
        if k == ord("?"):
            self.stack.append(TextView(self, "help", HELP.splitlines()))
            return None
        return None

    def _draw(self):
        scr = self.scr
        scr.erase()
        h, w = scr.getmaxyx()
        if h < 8 or w < 40:
            self.put(0, 0, "terminal too small")
            scr.refresh()
            return
        eng = self.eng
        with eng.lock:
            st = eng.stats()
            sevs = [x["severity"] for a in eng.aps.values() for x in a.alerts.values()]
        crit, warn = sevs.count("critical"), sevs.count("warning")
        radios = " ".join(hh.describe() for hh in eng.hoppers) or self.rt.source_desc
        if not eng.live:
            radios += " [done]" if self.rt.replay_done() else " [replaying]"
        tail = f" │ {st['fps']:.0f} f/s │ BSS {st['aps']} │ clients {st['clients']} │ "
        head = f" wlanscope {__version__} │ {self.rt.cfg.sensor_id} │ "
        right = time.strftime(" %H:%M:%S ", time.localtime(self.now))
        alert_txt = f" crit {crit} warn {warn} "
        room = w - len(head) - len(tail) - len(alert_txt) - len(right)
        if room < len(radios):
            radios = radios[:max(0, room - 1)] + "…" if room > 1 else ""
        left = head + radios + tail
        self.put(0, 0, left.ljust(w), self.attr(P_HDR))
        self.put(0, len(left), alert_txt,
                 (self.attr(P_RED) | curses.A_BOLD | curses.A_REVERSE) if crit else
                 self.attr(P_YELLOW) | curses.A_REVERSE if warn else self.attr(P_HDR))
        self.put(0, w - len(right), right, self.attr(P_HDR))

        crumbs = " › ".join(v.title for v in self.stack if v.title)
        extra = []
        t = self.stack[-1].table
        if t is not None and t.filter:
            extra.append(f"filter '{t.filter}'")
        if self.paused:
            extra.append("PAUSED")
        if st["bad_fcs"] or st["dropped"]:
            extra.append(f"badfcs {st['bad_fcs']} drop {st['dropped']}")
        self.put(1, 0, " " + crumbs, curses.A_BOLD)
        if extra:
            ex = " │ ".join(extra) + " "
            self.put(1, max(0, w - len(ex)), ex, self.attr(P_YELLOW) | curses.A_BOLD)

        try:
            self.stack[-1].draw(2, h - 3, w)
        except Exception as e:      # keep the UI alive on a rendering bug
            self.put(3, 0, f"render error: {e}", self.attr(P_RED))

        text, pair, until = self.msg
        if text and time.time() < until:
            self.put(h - 1, 0, (" " + text).ljust(w), self.attr(pair) | curses.A_REVERSE)
        else:
            self.put(h - 1, 0, (" " + self.stack[-1].hints).ljust(w), self.attr(P_DIM) | curses.A_REVERSE)
        scr.refresh()
