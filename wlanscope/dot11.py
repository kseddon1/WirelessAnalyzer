"""IEEE 802.11 MAC frame, information element, RSN and EAPOL parsing."""

import struct

from . import constants as C

BROADCAST = "ff:ff:ff:ff:ff:ff"


def mac(b, o=0):
    return b[o:o + 6].hex(":")


def is_multicast(m):
    """True for group addresses (I/G bit set) given 'aa:bb:..' form."""
    return bool(int(m[0:2], 16) & 0x01)


def is_local_admin(m):
    """Locally administered (randomised / virtual) address."""
    return bool(int(m[0:2], 16) & 0x02)


def strip_group_bit(m):
    """RTS/CTS bandwidth signalling sets the I/G bit of the TA; undo that."""
    first = int(m[0:2], 16)
    if first & 0x01:
        return f"{first & 0xFE:02x}{m[2:]}"
    return m


class Frame:
    __slots__ = ("ts", "radio", "length", "ftype", "subtype", "flags",
                 "duration", "a1", "a2", "a3", "a4", "seq", "frag", "tid",
                 "body", "hdr_len", "raw")

    def __init__(self):
        self.a1 = self.a2 = self.a3 = self.a4 = None
        self.seq = self.frag = self.tid = None
        self.body = b""
        self.hdr_len = 0

    # convenience flag accessors
    @property
    def retry(self):
        return bool(self.flags & C.FC_RETRY)

    @property
    def protected(self):
        return bool(self.flags & C.FC_PROTECTED)

    @property
    def pwr_mgmt(self):
        return bool(self.flags & C.FC_PWRMGT)

    @property
    def to_ds(self):
        return bool(self.flags & C.FC_TODS)

    @property
    def from_ds(self):
        return bool(self.flags & C.FC_FROMDS)

    @property
    def is_null(self):
        return self.ftype == C.DATA and bool(self.subtype & 0x04)

    @property
    def is_qos(self):
        return self.ftype == C.DATA and bool(self.subtype & 0x08)

    @property
    def name(self):
        if self.ftype == C.MGMT:
            return C.MGMT_NAMES.get(self.subtype, f"mgmt-{self.subtype}")
        if self.ftype == C.CTRL:
            return {8: "bar", 9: "ba", 10: "ps-poll", 11: "rts", 12: "cts",
                    13: "ack", 14: "cf-end", 15: "cf-end-ack", 2: "trigger",
                    5: "ndpa", 4: "bf-poll", 7: "ctrl-wrapper"}.get(
                        self.subtype, f"ctrl-{self.subtype}")
        if self.ftype == C.DATA:
            return {0: "data", 4: "null", 8: "qos-data", 12: "qos-null"}.get(
                self.subtype, f"data-{self.subtype}")
        return f"ext-{self.subtype}"


def parse_frame(buf, ts=0.0, radio=None):
    """Parse an 802.11 MAC frame (radiotap already removed).

    Returns a Frame or None when the frame is too short/invalid.
    """
    if radio is not None and radio.fcs and len(buf) >= 4:
        buf = buf[:-4]
    n = len(buf)
    if n < 10:
        return None
    fc0, fc1 = buf[0], buf[1]
    if fc0 & 0x03:
        return None                 # protocol version must be 0
    f = Frame()
    f.ts = ts
    f.radio = radio
    f.length = n
    f.ftype = (fc0 >> 2) & 0x03
    f.subtype = (fc0 >> 4) & 0x0F
    f.flags = fc1
    f.duration = struct.unpack_from("<H", buf, 2)[0]
    f.a1 = mac(buf, 4)

    if f.ftype == C.CTRL:
        if f.subtype in C.CTRL_WITH_TA and n >= 16:
            f.a2 = strip_group_bit(mac(buf, 10))
            f.hdr_len = 16
        else:
            f.hdr_len = 10
        f.body = buf[f.hdr_len:]
        return f

    if n < 24:
        return None
    f.a2 = mac(buf, 10)
    f.a3 = mac(buf, 16)
    sc = struct.unpack_from("<H", buf, 22)[0]
    f.seq, f.frag = sc >> 4, sc & 0x0F
    hl = 24
    if f.ftype == C.DATA:
        if fc1 & C.FC_TODS and fc1 & C.FC_FROMDS:
            if n < 30:
                return None
            f.a4 = mac(buf, 24)
            hl = 30
        if f.subtype & 0x08:
            if n < hl + 2:
                return None
            f.tid = buf[hl] & 0x0F
            hl += 2
            if fc1 & C.FC_ORDER:
                hl += 4
        if radio is not None and radio.datapad:
            hl = (hl + 3) & ~3
    elif f.ftype == C.MGMT and fc1 & C.FC_ORDER:
        hl += 4
    if hl > n:
        return None
    f.hdr_len = hl
    f.body = buf[hl:]
    return f


# ----------------------------------------------------------------- IEs

def iter_ies(b, off=0):
    n = len(b)
    while off + 2 <= n:
        eid, ln = b[off], b[off + 1]
        end = off + 2 + ln
        if end > n:
            return
        yield eid, b[off + 2:end]
        off = end


def find_ie(b, want, off=0):
    for eid, v in iter_ies(b, off):
        if eid == want:
            return v
    return None


def decode_ssid(raw):
    if not raw or raw.count(0) == len(raw):
        return ""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        s = raw.decode("latin-1")
    return "".join(ch if ch.isprintable() else "?" for ch in s)


class IEInfo:
    """Interpreted information elements of a beacon / probe / assoc frame."""

    __slots__ = ("ssid", "ssid_present", "hidden", "rates", "basic_rates",
                 "ds_channel", "dtim_period", "country", "bss_load", "ht",
                 "ht_op", "vht", "vht_op", "he", "he_op", "eht", "rsn", "wpa",
                 "wmm", "wps", "owe_transition", "p2p", "hs20",
                 "mobility_domain", "rm_caps", "ext_caps", "interworking",
                 "csa", "erp", "mesh_id", "ap_name", "vendor_ouis",
                 "multi_bssid", "supported_channels", "power_cap", "ie_ids",
                 "ext_ids", "power_constraint", "tpc_tx_power")

    def __init__(self):
        for s in self.__slots__:
            setattr(self, s, None)
        self.ssid = ""
        self.ssid_present = False
        self.hidden = False
        self.rates = []
        self.basic_rates = []
        self.vendor_ouis = []
        self.ie_ids = ()
        self.ext_ids = ()

    # ---- derived capabilities
    @property
    def btm(self):          # 802.11v BSS Transition Management
        return bool(self.ext_caps and len(self.ext_caps) > 2
                    and self.ext_caps[2] & 0x08)

    @property
    def dot11k(self):
        return self.rm_caps is not None

    @property
    def dot11r(self):
        return self.mobility_domain is not None

    @property
    def dot11u(self):
        return bool(self.interworking is not None or (
            self.ext_caps and len(self.ext_caps) > 3 and self.ext_caps[3] & 0x80))

    @property
    def generation(self):
        if self.eht:
            return "be"
        if self.he:
            return "ax"
        if self.vht:
            return "ac"
        if self.ht:
            return "n"
        if any(r > 11 for r in self.rates):
            return "g/a"
        if self.rates:
            return "b"
        return None

    @property
    def nss(self):
        vals = [x.get("nss") for x in (self.he, self.vht, self.ht) if x]
        vals = [v for v in vals if v]
        return max(vals) if vals else None


def parse_ies(b, off=0):
    info = IEInfo()
    ids, ext_ids, vendors = [], [], []
    for eid, v in iter_ies(b, off):
        ids.append(eid)
        try:
            if eid == 0:
                info.ssid_present = True
                info.ssid = decode_ssid(v)
                info.hidden = info.ssid == ""
            elif eid in (1, 50):
                for x in v:
                    rate = (x & 0x7F) / 2.0
                    if (x & 0x7F) in (127, 126, 122, 123):     # BSS membership selectors
                        continue
                    info.rates.append(rate)
                    if x & 0x80:
                        info.basic_rates.append(rate)
            elif eid == 3 and v:
                info.ds_channel = v[0]
            elif eid == 5 and len(v) >= 2:
                info.dtim_period = v[1]
            elif eid == 7 and len(v) >= 2:
                info.country = v[:2].decode("ascii", "replace")
            elif eid == 11 and len(v) >= 5:
                sta, util, aac = struct.unpack_from("<HBH", v, 0)
                info.bss_load = {"stations": sta, "util_pct": round(util * 100 / 255, 1),
                                 "admission_capacity": aac}
            elif eid == 32 and v:
                info.power_constraint = v[0]
            elif eid == 33 and len(v) >= 2:
                info.power_cap = (struct.unpack_from("<b", v, 0)[0],
                                  struct.unpack_from("<b", v, 1)[0])
            elif eid == 35 and v:
                info.tpc_tx_power = struct.unpack_from("<b", v, 0)[0]
            elif eid == 36:
                chans = []
                for i in range(0, len(v) - 1, 2):
                    first, cnt = v[i], v[i + 1]
                    step = 4 if first > 14 else 1
                    chans.extend(first + step * k for k in range(cnt))
                info.supported_channels = chans
            elif eid == 37 and len(v) >= 3:
                info.csa = {"mode": v[0], "new_channel": v[1], "count": v[2]}
            elif eid == 42 and v:
                info.erp = {"non_erp_present": bool(v[0] & 1),
                            "use_protection": bool(v[0] & 2),
                            "barker_long_preamble": bool(v[0] & 4)}
            elif eid == 45 and len(v) >= 7:
                cap = struct.unpack_from("<H", v, 0)[0]
                mcs = v[3:7]
                info.ht = {"width40": bool(cap & 0x0002), "sgi20": bool(cap & 0x0020),
                           "sgi40": bool(cap & 0x0040), "ldpc": bool(cap & 0x0001),
                           "nss": sum(1 for x in mcs if x) or 1}
            elif eid == 48:
                info.rsn = parse_rsn(v)
            elif eid == 54 and len(v) >= 3:
                info.mobility_domain = {"mdid": struct.unpack_from("<H", v, 0)[0],
                                        "ft_over_ds": bool(v[2] & 1)}
            elif eid == 61 and len(v) >= 2:
                info.ht_op = {"primary": v[0], "sec_offset": v[1] & 0x03,
                              "sta_width": bool(v[1] & 0x04)}
            elif eid == 70:
                info.rm_caps = bytes(v)
            elif eid == 71:
                info.multi_bssid = True
            elif eid == 107:
                info.interworking = bytes(v)
            elif eid == 113:
                info.mesh_id = decode_ssid(v)
            elif eid == 127:
                info.ext_caps = bytes(v)
            elif eid == 133 and len(v) >= 26:
                name = v[10:26].split(b"\x00", 1)[0]
                info.ap_name = name.decode("ascii", "replace") or None
            elif eid == 191 and len(v) >= 12:
                cap = struct.unpack_from("<I", v, 0)[0]
                rx_map = struct.unpack_from("<H", v, 4)[0]
                nss = sum(1 for i in range(8) if (rx_map >> (2 * i)) & 3 != 3)
                info.vht = {"width160": (cap >> 2) & 3 != 0, "sgi80": bool(cap & 0x20),
                            "sgi160": bool(cap & 0x40), "su_beamformer": bool(cap & (1 << 11)),
                            "mu_beamformer": bool(cap & (1 << 19)), "nss": nss}
            elif eid == 192 and len(v) >= 3:
                info.vht_op = {"width": v[0], "seg0": v[1], "seg1": v[2]}
            elif eid == 221 and len(v) >= 4:
                _vendor_ie(info, v, vendors)
            elif eid == 255 and v:
                ext = v[0]
                ext_ids.append(ext)
                _ext_ie(info, ext, v[1:])
        except (struct.error, IndexError):
            continue
    info.ie_ids = tuple(ids)
    info.ext_ids = tuple(ext_ids)
    info.vendor_ouis = vendors
    return info


def _vendor_ie(info, v, vendors):
    oui = v[:3].hex(":")
    vtype = v[3]
    vendors.append(f"{oui}/{vtype}")
    if oui == "00:50:f2":
        if vtype == 1:
            info.wpa = parse_rsn(v[4:], wpa=True)
        elif vtype == 2:
            info.wmm = True
        elif vtype == 4:
            info.wps = parse_wps(v[4:])
    elif oui == "50:6f:9a":
        if vtype == 0x1C and len(v) >= 11:
            ssid_len = v[10]
            info.owe_transition = {"bssid": mac(v, 4),
                                   "ssid": decode_ssid(v[11:11 + ssid_len])}
        elif vtype == 0x09:
            info.p2p = True
        elif vtype == 0x10:
            info.hs20 = True


def _ext_ie(info, ext, v):
    if ext == 35:                         # HE capabilities
        he = {"nss": None}
        if len(v) >= 17 + 2:
            phy0 = v[6]
            he["width40_2g"] = bool(phy0 & 0x02)
            he["width80_5g"] = bool(phy0 & 0x04)
            he["width160"] = bool(phy0 & 0x08)
            rx = struct.unpack_from("<H", v, 17)[0]
            he["nss"] = sum(1 for i in range(8) if (rx >> (2 * i)) & 3 != 3)
        info.he = he
    elif ext == 36 and len(v) >= 6:      # HE operation
        params = v[0] | (v[1] << 8) | (v[2] << 16)
        op = {"bss_color": v[3] & 0x3F, "color_disabled": bool(v[3] & 0x80)}
        o = 6
        if params & (1 << 14):
            if len(v) >= o + 3:
                op["vht_op"] = {"width": v[o], "seg0": v[o + 1], "seg1": v[o + 2]}
            o += 3
        if params & (1 << 15):
            o += 1
        if params & (1 << 17) and len(v) >= o + 5:
            op["6ghz"] = {"primary": v[o], "width": {0: 20, 1: 40, 2: 80, 3: 160}[v[o + 1] & 3],
                          "ccfs0": v[o + 2], "ccfs1": v[o + 3]}
        info.he_op = op
    elif ext in (106, 108):              # EHT operation / capabilities
        info.eht = True


def parse_rsn(v, wpa=False):
    """Parse an RSN element (or WPA vendor element body)."""
    rsn_oui = b"\x00\x50\xf2" if wpa else b"\x00\x0f\xac"
    out = {"version": None, "group": None, "pairwise": [], "akm": [],
           "akm_names": [], "mfpc": False, "mfpr": False, "group_mgmt": None,
           "pmkid_count": 0, "wpa1": wpa}

    def suite(o, table):
        s = v[o:o + 4]
        if s[:3] == rsn_oui:
            return s[3], table.get(s[3], f"type-{s[3]}")
        return None, "vendor:" + s.hex(":")

    if len(v) < 2:
        return out
    out["version"] = struct.unpack_from("<H", v, 0)[0]
    o = 2
    if len(v) >= o + 4:
        out["group"] = suite(o, C.CIPHER_SUITES)[1]
        o += 4
    if len(v) >= o + 2:
        cnt = struct.unpack_from("<H", v, o)[0]
        o += 2
        for _ in range(cnt):
            if len(v) < o + 4:
                break
            out["pairwise"].append(suite(o, C.CIPHER_SUITES)[1])
            o += 4
    if len(v) >= o + 2:
        cnt = struct.unpack_from("<H", v, o)[0]
        o += 2
        for _ in range(cnt):
            if len(v) < o + 4:
                break
            num, name = suite(o, C.AKM_SUITES)
            if num is not None:
                out["akm"].append(num)
            out["akm_names"].append(name)
            o += 4
    if not wpa and len(v) >= o + 2:
        caps = struct.unpack_from("<H", v, o)[0]
        out["mfpr"] = bool(caps & 0x0040)
        out["mfpc"] = bool(caps & 0x0080)
        o += 2
        if len(v) >= o + 2:
            out["pmkid_count"] = struct.unpack_from("<H", v, o)[0]
            o += 2 + 16 * out["pmkid_count"]
        if len(v) >= o + 4:
            out["group_mgmt"] = suite(o, C.CIPHER_SUITES)[1]
    return out


def parse_wps(v):
    out = {"state": None, "locked": False, "device_name": None,
           "manufacturer": None, "model": None, "version2": False}
    o = 0
    while o + 4 <= len(v):
        t, ln = struct.unpack_from(">HH", v, o)
        d = v[o + 4:o + 4 + ln]
        if t == 0x1044 and d:
            out["state"] = "configured" if d[0] == 2 else "unconfigured"
        elif t == 0x1057 and d:
            out["locked"] = bool(d[0])
        elif t == 0x1011:
            out["device_name"] = decode_ssid(d)
        elif t == 0x1021:
            out["manufacturer"] = decode_ssid(d)
        elif t == 0x1023:
            out["model"] = decode_ssid(d)
        elif t == 0x1049 and d[:3] == b"\x00\x37\x2a":
            out["version2"] = True
        o += 4 + ln
    return out


def summarize_security(privacy, rsn, wpa, owe_transition=None):
    """Return (label, class) e.g. ('WPA2/WPA3-Personal', 'WPA2').

    class is the weakest accepted family (used for ranking/mismatch checks).
    """
    if not rsn and not wpa:
        if privacy:
            return "WEP", "WEP"
        if owe_transition:
            return "OPEN (OWE transition)", "OPEN"
        return "OPEN", "OPEN"
    akms = set(rsn["akm"]) if rsn else set()
    wakms = set(wpa["akm"]) if wpa else set()
    ft = "+FT" if akms & C.AKM_FT else ""
    if akms & C.AKM_OWE and not akms - C.AKM_OWE:
        return "OWE", "OWE"
    if akms & C.AKM_EAP_192:
        return "WPA3-Enterprise-192" + ft, "WPA3"
    eap = bool((akms | wakms) & C.AKM_EAP or (wakms and 1 in wakms))
    sae = bool(akms & C.AKM_SAE)
    psk = bool(akms & C.AKM_PSK or wakms)
    if eap:
        if wpa and not rsn:
            return "WPA-Enterprise", "WPA"
        if wpa:
            return "WPA/WPA2-Enterprise" + ft, "WPA"
        if rsn and rsn["mfpr"] and akms <= {5, 11, 12, 13, 22}:
            return "WPA3-Enterprise" + ft, "WPA3"
        return "WPA2-Enterprise" + ft, "WPA2"
    if sae and psk:
        return "WPA2/WPA3-Personal" + ft, "WPA2"
    if sae:
        return "WPA3-Personal" + ft, "WPA3"
    if wpa and not rsn:
        return "WPA-Personal", "WPA"
    if wpa:
        return "WPA/WPA2-Personal" + ft, "WPA"
    if psk:
        return "WPA2-Personal" + ft, "WPA2"
    names = ",".join(rsn["akm_names"]) if rsn else "?"
    return f"RSN({names})", "WPA2"


def bss_width(info, band):
    """Return (width_mhz, center_freq or None) from HT/VHT/HE operation."""
    from .channels import channel_to_freq
    primary = info.ds_channel or (info.ht_op or {}).get("primary")
    if info.he_op and info.he_op.get("6ghz"):
        g = info.he_op["6ghz"]
        width = g["width"]
        center = g["ccfs1"] if width == 160 and g["ccfs1"] else g["ccfs0"]
        return width, channel_to_freq("6g", center) if center else None
    vop = info.vht_op or (info.he_op or {}).get("vht_op")
    if vop and vop["width"] in (1, 2, 3) and band == "5g":
        seg0, seg1 = vop["seg0"], vop["seg1"]
        if vop["width"] == 2:
            return 160, channel_to_freq("5g", seg0)
        if seg1 and abs(seg1 - seg0) == 8:
            return 160, channel_to_freq("5g", seg1)
        if seg1:
            return 160, channel_to_freq("5g", seg0)       # 80+80, approximate
        return 80, channel_to_freq("5g", seg0)
    if info.ht_op and info.ht_op["sec_offset"] in (1, 3) and info.ht_op["sta_width"]:
        if primary and band in ("2g", "5g"):
            off = 2 if info.ht_op["sec_offset"] == 1 else -2
            return 40, channel_to_freq(band, primary + off)
        return 40, None
    return 20, None


# ----------------------------------------------------------------- EAPOL

def llc_ethertype(payload):
    if len(payload) >= 8 and payload[0] == 0xAA and payload[1] == 0xAA and payload[2] == 0x03:
        return (payload[6] << 8) | payload[7]
    return None


def parse_eapol(p):
    """Parse EAPOL after the 8-byte LLC/SNAP header.

    Returns dict with 'kind' in {'key','eap','start','logoff','other'}.
    """
    if len(p) < 4:
        return None
    ptype = p[1]
    out = {"version": p[0], "ptype": ptype}
    if ptype == 1:
        out["kind"] = "start"
    elif ptype == 2:
        out["kind"] = "logoff"
    elif ptype == 0 and len(p) >= 8:
        out["kind"] = "eap"
        out["eap_code"] = p[4]             # 1 req, 2 resp, 3 success, 4 failure
        out["eap_type"] = p[8] if len(p) > 8 and p[4] in (1, 2) else None
    elif ptype == 3 and len(p) >= 4 + 95:
        out["kind"] = "key"
        info = struct.unpack_from(">H", p, 5)[0]
        out["key_info"] = info
        out["replay"] = struct.unpack_from(">Q", p, 9)[0]
        nonce = p[17:49]
        pairwise = bool(info & 0x0008)
        install = bool(info & 0x0040)
        ack = bool(info & 0x0080)
        mic = bool(info & 0x0100)
        secure = bool(info & 0x0200)
        if pairwise:
            if ack and not mic:
                msg = "M1"
            elif ack and mic and install:
                msg = "M3"
            elif mic and not ack:
                msg = "M4" if (secure or nonce.count(0) == 32) else "M2"
            else:
                msg = "?"
        else:
            msg = "G1" if ack else "G2"
        out["msg"] = msg
        out["error"] = bool(info & 0x0400)
        out["request"] = bool(info & 0x0800)
    else:
        out["kind"] = "other"
    return out
