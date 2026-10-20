"""Synthetic 802.11 frame builder and demo scenario generator.

Used by the unit tests, and handy for trying the UI without radios:

    python -m wlanscope.synth demo.pcap
    python -m wlanscope -r demo.pcap
"""

import random
import struct
import sys

from .capture import PcapWriter
from .channels import channel_to_freq, guess_band


def _mac(m):
    return bytes.fromhex(m.replace(":", ""))


def radiotap(channel=6, signal=-50, noise=-95, rate=None, mcs=None, band=None):
    """Radiotap header with flags, rate or MCS, channel, signal and noise."""
    band = band or guess_band(channel)
    freq = channel_to_freq(band, channel)
    present = (1 << 1) | (1 << 3) | (1 << 5)
    body = bytearray([0])                  # flags
    if mcs is None:
        present |= 1 << 2
        body.append(int((rate or (1.0 if band == "2g" else 6.0)) * 2))
    if (8 + len(body)) % 2:
        body.append(0)                     # align channel to 2 bytes
    body += struct.pack("<HH", freq, 0x0080 if band == "2g" else 0x0100)
    body += struct.pack("<b", signal)
    if noise is not None:
        present |= 1 << 6
        body += struct.pack("<b", noise)
    if mcs is not None:
        present |= 1 << 19
        body += bytes([0x07, 0x00, mcs])   # bandwidth, MCS and GI known; 20 MHz long GI
    return struct.pack("<BBHI", 0, 0, 8 + len(body), present) + bytes(body)


def hdr(ftype, subtype, a1, a2, a3, seq=0, flags=0, duration=0):
    fc0 = (subtype << 4) | (ftype << 2)
    return (struct.pack("<BBH", fc0, flags, duration) + _mac(a1) + _mac(a2) + _mac(a3)
            + struct.pack("<H", (seq & 0xFFF) << 4))


def ie(eid, data):
    return bytes([eid, len(data)]) + data


RSN_PSK = ie(48, struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
             + struct.pack("<H", 1) + b"\x00\x0f\xac\x02" + struct.pack("<H", 0x0080))
RSN_EAP_FT = ie(48, struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
                + struct.pack("<H", 2) + b"\x00\x0f\xac\x01" + b"\x00\x0f\xac\x03" + struct.pack("<H", 0x0080))
RSN_SAE = ie(48, struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
             + struct.pack("<H", 1) + b"\x00\x0f\xac\x08" + struct.pack("<H", 0x00C0))
RSN_TRANS = ie(48, struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
               + struct.pack("<H", 2) + b"\x00\x0f\xac\x02" + b"\x00\x0f\xac\x08" + struct.pack("<H", 0x0080))
WPA_TKIP = ie(221, b"\x00\x50\xf2\x01" + struct.pack("<H", 1) + b"\x00\x50\xf2\x02" + struct.pack("<H", 1)
              + b"\x00\x50\xf2\x02" + struct.pack("<H", 1) + b"\x00\x50\xf2\x02")
SECURITY = {"open": b"", "psk": RSN_PSK, "eap-ft": RSN_EAP_FT, "sae": RSN_SAE,
            "psk-sae": RSN_TRANS, "wpa-tkip": WPA_TKIP}

WMM = ie(221, b"\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")
CISCO_IE = ie(221, b"\x00\x40\x96\x03\x05")
HT_CAP = ie(45, struct.pack("<H", 0x016E) + b"\x17" + b"\xff\xff\x00\x00" + b"\x00" * 12 + b"\x00" * 7)
VHT_CAP = ie(191, struct.pack("<I", 0x0F8259B2) + struct.pack("<H", 0xFFFA) + b"\x00\x00"
             + struct.pack("<H", 0xFFFA) + b"\x00\x00")
EXT_CAPS_BTM = ie(127, b"\x04\x00\x08\x00\x00\x00\x00\x40")
RM_CAPS = ie(70, b"\x73\x00\x00\x00\x00")


def beacon_body(ssid, channel, security="psk", tsf=0, interval=100, hidden=False, ht=True,
                vht=False, bss_load=None, vendor=(WMM,), country=b"US", extra=b"", probe=False):
    privacy = 0x0010 if security != "open" else 0
    cap = 0x0001 | privacy | 0x0400 | (0x0200 if ht else 0)
    b = struct.pack("<QHH", tsf, interval, cap)
    raw = b"" if hidden else ssid.encode()
    b += ie(0, raw)
    b += ie(1, bytes([0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c]) if channel > 14
            else bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]))
    b += ie(3, bytes([channel]))
    if not probe:
        b += ie(5, b"\x00\x01\x00\x00")
    if country:
        b += ie(7, country + b" \x01\x0b\x1e")
    if bss_load is not None:
        b += ie(11, struct.pack("<HBH", bss_load[0], int(bss_load[1] * 255 / 100), 0))
    b += SECURITY[security]
    if ht:
        b += HT_CAP
        b += ie(61, bytes([channel, 0x00]) + b"\x00" * 20)
    if vht and channel > 14:
        b += VHT_CAP
        b += ie(192, bytes([1, channel + 6, 0]) + b"\x00\x00")
    b += extra
    for v in vendor:
        b += v
    return b


class Scene:
    """Collects (timestamp, radiotap+frame) records and writes a pcap."""

    def __init__(self, t0=1_760_000_000.0, seed=7):
        self.t0 = t0
        self.recs = []
        self.seq = {}
        self.rnd = random.Random(seed)

    def _seq(self, a):
        self.seq[a] = (self.seq.get(a, 0) + 1) & 0xFFF
        return self.seq[a]

    def add(self, t, rt, frame):
        self.recs.append((self.t0 + t, rt + frame))

    # -- frame helpers (t is seconds from scene start)
    def beacon(self, t, bssid, ssid, channel, signal=-55, tsf=None, **kw):
        tsf = int(t * 1e6) + 123_456_789 if tsf is None else tsf
        f = hdr(0, 8, "ff:ff:ff:ff:ff:ff", bssid, bssid, self._seq(bssid)) + \
            beacon_body(ssid, channel, tsf=tsf, **kw)
        self.add(t, radiotap(channel, signal), f)

    def probe_req(self, t, client, ssid, channel, signal=-60):
        f = hdr(0, 4, "ff:ff:ff:ff:ff:ff", client, "ff:ff:ff:ff:ff:ff", self._seq(client)) + \
            ie(0, ssid.encode()) + ie(1, b"\x82\x84\x8b\x96") + HT_CAP
        self.add(t, radiotap(channel, signal), f)

    def probe_resp(self, t, bssid, client, ssid, channel, signal=-55, **kw):
        f = hdr(0, 5, client, bssid, bssid, self._seq(bssid)) + \
            beacon_body(ssid, channel, tsf=int(t * 1e6), probe=True, **kw)
        self.add(t, radiotap(channel, signal), f)

    def auth(self, t, src, dst, bssid, channel, seq=1, status=0, algo=0, signal=-55):
        f = hdr(0, 11, dst, src, bssid, self._seq(src)) + struct.pack("<HHH", algo, seq, status)
        self.add(t, radiotap(channel, signal), f)

    def assoc_req(self, t, client, bssid, ssid, channel, security="psk", signal=-60, reassoc_from=None):
        body = struct.pack("<HH", 0x0411, 10)
        sub = 0
        if reassoc_from:
            body += _mac(reassoc_from)
            sub = 2
        body += ie(0, ssid.encode()) + ie(1, b"\x82\x84\x8b\x96\x0c\x12\x18\x24") + \
            SECURITY[security] + HT_CAP + VHT_CAP + RM_CAPS + EXT_CAPS_BTM + ie(33, b"\x00\x14")
        f = hdr(0, sub, bssid, client, bssid, self._seq(client)) + body
        self.add(t, radiotap(channel, signal), f)

    def assoc_resp(self, t, bssid, client, channel, status=0, aid=1, reassoc=False, signal=-55):
        f = hdr(0, 3 if reassoc else 1, client, bssid, bssid, self._seq(bssid)) + \
            struct.pack("<HHH", 0x0411, status, 0xC000 | aid) + ie(1, b"\x82\x84\x8b\x96")
        self.add(t, radiotap(channel, signal), f)

    def connect(self, t, client, bssid, ssid, channel, security="psk", sig_c=-60, sig_ap=-55,
                reassoc_from=None, aid=1):
        self.auth(t, client, bssid, bssid, channel, 1, signal=sig_c)
        self.auth(t + 0.002, bssid, client, bssid, channel, 2, signal=sig_ap)
        self.assoc_req(t + 0.004, client, bssid, ssid, channel, security, sig_c, reassoc_from)
        self.assoc_resp(t + 0.006, bssid, client, channel, 0, aid, bool(reassoc_from), sig_ap)
        if security != "open":
            for i, m in enumerate(("M1", "M2", "M3", "M4")):
                self.eapol(t + 0.01 + i * 0.003, bssid, client, channel, m, sig_c, sig_ap)

    def deauth(self, t, src, dst, bssid, channel, reason=7, disassoc=False, signal=-55):
        f = hdr(0, 10 if disassoc else 12, dst, src, bssid, self._seq(src)) + struct.pack("<H", reason)
        self.add(t, radiotap(channel, signal), f)

    def data(self, t, bssid, client, channel, up=True, length=200, retry=False, null=False,
             pm=False, signal=-60, mcs=7, protected=True):
        flags = 0x01 if up else 0x02
        if retry:
            flags |= 0x08
        if pm and up:
            flags |= 0x10
        if protected and not null:
            flags |= 0x40
        sub = 12 if null else 8
        a1, a2, a3 = (bssid, client, "00:11:22:33:44:55") if up else (client, bssid, "00:11:22:33:44:55")
        tx = client if up else bssid
        f = hdr(2, sub, a1, a2, a3, self._seq(tx), flags) + b"\x00\x00"
        if not null:
            f += b"\x00" * length
        self.add(t, radiotap(channel, signal, mcs=mcs), f)

    def eapol(self, t, bssid, client, channel, msg, sig_c=-60, sig_ap=-55):
        info = {"M1": 0x008A, "M2": 0x010A, "M3": 0x13CA, "M4": 0x030A}[msg]
        up = msg in ("M2", "M4")
        nonce = b"\x00" * 32 if msg == "M4" else bytes(self.rnd.randrange(256) for _ in range(32))
        key = struct.pack(">BH", 2, info) + struct.pack(">H", 16) + struct.pack(">Q", 1) + nonce + \
            b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8 + b"\x00" * 16 + struct.pack(">H", 0)
        eap = struct.pack(">BBH", 2, 3, len(key)) + key
        llc = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
        flags = 0x01 if up else 0x02
        a1, a2 = (bssid, client) if up else (client, bssid)
        f = hdr(2, 8, a1, a2, bssid, self._seq(a2), flags) + b"\x07\x00" + llc + eap
        self.add(t, radiotap(channel, sig_c if up else sig_ap), f)

    def eap(self, t, bssid, client, channel, code, etype=None):
        up = code == 2
        pkt = struct.pack(">BBH", code, 1, 5 if etype else 4) + (bytes([etype]) if etype else b"")
        eapol = struct.pack(">BBH", 2, 0, len(pkt)) + pkt
        a1, a2 = (bssid, client) if up else (client, bssid)
        f = hdr(2, 8, a1, a2, bssid, self._seq(a2), 0x01 if up else 0x02) + b"\x07\x00" + \
            b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + eapol
        self.add(t, radiotap(channel, -60), f)

    def write(self, path):
        self.recs.sort(key=lambda r: r[0])
        w = PcapWriter(path)
        for ts, data in self.recs:
            w.write(ts, data)
        w.close()
        return len(self.recs)


def demo(path, duration=120):
    """A busy little campus: enterprise WLAN, an evil twin, attacks, and
    clients with assorted problems."""
    s = Scene()
    R = s.rnd
    corp = [("70:69:5a:10:00:01", 1, -48), ("70:69:5a:10:00:02", 36, -52), ("70:69:5a:10:00:03", 149, -66)]
    twin = ("00:c0:ca:66:66:66", 6, -40)
    home = ("50:c7:bf:aa:00:01", 11, -58)
    guest = ("70:69:5a:20:00:01", 6, -50)
    legacy = ("00:1e:2a:33:00:01", 11, -71)
    hidden = ("70:69:5a:30:00:01", 44, -62)
    karma = ("02:13:37:00:00:01", 6, -45)
    busy = ("24:a4:3c:44:00:01", 1, -70)
    corp_kw = dict(security="eap-ft", vendor=(WMM, CISCO_IE), extra=RM_CAPS + EXT_CAPS_BTM +
                   ie(54, b"\x12\x34\x01"), vht=True, bss_load=(6, 22))

    bi = 0.1024
    n = int(duration / bi)
    for i in range(n):
        t = i * bi
        for b, ch, sig in corp:
            s.beacon(t + 0.001, b, "CorpWiFi", ch, sig + R.randint(-2, 2), **corp_kw)
        s.beacon(t + 0.002, guest[0], "Guest", guest[1], guest[2], security="open", vendor=(WMM, CISCO_IE))
        s.beacon(t + 0.003, home[0], "HomeNet", home[1], home[2], security="psk")
        s.beacon(t + 0.004, legacy[0], "IoT-Legacy", legacy[1], legacy[2], security="wpa-tkip", ht=False)
        s.beacon(t + 0.005, hidden[0], "", hidden[1], hidden[2], security="sae", hidden=True)
        s.beacon(t + 0.006, busy[0], "Warehouse", busy[1], busy[2], security="psk-sae", bss_load=(41, 86))
        s.beacon(t + 0.007, karma[0], "FreeWiFi", karma[1], karma[2], security="open", vendor=())
        if t >= 20:   # evil twin of CorpWiFi appears: open, other vendor, stronger
            s.beacon(t + 0.008, twin[0], "CorpWiFi", twin[1], twin[2], security="open", vendor=(),
                     country=None, interval=100)
        if t >= 30:   # a clone of HomeNet's BSSID on another channel with its own TSF
            s.beacon(t + 0.05, home[0], "HomeNet", 1, -45, security="psk", tsf=int(t * 1e6) + 9_000_000_000)

    clients = {
        "streamer": "a4:83:e7:01:01:01", "idle": "3c:22:fb:02:02:02", "sleepy": "f0:18:98:03:03:03",
        "weak": "b4:96:91:04:04:04", "roamer": "dc:53:60:05:05:05", "normal": "8c:85:90:06:06:06",
        "victim": "f4:0f:24:07:07:07", "twinned": "ac:bc:32:08:08:08", "wrongpsk": "5c:0a:5b:09:09:09",
        "eapfail": "7c:b2:7d:0a:0a:0a", "warehouse1": "24:0a:c4:0b:0b:0b", "warehouse2": "18:fe:34:0c:0c:0c",
    }
    c = clients
    ap1, ap2, ap3 = corp
    s.connect(0.5, c["streamer"], ap2[0], "CorpWiFi", 36, "eap-ft", -50, ap2[2], aid=1)
    s.connect(0.7, c["idle"], ap2[0], "CorpWiFi", 36, "eap-ft", -61, ap2[2], aid=2)
    s.connect(0.9, c["sleepy"], ap1[0], "CorpWiFi", 1, "eap-ft", -58, ap1[2], aid=1)
    s.connect(1.1, c["weak"], ap3[0], "CorpWiFi", 149, "eap-ft", -86, ap3[2], aid=1)
    s.connect(1.3, c["roamer"], ap2[0], "CorpWiFi", 36, "eap-ft", -63, ap2[2], aid=3)
    s.connect(1.5, c["normal"], ap1[0], "CorpWiFi", 1, "eap-ft", -55, ap1[2], aid=2)
    s.connect(1.7, c["victim"], ap1[0], "CorpWiFi", 1, "eap-ft", -57, ap1[2], aid=3)
    s.connect(2.0, c["warehouse1"], busy[0], "Warehouse", 1, "psk", -72, busy[2], aid=1)
    s.connect(2.2, c["warehouse2"], busy[0], "Warehouse", 1, "psk", -74, busy[2], aid=2)

    cur = ap2
    for sec in range(int(duration)):
        t = float(sec)
        # heavy streamer: ~250 data frames/s downlink, plus acks uplink
        for k in range(250):
            s.data(t + k / 250, ap2[0], c["streamer"], 36, up=False, length=400, signal=ap2[2],
                   mcs=15, retry=R.random() < 0.03)
            if k % 10 == 0:
                s.data(t + k / 250 + 0.001, ap2[0], c["streamer"], 36, up=True, length=60, signal=-50, mcs=15)
        # normal web user
        for k in range(R.randint(5, 25)):
            s.data(t + R.random(), ap1[0], c["normal"], 1, up=R.random() < 0.4, length=300,
                   signal=-55 if R.random() < 0.5 else ap1[2], mcs=7)
        # idle: a null frame every 10 s
        if sec % 10 == 3:
            s.data(t + 0.3, ap2[0], c["idle"], 36, up=True, null=True, signal=-61)
        # sleepy: power save nulls and occasional data
        if sec % 5 == 0:
            s.data(t + 0.4, ap1[0], c["sleepy"], 1, up=True, null=True, pm=True, signal=-58)
        if sec % 30 == 1:
            s.data(t + 0.5, ap1[0], c["sleepy"], 1, up=True, length=100, pm=True, signal=-58)
        # weak client: low rate, many retries
        for k in range(20):
            s.data(t + k / 20, ap3[0], c["weak"], 149, up=k % 2 == 0, length=200,
                   signal=-86 if k % 2 == 0 else ap3[2], mcs=0, retry=R.random() < 0.4)
        # victim and warehouse clients: some steady traffic
        if sec < 60 or sec > 70:
            for k in range(6):
                s.data(t + R.random(), ap1[0], c["victim"], 1, up=k % 2 == 0, length=250, signal=-57)
        for k in range(8):
            s.data(t + R.random(), busy[0], c["warehouse1"], 1, up=k % 2 == 0, length=400, signal=-72,
                   mcs=4, retry=R.random() < 0.15)
            s.data(t + R.random(), busy[0], c["warehouse2"], 1, up=k % 2 == 0, length=400, signal=-74,
                   mcs=4, retry=R.random() < 0.15)
        # roamer: ping-pongs between AP2 and AP3 every 8 s from t=30
        if sec >= 30 and sec % 8 == 0:
            nxt = ap3 if cur is ap2 else ap2
            s.connect(t + 0.1, c["roamer"], nxt[0], "CorpWiFi", nxt[1], "eap-ft", -67, nxt[2],
                      reassoc_from=cur[0], aid=4)
            cur = nxt
        for k in range(4):
            s.data(t + 0.2 + k / 5, cur[0], c["roamer"], cur[1], up=k % 2 == 0, length=150, signal=-67)
        # probing randomized phones
        if sec % 3 == 0:
            for j in range(3):
                m = f"{0x02 | (j << 4):02x}:5e:{sec % 256:02x}:00:{j:02x}:{R.randint(0, 255):02x}"
                s.probe_req(t + 0.6 + j * 0.01, m, R.choice(["", "CorpWiFi", "HomeNet", "eduroam"]),
                            R.choice([1, 6, 11]), signal=R.randint(-85, -55))
        # hidden network revealed by a directed probe at t=15
        if sec == 15:
            s.probe_req(t, "a4:83:e7:0d:0d:0d", "SecretLab", 44, -64)
            s.probe_resp(t + 0.002, hidden[0], "a4:83:e7:0d:0d:0d", "SecretLab", 44, hidden[2],
                         security="sae")
        # karma AP answers every probed SSID
        if sec >= 40 and sec % 4 == 0:
            for j, name in enumerate(("Starbucks", "attwifi", "Airport_Free", "CorpWiFi", "xfinitywifi")):
                cl = f"02:aa:bb:00:{j:02x}:{sec % 256:02x}"
                s.probe_req(t + 0.1 * j, cl, name, 6, -62)
                s.probe_resp(t + 0.1 * j + 0.003, karma[0], cl, name, 6, karma[2], security="open", vendor=())

    # client lured to the evil twin at t=25 (open: no handshake)
    s.connect(25.0, c["twinned"], twin[0], "CorpWiFi", 6, "open", -52, twin[2], aid=1)
    for sec in range(25, int(duration)):
        for k in range(10):
            s.data(sec + R.random(), twin[0], c["twinned"], 6, up=k % 2 == 0, length=300,
                   signal=-52, protected=False)

    # wrong passphrase on HomeNet: M1/M2 repeated then 4-way timeout
    for start in (20.0, 45.0, 70.0):
        s.auth(start, c["wrongpsk"], home[0], home[0], 11, 1, signal=-60)
        s.auth(start + 0.002, home[0], c["wrongpsk"], home[0], 11, 2, signal=home[2])
        s.assoc_req(start + 0.004, c["wrongpsk"], home[0], "HomeNet", 11, "psk", -60)
        s.assoc_resp(start + 0.006, home[0], c["wrongpsk"], 11, 0, 5)
        for r in range(3):
            s.eapol(start + 0.01 + r, home[0], c["wrongpsk"], 11, "M1", -60, home[2])
            s.eapol(start + 0.02 + r, home[0], c["wrongpsk"], 11, "M2", -60, home[2])
        s.deauth(start + 3.5, home[0], c["wrongpsk"], home[0], 11, reason=15, signal=home[2])

    # 802.1X failures on CorpWiFi
    for start in (35.0, 50.0):
        s.auth(start, c["eapfail"], ap1[0], ap1[0], 1, 1, signal=-62)
        s.auth(start + 0.002, ap1[0], c["eapfail"], ap1[0], 1, 2, signal=ap1[2])
        s.assoc_req(start + 0.004, c["eapfail"], ap1[0], "CorpWiFi", 1, "eap-ft", -62)
        s.assoc_resp(start + 0.006, ap1[0], c["eapfail"], 1, 0, 9)
        s.eap(start + 0.1, ap1[0], c["eapfail"], 1, 1, 1)
        s.eap(start + 0.2, ap1[0], c["eapfail"], 1, 2, 25)
        s.eap(start + 1.0, ap1[0], c["eapfail"], 1, 4)
        s.deauth(start + 1.1, ap1[0], c["eapfail"], ap1[0], 1, reason=23, signal=ap1[2])

    # deauth flood against AP1 / victim at t=60-66 (spoofed from the AP address)
    for k in range(240):
        t = 60 + k * 0.025
        s.deauth(t, ap1[0], c["victim"] if k % 3 else "ff:ff:ff:ff:ff:ff", ap1[0], 1, reason=7, signal=-38)
    s.connect(71.0, c["victim"], ap1[0], "CorpWiFi", 1, "eap-ft", -57, ap1[2], aid=3)
    return s.write(path)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m wlanscope.synth OUT.pcap [seconds]")
        return 2
    n = demo(argv[0], float(argv[1]) if len(argv) > 1 else 120)
    print(f"wrote {n} frames to {argv[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
