"""Radiotap header parser (https://www.radiotap.org).

Handles extended presence bitmaps, radiotap/vendor namespaces, per-chain
signal fields, and the HT (MCS), VHT and HE rate fields.
"""

import struct

from .channels import freq_to_channel, ht_rate, vht_rate, he_rate

# bit -> (alignment, size)
_FIELDS = {
    0: (8, 8),    # TSFT
    1: (1, 1),    # Flags
    2: (1, 1),    # Rate
    3: (2, 4),    # Channel
    4: (1, 2),    # FHSS
    5: (1, 1),    # dBm antenna signal
    6: (1, 1),    # dBm antenna noise
    7: (2, 2),    # lock quality
    8: (2, 2),    # TX attenuation
    9: (2, 2),    # dB TX attenuation
    10: (1, 1),   # dBm TX power
    11: (1, 1),   # antenna
    12: (1, 1),   # dB antenna signal
    13: (1, 1),   # dB antenna noise
    14: (2, 2),   # RX flags
    15: (2, 2),   # TX flags
    16: (1, 1),   # RTS retries
    17: (1, 1),   # data retries
    18: (4, 8),   # XChannel
    19: (1, 3),   # MCS
    20: (4, 8),   # A-MPDU status
    21: (2, 12),  # VHT
    22: (8, 12),  # timestamp
    23: (2, 12),  # HE
    24: (2, 12),  # HE-MU
    25: (2, 6),   # HE-MU-other-user
    26: (1, 1),   # 0-length PSDU
    27: (2, 4),   # L-SIG
}

F_FCS = 0x10
F_DATAPAD = 0x20
F_BADFCS = 0x40
F_SHORTGI = 0x80

_VHT_BW = {0: 20, 1: 40, 2: 40, 3: 40, 4: 80, 5: 80, 6: 80, 7: 80, 8: 80,
           9: 80, 10: 80, 11: 160}
_HE_GI = {0: 0.8, 1: 1.6, 2: 3.2}
_HE_BW = {0: 20, 1: 40, 2: 80, 3: 160}


class Radio:
    __slots__ = ("length", "tsft", "flags", "rate", "freq", "band", "channel",
                 "signal", "noise", "chains", "antenna", "phy", "mcs", "nss",
                 "bw", "fcs", "bad_fcs", "datapad", "ampdu_ref")

    def __init__(self):
        self.length = 0
        self.tsft = None
        self.flags = 0
        self.rate = None          # Mbps
        self.freq = None
        self.band = None
        self.channel = None
        self.signal = None        # dBm
        self.noise = None         # dBm
        self.chains = None        # per-antenna signals
        self.antenna = None
        self.phy = None           # 'legacy','ht','vht','he'
        self.mcs = None
        self.nss = None
        self.bw = None
        self.fcs = False
        self.bad_fcs = False
        self.datapad = False
        self.ampdu_ref = None

    def as_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


def _align(off, a):
    return (off + a - 1) & ~(a - 1)


_PLANS = {}        # presence-bitmap bytes -> [(bit, offset, size, first)]


def parse(buf):
    """Parse a radiotap header. Returns a Radio; Radio.length is header size."""
    if len(buf) < 8 or buf[0] != 0:
        raise ValueError("not a radiotap header")
    rlen = struct.unpack_from("<H", buf, 2)[0]
    if rlen > len(buf) or rlen < 8:
        raise ValueError("bad radiotap length")
    r = Radio()
    r.length = rlen

    off = 4
    while off + 4 <= rlen:
        w = struct.unpack_from("<I", buf, off)[0]
        off += 4
        if not w & 0x80000000:
            break
    key = bytes(buf[4:off])
    plan = _PLANS.get(key)
    if plan is None:
        plan, cacheable = _plan(buf, off, rlen)
        if cacheable and len(_PLANS) < 256:
            _PLANS[key] = plan
    for bit, o, size, first in plan:
        if o + size > rlen:
            break
        _field(r, bit, buf, o, first)
    return _finish(r)


def _plan(buf, off, rlen):
    """Work out where each field lives for one set of presence bitmaps.

    Data alignment is relative to the start of the header. A word with bit
    29 starts a fresh radiotap namespace (used for per-chain fields), bit 30
    starts a vendor namespace whose data we skip, and a word with neither
    extends the current namespace by 32 bits (no standard fields live there).
    Plans that depend on a vendor skip length read from the data are not cached.
    """
    words = list(struct.unpack_from(f"<{(off - 4) // 4}I", buf, 4))
    plan = []
    ns = "rt"
    extended = False
    vendor_skip = None
    first = True
    cacheable = True
    for w in words:
        if ns == "vendor":
            if vendor_skip is not None:
                off += vendor_skip
                vendor_skip = None
        elif extended:
            if w & 0x1FFFFFFF:
                break           # fields beyond bit 31 are not defined
        else:
            for bit in range(29):
                if not w & (1 << bit):
                    continue
                spec = _FIELDS.get(bit)
                if spec is None:
                    return plan, cacheable      # unknown field: cannot continue safely
                align, size = spec
                off = _align(off, align)
                plan.append((bit, off, size, first))
                off += size
        if w & (1 << 29):
            ns, extended, first = "rt", False, False
        elif w & (1 << 30):
            off = _align(off, 2)
            if off + 6 <= rlen:
                vendor_skip = struct.unpack_from("<H", buf, off + 4)[0]
            off += 6
            ns, extended = "vendor", False
            cacheable = False
        else:
            extended = True
    return plan, cacheable


def _finish(r):
    if r.signal is None and r.chains:
        r.signal = max(r.chains)
    if r.freq:
        r.band, r.channel = freq_to_channel(r.freq)
    r.fcs = bool(r.flags & F_FCS)
    r.bad_fcs = bool(r.flags & F_BADFCS)
    r.datapad = bool(r.flags & F_DATAPAD)
    if r.phy is None and r.rate is not None:
        r.phy = "legacy"
    return r


def _field(r, bit, b, o, first):
    if bit == 5:
        v = struct.unpack_from("<b", b, o)[0]
        if first:
            r.signal = v
        else:
            if r.chains is None:
                r.chains = []
            r.chains.append(v)
    elif not first:
        return              # only per-chain signal is kept from later namespaces
    elif bit == 0:
        r.tsft = struct.unpack_from("<Q", b, o)[0]
    elif bit == 1:
        r.flags = b[o]
    elif bit == 2:
        if b[o]:
            r.rate = b[o] / 2.0
    elif bit == 3:
        r.freq = struct.unpack_from("<H", b, o)[0]
    elif bit == 6:
        r.noise = struct.unpack_from("<b", b, o)[0]
    elif bit == 11:
        r.antenna = b[o]
    elif bit == 18:
        if not r.freq:
            r.freq = struct.unpack_from("<H", b, o + 4)[0]
    elif bit == 19:
        known, flags, mcs = b[o], b[o + 1], b[o + 2]
        bw = 40 if (known & 0x01 and flags & 0x03 == 1) else 20
        sgi = bool(known & 0x04 and flags & 0x04)
        r.phy, r.mcs, r.bw, r.nss = "ht", mcs, bw, mcs // 8 + 1
        if mcs < 32:
            r.rate = ht_rate(mcs, bw, sgi)
    elif bit == 20:
        r.ampdu_ref = struct.unpack_from("<I", b, o)[0]
    elif bit == 21:
        known, flags, bwc = struct.unpack_from("<HBB", b, o)
        mcs_nss = b[o + 4]
        mcs, nss = mcs_nss >> 4, mcs_nss & 0x0F
        bw = _VHT_BW.get(bwc & 0x1F, 20)
        sgi = bool(flags & 0x04)
        r.phy, r.mcs, r.nss, r.bw = "vht", mcs, nss, bw
        if nss:
            r.rate = vht_rate(mcs, nss, bw, sgi)
    elif bit == 23:
        d1, d2, d3, d4, d5, d6 = struct.unpack_from("<6H", b, o)
        mcs = (d3 >> 8) & 0x0F
        bwi = d5 & 0x0F
        gi = _HE_GI.get((d5 >> 4) & 0x03, 0.8)
        nss = d6 & 0x0F
        r.phy, r.mcs, r.nss = "he", mcs, nss
        r.bw = _HE_BW.get(bwi)
        if d1 & 0x0020 and nss and r.bw:
            r.rate = he_rate(mcs, nss, r.bw, gi)
