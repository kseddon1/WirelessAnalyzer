"""Channel/frequency helpers, PHY rate math and the channel hopper."""

import logging
import subprocess
import threading
import time

log = logging.getLogger(__name__)

CH_2G = list(range(1, 14))
CH_2G_COMMON = [1, 6, 11]
CH_5G_UNII1 = [36, 40, 44, 48]
CH_5G_UNII2 = [52, 56, 60, 64]
CH_5G_UNII2E = [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]
CH_5G_UNII3 = [149, 153, 157, 161, 165]
CH_5G = CH_5G_UNII1 + CH_5G_UNII2 + CH_5G_UNII2E + CH_5G_UNII3
CH_5G_NODFS = CH_5G_UNII1 + CH_5G_UNII3
CH_6G_PSC = list(range(5, 234, 16))          # preferred scanning channels
CH_6G = list(range(1, 234, 4))

PRESETS = {
    "2g": [("2g", c) for c in CH_2G[:11]],
    "2g-all": [("2g", c) for c in CH_2G],
    "2g-common": [("2g", c) for c in CH_2G_COMMON],
    "5g": [("5g", c) for c in CH_5G],
    "5g-nodfs": [("5g", c) for c in CH_5G_NODFS],
    "6g": [("6g", c) for c in CH_6G],
    "6g-psc": [("6g", c) for c in CH_6G_PSC],
}
PRESETS["all"] = PRESETS["2g"] + PRESETS["5g"]
PRESETS["default"] = PRESETS["2g"] + PRESETS["5g"]


def freq_to_channel(freq):
    """Return (band, channel) for a centre frequency in MHz."""
    if not freq:
        return None, None
    if 2412 <= freq <= 2472:
        return "2g", (freq - 2407) // 5
    if freq == 2484:
        return "2g", 14
    if freq == 5935:
        return "6g", 2
    if 5950 < freq <= 7125:
        return "6g", (freq - 5950) // 5
    if 4910 <= freq <= 5895:
        return "5g", (freq - 5000) // 5
    return None, None


def channel_to_freq(band, channel):
    if band == "2g":
        return 2484 if channel == 14 else 2407 + channel * 5
    if band == "5g":
        return 5000 + channel * 5
    if band == "6g":
        return 5935 if channel == 2 else 5950 + channel * 5
    raise ValueError(f"unknown band {band}")


def guess_band(channel):
    if channel <= 14:
        return "2g"
    return "5g"


BAND_LABEL = {"2g": "2.4", "5g": "5", "6g": "6", None: "?"}


def parse_channel_spec(spec):
    """Parse '1,6,11,36' / '5g' / '2g,6g-psc' / '6g:37' / '36:80'.

    Returns a list of (band, channel, width) tuples. width is None (20 MHz) or
    one of 40/80/160 for hopping wide; wide channels need the centre computed
    by the caller so they are only honoured when locking to a known BSS.
    """
    out = []
    for item in str(spec).split(","):
        item = item.strip().lower()
        if not item:
            continue
        if item in PRESETS:
            out.extend((b, c, None) for b, c in PRESETS[item])
            continue
        band = None
        if item.startswith(("2g:", "5g:", "6g:")):
            band, item = item[:2], item[3:]
        width = None
        if ":" in item:
            item, w = item.split(":", 1)
            width = int(w.replace("mhz", ""))
        if "-" in item:
            lo, hi = (int(x) for x in item.split("-", 1))
            chans = range(lo, hi + 1)
        else:
            chans = [int(item)]
        for ch in chans:
            out.append((band or guess_band(ch), ch, width))
    seen, dedup = set(), []
    for t in out:
        if t[:2] not in seen:
            seen.add(t[:2])
            dedup.append(t)
    return dedup


# ---------------------------------------------------------------- PHY rates

_HT20_LGI = [6.5, 13.0, 19.5, 26.0, 39.0, 52.0, 58.5, 65.0]
# coded bits per subcarrier for MCS 0..13 (VHT/HE/EHT)
_BITS = [0.5, 1, 1.5, 2, 3, 4, 4.5, 5, 6, 20 / 3, 7.5, 25 / 3, 9, 10]
_VHT_SC = {20: 52, 40: 108, 80: 234, 160: 468}
_HE_SC = {20: 234, 40: 468, 80: 980, 160: 1960, 320: 3920}


def ht_rate(mcs, bw, sgi):
    nss = mcs // 8 + 1
    base = _HT20_LGI[mcs % 8] * nss
    if bw == 40:
        base *= 135 / 65
    if sgi:
        base *= 10 / 9
    return round(base, 1)


def vht_rate(mcs, nss, bw, sgi):
    if mcs >= len(_BITS) or bw not in _VHT_SC:
        return None
    sym = 3.6 if sgi else 4.0
    return round(_VHT_SC[bw] * _BITS[mcs] * max(nss, 1) / sym, 1)


def he_rate(mcs, nss, bw, gi_us=0.8):
    if mcs >= len(_BITS) or bw not in _HE_SC:
        return None
    return round(_HE_SC[bw] * _BITS[mcs] * max(nss, 1) / (12.8 + gi_us), 1)


# ---------------------------------------------------------------- hopper

class ChannelHopper(threading.Thread):
    """Tunes a monitor interface across a channel list using `iw`.

    Reports dwell time per (band, channel) to `on_dwell(band, ch, seconds)` so
    the engine can normalise rates by how long each channel was observed.
    """

    def __init__(self, iface, channels, dwell=0.25, on_dwell=None, hop=True):
        super().__init__(name=f"hopper-{iface}", daemon=True)
        self.iface = iface
        self.channels = list(channels)
        self.dwell = dwell
        self.on_dwell = on_dwell
        self.hop = hop and len(self.channels) > 1
        self.current = None          # (band, channel)
        self.locked = None           # (band, channel, width, center_freq)
        self.failures = {}
        self._halt = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()

    # -- control API (called from UI/API threads)
    def lock(self, band, channel, width=None, center_freq=None):
        with self._lock:
            self.locked = (band, channel, width, center_freq)
        self._wake.set()

    def unlock(self):
        with self._lock:
            self.locked = None
        self._wake.set()

    def stop(self):
        self._halt.set()
        self._wake.set()

    @property
    def mode(self):
        if self.locked:
            return "locked"
        return "hopping" if self.hop else "fixed"

    def describe(self):
        cur = self.current
        txt = f"{BAND_LABEL[cur[0]]}G ch{cur[1]}" if cur else "ch?"
        if self.locked and self.locked[2]:
            txt += f"/{self.locked[2]}MHz"
        return f"{self.iface} {txt} [{self.mode}]"

    # -- tuning
    def _iw(self, *args):
        cmd = ["iw", "dev", self.iface, *args]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            raise OSError(r.stderr.strip() or r.stdout.strip() or "iw failed")

    def tune(self, band, channel, width=None, center_freq=None):
        freq = channel_to_freq(band, channel)
        if width and width > 20 and center_freq:
            try:
                self._iw("set", "freq", str(freq), str(width), str(center_freq))
                self.current = (band, channel)
                return True
            except (OSError, subprocess.TimeoutExpired) as e:
                log.warning("%s: %d MHz tune on ch%s failed (%s); using 20 MHz",
                            self.iface, width, channel, e)
        try:
            self._iw("set", "freq", str(freq))
            self.current = (band, channel)
            return True
        except (OSError, subprocess.TimeoutExpired) as e:
            n = self.failures.get((band, channel), 0) + 1
            self.failures[(band, channel)] = n
            if n == 3:
                log.warning("%s: dropping %s ch%s from hop list: %s",
                            self.iface, band, channel, e)
            return False

    def run(self):
        idx = 0
        last_tuned_lock = None
        if not self.hop and self.channels:
            band, ch, _w = self.channels[0]
            self.tune(band, ch)
        while not self._halt.is_set():
            with self._lock:
                locked = self.locked
            start = time.time()
            if locked:
                if locked != last_tuned_lock:
                    self.tune(*locked)
                    last_tuned_lock = locked
                self._wake.wait(1.0)
            elif self.hop:
                last_tuned_lock = None
                usable = [c for c in self.channels
                          if self.failures.get(c[:2], 0) < 3]
                if not usable:
                    log.error("%s: no tunable channels left", self.iface)
                    self._wake.wait(5)
                    self._wake.clear()
                    continue
                band, ch, _w = usable[idx % len(usable)]
                idx += 1
                if not self.tune(band, ch):
                    continue
                self._wake.wait(self.dwell)
            else:
                if last_tuned_lock is not None:
                    if self.channels:
                        band, ch, _w = self.channels[0]
                        self.tune(band, ch)
                    last_tuned_lock = None
                self._wake.wait(1.0)
            self._wake.clear()
            if self.on_dwell and self.current:
                self.on_dwell(self.current[0], self.current[1], time.time() - start)
