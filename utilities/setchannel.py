#!/usr/bin/env python3
"""Channel control utility for monitor-mode wireless interfaces.

Sets or hops channels on a monitor interface using the same channel parsing
and `iw` tuning logic as wlanscope (wlanscope.channels). Pure standard library
— no third-party dependencies, no scapy.

Usage:

    python3 utlities/setchannel.py wlan1mon 36              # lock to ch 36 (5 GHz)
    python3 utlities/setchannel.py wlan1mon 1,6,11          # hop 2.4 GHz channels
    python3 utlities/setchannel.py wlan1mon 5g              # hop all 5 GHz channels
    python3 utlities/setchannel.py wlan1mon 2g-common       # hop 1, 6, 11
    python3 utlities/setchannel.py wlan1mon 36:80           # 80 MHz on ch 36
    python3 utlities/setchannel.py wlan1mon 1,6,11 --dwell 0.5 --hop
    python3 utlities/setchannel.py wlan1mon --current       # show current channel
    python3 utlities/setchannel.py --list-presets           # show channel presets

Requires root (iw set freq) and a monitor-mode interface. Create the monitor
interface first with your own script or `iw dev <iface> set type monitor`.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

# Add the project root so `import wlanscope` works no matter where we run from.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from wlanscope.channels import (  # noqa: E402
    BAND_LABEL,
    channel_to_freq,
    guess_band,
    parse_channel_spec,
)


# ------------------------------------------------------------------- iw wrapper

def iw(iface, *args, timeout=3):
    """Run `iw dev <iface> <args>`, raising OSError on failure."""
    cmd = ["iw", "dev", iface, *args]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        detail = r.stderr.strip() or r.stdout.strip() or "iw failed"
        raise OSError(detail)
    return r.stdout.strip()


def set_freq(iface, band, channel, width=None, center_freq=None, timeout=3):
    """Tune `iface` to (band, channel), optionally at `width` MHz."""
    freq = channel_to_freq(band, channel)
    if width and width > 20 and center_freq:
        iw(iface, "set", "freq", str(freq), str(width), str(center_freq), timeout=timeout)
    else:
        iw(iface, "set", "freq", str(freq), timeout=timeout)
    return freq


def current_channel(iface, timeout=3):
    """Return (band, channel, freq_mhz, width_mhz) for the interface, or None."""
    out = iw(iface, "info", timeout=timeout)
    # Look for:  channel 36 (5180 MHz), width: 20 MHz, center1: 5180 MHz
    band = channel = freq = width = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("channel "):
            # "channel 36 (5180 MHz), width: 20 MHz, center1: 5180 MHz"
            rest = line[len("channel "):]
            ch_part = rest.split()[0]
            try:
                channel = int(ch_part)
            except ValueError:
                channel = None
            if "(" in rest and ")" in rest:
                freq = int(rest[rest.index("(") + 1 : rest.index(" MHz")])
            if "width:" in rest:
                w_part = rest.split("width:")[1].split()[0]
                try:
                    width = int(w_part.replace("MHz", ""))
                except ValueError:
                    width = None
            band = guess_band(channel) if channel else None
            break
    if channel is None:
        return None
    return band, channel, freq, width


# ------------------------------------------------------------------- tuning

def tune_single(iface, band, channel, width=None, center_freq=None):
    """Tune once to (band, channel). Returns the centre frequency in MHz."""
    freq = set_freq(iface, band, channel, width, center_freq)
    label = BAND_LABEL.get(band, "?")
    extra = f" {width} MHz" if width else ""
    print(f"{iface}: {label} ch{channel} ({freq} MHz){extra}")
    return freq


def tune_fixed(iface, channels, timeout=3):
    """Lock to the first usable channel in the list."""
    failures = {}
    for band, ch, width in channels:
        if failures.get((band, ch), 0) >= 3:
            continue
        try:
            return tune_single(iface, band, ch, width)
        except OSError as e:
            failures[(band, ch)] = failures.get((band, ch), 0) + 1
            print(f"{iface}: {band} ch{ch} failed: {e}", file=sys.stderr)
    raise OSError(f"{iface}: no tunable channels in {channels}")


def hop_channels(iface, channels, dwell=0.25, stop=None):
    """Cycle through channels, dwelling `dwell` seconds on each.

    `stop` is a threading.Event; when set, hopping stops. Prints each channel
    as it is tuned. Skips channels that fail 3 times.
    """
    import threading

    stop = stop or threading.Event()
    idx = 0
    failures = {}
    while not stop.is_set():
        usable = [c for c in channels if failures.get(c[:2], 0) < 3]
        if not usable:
            print(f"{iface}: no tunable channels left", file=sys.stderr)
            return
        band, ch, width = usable[idx % len(usable)]
        idx += 1
        try:
            tune_single(iface, band, ch, width)
        except OSError as e:
            failures[(band, ch)] = failures.get((band, ch), 0) + 1
            n = failures[(band, ch)]
            print(f"{iface}: {band} ch{ch} failed: {e}", file=sys.stderr)
            if n >= 3:
                print(f"{iface}: dropping {band} ch{ch} from hop list", file=sys.stderr)
            continue
        stop.wait(dwell)


# ------------------------------------------------------------------- CLI

def list_presets():
    from wlanscope.channels import PRESETS  # noqa: E402
    for name in sorted(PRESETS):
        chans = PRESETS[name]
        sample = ", ".join(f"{BAND_LABEL[b]} {c}" for b, c, _ in chans[:6])
        more = f" (+{len(chans) - 6} more)" if len(chans) > 6 else ""
        print(f"{name:12} {sample}{more}")


def build_parser():
    p = argparse.ArgumentParser(
        description="Set or hop channels on a monitor interface (wlanscope logic)."
    )
    p.add_argument("iface", nargs="?", help="monitor interface (e.g. wlan1mon)")
    p.add_argument(
        "channels",
        nargs="?",
        help="channel spec: 36 | 1,6,11 | 5g | 2g-common | 36:80 (default: show current)",
    )
    p.add_argument("--dwell", type=float, default=0.25,
                   help="seconds per channel when hopping (default 0.25)")
    p.add_argument("--hop", action="store_true",
                   help="hop through the channel list instead of locking to the first")
    p.add_argument("--current", action="store_true",
                   help="show the current channel and exit")
    p.add_argument("--list-presets", action="store_true",
                   help="list available channel presets and exit")
    p.add_argument("--width", type=int, choices=[20, 40, 80, 160], default=None,
                   help="channel width in MHz (with a single channel and --lock)")
    p.add_argument("--center-freq", type=int, default=None,
                   help="centre frequency in MHz for wide channels (with --width)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list_presets:
        list_presets()
        return 0

    if args.current or not args.iface:
        if not args.iface:
            print("error: an interface is required (e.g. wlan1mon)", file=sys.stderr)
            return 2
        cur = current_channel(args.iface)
        if cur is None:
            print(f"{args.iface}: could not read channel (is it up / in monitor mode?)",
                  file=sys.stderr)
            return 1
        band, ch, freq, width = cur
        label = BAND_LABEL.get(band, "?")
        extra = f", width {width} MHz" if width else ""
        print(f"{args.iface}: {label} ch{ch} ({freq} MHz){extra}")
        return 0

    channels = parse_channel_spec(args.channels)
    if not channels:
        print(f"error: no channels parsed from '{args.channels}'", file=sys.stderr)
        return 2

    if args.hop:
        try:
            hop_channels(args.iface, channels, dwell=args.dwell)
        except KeyboardInterrupt:
            print("\nstopped.")
        return 0

    try:
        if len(channels) == 1 and (args.width or args.center_freq):
            band, ch, _ = channels[0]
            set_freq(args.iface, band, ch, args.width or 20,
                     args.center_freq or channel_to_freq(band, ch))
            tune_single(args.iface, band, ch, args.width or 20,
                        args.center_freq or channel_to_freq(band, ch))
        else:
            tune_fixed(args.iface, channels)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
