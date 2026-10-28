#!/usr/bin/env python3
"""Channel hopping utility for monitor-mode wireless interfaces.

Cycles a monitor interface through a list of channels using `iw`, dwelling on
each channel for a configurable interval. Reuses wlanscope's channel parsing
(`wlanscope.channels.parse_channel_spec`) and `iw` tuning logic so the channel
lists, presets, and band/frequency maths match what the analyzer uses.

Pure standard library — no third-party dependencies, no scapy.

Usage:

    python3 utilities/channel_hop.py wlan1mon                    # hop default (2g + 5g)
    python3 utilities/channel_hop.py wlan1mon 1,6,11             # hop only these
    python3 utilities/channel_hop.py wlan1mon 5g --dwell 0.5     # hop 5 GHz, 0.5s each
    python3 utilities/channel_hop.py wlan1mon 2g-common --dwell 1.0
    python3 utilities/channel_hop.py wlan1mon 36,40,44,48 --once  # one pass, then stop
    python3 utilities/channel_hop.py --list-presets

Requires root and a monitor-mode interface. Create it first:

    iw dev wlan1 set type monitor
    ip link set wlan1 up

Press Ctrl-C to stop hopping.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from wlanscope.channels import (  # noqa: E402
    BAND_LABEL,
    channel_to_freq,
    parse_channel_spec,
)


def iw(iface, *args, timeout=3):
    """Run `iw dev <iface> <args>`, raising OSError on failure."""
    cmd = ["iw", "dev", iface, *args]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        detail = r.stderr.strip() or r.stdout.strip() or "iw failed"
        raise OSError(detail)
    return r.stdout.strip()


def tune(iface, band, channel, width=None, center_freq=None, timeout=3):
    """Tune `iface` to (band, channel). Returns the centre frequency in MHz."""
    freq = channel_to_freq(band, channel)
    if width and width > 20 and center_freq:
        iw(iface, "set", "freq", str(freq), str(width), str(center_freq), timeout=timeout)
    else:
        iw(iface, "set", "freq", str(freq), timeout=timeout)
    return freq


def hop(iface, channels, dwell=0.25, once=False):
    """Hop through `channels`, dwelling `dwell` seconds on each.

    `channels` is a list of (band, channel, width) tuples as returned by
    `parse_channel_spec`. Channels that fail to tune 3 times are dropped from
    the current pass. Runs forever (or one pass if `once`) until interrupted.
    Returns 0 on clean stop, 1 if no tunable channels remain.
    """
    failures = {}   # (band, channel) -> consecutive failure count

    while True:
        usable = [c for c in channels if failures.get(c[:2], 0) < 3]
        if not usable:
            print(f"{iface}: no tunable channels left", file=sys.stderr)
            return 1

        tuned_this_pass = 0
        for band, ch, width in usable:
            try:
                freq = tune(iface, band, ch, width)
            except OSError as e:
                n = failures.get((band, ch), 0) + 1
                failures[(band, ch)] = n
                print(f"{iface}: {band} ch{ch} failed ({e})", file=sys.stderr)
                if n >= 3:
                    print(f"{iface}: dropping {band} ch{ch} from hop list",
                          file=sys.stderr)
                continue

            print(f"{iface}: {BAND_LABEL.get(band, '?')} ch{ch} ({freq} MHz)"
                  + (f" {width}MHz" if width else ""), flush=True)
            tuned_this_pass += 1
            time.sleep(dwell)

        if once:
            print(f"{iface}: single pass complete ({tuned_this_pass}/{len(usable)} channels)")
            return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Hop a monitor interface across channels (wlanscope channel logic)."
    )
    p.add_argument("iface", nargs="?", help="monitor interface (e.g. wlan1mon)")
    p.add_argument("channels", nargs="?",
                   help="channel spec: 36 | 1,6,11 | 5g | 2g-common | 36:80 "
                        "(default: default preset = 2g + 5g)")
    p.add_argument("--dwell", type=float, default=0.25,
                   help="seconds to dwell on each channel (default 0.25)")
    p.add_argument("--once", action="store_true",
                   help="make one pass through the channel list then stop")
    p.add_argument("--list-presets", action="store_true",
                   help="list available channel presets and exit")
    return p


def list_presets():
    from wlanscope.channels import PRESETS  # noqa: E402
    for name in sorted(PRESETS):
        chans = PRESETS[name]
        sample = ", ".join(f"{BAND_LABEL[b]} {c}" for b, c, _ in chans[:6])
        more = f" (+{len(chans) - 6} more)" if len(chans) > 6 else ""
        print(f"{name:14} {sample}{more}")


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list_presets:
        list_presets()
        return 0

    if not args.iface:
        print("error: an interface is required (e.g. wlan1mon)", file=sys.stderr)
        return 2

    spec = args.channels or "default"
    channels = parse_channel_spec(spec)
    if not channels:
        print(f"error: no channels parsed from '{spec}'", file=sys.stderr)
        return 2

    print(f"{args.iface}: hopping {spec} ({len(channels)} channels), "
          f"{args.dwell}s dwell. Ctrl-C to stop.")
    try:
        return hop(args.iface, channels, dwell=args.dwell, once=args.once)
    except KeyboardInterrupt:
        print("\nstopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
