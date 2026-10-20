"""Headless sensor loop: ticks the engine, emits heartbeats, writes the
state file, and stops on signal, --duration, or end of a pcap."""

import json
import logging
import os
import sys
import time
from collections import Counter

log = logging.getLogger(__name__)


def write_state(path, snap):
    tmp = f"{path}.tmp"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, default=str)
    os.replace(tmp, path)


def run(rt, duration=None, report=None):
    cfg, eng, bus = rt.cfg, rt.engine, rt.bus
    bus.emit("SENSOR_STARTED", "info", "sensor",
             f"sensor {cfg.sensor_id} started ({rt.source_desc})",
             details={"source": rt.source_desc, "channels": cfg.channels,
                      "dwell": cfg.dwell, "version": rt.version}, cooldown=0)
    start = time.time()
    last_hb = start
    last_state = 0.0
    try:
        while not rt.stop.is_set():
            rt.stop.wait(0.5)
            wall = time.time()
            if eng.live:
                eng.tick_if_due()
            if cfg.heartbeat_interval and wall - last_hb >= cfg.heartbeat_interval:
                last_hb = wall
                with eng.lock:
                    stats = eng.stats()
                bus.emit("SENSOR_HEARTBEAT", "info", "sensor",
                         f"{stats['fps']} frames/s, {stats['aps']} BSS, {stats['clients']} clients",
                         details={"stats": stats, "radios": [h.describe() for h in eng.hoppers],
                                  "capture_errors": rt.capture_errors()},
                         cooldown=0)
            if cfg.state_file and wall - last_state >= cfg.state_interval:
                last_state = wall
                write_state(cfg.state_file, eng.snapshot())
            if rt.replay_done():
                break
            if duration and wall - start >= duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        snap = eng.snapshot(brief=False)
        if cfg.state_file:
            write_state(cfg.state_file, eng.snapshot())
        if report:
            write_state(report, snap)
        bus.emit("SENSOR_STOPPED", "info", "sensor", f"sensor {cfg.sensor_id} stopped",
                 details={"stats": snap["stats"]}, cooldown=0)
        _summary(snap, bus)


def _summary(snap, bus):
    s = snap["stats"]
    alerts = Counter(e["alert"] for e in bus.recent)
    print(f"summary: {s['frames']} frames, {len(snap['wlans'])} WLANs, {s['aps']} BSS, "
          f"{s['clients']} clients; events: {dict(alerts.most_common(15))}", file=sys.stderr)
