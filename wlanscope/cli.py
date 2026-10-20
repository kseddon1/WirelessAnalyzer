"""Command line entry point."""

import argparse
import logging
import os
import signal
import sys
import threading

from . import __version__
from . import config as config_mod
from .capture import (LiveCapture, PcapReplay, PcapWriter, is_root,
                      list_wireless, setup_monitor)
from .channels import ChannelHopper, parse_channel_spec
from .engine import Engine
from .events import EventBus, FileSink, StreamSink, SyslogSink, WebhookSink
from .oui import OuiDB

log = logging.getLogger("wlanscope")


class Runtime:
    """Everything a front end (TUI or headless) needs."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.version = __version__
        self.stop = threading.Event()
        self.bus = None
        self.engine = None
        self.sources = []
        self.hoppers = []
        self.writer = None
        self.api = None
        self.source_desc = ""
        self.replay = None

    def replay_done(self):
        return self.replay is not None and self.replay.done

    def capture_errors(self):
        return {s.name: s.error for s in self.sources if getattr(s, "error", None)}

    def shutdown(self):
        self.stop.set()
        for h in self.hoppers:
            h.stop()
        for s in self.sources:
            s.join(timeout=1.5)
        if self.writer:
            self.writer.close()
        if self.api:
            self.api.shutdown()
        if self.bus:
            self.bus.close()


def build_parser():
    p = argparse.ArgumentParser(
        prog="wlanscope",
        description="802.11 WLAN discovery and analysis: interactive curses UI or headless "
                    "event sensor. Needs a monitor-mode interface (root) or a pcap file.")
    src = p.add_argument_group("source")
    src.add_argument("-i", "--interface", action="append", dest="interfaces",
                     help="monitor-mode interface (repeatable; default $WA_IFACE or wlan1mon)")
    src.add_argument("-r", "--read", dest="pcap", help="read a pcap/pcapng file instead of live capture")
    src.add_argument("--replay-speed", type=float,
                     help="pcap replay speed: 0 = as fast as possible (default headless), "
                          "1 = real time (default in the UI)")
    src.add_argument("--setup-monitor", action="store_true",
                     help="put the interface(s) into monitor mode with iw first")
    src.add_argument("--list-interfaces", action="store_true", help="list wireless interfaces and exit")
    src.add_argument("--write-pcap", help="also save every captured frame to this pcap")

    ch = p.add_argument_group("channels")
    ch.add_argument("--channels", help="channel list or presets: 1,6,11 | 36-48 | 2g 5g 5g-nodfs "
                                       "6g 6g-psc all (default: 2g+5g)")
    ch.add_argument("--channel", type=int, help="stay on one channel (no hopping)")
    ch.add_argument("--dwell", type=float, help="seconds per channel when hopping (default 0.25)")
    ch.add_argument("--no-hop", action="store_true", help="never retune the radio")
    ch.add_argument("--no-split", action="store_true",
                    help="with several interfaces, give every interface the full channel list "
                         "instead of splitting it between them")

    mode = p.add_argument_group("mode")
    mode.add_argument("--headless", action="store_true", help="run as a sensor without the UI")
    mode.add_argument("--duration", type=float, help="stop after N seconds")
    mode.add_argument("--report", help="on exit write a full JSON state report here")
    mode.add_argument("-c", "--config", help="TOML config file")
    mode.add_argument("--sensor-id", help="sensor name in events (default $WA_SENSOR or hostname)")

    ev = p.add_argument_group("events / outputs")
    ev.add_argument("--events-file", help="append JSON-lines events here (rotated)")
    ev.add_argument("--stdout-events", action=argparse.BooleanOptionalAction, default=None,
                    help="JSON-lines events on stdout (default on in headless mode without "
                         "other outputs)")
    ev.add_argument("--min-severity", choices=["info", "warning", "critical"],
                    help="minimum severity for file/stdout events (default info)")
    ev.add_argument("--webhook", dest="webhook_url",
                    help="POST events here, e.g. an Event-Driven Ansible webhook (env WA_EDA_URL)")
    ev.add_argument("--webhook-token", help="Bearer token for the webhook (env WA_EDA_TOKEN)")
    ev.add_argument("--webhook-min-severity", choices=["info", "warning", "critical"])
    ev.add_argument("--syslog", help="send events to syslog over UDP host[:port]")
    ev.add_argument("--state-file", help="periodically write the full state as JSON here")
    ev.add_argument("--state-interval", type=float, help="seconds between state-file writes")
    ev.add_argument("--heartbeat-interval", type=float, help="seconds between SENSOR_HEARTBEAT events")
    ev.add_argument("--api", help="serve the HTTP JSON API on host:port (e.g. 0.0.0.0:8088)")
    ev.add_argument("--api-token", help="require this Bearer token on the API")

    det = p.add_argument_group("detection")
    det.add_argument("--managed-ssid", action="append", default=[], metavar="SSID[=SECURITY]",
                     help="an SSID you own, with optional expected security (e.g. "
                          "'CorpWiFi=WPA2-Enterprise'); other BSSs using it are flagged")
    det.add_argument("--noise-floor", type=float, help="dBm used for SNR when the driver reports no noise")
    det.add_argument("--oui-file", help="Wireshark manuf or IEEE oui.txt for vendor names")

    p.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING (default INFO)")
    p.add_argument("--log-file", help="log file (default: stderr headless, "
                                      "/tmp/wlanscope.log with the UI)")
    p.add_argument("--version", action="version", version=f"wlanscope {__version__}")
    return p


def make_config(args):
    cfg = config_mod.load(args.config) if args.config else config_mod.Config()
    for name in ("pcap", "replay_speed", "write_pcap", "channels", "dwell", "sensor_id",
                 "events_file", "stdout_events", "min_severity", "webhook_url", "webhook_token",
                 "webhook_min_severity", "syslog", "state_file", "state_interval",
                 "heartbeat_interval", "api", "api_token", "oui_file"):
        v = getattr(args, name, None)
        if v is not None:
            setattr(cfg, name, v)
    if args.interfaces:
        cfg.interfaces = args.interfaces
    if args.channel is not None:
        cfg.channels = str(args.channel)
    if args.no_hop:
        cfg.hop = False
    if args.noise_floor is not None:
        cfg.thresholds.noise_floor = args.noise_floor
    for m in args.managed_ssid:
        ssid, _, sec = m.partition("=")
        cfg.managed.append(config_mod.ManagedSSID(ssid=ssid, security=[sec] if sec else []))
    if not cfg.pcap and not cfg.interfaces:
        cfg.interfaces = [os.environ.get("WA_IFACE", "wlan1mon")]
    return cfg


def setup_logging(args, headless):
    level = getattr(logging, str(args.log_level).upper(), logging.INFO)
    path = args.log_file or (None if headless else "/tmp/wlanscope.log")
    handler = logging.FileHandler(path) if path else logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)


def build_runtime(cfg, headless):
    rt = Runtime(cfg)
    bus = EventBus(cfg.sensor_id, cooldown=cfg.event_cooldown)
    rt.bus = bus
    if cfg.events_file:
        bus.add_sink(FileSink(cfg.events_file, cfg.events_max_mb, cfg.events_keep, cfg.min_severity))
    if cfg.webhook_url:
        bus.add_sink(WebhookSink(cfg.webhook_url, cfg.webhook_token, cfg.webhook_min_severity))
    if cfg.syslog:
        bus.add_sink(SyslogSink(cfg.syslog, cfg.syslog_min_severity))
    stdout = cfg.stdout_events
    if stdout is None:
        stdout = headless and not (cfg.events_file or cfg.webhook_url or cfg.syslog)
    if stdout and headless:
        bus.add_sink(StreamSink(sys.stdout, cfg.min_severity))

    oui = OuiDB(cfg.oui_file)
    log.info("vendor database: %s", oui.source)
    live = not cfg.pcap
    eng = Engine(cfg, bus, oui, live=live)
    rt.engine = eng

    if not live:
        speed = cfg.replay_speed
        if speed is None:
            speed = 0.0 if headless else 1.0
        rt.replay = PcapReplay(cfg.pcap, eng, speed=speed, stop=rt.stop)
        rt.sources.append(rt.replay)
        rt.source_desc = f"{os.path.basename(cfg.pcap)} x{speed:g}" if speed else os.path.basename(cfg.pcap)
        return rt

    if not is_root():
        raise SystemExit("live capture needs root (raw sockets + iw): re-run with sudo, "
                         "or use -r file.pcap")
    if cfg.write_pcap:
        rt.writer = PcapWriter(cfg.write_pcap)
    chans = parse_channel_spec(cfg.channels) if cfg.channels else []
    ifaces = cfg.interfaces
    split = len(ifaces) > 1 and cfg.hop and cfg.split_channels
    for i, iface in enumerate(ifaces):
        cap = LiveCapture(iface, eng, rt.writer, rt.stop)
        rt.sources.append(cap)
        mine = chans[i::len(ifaces)] if split else chans
        hop = ChannelHopper(iface, mine if cfg.hop else [], cfg.dwell, eng.on_dwell, hop=cfg.hop)
        rt.hoppers.append(hop)
    eng.hoppers = rt.hoppers
    rt.source_desc = ",".join(ifaces)
    return rt


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.list_interfaces:
        rows = list_wireless()
        if not rows:
            print("no wireless interfaces found (is `iw` installed?)")
        for r in rows:
            print(f"{r['iface']:12} {r['type']:10} {r['channel']}")
        return 0
    headless = args.headless
    setup_logging(args, headless)
    try:
        cfg = make_config(args)
    except (OSError, ValueError, TypeError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    if args.no_split:
        cfg.split_channels = False
    if args.setup_monitor and not cfg.pcap:
        for iface in cfg.interfaces:
            try:
                setup_monitor(iface)
            except OSError as e:
                print(f"cannot enable monitor mode on {iface}: {e}", file=sys.stderr)
                return 1
    try:
        rt = build_runtime(cfg, headless)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    def _term(_sig, _frm):
        rt.stop.set()
    signal.signal(signal.SIGTERM, _term)
    if headless:
        signal.signal(signal.SIGINT, _term)

    if cfg.api:
        from .api import start_api
        try:
            rt.api = start_api(rt.engine, cfg.api, cfg.api_token)
        except OSError as e:
            print(f"cannot start API on {cfg.api}: {e}", file=sys.stderr)
            return 1
    for h in rt.hoppers:
        h.start()
    for s in rt.sources:
        s.start()
    try:
        if headless:
            from .headless import run
            run(rt, duration=args.duration, report=args.report)
        else:
            from .tui import TUI
            if args.duration:
                threading.Timer(args.duration, rt.stop.set).start()
            ui = TUI(rt)
            _attach_ui_logging(ui)
            ui.run()
            if args.report:
                from .headless import write_state
                write_state(args.report, rt.engine.snapshot(brief=False))
    finally:
        rt.shutdown()
    if rt.replay and rt.replay.error:
        print(f"pcap error: {rt.replay.error}", file=sys.stderr)
        return 1
    return 0


def _attach_ui_logging(ui):
    from .tui import P_RED, P_YELLOW

    class H(logging.Handler):
        def emit(self, record):
            ui.message(record.getMessage(), P_YELLOW if record.levelno < logging.ERROR else P_RED, 8)
    h = H(logging.WARNING)
    logging.getLogger().addHandler(h)


if __name__ == "__main__":
    sys.exit(main())
