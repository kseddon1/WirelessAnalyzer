"""Frame sources: live monitor-mode interfaces and pcap/pcapng files."""

import logging
import os
import socket
import struct
import subprocess
import threading
import time

from . import radiotap
from .dot11 import parse_frame

log = logging.getLogger(__name__)

DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIO = 127
ARPHRD_IEEE80211 = 801
ARPHRD_IEEE80211_RADIOTAP = 803
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_STATISTICS = 6


def decode(data, ts, linktype):
    """Raw capture bytes -> Frame (or None)."""
    radio = None
    if linktype == DLT_IEEE802_11_RADIO:
        radio = radiotap.parse(data)
        data = data[radio.length:]
    elif linktype != DLT_IEEE802_11:
        return None
    return parse_frame(data, ts, radio)


class PcapWriter:
    def __init__(self, path, linktype=DLT_IEEE802_11_RADIO, snaplen=65535):
        self.fh = open(path, "wb")
        self.lock = threading.Lock()
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts, data):
        sec = int(ts)
        usec = int((ts - sec) * 1e6)
        with self.lock:
            self.fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            self.fh.write(data)

    def close(self):
        with self.lock:
            self.fh.close()


def read_pcap(path):
    """Yield (ts, linktype, data) from a pcap or pcapng file."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(fh)
        else:
            yield from _read_classic(fh)


def _read_classic(fh):
    hdr = fh.read(24)
    if len(hdr) < 24:
        raise ValueError("truncated pcap header")
    magic = struct.unpack("<I", hdr[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        e = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        e = ">"
        magic = struct.unpack(">I", hdr[:4])[0]
    else:
        raise ValueError("not a pcap/pcapng file")
    div = 1e9 if magic == 0xA1B23C4D else 1e6
    linktype = struct.unpack(e + "I", hdr[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(e + "IIII")
    while True:
        h = fh.read(16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = rec.unpack(h)
        data = fh.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / div, linktype, data


def _read_pcapng(fh):
    e = "<"
    ifaces = []          # (linktype, ts divisor)
    while True:
        h = fh.read(8)
        if len(h) < 8:
            return
        btype, blen = struct.unpack(e + "II", h)
        if btype == 0x0A0D0D0A:
            bom = fh.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(e + "I", h[4:8])[0]
            fh.seek(blen - 12, 1)
            ifaces = []
            continue
        if blen < 12:
            return
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]
        if btype == 1:                                  # IDB
            linktype = struct.unpack_from(e + "H", body, 0)[0]
            div = 1e6
            o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack_from(e + "HH", body, o)
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[o + 4]
                    div = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                o += 4 + ((ln + 3) & ~3)
            ifaces.append((linktype, div))
        elif btype == 6:                                # EPB
            iid, th, tl, cap, _orig = struct.unpack_from(e + "IIIII", body, 0)
            if iid >= len(ifaces):
                continue
            lt, div = ifaces[iid]
            yield ((th << 32) | tl) / div, lt, body[20:20 + cap]
        elif btype == 3 and ifaces:                     # SPB
            _orig = struct.unpack_from(e + "I", body, 0)[0]
            yield time.time(), ifaces[0][0], body[4:]


class PcapReplay(threading.Thread):
    def __init__(self, path, engine, speed=0.0, stop=None, on_done=None):
        super().__init__(name="pcap-replay", daemon=True)
        self.path = path
        self.engine = engine
        self.speed = speed
        self.stop_ev = stop or threading.Event()
        self.on_done = on_done
        self.count = 0
        self.done = False
        self.error = None

    def run(self):
        first_pkt = first_wall = None
        try:
            for ts, lt, data in read_pcap(self.path):
                if self.stop_ev.is_set():
                    break
                if self.speed > 0:
                    if first_pkt is None:
                        first_pkt, first_wall = ts, time.time()
                    delay = (ts - first_pkt) / self.speed - (time.time() - first_wall)
                    if delay > 0:
                        if self.stop_ev.wait(min(delay, 5.0)):
                            break
                try:
                    f = decode(data, ts, lt)
                except ValueError:
                    self.engine.parse_errors += 1
                    continue
                if f is not None:
                    self.engine.ingest(f)
                self.count += 1
        except (OSError, ValueError) as e:
            self.error = str(e)
            log.error("pcap read failed: %s", e)
        finally:
            self.done = True
            self.engine.tick_if_due(self.engine.now() + 1.0)
            if self.on_done:
                self.on_done()


def iface_type(iface):
    try:
        with open(f"/sys/class/net/{iface}/type") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def setup_monitor(iface):
    """Put an interface into monitor mode with iw (needs root)."""
    for cmd in (["ip", "link", "set", iface, "down"],
                ["iw", "dev", iface, "set", "type", "monitor"],
                ["ip", "link", "set", iface, "up"]):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise OSError(f"{' '.join(cmd)}: {r.stderr.strip()}")


def list_wireless():
    """Return [(iface, type, channel-info)] from `iw dev`."""
    try:
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    res, cur = [], None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            cur = {"iface": line.split()[1], "type": "?", "channel": ""}
            res.append(cur)
        elif cur and line.startswith("type "):
            cur["type"] = line.split()[1]
        elif cur and line.startswith("channel "):
            cur["channel"] = line
    return res


class LiveCapture(threading.Thread):
    def __init__(self, iface, engine, writer=None, stop=None):
        super().__init__(name=f"capture-{iface}", daemon=True)
        self.iface = iface
        self.engine = engine
        self.writer = writer
        self.stop_ev = stop or threading.Event()
        self.count = 0
        self.error = None
        t = iface_type(iface)
        if t == ARPHRD_IEEE80211_RADIOTAP:
            self.linktype = DLT_IEEE802_11_RADIO
        elif t == ARPHRD_IEEE80211:
            self.linktype = DLT_IEEE802_11
        elif t is None:
            raise OSError(f"interface {iface} does not exist")
        else:
            raise OSError(f"{iface} is not in monitor mode (ARPHRD type {t}); "
                          "use --setup-monitor or your monitor-mode script")
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        except OSError:
            pass
        self.sock.bind((iface, ETH_P_ALL))
        self.sock.settimeout(0.5)

    def kernel_drops(self):
        try:
            raw = self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            _pkts, drops = struct.unpack("II", raw)
            return drops
        except OSError:
            return 0

    def run(self):
        eng = self.engine
        lt = self.linktype
        last_stats = time.time()
        while not self.stop_ev.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                self.error = str(e)
                log.error("%s: capture error: %s", self.iface, e)
                if self.stop_ev.wait(1.0):
                    break
                continue
            if addr[2] == socket.PACKET_OUTGOING:
                continue            # frames injected by this host are not observations
            ts = time.time()
            self.count += 1
            if self.writer:
                self.writer.write(ts, data)
            try:
                f = decode(data, ts, lt)
            except ValueError:
                eng.parse_errors += 1
                continue
            if f is not None:
                eng.ingest(f)
            if ts - last_stats > 5:
                last_stats = ts
                eng.dropped += self.kernel_drops()
        self.sock.close()


def is_root():
    return os.geteuid() == 0
