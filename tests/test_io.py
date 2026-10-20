import json
import os
import stat
import struct
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from wlanscope import synth as S
from wlanscope.api import start_api
from wlanscope.capture import read_pcap
from wlanscope.channels import ChannelHopper, parse_channel_spec, freq_to_channel
from wlanscope.config import Config, load
from wlanscope.engine import Engine
from wlanscope.events import EventBus, FileSink, WebhookSink
from wlanscope.oui import OuiDB


class ChannelTests(unittest.TestCase):
    def test_specs(self):
        self.assertEqual(parse_channel_spec("1,6,11"), [("2g", 1, None), ("2g", 6, None), ("2g", 11, None)])
        self.assertEqual(len(parse_channel_spec("5g-nodfs")), 9)
        self.assertEqual(parse_channel_spec("6g:37"), [("6g", 37, None)])
        self.assertEqual(parse_channel_spec("36-40"), [("5g", 36, None), ("5g", 37, None),
                                                       ("5g", 38, None), ("5g", 39, None),
                                                       ("5g", 40, None)])
        self.assertEqual(freq_to_channel(5955), ("6g", 1))
        self.assertEqual(freq_to_channel(2484), ("2g", 14))

    def test_hopper_uses_iw(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "iw.log")
            iw = os.path.join(d, "iw")
            with open(iw, "w") as fh:
                fh.write(f"#!/bin/sh\necho \"$@\" >> {log}\n")
            os.chmod(iw, stat.S_IRWXU)
            old = os.environ["PATH"]
            os.environ["PATH"] = d + os.pathsep + old
            try:
                dwell = {}
                h = ChannelHopper("mon0", parse_channel_spec("1,6,36"), 0.05,
                                  lambda b, c, s: dwell.__setitem__((b, c), dwell.get((b, c), 0) + s))
                h.start()
                time.sleep(0.5)
                h.lock("5g", 36, 80, 5210)
                time.sleep(0.3)
                h.stop()
                h.join(2)
            finally:
                os.environ["PATH"] = old
            with open(log) as fh:
                calls = fh.read().splitlines()
            self.assertIn("dev mon0 set freq 2412", calls)
            self.assertIn("dev mon0 set freq 5180", calls)
            self.assertIn("dev mon0 set freq 5180 80 5210", calls)
            self.assertTrue(dwell.get(("2g", 6), 0) > 0)


class EventTests(unittest.TestCase):
    def test_cooldown_and_escalation(self):
        bus = EventBus("s", cooldown=60, clock=lambda: 1000.0)
        self.assertIsNotNone(bus.emit("X", "info", "ap", "m", bssid="b"))
        self.assertIsNone(bus.emit("X", "info", "ap", "m", bssid="b"))
        self.assertIsNotNone(bus.emit("X", "critical", "ap", "m", bssid="b"))
        self.assertIsNotNone(bus.emit("X", "info", "ap", "m", bssid="c"))
        bus.reset_cooldown(("X", "b"))
        self.assertIsNotNone(bus.emit("X", "info", "ap", "m", bssid="b"))
        self.assertEqual(bus.suppressed, 1)

    def test_file_sink_rotation(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ev.jsonl")
            sink = FileSink(p, max_mb=0.001, keep=2)
            bus = EventBus("s", cooldown=0)
            bus.add_sink(sink)
            for i in range(40):
                bus.emit("E", "info", "x", "y" * 50, bssid=str(i))
            sink.close()
            self.assertTrue(os.path.exists(p + ".1"))
            self.assertTrue(os.path.exists(p + ".2"))
            self.assertFalse(os.path.exists(p + ".3"))
            with open(p) as fh:
                json.loads(fh.readline())

    def test_webhook_eda_contract(self):
        got = []

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                got.append((self.headers.get("Authorization"), json.loads(body)))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        sink = WebhookSink(f"http://127.0.0.1:{srv.server_port}/endpoint", "tok", "warning")
        bus = EventBus("pi-01", cooldown=0)
        bus.add_sink(sink)
        bus.emit("OPEN_NETWORK", "info", "security", "filtered out", ssid="CorpWiFi", bssid="aa")
        bus.emit("EVIL_TWIN", "critical", "security", "twin", ssid="CorpWiFi", bssid="bb")
        for _ in range(50):
            if got:
                break
            time.sleep(0.05)
        sink.close()
        srv.shutdown()
        srv.server_close()
        self.assertEqual(len(got), 1)
        auth, payload = got[0]
        self.assertEqual(auth, "Bearer tok")
        self.assertEqual((payload["alert"], payload["ssid"], payload["bssid"], payload["sensor"]),
                         ("EVIL_TWIN", "CorpWiFi", "bb", "pi-01"))


class PcapngTests(unittest.TestCase):
    def test_pcapng_read(self):
        frame = S.radiotap(6, -50) + S.hdr(0, 8, "ff:ff:ff:ff:ff:ff", "aa:bb:cc:00:00:01",
                                           "aa:bb:cc:00:00:01") + S.beacon_body("x", 6)

        def block(btype, body):
            pad = (-len(body)) % 4
            total = 12 + len(body) + pad
            return struct.pack("<II", btype, total) + body + b"\x00" * pad + struct.pack("<I", total)
        shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        idb = block(1, struct.pack("<HHI", 127, 0, 65535) + struct.pack("<HHB3x", 9, 1, 9) + b"\x00" * 4)
        ts = int(1_700_000_000.5 * 1e9)
        epb = block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.pcapng")
            with open(p, "wb") as fh:
                fh.write(shb + idb + epb)
            recs = list(read_pcap(p))
        self.assertEqual(len(recs), 1)
        self.assertAlmostEqual(recs[0][0], 1_700_000_000.5, places=3)
        self.assertEqual(recs[0][1], 127)
        self.assertEqual(recs[0][2], frame)


class ApiAndConfigTests(unittest.TestCase):
    def test_api(self):
        cfg = Config(sensor_id="api")
        bus = EventBus("api")
        eng = Engine(cfg, bus, OuiDB("/nonexistent"), live=True)
        bus.emit("TEST", "warning", "x", "hello", bssid="aa")
        srv = start_api(eng, "127.0.0.1:0", token="secret")
        port = srv.server_address[1]
        try:
            def get(path, token="secret"):
                req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                             headers={"Authorization": f"Bearer {token}"})
                with urllib.request.urlopen(req, timeout=3) as r:
                    return json.loads(r.read())
            self.assertEqual(get("/health")["sensor"], "api")
            self.assertEqual(get("/events?min_severity=warning")[0]["alert"], "TEST")
            self.assertIn("wlans", get("/state"))
            with self.assertRaises(urllib.error.HTTPError) as cm:
                get("/health", token="wrong")
            self.assertEqual(cm.exception.code, 401)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_toml_config(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.toml")
            with open(p, "w") as fh:
                fh.write(
                '[sensor]\nsensor_id = "pi-07"\nchannels = "1,6,11"\n'
                '[events]\nwebhook_url = "http://x:5000/endpoint"\n'
                '[thresholds]\nlow_rssi = -78.0\n'
                '[[managed_ssid]]\nssid = "CorpWiFi"\nsecurity = ["WPA2-Enterprise"]\n'
                'allowed_ouis = ["70:69:5a"]\n')
            cfg = load(p)
        self.assertEqual(cfg.sensor_id, "pi-07")
        self.assertEqual(cfg.thresholds.low_rssi, -78.0)
        self.assertEqual(cfg.managed[0].allowed_ouis, ["70:69:5a"])
        self.assertEqual(cfg.webhook_url, "http://x:5000/endpoint")


if __name__ == "__main__":
    unittest.main()
