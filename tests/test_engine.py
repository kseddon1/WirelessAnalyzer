import os
import tempfile
import unittest

from wlanscope import synth as S
from wlanscope.capture import decode, read_pcap
from wlanscope.config import Config, ManagedSSID
from wlanscope.engine import Engine
from wlanscope.events import EventBus
from wlanscope.oui import OuiDB

AP = "70:69:5a:10:00:01"
AP2 = "70:69:5a:10:00:02"
CL = "a4:83:e7:01:01:01"


def run_scene(scene, cfg=None):
    cfg = cfg or Config(sensor_id="test")
    cfg.thresholds.learning_period = 0
    bus = EventBus("test", cooldown=cfg.event_cooldown)
    eng = Engine(cfg, bus, OuiDB("/nonexistent"), live=False)
    scene.recs.sort(key=lambda r: r[0])
    for ts, data in scene.recs:
        f = decode(data, ts, 127)
        if f is not None:
            eng.ingest(f)
    eng.tick(eng.now() + 1.0)
    return eng, bus


def alerts(bus):
    return [e["alert"] for e in bus.recent]


def beacons(sc, bssid, ssid, ch, secs, start=0.0, **kw):
    t = start
    while t < start + secs:
        sc.beacon(t, bssid, ssid, ch, **kw)
        t += 0.1024


class EngineTests(unittest.TestCase):
    def test_discovery_and_association(self):
        sc = S.Scene()
        beacons(sc, AP, "CorpWiFi", 36, 5, security="eap-ft", vht=True)
        sc.connect(1.0, CL, AP, "CorpWiFi", 36, "eap-ft")
        for i in range(30):
            sc.data(1.5 + i * 0.1, AP, CL, 36, up=i % 2 == 0, length=500)
        eng, bus = run_scene(sc)
        ap = eng.aps[AP]
        self.assertEqual(ap.ssid, "CorpWiFi")
        self.assertEqual(ap.security, "WPA2-Enterprise+FT")
        self.assertEqual((ap.channel, ap.band, ap.width), (36, "5g", 80))
        cl = eng.clients[CL]
        self.assertEqual(cl.bssid, AP)
        self.assertEqual(cl.state, "associated")
        self.assertEqual(cl.hs_complete, 1)
        self.assertEqual((cl.data_up, cl.data_down), (17, 17))   # 15 + EAPOL M2/M4 and M1/M3
        self.assertIn(CL, ap.clients)
        self.assertEqual(cl.status, "ACTIVE")
        self.assertIn("CLIENT_ASSOCIATED", alerts(bus))
        self.assertIn("HANDSHAKE_COMPLETE", alerts(bus))
        wl = eng.wlans()
        self.assertEqual(wl[0]["ssid"], "CorpWiFi")
        self.assertEqual(wl[0]["clients"], 1)

    def test_idle_and_power_save(self):
        sc = S.Scene()
        beacons(sc, AP, "Net", 6, 50, security="psk")
        sc.connect(0.5, CL, AP, "Net", 6)
        sc.connect(0.6, "a4:83:e7:01:01:02", AP, "Net", 6, aid=2)
        for t in range(1, 50, 5):
            sc.data(t, AP, "a4:83:e7:01:01:02", 6, up=True, null=True, pm=True)
        eng, _ = run_scene(sc)
        self.assertEqual(eng.clients[CL].status, "IDLE")
        self.assertEqual(eng.clients["a4:83:e7:01:01:02"].status, "POWER_SAVE")

    def test_evil_twin_by_policy_and_majority(self):
        sc = S.Scene()
        for b, ch in ((AP, 1), (AP2, 36), ("70:69:5a:10:00:03", 149)):
            beacons(sc, b, "CorpWiFi", ch, 3, security="eap-ft", vendor=(S.WMM, S.CISCO_IE))
        beacons(sc, "00:c0:ca:66:66:66", "CorpWiFi", 6, 3, security="open", vendor=())
        sc.connect(1.0, CL, "00:c0:ca:66:66:66", "CorpWiFi", 6, "open")
        for i in range(10):
            sc.data(1.2 + i * 0.1, "00:c0:ca:66:66:66", CL, 6, protected=False)
        eng, bus = run_scene(sc)
        twin = eng.aps["00:c0:ca:66:66:66"]
        self.assertIn("EVIL_TWIN", twin.alerts)
        self.assertEqual(twin.alerts["EVIL_TWIN"]["severity"], "critical")
        for b in (AP, AP2):
            self.assertNotIn("EVIL_TWIN", eng.aps[b].alerts)
        self.assertEqual(eng.clients[CL].status, "EVIL_TWIN")
        self.assertIn("CLIENT_EVIL_TWIN", alerts(bus))

        # policy-only detection with a single BSS
        sc = S.Scene()
        beacons(sc, "00:c0:ca:66:66:66", "CorpWiFi", 6, 2, security="psk")
        cfg = Config(sensor_id="t")
        cfg.managed = [ManagedSSID("CorpWiFi", security=["WPA2-Enterprise"])]
        eng, _ = run_scene(sc, cfg)
        self.assertIn("EVIL_TWIN", eng.aps["00:c0:ca:66:66:66"].alerts)

    def test_no_evil_twin_for_consistent_ess(self):
        sc = S.Scene()
        for b, ch in ((AP, 1), (AP2, 36)):
            beacons(sc, b, "CorpWiFi", ch, 3, security="eap-ft")
        eng, _ = run_scene(sc)
        self.assertFalse(any("EVIL_TWIN" in a.alerts for a in eng.aps.values()))

    def test_spoofed_bssid_tsf_and_channel(self):
        sc = S.Scene()
        beacons(sc, AP, "Home", 11, 5, security="psk")
        beacons(sc, AP, "Home", 1, 5, start=0.05, security="psk", tsf=9_999_000_000)
        eng, bus = run_scene(sc)
        self.assertIn("SPOOFED_BSSID", eng.aps[AP].alerts)

    def test_single_reboot_is_not_spoofing(self):
        sc = S.Scene()
        beacons(sc, AP, "Home", 11, 3, security="psk")
        t = 3.0
        while t < 6:
            sc.beacon(t, AP, "Home", 11, tsf=int((t - 3) * 1e6) + 100, security="psk")
            t += 0.1024
        eng, _ = run_scene(sc)
        self.assertNotIn("SPOOFED_BSSID", eng.aps[AP].alerts)

    def test_karma(self):
        sc = S.Scene()
        beacons(sc, "02:13:37:00:00:01", "FreeWiFi", 6, 3, security="open")
        for i, name in enumerate(("a", "b", "c", "d")):
            sc.probe_resp(1 + i * 0.1, "02:13:37:00:00:01", CL, name, 6, security="open")
        eng, _ = run_scene(sc)
        self.assertIn("KARMA", eng.aps["02:13:37:00:00:01"].alerts)
        self.assertEqual(eng.aps["02:13:37:00:00:01"].ssid, "FreeWiFi")

    def test_hidden_ssid_revealed(self):
        sc = S.Scene()
        beacons(sc, AP, "", 44, 2, security="sae", hidden=True)
        sc.probe_resp(1.0, AP, CL, "SecretLab", 44, security="sae")
        eng, _ = run_scene(sc)
        ap = eng.aps[AP]
        self.assertTrue(ap.hidden)
        self.assertTrue(ap.ssid_revealed)
        self.assertEqual(ap.display_ssid, "SecretLab")

    def test_deauth_flood_and_client_attack(self):
        sc = S.Scene()
        beacons(sc, AP, "Net", 6, 8, security="psk")
        sc.connect(0.5, CL, AP, "Net", 6)
        for k in range(60):
            sc.deauth(2 + k * 0.05, AP, CL, AP, 6, reason=7)
        eng, bus = run_scene(sc)
        self.assertIn("DEAUTH_FLOOD", eng.aps[AP].alerts)
        self.assertEqual(eng.clients[CL].status, "DEAUTH_ATTACK")
        self.assertEqual(eng.clients[CL].last_disconnect["reason"], 7)

    def test_deauth_flood_without_beacons(self):
        sc = S.Scene()
        for k in range(40):
            sc.deauth(k * 0.05, AP, "ff:ff:ff:ff:ff:ff", AP, 6, reason=7)
        eng, bus = run_scene(sc)
        self.assertIn("DEAUTH_FLOOD", eng.aps[AP].alerts)
        self.assertIn("BROADCAST_DEAUTH", alerts(bus))

    def test_wrong_psk_handshake_failure(self):
        sc = S.Scene()
        beacons(sc, AP, "Home", 11, 6, security="psk")
        sc.auth(0.5, CL, AP, AP, 11)
        sc.auth(0.51, AP, CL, AP, 11, 2)
        sc.assoc_req(0.52, CL, AP, "Home", 11)
        sc.assoc_resp(0.53, AP, CL, 11)
        for r in range(3):
            sc.eapol(1 + r, AP, CL, 11, "M1")
            sc.eapol(1.01 + r, AP, CL, 11, "M2")
        sc.deauth(4.5, AP, CL, AP, 11, reason=15)
        eng, bus = run_scene(sc)
        cl = eng.clients[CL]
        self.assertIn("HANDSHAKE_FAIL", cl.issues)
        self.assertEqual(cl.status, "HANDSHAKE_FAIL")
        self.assertIn("HANDSHAKE_FAILED", alerts(bus))

    def test_eap_failure_and_assoc_reject(self):
        sc = S.Scene()
        beacons(sc, AP, "Corp", 1, 3, security="eap-ft")
        sc.assoc_req(0.5, CL, AP, "Corp", 1, "eap-ft")
        sc.assoc_resp(0.51, AP, CL, 1)
        sc.eap(0.6, AP, CL, 1, 2, 25)
        sc.eap(0.7, AP, CL, 1, 4)
        sc.assoc_resp(1.0, AP, "a4:83:e7:01:01:09", 1, status=17)
        eng, bus = run_scene(sc)
        self.assertEqual(eng.clients[CL].eap_method, "peap")
        self.assertEqual(eng.clients[CL].status, "AUTH_FAILURE")
        self.assertIn("EAP_REJECTED", alerts(bus))
        self.assertIn("ASSOC_REJECTED", alerts(bus))

    def test_roaming_and_storm(self):
        sc = S.Scene()
        beacons(sc, AP, "Corp", 1, 30, security="eap-ft")
        beacons(sc, AP2, "Corp", 36, 30, security="eap-ft")
        sc.connect(0.5, CL, AP, "Corp", 1, "eap-ft")
        cur, nxt = AP, AP2
        for i in range(5):
            sc.connect(2 + i * 5, CL, nxt, "Corp", 36 if nxt == AP2 else 1, "eap-ft", reassoc_from=cur)
            cur, nxt = nxt, cur
        eng, bus = run_scene(sc)
        cl = eng.clients[CL]
        self.assertEqual(len(cl.roams), 5)
        self.assertIn("ROAMING_STORM", cl.issues)
        self.assertEqual(alerts(bus).count("CLIENT_ROAMED"), 5)
        self.assertNotIn(CL, eng.aps[AP].clients)
        self.assertIn(CL, eng.aps[AP2].clients)

    def test_high_util_and_retry(self):
        sc = S.Scene()
        beacons(sc, AP, "Net", 36, 12, security="psk")
        sc.connect(0.5, CL, AP, "Net", 36)
        sc.connect(0.6, "a4:83:e7:01:01:02", AP, "Net", 36, aid=2)
        for t in range(1, 12):
            for k in range(250):
                sc.data(t + k / 250, AP, CL, 36, up=False, length=1000)
            for k in range(20):
                sc.data(t + k / 20, AP, "a4:83:e7:01:01:02", 36, up=True, retry=k % 2 == 0, mcs=0)
        eng, _ = run_scene(sc)
        self.assertIn("HIGH_UTIL", eng.clients[CL].issues)
        self.assertIn("HIGH_RETRY", eng.clients["a4:83:e7:01:01:02"].issues)
        self.assertIn("LOW_RATE", eng.clients["a4:83:e7:01:01:02"].issues)

    def test_bad_fcs_frames_ignored(self):
        sc = S.Scene()
        beacons(sc, AP, "Net", 6, 1)
        rt = bytearray(S.radiotap(6, -50))
        rt[8] |= 0x40                                      # bad-FCS flag
        frame = S.hdr(0, 8, "ff:ff:ff:ff:ff:ff", "de:ad:be:ef:00:01", "de:ad:be:ef:00:01") + \
            S.beacon_body("ghost", 6)
        sc.add(0.5, bytes(rt), frame)
        eng, _ = run_scene(sc)
        self.assertNotIn("de:ad:be:ef:00:01", eng.aps)
        self.assertEqual(eng.bad_fcs, 1)

    def test_static_alerts(self):
        sc = S.Scene()
        beacons(sc, AP, "Guest", 6, 2, security="open")
        beacons(sc, AP2, "IoT", 11, 2, security="wpa-tkip", ht=False)
        beacons(sc, "70:69:5a:10:00:03", "Busy", 1, 2, security="psk", bss_load=(40, 90))
        eng, bus = run_scene(sc)
        self.assertIn("OPEN_NETWORK", eng.aps[AP].alerts)
        self.assertIn("WEAK_SECURITY", eng.aps[AP2].alerts)
        self.assertIn("LEGACY", eng.aps[AP2].flags)
        self.assertIn("HIGH_CHANNEL_UTIL", eng.aps["70:69:5a:10:00:03"].alerts)
        ev = [e for e in bus.recent if e["alert"] == "OPEN_NETWORK"][0]
        self.assertEqual((ev["ssid"], ev["bssid"], ev["state"]), ("Guest", AP, "raised"))

    def test_security_downgrade(self):
        sc = S.Scene()
        beacons(sc, AP, "Net", 6, 3, security="sae")
        beacons(sc, AP, "Net", 6, 3, start=3.0, security="psk")
        eng, bus = run_scene(sc)
        self.assertIn("SECURITY_DOWNGRADE", eng.aps[AP].alerts)

    def test_demo_pcap_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "demo.pcap")
            n = S.demo(p, duration=30)
            recs = list(read_pcap(p))
            self.assertEqual(len(recs), n)
            sc = S.Scene()
            sc.recs = [(ts, data) for ts, _lt, data in recs]
            sc.t0 = 0
            eng, bus = run_scene(sc)
            self.assertGreaterEqual(len(eng.wlans()), 6)
            self.assertIn("EVIL_TWIN", alerts(bus))


if __name__ == "__main__":
    unittest.main()
