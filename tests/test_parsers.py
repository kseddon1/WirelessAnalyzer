import struct
import unittest

from wlanscope import dot11, radiotap
from wlanscope import synth as S


class RadiotapTests(unittest.TestCase):
    def test_basic_fields(self):
        r = radiotap.parse(S.radiotap(36, -61, -92, rate=24.0))
        self.assertEqual((r.freq, r.band, r.channel), (5180, "5g", 36))
        self.assertEqual((r.signal, r.noise, r.rate), (-61, -92, 24.0))
        self.assertEqual(r.phy, "legacy")

    def test_mcs_rate(self):
        r = radiotap.parse(S.radiotap(6, -50, mcs=7))
        self.assertEqual((r.phy, r.mcs, r.nss, r.bw), ("ht", 7, 1, 20))
        self.assertEqual(r.rate, 65.0)
        r = radiotap.parse(S.radiotap(6, -50, mcs=15))
        self.assertEqual(r.rate, 130.0)

    def test_extended_bitmaps_per_chain(self):
        # word0: TSFT|flags|channel|signal + radiotap-ns + ext; word1: signal|antenna + ns + ext;
        # word2: signal|antenna  (iwlwifi/ath9k style per-chain fields)
        w0 = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 5) | (1 << 29) | (1 << 31)
        w1 = (1 << 5) | (1 << 11) | (1 << 29) | (1 << 31)
        w2 = (1 << 5) | (1 << 11)
        hdr_len = 8 + 8                                   # 3 words = 12 bytes, pad to 16 for TSFT
        body = struct.pack("<Q", 123456) + bytes([0x10]) + b"\x00" + struct.pack("<HH", 2437, 0x80) \
            + struct.pack("<b", -40) + struct.pack("<bB", -42, 0) + struct.pack("<bB", -45, 1)
        total = hdr_len + len(body)
        buf = struct.pack("<BBHIII", 0, 0, total, w0, w1, w2) + b"\x00" * 0 + body
        # the 3 presence words end at offset 16 which is already 8-aligned for TSFT
        r = radiotap.parse(buf)
        self.assertEqual(r.tsft, 123456)
        self.assertEqual(r.freq, 2437)
        self.assertEqual(r.signal, -40)
        self.assertEqual(r.chains, [-42, -45])
        self.assertTrue(r.fcs)

    def test_vendor_namespace_skipped(self):
        w0 = (1 << 1) | (1 << 3) | (1 << 30) | (1 << 31)
        w1 = 0x1                           # vendor-defined bit
        w2 = (1 << 5)                      # back in radiotap ns (via bit 29 on vendor word)
        w1 |= (1 << 29) | (1 << 31)
        flags = bytes([0])
        pad = b"\x00"
        chan = struct.pack("<HH", 5180, 0x100)
        vns = b"\x00\x11\x22" + b"\x01" + struct.pack("<H", 4)
        vdata = b"\xde\xad\xbe\xef"
        sig = struct.pack("<b", -70)
        body = flags + pad + chan + vns + vdata + sig
        buf = struct.pack("<BBHIII", 0, 0, 16 + len(body), w0, w1, w2) + body
        r = radiotap.parse(buf)
        self.assertEqual(r.freq, 5180)
        self.assertEqual(r.chains, [-70])     # later namespace => per-chain
        self.assertEqual(r.signal, -70)

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            radiotap.parse(b"\x01\x00\x08\x00\x00\x00\x00\x00")


class Dot11Tests(unittest.TestCase):
    def test_beacon_ies_and_security(self):
        body = S.beacon_body("CorpWiFi", 36, security="eap-ft", vht=True, bss_load=(5, 40),
                             vendor=(S.WMM, S.CISCO_IE), extra=S.RM_CAPS + S.EXT_CAPS_BTM +
                             S.ie(54, b"\x12\x34\x01"))
        frame = S.hdr(0, 8, "ff:ff:ff:ff:ff:ff", "70:69:5a:10:00:02", "70:69:5a:10:00:02") + body
        f = dot11.parse_frame(frame)
        self.assertEqual((f.ftype, f.subtype, f.a3), (0, 8, "70:69:5a:10:00:02"))
        info = dot11.parse_ies(f.body, 12)
        self.assertEqual(info.ssid, "CorpWiFi")
        self.assertEqual(info.ds_channel, 36)
        self.assertEqual(info.bss_load["stations"], 5)
        self.assertTrue(info.dot11k and info.btm and info.dot11r and info.wmm)
        self.assertEqual(info.generation, "ac")
        self.assertEqual(info.nss, 2)
        self.assertEqual(dot11.bss_width(info, "5g"), (80, 5210))
        label, klass = dot11.summarize_security(True, info.rsn, info.wpa)
        self.assertEqual((label, klass), ("WPA2-Enterprise+FT", "WPA2"))
        self.assertIn("00:40:96/3", info.vendor_ouis)

    def test_security_labels(self):
        def sec(kind, privacy=True):
            info = dot11.parse_ies(S.SECURITY[kind])
            return dot11.summarize_security(privacy, info.rsn, info.wpa)
        self.assertEqual(sec("open", False), ("OPEN", "OPEN"))
        self.assertEqual(sec("open", True), ("WEP", "WEP"))
        self.assertEqual(sec("psk"), ("WPA2-Personal", "WPA2"))
        self.assertEqual(sec("sae"), ("WPA3-Personal", "WPA3"))
        self.assertEqual(sec("psk-sae"), ("WPA2/WPA3-Personal", "WPA2"))
        self.assertEqual(sec("wpa-tkip"), ("WPA-Personal", "WPA"))
        info = dot11.parse_ies(S.SECURITY["sae"])
        self.assertTrue(info.rsn["mfpr"])

    def test_hidden_ssid(self):
        info = dot11.parse_ies(S.ie(0, b"\x00\x00\x00") + S.ie(3, b"\x06"))
        self.assertTrue(info.hidden)
        self.assertEqual(info.ssid, "")

    def test_data_frame_qos_and_eapol(self):
        sc = S.Scene()
        sc.eapol(0, "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02", 6, "M1")
        sc.eapol(0, "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02", 6, "M2")
        sc.eapol(0, "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02", 6, "M3")
        sc.eapol(0, "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02", 6, "M4")
        msgs = []
        for _, data in sc.recs:
            r = radiotap.parse(data)
            f = dot11.parse_frame(data[r.length:], 0, r)
            self.assertTrue(f.is_qos)
            self.assertEqual(f.tid, 7)
            self.assertEqual(dot11.llc_ethertype(f.body), 0x888E)
            msgs.append(dot11.parse_eapol(f.body[8:])["msg"])
        self.assertEqual(msgs, ["M1", "M2", "M3", "M4"])

    def test_ctrl_bandwidth_signalling_ta(self):
        rts = struct.pack("<BBH", 0xB4, 0, 100) + bytes.fromhex("aabbccddeeff") + bytes.fromhex("031122334455")
        f = dot11.parse_frame(rts)
        self.assertEqual(f.a2, "02:11:22:33:44:55")

    def test_fcs_stripped(self):
        frame = S.hdr(0, 4, "ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", "ff:ff:ff:ff:ff:ff") + S.ie(0, b"x")
        r = radiotap.Radio()
        r.fcs = True
        f = dot11.parse_frame(frame + b"\x01\x02\x03\x04", 0, r)
        self.assertEqual(len(f.body), 3)

    def test_truncated_frames(self):
        self.assertIsNone(dot11.parse_frame(b"\x80\x00"))
        self.assertIsNone(dot11.parse_frame(b"\x80\x00" + b"\x00" * 15))
        # truncated IEs must not raise
        info = dot11.parse_ies(b"\x00\x05ab\x30\x02\x01")
        self.assertIsNotNone(info)


if __name__ == "__main__":
    unittest.main()
