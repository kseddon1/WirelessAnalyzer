"""Tests for the observation model (wlanscope.observations).

Deterministic: every observation carries an explicit timestamp, so windowed
queries are predictable and repeatable.
"""

import time
import unittest

from wlanscope.observations import (Observation, ObservationStore,
                                    CONNECTIVITY, RADIO, PERFORMANCE, PROTOCOL,
                                    OBS_ROAM, OBS_DISCONNECT, OBS_AUTH_FAIL,
                                    OBS_ASSOC_FAIL, OBS_RETRY_SPIKE,
                                    OBS_RSSI_DROP, OBS_CHANNEL_UTIL,
                                    OBS_RATE_CHANGE, OBS_THROUGHPUT_DROP,
                                    OBS_LATENCY_SPIKE, OBS_PACKET_LOSS,
                                    OBS_CONNECTED_IDLE, OBS_DEAUTH,
                                    OBS_DISASSOC, OBS_HANDSHAKE_FAIL,
                                    OBS_EAP_FAILURE, OBS_MGMT_ANOMALY,
                                    OBS_ASSOC, OBS_REASSOC, OBS_BSSID_CHANGE,
                                    OBSERVATION_TYPES)


class ObservationStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = ObservationStore()
        self.now = time.time()

    def _add(self, obs_type, client=None, bssid=None, category=CONNECTIVITY,
             offset=0.0, rssi=None, details=None):
        self.store.add(Observation(category=category, obs_type=obs_type,
                                   ts=self.now - offset, client=client,
                                   bssid=bssid, rssi=rssi,
                                   details=details or {}))

    def test_add_and_len(self):
        self.assertEqual(len(self.store), 0)
        self._add(OBS_ROAM, client="aa:bb:cc:00:00:01", offset=0.0)
        self._add(OBS_DISCONNECT, client="aa:bb:cc:00:00:02", offset=1.0)
        self.assertEqual(len(self.store), 2)

    def test_window(self):
        self._add(OBS_ROAM, client="c1", offset=0.0)
        self._add(OBS_ROAM, client="c2", offset=5.0)
        self._add(OBS_ROAM, client="c3", offset=10.0)
        self._add(OBS_ROAM, client="c4", offset=20.0)
        hits = self.store.window(10.0, self.now)
        self.assertEqual(len(hits), 3)   # offsets 0, 5, 10 within 10s window
        hits = self.store.window(6.0, self.now)
        self.assertEqual(len(hits), 2)   # offsets 0, 5

    def test_by_type(self):
        self._add(OBS_ROAM, offset=0.0)
        self._add(OBS_DISCONNECT, offset=1.0)
        self._add(OBS_ROAM, offset=2.0)
        self.assertEqual(len(self.store.by_type(OBS_ROAM)), 2)
        self.assertEqual(len(self.store.by_type(OBS_ROAM, seconds=1.0, now=self.now)), 1)

    def test_by_client(self):
        self._add(OBS_ROAM, client="c1", offset=0.0)
        self._add(OBS_DISCONNECT, client="c1", offset=1.0)
        self._add(OBS_ROAM, client="c2", offset=2.0)
        self.assertEqual(len(self.store.by_client("c1")), 2)
        self.assertEqual(len(self.store.by_client("c2")), 1)

    def test_by_bssid(self):
        self._add(OBS_DEAUTH, bssid="aa:bb:cc:00:00:01", category=PROTOCOL)
        self._add(OBS_RSSI_DROP, bssid="aa:bb:cc:00:00:01", category=RADIO)
        self._add(OBS_DISCONNECT, bssid="aa:bb:cc:00:00:02", category=CONNECTIVITY)
        self.assertEqual(len(self.store.by_bssid("aa:bb:cc:00:00:01")), 2)

    def test_by_category(self):
        self._add(OBS_ROAM, category=CONNECTIVITY)
        self._add(OBS_RSSI_DROP, category=RADIO)
        self._add(OBS_THROUGHPUT_DROP, category=PERFORMANCE)
        self._add(OBS_DEAUTH, category=PROTOCOL)
        self.assertEqual(len(self.store.by_category(CONNECTIVITY)), 1)
        self.assertEqual(len(self.store.by_category(RADIO)), 1)
        self.assertEqual(len(self.store.by_category(PERFORMANCE)), 1)
        self.assertEqual(len(self.store.by_category(PROTOCOL)), 1)

    def test_count(self):
        self._add(OBS_ROAM, offset=0.0)
        self._add(OBS_ROAM, offset=5.0)
        self._add(OBS_ROAM, offset=15.0)
        self.assertEqual(self.store.count(OBS_ROAM, 10.0, self.now), 2)   # 0, 5
        self.assertEqual(self.store.count(OBS_ROAM, 20.0, self.now), 3)   # 0, 5, 15

    def test_all_observation_types_have_labels(self):
        for obs_type, label in OBSERVATION_TYPES.items():
            self.assertIsInstance(label, str)
            self.assertGreater(len(label), 0)


class ObservationEventTests(unittest.TestCase):
    def test_as_event_shape(self):
        obs = Observation(category=CONNECTIVITY, obs_type=OBS_ROAM, ts=1234.5,
                          client="aa:bb:cc:00:00:01", bssid="dd:ee:ff:11:22:33",
                          ssid="CorpWiFi", channel=36, band="5g", rssi=-55.0,
                          message="client roamed", details={"from": "b1", "to": "b2"})
        ev = obs.as_event("sensor-1", 7)
        self.assertEqual(ev["alert"], "OBS_ROAM")
        self.assertEqual(ev["state"], "observed")
        self.assertEqual(ev["severity"], "info")
        self.assertEqual(ev["category"], CONNECTIVITY)
        self.assertEqual(ev["client"], "aa:bb:cc:00:00:01")
        self.assertEqual(ev["bssid"], "dd:ee:ff:11:22:33")
        self.assertEqual(ev["channel"], 36)
        self.assertEqual(ev["band"], "5g")
        self.assertEqual(ev["rssi"], -55.0)
        self.assertEqual(ev["message"], "client roamed")
        self.assertEqual(ev["details"], {"from": "b1", "to": "b2"})
        self.assertEqual(ev["sensor"], "sensor-1")
        self.assertEqual(ev["seq"], 7)
