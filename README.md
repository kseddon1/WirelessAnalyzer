# wlanscope

802.11 WLAN discovery and analysis for Raspberry Pi monitor-mode sensors. It
has two front ends:

* **Interactive (curses)**: analysts drill down from WLANs (SSIDs) to the
  BSSIDs of an SSID, then to one BSS with its clients, then to one client.
* **Headless sensor**: emits structured JSON events for automation (Event-Driven
  Ansible webhook, JSON-lines file, syslog), writes a live state file, and
  serves a small HTTP API.

It is pure Python 3 (3.9+, 3.11+ for TOML config) with **no third-party
dependencies**. Radiotap, 802.11, information elements, RSN and EAPOL are
parsed directly from `AF_PACKET` sockets. No scapy.

## Quick start

```bash
# your existing script creates wlan1mon (airmon-ng start wlan1)
sudo python3 -m wlanscope -i wlan1mon                      # interactive, hops 2.4 + 5 GHz
sudo python3 -m wlanscope -i wlan1mon --channels 1,6,11    # only these channels
sudo python3 -m wlanscope -i wlan1mon --channel 36         # stay on one channel
sudo python3 -m wlanscope -i wlan1 --setup-monitor         # let wlanscope set monitor mode
sudo python3 -m wlanscope -i wlan1mon -i wlan2mon          # two adapters split the channel list

# headless sensor -> EDA webhook + local event log + state file + API
sudo WA_EDA_TOKEN=secret python3 -m wlanscope -i wlan1mon --headless \
     --sensor-id pi-lobby --webhook http://eda:5000/endpoint \
     --events-file /var/log/wlanscope/events.jsonl --state-file /run/wlanscope/state.json \
     --api 0.0.0.0:8088 --managed-ssid CorpWiFi=WPA2-Enterprise

# offline: analyse a capture (pcap or pcapng, radiotap or plain 802.11)
python3 -m wlanscope -r capture.pcapng                     # UI, real-time replay
python3 -m wlanscope -r capture.pcapng --headless --report report.json > events.jsonl

# no radio handy? generate a synthetic campus scenario and explore it
python3 -m wlanscope.synth /tmp/demo.pcap && python3 -m wlanscope -r /tmp/demo.pcap
```

`python3 -m wlanscope --help` lists every option. A TOML config holds the
same settings plus detection thresholds and managed SSIDs; see
`wlanscope.example.toml`. CLI flags override the config. Environment
defaults are `WA_IFACE` (interface), `WA_SENSOR` (sensor id), `WA_EDA_URL` and
`WA_EDA_TOKEN` (webhook).

Live capture needs root (raw socket + `iw`). The Pi's built-in Broadcom radio
has no monitor mode without nexmon, so use a USB adapter with a monitor-capable
driver (mt76 / mt7921u, ath9k_htc, rtl8812au, ...).

## Interactive UI

```
WLANs › CorpWiFi › 70:69:5a:10:00:02 › a4:83:e7:01:01:01
```

| View | Shows |
|---|---|
| **WLANs** (`1`/`w`) | per SSID: BSS count, clients, bands, channels, security, best RSSI, beacons, data/s, alerts |
| **BSSIDs of an SSID** | vendor / AP name, channel, band, width, PHY (n/ac/ax/be), RSSI, SNR, clients, beacons, data, retry %, BSS-load utilisation, security, alerts and flags |
| **BSS detail** | AP perspective. RF: channel, width, centre, PHY, NSS, max rate, RSSI last/avg/min/max, SNR, noise, signal sparkline, beacon interval, DTIM, BSS load, country, TSF uptime. Security and capabilities: AKMs, ciphers, PMF, WPS, capability bits, 802.11k/v/r/u, WMM, rates, HT/VHT/HE caps, vendor IEs. A counter table (total, **+Δ in the last second**, rate per second) for frames, beacons, probe responses, mgmt, ctrl, data, null, auth, assoc, reassoc, deauth, disassoc, action, EAPOL, retries and bytes. Then active alerts with explanations, then the **client list** |
| **Client list** (in BSS detail) | MAC, vendor, RSSI, SNR, TX/RX PHY rate, data up/down, data/s, mgmt, retry %, power save, last seen, **STATUS**, issues and flags |
| **Client detail** | state, network, AID, signal and sparkline, rates and medians, power save, listen interval, capabilities (PHY, NSS, widths, 11k/v/r, AKM, cipher, PMF, power capability), 4-way handshake and EAP state, probed SSIDs, counters (total/+Δ/s plus up/down split), issues, disconnect reason, roam / auth-failure / BTM history, recent events |
| **All clients** (`2`/`c`) | every station, including unassociated probing devices; `a` toggles associated-only |
| **Channels** (`3`/`n`) | per channel: BSSs, clients, frames/s, data/s, retry %, BSS-load, dwell time; Enter locks the radio there |
| **Events** (`4`/`e`) | live event stream; Enter shows the event JSON, `f` sets the minimum severity |

Keys: arrows/`j` `k`, Enter to drill down, Esc/Backspace to go back, `s`/`r`
to sort, `/` to filter, `p` to pause, `S` for a JSON snapshot, `?` for help,
`q` to quit. In the BSS detail view, `i` cycles the layout (split, info only,
clients only) for small terminals.

**Lock to a BSS (`l`)** tunes every radio to that BSS's primary channel *and
width*, using `iw set freq <primary> 80 <centre>`. A radio hopping at 20 MHz
still decodes beacons and management frames, but it cannot decode data
frames sent at 40/80/160 MHz. Lock before judging a client's data
utilisation. `u` resumes hopping.

### Client status

The worst current issue wins; otherwise the activity state is shown.

| Status | Meaning |
|---|---|
| `EVIL-TWIN` | associated to a BSS flagged EVIL_TWIN, SPOOFED_BSSID or KARMA |
| `DEAUTH-ATK` | receiving a burst of deauth/disassoc frames, or its BSS is under a deauth flood |
| `4WAY-FAIL` | 4-way handshake failed: the AP restarted it after M2 (classic wrong passphrase), M1 is ignored, or the disconnect reason was 14/15/17 |
| `AUTH-FAIL` | auth/assoc rejected (status code), EAP-Failure, or auth-related disconnect reasons |
| `ROAM-STORM` | roams or re-associations ≥ 4 in 60 s |
| `HIGH-RETRY` | ≥ 20 % of the client's data frames retried (10 s window) |
| `WEAK-SIGNAL` | RSSI < −80 dBm or SNR < 15 dB at the sensor |
| `LOW-RATE` | median PHY rate ≤ 12 Mbps on an HT-or-better BSS |
| `STICKY?` | weak link while another BSS of the same SSID is ≥ 10 dB stronger *at the sensor* (heuristic) |
| `HIGH-UTIL` | ≥ 200 data frames/s, ≥ 5 Mbps, or ≥ 60 % of the BSS's data |
| `ACTIVE` / `PWR-SAVE` / `IDLE` | data in the last 10 s / power-save bit set / no data for 30 s |
| `PROBING` / `CONNECTING` / `DISCONN` / `GONE` | unassociated and probing / auth or assoc in progress / deauthed or disassociated / unseen for 5 min |

Flags such as `RANDOMIZED_MAC`, `LEGACY_CLIENT` and `BTM_STEERED` are shown next to the status.
All thresholds are in the `[thresholds]` config section.

## Detection

| Alert | Severity | How |
|---|---|---|
| `EVIL_TWIN` | warning/critical | per-SSID scoring. A **managed SSID** advertised with the wrong security, or from a BSSID/OUI that isn't allowed, scores high. Without config, a BSS whose security differs from the other BSSIDs of the SSID (or is weaker in a tie) scores +3; a vendor-IE fingerprint, beacon interval or country that differs from the majority adds more. A score ≥ 3 raises the alert, ≥ 5 makes it critical |
| `SPOOFED_BSSID` | critical | one BSSID with discontinuous beacon TSF (≥ 3 jumps in 60 s) or beacons claiming alternating channels: two transmitters sharing a BSSID |
| `KARMA` | critical | one BSSID answering probe requests for ≥ 3 different SSIDs (Karma/MANA) |
| `DEAUTH_FLOOD` | critical | ≥ 20 deauth/disassoc frames per BSS in 10 s; also `BROADCAST_DEAUTH` |
| `SECURITY_DOWNGRADE` / `SECURITY_CHANGED` | critical / warning | a BSS's beaconed security changed |
| `OPEN_NETWORK`, `WEAK_SECURITY` | info (warning for managed SSIDs) / warning | open, WEP, WPA1 or TKIP |
| `HIGH_CHANNEL_UTIL`, `HIGH_RETRY` | warning | the AP's BSS Load element ≥ 70 %; BSS data retry rate ≥ 25 % |
| `AP_LOST` | info (warning for managed SSIDs) | an established BSS hasn't been heard for 3 min |
| `BEACON_FLOOD` | warning | ≥ 50 new BSSIDs in a minute |

There are also observed (one-shot) events: `AP_NEW`, `CLIENT_NEW`,
`CLIENT_ASSOCIATED`, `CLIENT_ROAMED`, `CLIENT_DISCONNECTED` (with the decoded
reason code), `AUTH_REJECTED` / `ASSOC_REJECTED` / `EAP_REJECTED` (with the
decoded status), `HANDSHAKE_COMPLETE`, `HANDSHAKE_FAILED`, `BTM_REQUEST` /
`BTM_RESPONSE`, `CHANNEL_SWITCH`, `SSID_CHANGED`, and `SENSOR_STARTED` /
`SENSOR_HEARTBEAT` / `SENSOR_STOPPED`. Client issues produce
`CLIENT_<ISSUE>` events (e.g. `CLIENT_HIGH_UTIL`).

Frames with a bad FCS are dropped before they can create ghost stations.
While hopping, rates (`/s`) are divided by the time the radio actually spent
on that BSS's channel, not by wall-clock time.

## Event format

One JSON object per event. `alert`, `ssid`, `bssid` and `sensor` are top-level
so EDA rules can match `event.payload.alert` directly. The existing
`netops/rulebooks/wireless_alerts.yml` works unchanged: list the same SSIDs
with `--managed-ssid` / `[[managed_ssid]]` so their `OPEN_NETWORK` events are
`warning` and pass the webhook's default severity filter.

```json
{
  "event_id": "3df56690-c615-41d8-a97c-90bd261e2d3c", "seq": 82,
  "ts": "2026-10-20T08:55:13.000+00:00", "epoch": 1792486513.0,
  "sensor": "pi-lobby", "alert": "EVIL_TWIN", "state": "raised",
  "severity": "critical", "category": "security",
  "ssid": "CorpWiFi", "bssid": "00:c0:ca:66:66:66", "client": null,
  "channel": 6, "band": "2g", "rssi": -45.0,
  "message": "possible evil twin of 'CorpWiFi' at 00:c0:ca:66:66:66: ...",
  "details": {"score": 8, "reasons": ["security 'OPEN' violates policy ..."], "ssid_bssids": ["..."]}
}
```

* `state` is `raised`, `cleared` or `observed`. A stateful alert fires once when
  it starts and once more as `<ALERT>_CLEARED` after it has been false for its
  hold time.
* Identical events are suppressed for `event_cooldown` seconds (default 300)
  unless the severity rises.
* Each sink has its own minimum severity. The webhook and syslog default to
  `warning`; the file and stdout default to `info`.
* The webhook POSTs one event per request with `Authorization: Bearer <token>`
  from a background queue, so a slow receiver never stalls capture.

## HTTP API (`--api host:port`, optional `--api-token`)

The API is **off by default** — it only starts when you pass `--api host:port`.
`--api-token` (or `WA_API_TOKEN`) requires a `Authorization: Bearer <token>`
header on every request.

| Request | Returns |
|---|---|
| `GET /health` | sensor id, uptime, radios, frame/event counters |
| `GET /state[?full=1]` | every WLAN, BSS, client and channel |
| `GET /wlans`, `GET /bss/<bssid>`, `GET /client/<mac>` | detail objects |
| `GET /events?since=<seq>&min_severity=warning&limit=500` | recent events (poll with `since`) |
| `POST /lock {"bssid": "..."}` or `{"band": "5g", "channel": 36}` | focus the radio(s) |
| `POST /unlock` | resume hopping |

### Pulling events from an agent (Hermes, cron, etc.)

Instead of pushing webhooks, an external agent can poll `/events` and remember the last `seq` it saw:

```bash
API=http://127.0.0.1:8088
TOKEN="$WA_API_TOKEN"

# sensor liveness
curl -s -H "Authorization: Bearer $TOKEN" "$API/health"

# new warning+ events since the last sequence we processed
curl -s -H "Authorization: Bearer $TOKEN" \
  "$API/events?since=0&min_severity=warning&limit=50"

# detail on a suspicious BSS
curl -s -H "Authorization: Bearer $TOKEN" \
  "$API/bss/00:c0:ca:66:66:66"
```

A polling script keeps `since` in a small state file so it never processes the same event twice:

```python
#!/usr/bin/env python3
import json, os, urllib.request

API   = os.environ["WL_API"]          # e.g. http://127.0.0.1:8088
TOKEN = os.environ["WL_API_TOKEN"]
SEQF  = os.path.expanduser("~/.wlanscope-since.txt")

def read_seq():
    try:
        return int(open(SEQF).read().strip())
    except Exception:
        return 0

def write_seq(seq):
    with open(SEQF, "w") as f:
        f.write(str(seq))

since = read_seq()
url = f"{API}/events?since={since}&min_severity=warning&limit=100"
req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
with urllib.request.urlopen(req, timeout=15) as r:
    events = json.loads(r.read())

max_seq = since
for ev in events:
    max_seq = max(max_seq, ev.get("seq", 0))
    print(f"[{ev.get('severity')}] {ev.get('alert')} "
          f"{ev.get('ssid','')} {ev.get('bssid','')} {ev.get('client','')} "
          f"{ev.get('message','')}")

if events:
    write_seq(max_seq)
```

Hermes can run this via its `terminal` tool (or a Hermes cron job), then fetch `/bss/<bssid>` or `/client/<mac>` for the full picture on anything that looks wrong, and decide whether to orchestrate a response.

### Testing without a radio

Generate a synthetic campus scenario and replay it with the API on, so you can validate the pull flow before deploying to a sensor with a real radio:

```bash
python3 -m wlanscope.synth /tmp/demo.pcap
python3 -m wlanscope --headless -r /tmp/demo.pcap \
  --api 127.0.0.1:8088 --api-token test --replay-speed 1
```

Then hit `http://127.0.0.1:8088/health` and `/events` from another terminal while it replays.

### Security

The API binds to the host:port you give. `127.0.0.1` keeps it local to the machine. `0.0.0.0` exposes it on all interfaces — only do that on a trusted network, or firewall the port. Always pair `--api-token` with `--api` when the port is reachable beyond localhost.

`--state-file` writes the same data as `/state`, atomically, every
`state_interval` seconds, for agents that would rather read a file.

## Defaults: what's off unless you turn it on

Everything that reaches outside the process is opt-in:

| Integration | CLI flag | Default |
|---|---|---|
| HTTP API | `--api host:port` | off |
| Webhook sink | `--webhook URL` | off |
| Syslog sink | `--syslog host[:port]` | off |
| JSON-lines event file | `--events-file path` | off |
| State file | `--state-file path` | off |
| Stdout events (headless only) | `--stdout-events` | off unless headless with no other output |
| Interactive TUI (no flags) | none | capture + UI only, nothing external |

Running `python3 -m wlanscope -i wlan1mon` interactively starts capture and the curses UI with **no external integration code** executing — no API listener, no webhook posts, no syslog, no file writes.

## Running as a service

`deploy/wlanscope.service` is a systemd unit that runs the headless sensor
from `/opt/wlanscope` with `/etc/wlanscope.toml`. Put the webhook token in
`/etc/default/wlanscope` as `WA_EDA_TOKEN=...`. To spread a cluster across
the band, give each Pi its own `channels` (e.g. one on `2g-common` plus
`5g-nodfs`, another on DFS channels). A Pi with two adapters splits its list
automatically.

## Layout

```
wlanscope/
  radiotap.py   radiotap parser (extended bitmaps, namespaces, per-chain signal, MCS/VHT/HE rates)
  dot11.py      802.11 frames, information elements, RSN/WPA/WPS, security labels, EAPOL
  capture.py    AF_PACKET live capture, pcap/pcapng reader, pcap writer, monitor-mode helper
  channels.py   frequency/channel maths, PHY rate tables, iw channel hopper
  engine.py     state engine: BSSs, clients, counters, association/roam/handshake tracking
  detect.py     alerts, evil-twin scoring, client status
  events.py     event bus with cooldown; stdout, file, webhook and syslog sinks
  api.py        HTTP JSON API
  headless.py   sensor loop (heartbeat, state file)
  tui.py        curses UI
  synth.py      synthetic frame builder and demo scenario (also used by the tests)
tests/          python3 -m unittest discover -s tests -t .
```

## Limits worth knowing

* RSSI and SNR are measured **at the sensor**, not at the AP or the client.
  `STICKY?` is a heuristic for that reason.
* Many drivers don't report noise. SNR then uses `noise_floor` (−95 dBm) and
  shows `~`.
* While hopping, each channel is observed only part of the time, so frame
  counts are samples. Lock to a channel or BSS when the numbers matter.
* Protected management frames (PMF) hide deauth reason codes and encrypted
  action frames; those show as "n/a".
* MU-MIMO/OFDMA (HE-MU) PPDUs are counted, but per-user rates come from the
  radiotap HE field only when the driver provides it.
