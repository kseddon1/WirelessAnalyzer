"""
Processor – translates live scapy packets into stat structures.
"""

from datetime import datetime
from scapy.layers.inet import IP
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11ProbeReq,
    Dot11AssoReq, Dot11AssoResp, Dot11Auth, Dot11Ack, Dot11QoS,
    RadioTap, Dot11EltRates
)

from network_store import NetworkStore
from utils import (
    get_signal_strength,
    get_transmission_rate,
    get_data_rates,
    extract_channel,
    get_ssid,
    get_ap_uptime,
    determine_encryption,
)

# Map scapy packet types to a string used internally
TYPE_MAP = {
    Dot11Beacon: "beacon",
    Dot11ProbeResp: "proberesp",
    Dot11ProbeReq: "probereq",
    Dot11Auth: "auth",
    Dot11AssoReq: "asso_req",
    Dot11AssoResp: "asso_resp",
    Dot11Ack: "ack",
    Dot11QoS: "qos_data",
}


# ----------------------------------------------------------------------
#  Insight engine integration
# ----------------------------------------------------------------------
from alerts import evaluate


def process_packet(packet, store: NetworkStore):
    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]
    # determine AP BSSID – for probe requests the destination is the BSSID
    bssid = (dot11.addr1 or dot11.addr2 or dot11.addr3 or "").lower()
    if not bssid or bssid in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or bssid.startswith("01:"):
        return

    ap = store.upsert_ap(bssid)
    t = TYPE_MAP.get(type(packet))
    if t is None:
        # Management frames – look at subtype
        if packet.haslayer(Dot11Ack):
            t = "ack"
    if t is None:
        return

    signal = get_signal_strength(packet)
    tx_rate = get_transmission_rate(packet)

    # ---------- AP discovery ------------------------------------------
    if t in ("beacon", "proberesp"):
        if ap.ssid == "<hidden>":
            ssid = get_ssid(packet)
            if ssid:
                ap.ssid = ssid
        ap.enc = determine_encryption(packet)
        ch = extract_channel(packet)
        if ch is not None:
            ap.channel = ch
        if signal is not None:
            ap.signal = signal
        if t == "beacon":
            ap.uptime = get_ap_uptime(packet)
            ap.data_rates = get_data_rates(packet)
        ap.add_frame(signal, is_qos=False, retry=False)
        # Attach seeing insights for the AP (first de‑fined, will be updated for newer frames)
        ap.insights = evaluate(ap)
        return

    # ---------- Update AP stats & find client MAC ---------------------
    ap.add_frame(signal, is_qos=(t == "qos_data"), retry=(dot11.FCfield & 0x08 != 0))

    mac_cl = dot11.addr2
    if not mac_cl or mac_cl.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac_cl.lower().startswith("01:"):
        return
    client = ap.add_client(mac_cl.lower(), signal, tx_rate)
    if t == "qos_data":
        ip_src = packet[IP].src if packet.haslayer(IP) else None
        ip_dst = packet[IP].dst if packet.haslayer(IP) else None
        client.ip = ip_src or ip_dst
    client.update_frame(signal, tx_rate, t)
    if ap.frames > 0:
        client.aatime_pct = round(client.frames / ap.frames * 100, 1)

    # Attach insights for client & AP (after all frame updates)
    client.insights = evaluate(client)
    ap.insights = evaluate(ap)
