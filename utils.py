"""Utility helpers for WirelessAnalyzer.

They were previously scattered through the original main.py.  The
functions are small, pure, and testable.
"""

import re
from datetime import datetime, timedelta

from scapy.layers.dot11 import Dot11Elt, Dot11EltRates, Dot11Beacon, Dot11ProbeResp, RadioTap

RETRY_RATE_THRESHOLD = 0.2  # 20 % of frames
FLAG_LENGTH = 50


def get_signal_strength(packet):
    """Return dBm_AntSignal from the RadioTap header if present."""
    return packet[RadioTap].fields.get('dBm_AntSignal') if packet.haslayer(RadioTap) else None


def get_transmission_rate(packet):
    return packet[RadioTap].Rate if packet.haslayer(RadioTap) else None


def get_data_rates(packet):
    if packet.haslayer(Dot11EltRates):
        rates = sorted(packet[Dot11EltRates].rates)
        return ",".join(str(r) for r in rates)
    return "N/A"


def extract_channel(packet):
    if packet.haslayer(RadioTap) and packet.haslayer(Dot11Elt):
        try:
            # id 3 is the channel info
            return ord(packet[Dot11Elt:3].info)
        except Exception:
            pass
    return None


def get_ssid(packet):
    if packet.haslayer(Dot11Elt) and (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        raw = packet[Dot11Elt].info
        return raw.decode('utf-8', 'ignore') if raw else "<hidden>"
    return None


def get_ap_uptime(packet):
    if packet.haslayer(Dot11Beacon):
        ts = packet[Dot11Beacon].timestamp
        delta = timedelta(seconds=int(ts/1_000_000))
        return f"{delta.days}d {delta.seconds//3600}h"
    return None


def parse_rsn_element(rsn_elt):
    encryption = "WPA2"
    if len(rsn_elt.info) > 12:
        asc = int.from_bytes(rsn_elt.info[10:12], 'little')
        akm_offset = 12
        for _ in range(asc):
            akm_suite = rsn_elt.info[akm_offset:akm_offset+4]
            if akm_suite in (b'\x00\x0F\xAC\x02', b'\x00\x0F\xAC\x05'):
                encryption = "WPA2 (Personal)"
            elif akm_suite == b'\x00\x0F\xAC\x01':
                encryption = "WPA2 Enterprise"
            elif akm_suite in (b'\x00\x0F\xAC\x08', b'\x00\x0F\xAC\x09', b'\x00\x0F\xAC\x12'):
                encryption = "WPA3 Enterprise"
            elif akm_suite == b'\x00\x0F\xAC\x04':
                encryption = "WPA3"
            akm_offset += 4
    return encryption


def determine_encryption(packet):
    if packet.haslayer(Dot11Elt):
        rsn = packet.getlayer(Dot11Elt, ID=48)
        wpa = packet.getlayer(Dot11Elt, ID=221)
        if rsn:
            return parse_rsn_element(rsn)
        if wpa and b'\x00P\xf2\x01\x01\x00' in wpa.info:
            return "WPA"
    return "Open"

# Export for processor to import
__all__ = [
    'get_signal_strength',
    'get_transmission_rate',
    'get_data_rates',
    'extract_channel',
    'get_ssid',
    'get_ap_uptime',
    'determine_encryption',
]
