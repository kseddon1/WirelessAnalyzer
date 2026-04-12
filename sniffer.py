"""
Sniffer thread – captures packets and hands them to the processor.
"""
import time
from threading import Event
from scapy.all import sniff

from processor import process_packet


def sniff_loop(iface: str, store, stop_event: Event):
    while not stop_event.is_set():
        try:
            sniff(iface=iface, prn=lambda p: process_packet(p, store), store=False, timeout=2)
            store.purge()
        except Exception:
            time.sleep(0.5)
