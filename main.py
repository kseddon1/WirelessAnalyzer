"""
Entry point for the refactored WirelessAnalyzer.
"""
import threading
import signal
import curses
from network_store import NetworkStore
from sniffer import sniff_loop
from ui import ui_loop


def main():
    iface = "wlan1mon"
    store = NetworkStore()
    stop_event = threading.Event()

    sniffer_thread = threading.Thread(target=sniff_loop, args=(iface, store, stop_event), daemon=True)
    sniffer_thread.start()

    def sigint_handler(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, sigint_handler)
    curses.wrapper(lambda stdscr: ui_loop(stdscr, store))
    stop_event.set()


if __name__ == "__main__":
    main()
