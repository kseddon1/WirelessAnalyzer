"""
Curses based UI for WirelessAnalyzer.
"""
import curses
import time
from datetime import datetime
from network_store import NetworkStore


FLAG_LENGTH = 50


def format_ap_line(ap, selected, max_x):
    ssid = (ap.ssid or "<hidden>")[:22]
    ch   = f"{ap.channel:>3}"
    sig  = f"{ap.signal or '?':>5}"
    enc  = (ap.enc or "Open")[:16]
    cli  = f"{len(ap.clients):>4}"
    frm  = f"{ap.frames:>6}"
    rate  = f"{ap.pkt_rate:>5.1f}"
    alerts = ",".join(getattr(ap, "insights", [])) or "-"
    line = f"{ssid:<22} {ap.bssid:<19} {ch:>3} {sig:>5} {enc:<16} {cli:>4} {frm:>6} {rate:>6}  {alerts}"
    if selected:
        line = line.ljust(max_x - 1)
    return line[:max_x-2]


def ui_loop(stdscr, store: NetworkStore):
    stdscr.nodelay(True)
    curses.curs_set(0)
    max_y, max_x = stdscr.getmaxyx()
    net_h, cli_h, act_h = max_y//2, max_y//2-3, 3
    net_win = curses.newwin(net_h, max_x, 0, 0)
    cli_win = curses.newwin(cli_h, max_x, net_h, 0)
    act_win = curses.newwin(act_h, max_x, net_h+cli_h, 0)
    selected = 0
    paused = False

    while True:
        ap_list = store.get_sorted_by_signal()
        if selected >= len(ap_list):
            selected = max(0, len(ap_list)-1)
        # AP list
        net_win.erase()
        net_win.border()
        net_win.addstr(0, 2, f" Networks ({len(ap_list)}) ")
        header = f"{'SSID':<22} {'BSSID':<19} {'CH':>3} {'SIG':>5} {'ENC':<16} {'CLI':>4} {'FRM':>6} {'PKT/S':>6}  ALERTS"
        net_win.addstr(1, 2, header)
        for i, ap in enumerate(ap_list[:net_h-3]):
            line = format_ap_line(ap, i==selected, max_x)
            net_win.addstr(i+2, 2, line)
        # Client details for selected AP
        cli_win.erase()
        cli_win.border()
        if ap_list:
            sel_ap = ap_list[selected]
            cli_win.addstr(0, 2, f" Clients of {sel_ap.ssid} ({sel_ap.bssid}) ")
            header = f"{'MAC':<19} {'IP':<15} {'SIG':>5} {'PKT/S':>6} {'LAST SEEN':<14} {'AIRTIME%':>8} {'FLAGS':<{FLAG_LENGTH}}  INSIGHTS"
            cli_win.addstr(1, 2, header)
            for i, (mac, ci) in enumerate(list(sel_ap.clients.items())[:cli_h-3]):
                ip = ci.ip or "-"
                insights = ",".join(getattr(ci, "insights", [])) or "-"
                rate = f"{ci.pkt_rate:>5.1f}"
                line = f"{mac:<19} {ip:<15} {ci.signal or '?':>5} {rate:>6} {ci.last_seen:<14} {ci.aatime_pct:>8}%  {ci.flags}  {insights}"
                cli_win.addstr(i+2, 2, line[:max_x-4])
        # Actions
        act_win.erase()
        act_win.border()
        status = "[PAUSED]" if paused else ""
        act_win.addstr(1, 2, f"[UP/DOWN] select  [P] pause  [Q] quit {status}")
        net_win.refresh(); cli_win.refresh(); act_win.refresh()

        try:
            ch = stdscr.getch()
            if ch == ord('q'):
                break
            if ch == ord('p'):
                paused = not paused
            if ch == curses.KEY_UP:
                selected = max(0, selected-1)
            if ch == curses.KEY_DOWN:
                selected = min(len(ap_list)-1, selected+1)
        except Exception:
            pass
        time.sleep(0.5)
