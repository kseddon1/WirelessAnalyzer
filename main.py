#!/usr/bin/env python3
#
#  main.py
#  
#  Copyright 2024 kirk <kirk@gzs76>
#  

import sys
import time
import curses
import signal
from threading import Thread
from datetime import datetime, timedelta
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11Auth, RadioTap, Dot11AssoResp, Dot11Ack, Dot11QoS 

target_ap = "1e:e8:29:15:30:b4"
target_ssid = "Plato"
old_mac_ap = "00:00:00:00:00:00"
ap_info = { "BSSID" : "11:11:11:11:11:11", "CHANNEL(s)" : 0, "SSID(s)" : "empty", "SIGNAL" : 0, "CLIENTS" : 0, "ENC" : "none", "FRAMES" : 0, "DATA(QoS)" : 0, "UPTIME" : "0", "Retries" : 0, "DataRates" : "N/A" }
clients = {}
frame_count = 1
executeIsTrue = True

# Helper for client flags length
FLAG_LENGTH = 18
RETRY_RATE_THRESHOLD = 0.2  # 20% of frames being retries triggers HIGH_RETRIES

def check_for_retries(packet):
    global ap_info
    if packet.haslayer(Dot11):
        if packet.FCfield & 0x08:  # Retry bit
           ap_info["Retries"] += 1
           mac_cl, mac_ap = packet.addr2, packet.addr1
           if mac_ap == target_ap:
               if mac_cl in clients:
                   clients[mac_cl]["Retries"] += 1

def get_macs(packet, types):
    if types == "probereq":
        mac_cl = packet.addr2
        mac_ap = packet.addr1
    elif types == "rts":
        mac_cl = packet.addr2
        mac_ap = packet.addr1
    elif types == "qos_data":
        mac_cl = packet.addr2
        mac_ap = packet.addr1
    elif types == "cts":
        mac_cl = packet.addr2
        mac_ap = packet.addr1
    elif types == "block_ack_req":
        mac_cl = packet.addr1
        mac_ap = packet.addr2
    elif types == "block_ack":
        mac_cl = packet.addr1
        mac_ap = packet.addr2
    else:
        mac_cl = packet.addr1
        mac_ap = packet.addr2
    return mac_cl, mac_ap

def parse_rsn_element(rsn_elt):
    encryption = "WPA2"
    if len(rsn_elt.info) > 2:
        asc = int.from_bytes(rsn_elt.info[10:12], byteorder='little')
        if asc > 0:
            akm_offset = 12
            for _ in range(asc):
                akm_suite = rsn_elt.info[akm_offset:akm_offset+4]
                if akm_suite in [b'\x00\x0F\xAC\x02', b'\x00\x0F\xAC\x05']:
                    encryption += " (Personal)"
                elif akm_suite in [b'\x00\x0F\xAC\x01', b'\x00\x0F\xAC\x05']:
                    encryption = "WPA2 Enterprise"
                elif akm_suite in [b'\x00\x0F\xAC\x08', b'\x00\x0F\xAC\x09', b'\x00\x0F\xAC\x12']:
                    encryption = "WPA3 Enterprise"
                elif akm_suite == b'\x00\x0F\xAC\x04':
                    encryption = "WPA3"
                akm_offset += 4
    return encryption

def determine_encryption(packet):
    encryption = "Open"
    if packet.haslayer(Dot11Elt):
        rsn_found = packet.getlayer(Dot11Elt, ID=48)
        wpa_found = packet.getlayer(Dot11Elt, ID=221)
        if rsn_found:
            encryption = parse_rsn_element(rsn_found)
        elif wpa_found and b'\x00P\xf2\x01\x01\x00' in wpa_found.info:
            encryption = "WPA"
    return encryption

def get_ssid(packet):
    if packet.haslayer(Dot11Elt) and (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        ssid = packet[Dot11Elt].info.decode('utf-8', 'ignore') if packet[Dot11Elt].info else "Hidden SSID"
        return ssid
    return "0"

def extract_channel(packet):
    channel = "N/A"
    if packet.haslayer(RadioTap) and packet.haslayer(Dot11Elt):
        try:
            channel = ord(packet[Dot11Elt:3].info)
        except Exception:
            pass
    return channel

def get_ap_uptime(packet):
    if packet.haslayer(Dot11Beacon):
        timestamp = packet[Dot11Beacon].timestamp
        uptime_seconds = timestamp / 1000000
        uptime_delta = timedelta(seconds=int(uptime_seconds))
        days = uptime_delta.days
        hours = uptime_delta.seconds // 3600
        return f"{days}d {hours}h"
    return None

def get_signal_strength(packet):
    if packet.haslayer(RadioTap):
        radiotap_fields = packet[RadioTap].fields
        if 'dBm_AntSignal' in radiotap_fields:
            return radiotap_fields['dBm_AntSignal']
    return None

def get_data_rates(packet):
    firstelement = True
    data_rates = ""
    if packet.haslayer(Dot11EltRates):
        eltrateslayer = packet.getlayer(Dot11EltRates)
        rates = eltrateslayer.rates
        rates.sort()
        for rate in rates:
            if firstelement:
                data_rates = data_rates + str(rate)
                firstelement = False
            else:
                data_rates = data_rates + "," + str(rate)
    else:
        data_rates = "N/A"
    return data_rates

def get_data_transmission_rate(packet):
    transmission_rate = "N/A"
    if packet.haslayer(RadioTap):
        radiotaplayer = packet.getlayer(RadioTap)
        transmission_rate = radiotaplayer.Rate
    return transmission_rate

def frame_analyzer(packet, types):
    global target_ap, target_ssid, clients, ap_info

    mac_cl, mac_ap = get_macs(packet, types)
    enc = determine_encryption(packet)
    ssid = get_ssid(packet)
    channel = extract_channel(packet)
    signal = get_signal_strength(packet)
    uptime = get_ap_uptime(packet)
    timestamp = datetime.now().strftime('%m-%d %H:%M')
    transmission_rate = get_data_transmission_rate(packet)

    # ---------- AP Info Updates ----------
    if mac_ap == target_ap:
        if types == "beacon":
            ap_info['UPTIME'] = uptime
            ap_info['DataRates'] = get_data_rates(packet)
        elif types == "qos_data":
            ap_info['DATA(QoS)'] += 1 

        if packet.haslayer(RadioTap) and packet.haslayer(Dot11Elt):
            if channel != "N/A":
                ap_info['CHANNEL(s)'] = channel
            ap_info['SIGNAL'] = signal
            if ssid != "0":
                ap_info['SSID(s)'] = ssid
            ap_info['ENC'] = enc
        ap_info['FRAMES'] += 1
        check_for_retries(packet)

    # ---------- Client Updates ----------
    if types in ["auth", "asso_req", "asso_resp"] and ssid == target_ssid:
        if mac_cl not in clients:
            clients[mac_cl] = { "SIGNAL": signal, "LAST SEEN": timestamp, "DataRate": transmission_rate, "Frames": 0, "Airtime%": 0, "Retries": 0, "Flags": " " * FLAG_LENGTH, "LastRetryReset": datetime.now() }

    if types in ["rts", "qos_data", "block_ack"] and mac_ap == target_ap:
        if mac_cl not in clients:
            clients[mac_cl] = { "SIGNAL": signal, "LAST SEEN": timestamp, "DataRate": transmission_rate, "Frames": 0, "Airtime%": 0, "Retries": 0, "Flags": " " * FLAG_LENGTH, "LastRetryReset": datetime.now() }
        else:
            clients[mac_cl]["LAST SEEN"] = timestamp
            clients[mac_cl]["SIGNAL"] = signal
            if types == "qos_data" and (clients[mac_cl]["DataRate"] is None or clients[mac_cl]["DataRate"] < transmission_rate):
                clients[mac_cl]["DataRate"] = transmission_rate

        # Count frames for Airtime %
        clients[mac_cl]["Frames"] += 1
        if ap_info['FRAMES'] > 0:
            clients[mac_cl]["Airtime%"] = round(clients[mac_cl]["Frames"] / ap_info['FRAMES'] * 100, 1)

        # Reset retries every 60s
        if (datetime.now() - clients[mac_cl]["LastRetryReset"]).total_seconds() > 60:
            clients[mac_cl]["Retries"] = 0
            clients[mac_cl]["LastRetryReset"] = datetime.now()

        # ---------- Set Flags ----------
        flags = []
        if clients[mac_cl]["SIGNAL"] and clients[mac_cl]["SIGNAL"] < -70:
            flags.append("WEAK_SIGNAL")
        if clients[mac_cl]["Airtime%"] > 40:
            flags.append("HIGH_USAGE")
        if clients[mac_cl]["Frames"] < 5:
            flags.append("IDLE")
        # Retry rate flag
        retry_rate = clients[mac_cl]["Retries"] / max(1, clients[mac_cl]["Frames"])
        if retry_rate > RETRY_RATE_THRESHOLD:
            flags.append("HIGH_RETRIES")

        clients[mac_cl]["Flags"] = (",".join(flags)).ljust(FLAG_LENGTH)[:FLAG_LENGTH]

def frame_handler(packet):
    if packet.haslayer(Dot11):
        if packet.haslayer(Dot11Beacon):
            frame_analyzer(packet, "beacon")
        elif packet.haslayer(Dot11ProbeReq):
            frame_analyzer(packet, "probereq")
        elif packet.haslayer(Dot11ProbeResp):
            frame_analyzer(packet, "proberesp")
        elif packet.haslayer(Dot11Auth):
            frame_analyzer(packet, "auth")
        elif packet.haslayer(Dot11AssoReq):
            frame_analyzer(packet, "asso_req")
        elif packet.haslayer(Dot11AssoResp):
            frame_analyzer(packet, "asso_resp")
        elif packet.haslayer(Dot11Ack):
            frame_analyzer(packet, "ack")
        elif packet.haslayer(Dot11QoS):
            frame_analyzer(packet, "qos_data")
        else:
            if packet.type == 1:
                subtype = packet.subtype
                if subtype == 0x09:
                    frame_analyzer(packet, "block_ack_req")
                elif subtype == 0x0b:
                    frame_analyzer(packet, "block_ack")
                elif subtype == 0x0B:
                    frame_analyzer(packet, "rts")
                elif subtype == 0x0C:
                    frame_analyzer(packet, "cts")

def run_sniff():
    global executeIsTrue
    while executeIsTrue:
        try:
            sniff(prn=frame_handler, iface="wlan1mon")
        except Exception:
            pass

def display_ap_info(window):
    global ap_info, clients
    window.border()
    window.addstr(0, 2, "Access Point")
    window.addstr(2, 2, "BSSID: " + target_ap)
    window.addstr(3, 2, "SSID(s): " + target_ssid)
    window.addstr(4, 2, "Channels(s): " + str(ap_info["CHANNEL(s)"]))
    window.addstr(5, 2, "Signal: " + str(ap_info["SIGNAL"]))
    window.addstr(6, 2, "Clients: " + str(len(clients)))
    window.addstr(7, 2, "Encryption: " + str(ap_info["ENC"]))
    window.addstr(8, 2, "Frames: " + str(ap_info["FRAMES"]))
    window.addstr(9, 2, "Data(QoS): " + str(ap_info["DATA(QoS)"]))
    window.addstr(10, 2, "Retries: " + str(ap_info["Retries"]))
    window.addstr(11, 2, "Uptime: " + str(ap_info["UPTIME"]))
    window.addstr(12, 2, "Data Rates")
    window.addstr(13, 2, str(ap_info["DataRates"]))
    window.refresh()

def display_action_info(window):
    window.border()
    window.addstr(0, 2, "Actions")
    window.addstr(2, 2, "Pause - P")
    window.addstr(3, 2, "Quit - Q")
    window.refresh()

def display_client_info(window):
    global clients
    count = 2
    window.border()
    window.addstr(0, 2, "Clients")
    if bool(clients):
        for key, value in clients.items():
            client_output = f"Mac: {key} Sig:{value['SIGNAL']} Last:{value['LAST SEEN']} Airtime:{value['Airtime%']}% Flags:{value['Flags']}"
            window.addstr(count, 2, client_output)
            count += 1
    window.refresh()

def print_all(stdscr, target_window, actions_window, clients_window):
    global executeIsTrue
    while executeIsTrue:
        display_ap_info(target_window)
        display_action_info(actions_window)
        display_client_info(clients_window)
        stdscr.refresh()

def signal_handler(sig, frame):
    exit()

def main(stdscr, *args):
    global executeIsTrue
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.clear()
    stdscr.refresh()
    max_y, max_x = stdscr.getmaxyx()
    if max_y < 28:
        max_y = 28

    target_window = curses.newwin(max_y // 2, 30, 0, 0)
    actions_window = curses.newwin(max_y // 2, 30, max_y // 2, 0)
    clients_window = curses.newwin(max_y, max_x//3*2, 0, 30)

    target_window.border()
    actions_window.border()
    clients_window.border()
    display_ap_info(target_window)
    display_action_info(actions_window)
    display_client_info(clients_window)
    stdscr.refresh()  

    printer = Thread(target=print_all, args=(stdscr,target_window, actions_window, clients_window))
    printer.daemon = True
    printer.start()

    wifisniffer = Thread(target=run_sniff)
    wifisniffer.daemon = True
    wifisniffer.start()

    signal.signal(signal.SIGINT, signal_handler)

    wifiAnalyzerRunning = True
    while wifiAnalyzerRunning:
        c = stdscr.getch()
        if c == ord('q'):
            wifiAnalyzerRunning = False
        if c == ord('p'):
            executeIsTrue = False
    return 0

if __name__ == '__main__':
    curses.wrapper(main)

