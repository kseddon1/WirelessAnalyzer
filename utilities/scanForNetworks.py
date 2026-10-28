from scapy.all import *
from threading import Thread
import pandas
import time
import os
import signal

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "HT", "VHT", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

bssidList = []

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")

        ######### get HT, VHT information - have to parse it manually #########
        
        bList = [] 
        htChannelWidth = 'unknown'
        vhtChannelWidth = 'unknown'
        if packet.haslayer(Dot11Elt): 
             dot11elt = packet.getlayer(Dot11Elt)
             #print(dot11elt)
             while dot11elt:
                   #print(dot11elt.ID) 
                   #print(dot11elt.info)
                   if dot11elt.ID == 61:
                      ht_op_info_bytes = dot11elt.info
                      for byte in ht_op_info_bytes:
                         bList.append(byte) 
                      #print(ssid + ": " + format(bList[1], '08b'))
                      htfortyMhz = bool(int(format(bList[1], '08b'),2) & int('00000100',2)) 

                      if htfortyMhz:
                         #print("40Mhz") 
                         htChannelWidth = '40Mhz'
                      else:
                         #print("20Mhz")
                         htChannelWidth = '20Mhz'
                   
                   if dot11elt.ID == 192:
                      vht_op_info_bytes = dot11elt.info
                      for byte in vht_op_info_bytes:
                         bList.append(byte)
                      
                      #print(ssid + ": " + format(bList[0], '08b')) 
                      eightyMhz = bool(int(format(bList[0], '08b'),2) & int('00000001',2))
                      hundredSixtyMhz = bool(int(format(bList[0], '08b'),2) & int('00000010',2))
                      eightyeightyMhz = bool(int(format(bList[0], '08b'),2) & int('00000011',2))

                      if eightyMhz:
                         vhtChannelWidth = '80Mhz'
                      elif hundredSixtyMhz:
                         vhtChannelWidth = '160Mhz'
                      elif eightyeightyMhz:
                         vhtChannelWidth = '80+80Mhz'
                      else:
                         vhtChannelWidth = '20/40Mhz'

                   bList = []
                   dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        if ssid != "" and bssid not in bssidList:
            networks.loc[bssid] = (ssid, dbm_signal, channel, htChannelWidth, vhtChannelWidth, crypto)
            bssidList.append(bssid)
            networks.sort_values(['SSID'],inplace=True)


def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(3)


def signal_handler(sig, frame):
    exit()	


if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlan1mon"
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    signal.signal(signal.SIGINT, signal_handler)
    
    while True:

       try:
          sniff(prn=callback, iface=interface)
       except Exception as e:
          pass
