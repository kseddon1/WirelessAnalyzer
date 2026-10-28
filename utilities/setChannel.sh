#! /bin/bash
echo "changing channel"
#sudo iwconfig wlan1mon channel $1
sudo iw dev wlan1mon set channel $1 HT20
#sudo iw dev wlan1mon set channel $1 HT40+
#sudo iw dev wlan1mon set channel $1 HT40-
