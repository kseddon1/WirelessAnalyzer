#! /bin/bash
echo "wlan0"
iwlist wlan0 channel | grep Current
echo "wlan1mon"
iwlist wlan1mon channel | grep Current
