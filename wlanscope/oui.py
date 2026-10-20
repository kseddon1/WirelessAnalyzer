"""MAC vendor (OUI) lookup.

Loads the Wireshark `manuf` file or the IEEE `oui.txt` when present on the
system (apt: wireshark-common / ieee-data) and falls back to a small built-in
table of common enterprise AP and client vendors.
"""

import logging
import os
import re

log = logging.getLogger(__name__)

SEARCH_PATHS = [
    "/usr/share/wireshark/manuf",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/misc/oui.txt",
    "/var/lib/ieee-data/oui.txt",
]

_BUILTIN = {
    "00:0b:86": "Aruba", "00:1a:1e": "Aruba", "00:24:6c": "Aruba", "20:4c:03": "Aruba",
    "24:de:c6": "Aruba", "6c:f3:7f": "Aruba", "94:b4:0f": "Aruba", "d8:c7:c8": "Aruba",
    "00:40:96": "Cisco", "00:0b:85": "Cisco", "00:17:df": "Cisco", "00:1d:a2": "Cisco",
    "00:3a:7d": "Cisco", "70:69:5a": "Cisco", "a0:e0:af": "Cisco", "f4:db:e6": "Cisco",
    "00:18:0a": "Meraki", "0c:8d:db": "Meraki", "88:15:44": "Meraki", "e0:55:3d": "Meraki",
    "ac:17:c8": "Meraki", "34:56:fe": "Meraki",
    "5c:5b:35": "Mist", "d4:20:b0": "Mist",
    "00:24:82": "Ruckus", "2c:5d:93": "Ruckus", "74:91:1a": "Ruckus", "c4:01:7c": "Ruckus",
    "04:18:d6": "Ubiquiti", "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "f0:9f:c2": "Ubiquiti", "fc:ec:da": "Ubiquiti", "74:83:c2": "Ubiquiti",
    "00:1b:17": "PaloAlto", "00:09:0f": "Fortinet",
    "90:6c:ac": "Fortinet", "00:a0:57": "Lancom", "00:1e:2a": "Netgear",
    "a0:40:a0": "Netgear", "50:c7:bf": "TP-Link", "f4:f2:6d": "TP-Link",
    "00:90:4c": "Broadcom", "00:10:18": "Broadcom", "00:03:7f": "Atheros",
    "00:13:74": "Atheros", "8c:fd:f0": "Qualcomm", "00:c0:ca": "Alfa",
    "dc:a6:32": "RaspberryPi",
    "b8:27:eb": "RaspberryPi", "e4:5f:01": "RaspberryPi", "d8:3a:dd": "RaspberryPi",
    "28:cd:c1": "RaspberryPi", "2c:cf:67": "RaspberryPi",
    "00:1b:63": "Apple", "3c:22:fb": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
    "ac:bc:32": "Apple", "8c:85:90": "Apple", "bc:d0:74": "Apple", "f4:0f:24": "Apple",
    "00:16:6c": "Samsung", "5c:0a:5b": "Samsung", "8c:77:12": "Samsung",
    "f8:04:2e": "Samsung", "00:1d:e0": "Intel", "3c:a9:f4": "Intel", "7c:b2:7d": "Intel",
    "a4:34:d9": "Intel", "b4:96:91": "Intel", "f8:63:3f": "Intel", "dc:53:60": "Intel",
    "00:50:f2": "Microsoft", "3c:5a:b4": "Google", "f4:f5:d8": "Google",
    "00:e0:4c": "Realtek", "00:0c:e7": "MediaTek", "00:0c:43": "Ralink",
    "18:fe:34": "Espressif", "24:0a:c4": "Espressif", "ac:67:b2": "Espressif",
    "00:17:88": "Philips", "18:b4:30": "Nest", "fc:65:de": "Amazon", "44:65:0d": "Amazon",
}

_MANUF_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2})\s+(\S+)(?:\s+(.*))?$")
_OUITXT_RE = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)$")


class OuiDB:
    def __init__(self, path=None):
        self.table = dict(_BUILTIN)
        self.source = "builtin"
        paths = [path] if path else SEARCH_PATHS
        for p in paths:
            if p and os.path.exists(p):
                try:
                    n = self._load(p)
                    self.source = f"{p} ({n} entries)"
                    break
                except OSError as e:
                    log.warning("cannot read OUI file %s: %s", p, e)

    def _load(self, path):
        n = 0
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _OUITXT_RE.match(line)
                if m:
                    key = m.group(1).replace("-", ":").lower()
                    self.table[key] = _short(m.group(2).strip())
                    n += 1
                    continue
                m = _MANUF_RE.match(line)
                if m:
                    key = m.group(1).replace("-", ":").lower()
                    self.table[key] = m.group(2)
                    n += 1
        return n

    def lookup(self, m):
        if not m:
            return ""
        v = self.table.get(m[:8])
        if v:
            return v
        if int(m[0:2], 16) & 0x02:
            return "(random)"
        return ""


def _short(name):
    name = re.sub(r"[,.]?\s*(Inc|Ltd|Co|Corp|Corporation|LLC|GmbH|S\.A|AB|Limited|"
                  r"Technologies|Technology|Electronics|Communications|Networks)\b\.?", "", name)
    return name.strip(" ,.")[:20] or name[:20]
