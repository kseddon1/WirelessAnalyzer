"""802.11 protocol constants and human readable code tables."""

# Frame types
MGMT, CTRL, DATA, EXT = 0, 1, 2, 3

# Management subtypes
ASSOC_REQ = 0
ASSOC_RESP = 1
REASSOC_REQ = 2
REASSOC_RESP = 3
PROBE_REQ = 4
PROBE_RESP = 5
TIMING_ADV = 6
BEACON = 8
ATIM = 9
DISASSOC = 10
AUTH = 11
DEAUTH = 12
ACTION = 13
ACTION_NOACK = 14

MGMT_NAMES = {
    0: "assoc-req", 1: "assoc-resp", 2: "reassoc-req", 3: "reassoc-resp",
    4: "probe-req", 5: "probe-resp", 6: "timing-adv", 8: "beacon", 9: "atim",
    10: "disassoc", 11: "auth", 12: "deauth", 13: "action", 14: "action-noack",
}

# Control subtypes
CTRL_TRIGGER = 2
CTRL_BF_POLL = 4
CTRL_NDPA = 5
CTRL_WRAPPER = 7
CTRL_BAR = 8
CTRL_BA = 9
CTRL_PSPOLL = 10
CTRL_RTS = 11
CTRL_CTS = 12
CTRL_ACK = 13
CTRL_CFEND = 14
CTRL_CFEND_ACK = 15

# Control frames that carry a transmitter address (addr2)
CTRL_WITH_TA = {CTRL_TRIGGER, CTRL_BF_POLL, CTRL_NDPA, CTRL_BAR, CTRL_BA,
                CTRL_PSPOLL, CTRL_RTS, CTRL_CFEND, CTRL_CFEND_ACK}

# Frame control flags
FC_TODS = 0x01
FC_FROMDS = 0x02
FC_MOREFRAG = 0x04
FC_RETRY = 0x08
FC_PWRMGT = 0x10
FC_MOREDATA = 0x20
FC_PROTECTED = 0x40
FC_ORDER = 0x80

# Capability information bits
CAP_ESS = 0x0001
CAP_IBSS = 0x0002
CAP_PRIVACY = 0x0010
CAP_SHORT_PREAMBLE = 0x0020
CAP_SPECTRUM_MGMT = 0x0100
CAP_QOS = 0x0200
CAP_SHORT_SLOT = 0x0400
CAP_APSD = 0x0800
CAP_RADIO_MEAS = 0x1000

AUTH_ALGOS = {0: "open", 1: "shared-key", 2: "ft", 3: "sae", 4: "fils-sk",
              5: "fils-sk-pfs", 6: "fils-pk", 7: "pasn"}

CIPHER_SUITES = {
    0: "USE-GROUP", 1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 5: "WEP-104",
    6: "BIP-CMAC-128", 7: "NO-GROUP-TRAFFIC", 8: "GCMP-128", 9: "GCMP-256",
    10: "CCMP-256", 11: "BIP-GMAC-128", 12: "BIP-GMAC-256", 13: "BIP-CMAC-256",
}

AKM_SUITES = {
    1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256",
    6: "PSK-SHA256", 7: "TDLS", 8: "SAE", 9: "FT-SAE", 10: "AP-PEER-KEY",
    11: "802.1X-SUITE-B", 12: "802.1X-SUITE-B-192", 13: "FT-802.1X-SHA384",
    14: "FILS-SHA256", 15: "FILS-SHA384", 16: "FT-FILS-SHA256",
    17: "FT-FILS-SHA384", 18: "OWE", 19: "FT-PSK-SHA384", 20: "PSK-SHA384",
    22: "802.1X-SHA384", 24: "SAE-EXT-KEY", 25: "FT-SAE-EXT-KEY",
}
AKM_EAP = {1, 3, 5, 11, 12, 13, 14, 15, 16, 17, 22}
AKM_EAP_192 = {12, 13}
AKM_PSK = {2, 4, 6, 19, 20}
AKM_SAE = {8, 9, 24, 25}
AKM_OWE = {18}
AKM_FT = {3, 4, 9, 13, 16, 17, 19, 25}

# Security ranking used to decide which BSS of a mismatched SSID is suspect.
SECURITY_RANK = {"OPEN": 0, "WEP": 1, "WPA": 2, "OWE": 3, "WPA2": 4, "WPA3": 5}

ACTION_CATEGORIES = {
    0: "spectrum-mgmt", 1: "qos", 2: "dls", 3: "block-ack", 4: "public",
    5: "radio-measurement", 6: "fast-bss-transition", 7: "ht", 8: "sa-query",
    9: "protected-dual-public", 10: "wnm", 11: "unprotected-wnm", 12: "tdls",
    13: "mesh", 14: "multihop", 15: "self-protected", 17: "dmg",
    19: "fst", 20: "robust-av", 21: "vht", 22: "unprotected-s1g", 23: "s1g",
    26: "he", 27: "protected-he", 30: "protected-eht", 36: "eht",
    126: "vendor-protected", 127: "vendor",
}

EAP_TYPES = {1: "identity", 2: "notification", 3: "nak", 4: "md5", 13: "eap-tls",
             17: "leap", 18: "eap-sim", 21: "eap-ttls", 23: "eap-aka", 25: "peap",
             26: "mschapv2", 43: "eap-fast", 50: "eap-aka'", 52: "eap-pwd",
             55: "teap"}

REASON_CODES = {
    0: "Reserved",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Station is leaving (or has left) the ESS",
    4: "Disassociated due to inactivity",
    5: "AP is unable to handle all currently associated stations",
    6: "Class 2 frame received from nonauthenticated station",
    7: "Class 3 frame received from nonassociated station",
    8: "Station is leaving the BSS",
    9: "Station requesting (re)association is not authenticated",
    10: "Power Capability element is unacceptable",
    11: "Supported Channels element is unacceptable",
    12: "Disassociated due to BSS transition management",
    13: "Invalid element",
    14: "Message integrity code (MIC) failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "4-Way Handshake element differs from (Re)Assoc/Probe/Beacon",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of security policy",
    25: "TDLS teardown: peer unreachable",
    26: "TDLS teardown: unspecified",
    27: "SSP requested disassociation",
    28: "No SSP roaming agreement",
    29: "Bad cipher or AKM",
    30: "Not authorized in this location",
    31: "Service change precludes TS",
    32: "Unspecified QoS-related reason",
    33: "Not enough bandwidth for QoS station",
    34: "Excessive frames not acknowledged (poor channel conditions)",
    35: "Transmission outside TXOP limits",
    36: "Requesting station is leaving",
    37: "Peer does not want to use the mechanism",
    38: "Mechanism requires setup",
    39: "Timeout",
    45: "Peer does not support the requested cipher suite",
    46: "Authorized access limit reached",
    47: "External service requirements",
    48: "Invalid FT Action frame count",
    49: "Invalid PMKID",
    50: "Invalid MDE",
    51: "Invalid FTE",
    53: "Mesh peering cancelled",
    54: "Mesh max peers reached",
    66: "Mesh channel switch unspecified",
}

STATUS_CODES = {
    0: "Success",
    1: "Unspecified failure",
    5: "Security disabled",
    6: "Unacceptable lifetime",
    7: "Not in same BSS",
    10: "Cannot support all requested capabilities",
    11: "Reassociation denied: association cannot be confirmed",
    12: "Association denied: reason outside the scope of the standard",
    13: "Authentication algorithm not supported",
    14: "Authentication transaction sequence out of order",
    15: "Authentication rejected: challenge failure",
    16: "Authentication rejected: timeout waiting for next frame",
    17: "AP unable to handle additional associated stations",
    18: "Station does not support all basic rates",
    19: "Station does not support short preamble",
    22: "Spectrum management required",
    23: "Power Capability element unacceptable",
    24: "Supported Channels element unacceptable",
    25: "Station does not support short slot time",
    27: "Station does not support HT features",
    28: "R0KH unreachable",
    30: "Association rejected temporarily; try again later",
    31: "Robust management frame policy violation",
    32: "Unspecified QoS-related failure",
    33: "Insufficient bandwidth for QoS station",
    34: "Poor channel conditions",
    35: "QoS not supported",
    37: "Request declined",
    38: "Invalid parameters",
    40: "Invalid element",
    41: "Invalid group cipher",
    42: "Invalid pairwise cipher",
    43: "Invalid AKMP",
    44: "Unsupported RSNE version",
    45: "Invalid RSNE capabilities",
    46: "Cipher suite rejected by security policy",
    47: "TS not created; try later",
    52: "Listen interval too large",
    53: "Invalid FT Action frame count",
    54: "Invalid PMKID",
    55: "Invalid MDE",
    56: "Invalid FTE",
    72: "Invalid contents of RSNE",
    76: "SAE anti-clogging token required",
    77: "SAE finite cyclic group not supported",
    82: "Rejected with suggested BSS transition",
    93: "Denied: no more stations",
    122: "Denied: password identifier mismatch (SAE)",
    123: "SAE password identifier unknown",
    126: "SAE hash-to-element required",
}

BTM_STATUS = {0: "accept", 1: "reject-unspecified", 2: "reject-insufficient-beacons",
              3: "reject-insufficient-capacity", 4: "reject-bss-termination-undesired",
              5: "reject-bss-termination-delay", 6: "reject-sta-candidate-list",
              7: "reject-no-suitable-candidates", 8: "reject-leaving-ess"}


def reason_text(code):
    if code is None:
        return "n/a (protected frame)"
    return f"{code}: {REASON_CODES.get(code, 'Reserved/unknown')}"


def status_text(code):
    if code is None:
        return "n/a"
    return f"{code}: {STATUS_CODES.get(code, 'Reserved/unknown')}"
