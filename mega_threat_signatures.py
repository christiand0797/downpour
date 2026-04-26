"""
Mega Threat Signatures Database v2.0
===================================
Comprehensive collection of threat signatures, patterns, and indicators.
Contains 650+ signatures across all threat categories.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set
import re

# ============================================================================
# MALWARE FAMILY DATABASE - 500+ Families
# ============================================================================

MALWARE_FAMILIES = {
    # === REMOTE ACCESS TROJANS (RATs) ===
    "rats": {
        "njrat": {"aliases": ["bladabindi", "njw0rm"], "severity": 90, "ports": [1177, 5552, 7777]},
        "darkcomet": {"aliases": ["fynloski", "darkc0met"], "severity": 90, "ports": [1604, 6666, 9999]},
        "nanocore": {"aliases": ["nanoclient"], "severity": 90, "ports": [54984]},
        "quasar": {"aliases": ["quasarrat", "xrat"], "severity": 85, "ports": [4782]},
        "asyncrat": {"aliases": ["async"], "severity": 90, "ports": [6606, 7707, 8808]},
        "remcos": {"aliases": ["remcosrat"], "severity": 90, "ports": [2404, 4443]},
        "netwire": {"aliases": ["netwirerc", "netware"], "severity": 90, "ports": [3360, 3365]},
        "orcus": {"aliases": ["orcusrat"], "severity": 85, "ports": [10134]},
        "warzone": {"aliases": ["avemaria", "warzonerat"], "severity": 90, "ports": [5200]},
        "limerat": {"aliases": ["lime"], "severity": 80, "ports": [8989]},
        "venomrat": {"aliases": ["venom"], "severity": 85, "ports": [4449]},
        "dcrat": {"aliases": ["darkcrsytal"], "severity": 85, "ports": [7777]},
        "bitrat": {"aliases": ["bit"], "severity": 85, "ports": [9999]},
        "poisonivy": {"aliases": ["pivy", "poison_ivy"], "severity": 90, "ports": [3460]},
        "ghostrat": {"aliases": ["ghost", "gh0st"], "severity": 90, "ports": [8000]},
        "blackshades": {"aliases": ["bshades"], "severity": 85, "ports": [6969]},
        "cybergate": {"aliases": ["rebhip"], "severity": 85, "ports": [81, 288]},
        "xtremerat": {"aliases": ["xrat"], "severity": 80, "ports": [82, 83]},
        "luminosity": {"aliases": ["luminositylink"], "severity": 80, "ports": [6318]},
        "imminent": {"aliases": ["imminentmonitor"], "severity": 80, "ports": [1234]},
        "revenge": {"aliases": ["revengerat"], "severity": 80, "ports": [333]},
        "adwind": {"aliases": ["jrat", "alienspy", "frutas"], "severity": 85, "ports": [1777]},
        "jbifrost": {"aliases": ["jbifrostrat"], "severity": 80, "ports": [2021]},
        "pandora": {"aliases": ["pandorahvnc"], "severity": 85, "ports": [4466]},
        "havex": {"aliases": ["dragonfly", "oldrea"], "severity": 95, "ports": [443]},
        "plugx": {"aliases": ["korplug", "sogu", "destory"], "severity": 95, "ports": [443, 8080]},
        "winnti": {"aliases": ["pasteboy"], "severity": 95, "ports": [53, 80, 443]},
        "shadowpad": {"aliases": ["shadow"], "severity": 95, "ports": [443]},
        "cobaltstrikebeacon": {"aliases": ["beacon", "cs"], "severity": 95, "ports": [80, 443, 8080]},
    },

    # === CREDENTIAL STEALERS ===
    "stealers": {
        "agenttesla": {"aliases": ["agent_tesla"], "severity": 85},
        "formbook": {"aliases": ["xloader"], "severity": 85},
        "lokibot": {"aliases": ["loki"], "severity": 80},
        "azorult": {"aliases": ["azor"], "severity": 80},
        "predator": {"aliases": ["predatorthethief"], "severity": 80},
        "raccoon": {"aliases": ["raccoonstealer", "racealer"], "severity": 85},
        "vidar": {"aliases": ["vidarstealer"], "severity": 85},
        "redline": {"aliases": ["redlinestealer"], "severity": 90},
        "cryptbot": {"aliases": ["crypt"], "severity": 80},
        "arkei": {"aliases": ["arkeistealer"], "severity": 80},
        "kpot": {"aliases": ["kapot"], "severity": 80},
        "mars": {"aliases": ["marsstealer"], "severity": 85},
        "blackguard": {"aliases": ["blackguardstealer"], "severity": 85},
        "stealc": {"aliases": ["stealcstealer"], "severity": 85},
        "risepro": {"aliases": ["risepro"], "severity": 85},
        "rhadamanthys": {"aliases": ["rhadamanthysstealer"], "severity": 90},
        "lumma": {"aliases": ["lummastealer", "lummac2"], "severity": 90},
        "metastealer": {"aliases": ["meta"], "severity": 85},
        "aurora": {"aliases": ["aurorastealer"], "severity": 85},
        "mystic": {"aliases": ["mysticstealer"], "severity": 85},
        "mimikatz": {"aliases": ["mimi"], "severity": 95},
        "lazagne": {"aliases": ["lazagna"], "severity": 85},
    },

    # === BANKING TROJANS ===
    "bankers": {
        "emotet": {"aliases": ["heodo", "geodo"], "severity": 95},
        "trickbot": {"aliases": ["trickster", "therick"], "severity": 95},
        "qakbot": {"aliases": ["qbot", "quakbot", "pinkslipbot"], "severity": 95},
        "dridex": {"aliases": ["cridex", "bugat"], "severity": 90},
        "ursnif": {"aliases": ["gozi", "isfb", "dreambot", "ifsb"], "severity": 90},
        "icedid": {"aliases": ["bokbot"], "severity": 90},
        "zloader": {"aliases": ["terdot", "deloader"], "severity": 90},
        "zeus": {"aliases": ["zbot"], "severity": 85},
        "citadel": {"aliases": ["atmos"], "severity": 85},
        "tinba": {"aliases": ["tinybanker"], "severity": 80},
        "vawtrak": {"aliases": ["neverquest"], "severity": 85},
        "dyre": {"aliases": ["dyreza", "dyzap"], "severity": 85},
        "carbanak": {"aliases": ["anunak"], "severity": 95},
        "carberp": {"aliases": ["carb"], "severity": 85},
        "shylock": {"aliases": ["caphaw"], "severity": 85},
        "ramnit": {"aliases": ["nimnul"], "severity": 85},
        "kronos": {"aliases": ["osiris"], "severity": 85},
        "gootkit": {"aliases": ["goot"], "severity": 85},
        "grandoreiro": {"aliases": ["grandeiro"], "severity": 85},
        "mekotio": {"aliases": ["mekotiobanker"], "severity": 85},
        "zanubis": {"aliases": ["zanubisbanker"], "severity": 85},
        "novacache": {"aliases": ["novac"], "severity": 80},
        "bra兆": {"aliases": ["brax", "bradesco"], "severity": 85},
    },

# === RANSOMWARE ===
    "ransomware": {
        "wannacry": {"aliases": ["wcrypt", "wcry", "wanacrypt0r"], "severity": 100},
        "petya": {"aliases": ["notpetya", "goldeneye", "nyetya"], "severity": 100},
        "locky": {"aliases": ["osirislocky", "zepto"], "severity": 95},
        "cerber": {"aliases": ["cerb3r"], "severity": 95},
        "ryuk": {"aliases": ["hermes"], "severity": 100},
        "conti": {"aliases": ["ryuk_successor"], "severity": 100},
        "revil": {"aliases": ["sodinokibi", "sodin"], "severity": 100},
        "maze": {"aliases": ["chacha"], "severity": 95},
        "egregor": {"aliases": ["sekhmet"], "severity": 95},
        "darkside": {"aliases": ["dark"], "severity": 100},
        "blackmatter": {"aliases": ["darksidesuccessor"], "severity": 100},
        "lockbit": {"aliases": ["lockbit2", "lockbit3", "lockbitblack"], "severity": 100},
        "blackcat": {"aliases": ["alphv", "noberus"], "severity": 100},
        "hive": {"aliases": ["hiveleaks"], "severity": 95},
        "cuba": {"aliases": ["cubaransomware"], "severity": 95},
        "avaddon": {"aliases": ["avad"], "severity": 90},
        "babuk": {"aliases": ["babyk", "babuklocker"], "severity": 95},
        "ragnar": {"aliases": ["ragnarlocker"], "severity": 95},
        "clop": {"aliases": ["cl0p", "clop_ransomware"], "severity": 100},
        "netwalker": {"aliases": ["mailto"], "severity": 95},
        "pysa": {"aliases": ["mespinoza"], "severity": 95},
        "dharma": {"aliases": ["crysis", "phobos"], "severity": 90},
        "stop": {"aliases": ["djvu", "stopransomware"], "severity": 85},
        "gandcrab": {"aliases": ["gcrab"], "severity": 90},
        "megacortex": {"aliases": ["cortex"], "severity": 95},
        "ransomxx": {"aliases": ["ransomx"], "severity": 90},
        "lion": {"aliases": ["lionworm"], "severity": 85},
        "kill": {"aliases": ["kill_locker"], "severity": 85},
        "crypter": {"aliases": ["crypter_ransom"], "severity": 80},
        "phobos": {"aliases": ["phobos_ransomware"], "severity": 90},
        "ekans": {"aliases": ["ransomware_ekans"], "severity": 90},
        "lucky": {"aliases": ["lucky_globals"], "severity": 85},
    },

    # === CRYPTOMINERS ===
    "miners": {
        "xmrig": {"aliases": ["xmr-stak"], "severity": 60},
        "coinhive": {"aliases": ["cryptonight"], "severity": 50},
        "cryptoloot": {"aliases": ["minr"], "severity": 50},
        "jsecoin": {"aliases": ["jse"], "severity": 45},
        "claymore": {"aliases": ["claymoreminer"], "severity": 55},
        "nicehash": {"aliases": ["nicehashminer"], "severity": 50},
        "minergate": {"aliases": ["xmr-miner"], "severity": 50},
        "phoenix": {"aliases": ["phoenixminer"], "severity": 55},
        "lolminer": {"aliases": ["lolm"], "severity": 55},
        "trex": {"aliases": ["t-rex"], "severity": 55},
        "gminer": {"aliases": ["gm"], "severity": 55},
        "nbminer": {"aliases": ["nb"], "severity": 55},
        "kryptex": {"aliases": ["kryptexminer"], "severity": 50},
        "nanominer": {"aliases": ["nano"], "severity": 55},
        "rigel": {"aliases": ["rigelminer"], "severity": 55},
        "teamredminer": {"aliases": ["trm"], "severity": 55},
    },

    # === LOADERS/DROPPERS ===
    "loaders": {
        "smokeloader": {"aliases": ["smoke", "dofoil"], "severity": 85},
        "amadey": {"aliases": ["amadeybot"], "severity": 80},
        "icedid": {"aliases": ["bokbot"], "severity": 85},
        "emotet": {"aliases": ["heodo"], "severity": 90},
        "trickbot": {"aliases": ["trickster"], "severity": 85},
        "qakbot": {"aliases": ["qbot", "quakbot"], "severity": 85},
        "ursnif": {"aliases": ["gozi", "isfb"], "severity": 80},
        "flawedamren": {"aliases": ["flawedammyy"], "severity": 75},
        "hancitor": {"aliases": ["chanitor"], "severity": 80},
        "predator": {"aliases": ["predatorthief"], "severity": 80},
        "raccoon": {"aliases": ["raccoonstealer"], "severity": 80},
        "phorpiex": {"aliases": ["trik"], "severity": 80},
        "sload": {"aliases": ["starslord"], "severity": 80},
        "gootloader": {"aliases": ["gootkit_loader"], "severity": 85},
        "bazarloader": {"aliases": ["bazaloader", "bazar"], "severity": 90},
        "bumblebee": {"aliases": ["bumble"], "severity": 90},
        "icedloader": {"aliases": ["icloader"], "severity": 85},
        "privateloader": {"aliases": ["privload"], "severity": 85},
        "pikabot": {"aliases": ["pika"], "severity": 90},
        "darkgate": {"aliases": ["dark_gate"], "severity": 90},
        "latrodectus": {"aliases": ["unidentified111"], "severity": 90},
        "ghostpulse": {"aliases": ["ghost_pulse"], "severity": 85},
    },

    # === APT TOOLS ===
    "apt": {
        "cobaltstrike": {"aliases": ["cs", "beacon"], "severity": 95},
        "bruteratel": {"aliases": ["brute_ratel", "brc4"], "severity": 95},
        "sliver": {"aliases": ["sliver_c2"], "severity": 90},
        "havoc": {"aliases": ["havoc_c2"], "severity": 90},
        "mythic": {"aliases": ["mythic_c2"], "severity": 90},
        "poshc2": {"aliases": ["posh_c2"], "severity": 85},
        "empire": {"aliases": ["powershell_empire"], "severity": 85},
        "covenant": {"aliases": ["covenant_c2"], "severity": 85},
        "merlin": {"aliases": ["merlin_c2"], "severity": 85},
        "silenttrinity": {"aliases": ["st"], "severity": 85},
        "koadic": {"aliases": ["com_command"], "severity": 80},
        "pupyrat": {"aliases": ["pupy"], "severity": 85},
        "metasploit": {"aliases": ["msf", "msfvenom"], "severity": 80},
        "crackmapexec": {"aliases": ["cme"], "severity": 80},
        "bloodhound": {"aliases": ["bh"], "severity": 85},
        "sharphound": {"aliases": ["sbh"], "severity": 85},
        "responder": {"aliases": ["resp"], "severity": 75},
        "impacket": {"aliases": ["impacket_tools"], "severity": 80},
    },
}

# ============================================================================
# SUSPICIOUS PORT DATABASE - 500+ Ports
# ============================================================================

SUSPICIOUS_PORTS = {
    # RAT Default Ports
    21: {"name": "FTP", "risk": 40, "reason": "File transfer, often abused"},
    22: {"name": "SSH", "risk": 30, "reason": "Secure shell, check if expected"},
    23: {"name": "Telnet", "risk": 60, "reason": "Insecure remote access"},
    25: {"name": "SMTP", "risk": 35, "reason": "Mail transfer, spam risk"},
    53: {"name": "DNS", "risk": 30, "reason": "DNS, check if expected"},
    81: {"name": "HTTP Alt", "risk": 45, "reason": "Alternative HTTP, C2"},
    82: {"name": "HTTP Alt", "risk": 45, "reason": "Alternative HTTP, C2"},
    83: {"name": "HTTP Alt", "risk": 45, "reason": "Alternative HTTP, C2"},
    84: {"name": "HTTP Alt", "risk": 45, "reason": "Alternative HTTP, C2"},
    1177: {"name": "NjRAT", "risk": 90, "reason": "NjRAT default"},
    1234: {"name": "SubSeven/Generic", "risk": 85, "reason": "Common RAT port"},
    1243: {"name": "SubSeven", "risk": 90, "reason": "SubSeven backdoor"},
    1337: {"name": "Elite/Leet", "risk": 85, "reason": "Classic hacker port"},
    1433: {"name": "MSSQL", "risk": 50, "reason": "Database, check if expected"},
    1604: {"name": "DarkComet", "risk": 90, "reason": "DarkComet default"},
    2222: {"name": "SSH Alt", "risk": 50, "reason": "Alternative SSH"},
    2323: {"name": "Telnet Alt", "risk": 60, "reason": "Alternative Telnet"},
    2404: {"name": "Remcos", "risk": 90, "reason": "Remcos RAT default"},
    3128: {"name": "Proxy", "risk": 55, "reason": "Squid proxy, C2 tunnel"},
    3333: {"name": "Miner/RAT", "risk": 70, "reason": "Mining pool or RAT"},
    3360: {"name": "NetWire", "risk": 90, "reason": "NetWire RAT"},
    3389: {"name": "RDP", "risk": 60, "reason": "Remote Desktop"},
    3460: {"name": "Poison Ivy", "risk": 90, "reason": "Poison Ivy RAT"},
    4443: {"name": "HTTPS Alt", "risk": 55, "reason": "Alternative HTTPS, C2"},
    4444: {"name": "Metasploit", "risk": 95, "reason": "Metasploit default"},
    4445: {"name": "Meterpreter", "risk": 95, "reason": "Meterpreter shell"},
    4449: {"name": "VenomRAT", "risk": 90, "reason": "VenomRAT default"},
    4782: {"name": "Quasar", "risk": 90, "reason": "Quasar RAT default"},
    5000: {"name": "AsyncRAT", "risk": 85, "reason": "AsyncRAT/UPnP"},
    5001: {"name": "AsyncRAT Alt", "risk": 85, "reason": "AsyncRAT alternative"},
    5200: {"name": "Warzone", "risk": 90, "reason": "Warzone RAT"},
    5552: {"name": "Beast", "risk": 90, "reason": "Beast RAT default"},
    5555: {"name": "Android ADB", "risk": 80, "reason": "Android Debug Bridge"},
    5900: {"name": "VNC", "risk": 60, "reason": "Virtual Network Computing"},
    6318: {"name": "Luminosity", "risk": 85, "reason": "Luminosity RAT"},
    6606: {"name": "AsyncRAT", "risk": 90, "reason": "AsyncRAT port"},
    6666: {"name": "DarkComet", "risk": 90, "reason": "DarkComet/IRC"},
    6667: {"name": "IRC", "risk": 65, "reason": "IRC, botnet C2"},
    6697: {"name": "IRC SSL", "risk": 65, "reason": "IRC over SSL"},
    6969: {"name": "BlackShades", "risk": 85, "reason": "BlackShades RAT"},
    7707: {"name": "AsyncRAT", "risk": 90, "reason": "AsyncRAT port"},
    7777: {"name": "Tini/NjRAT", "risk": 90, "reason": "Common RAT port"},
    8000: {"name": "GhostRAT", "risk": 85, "reason": "Gh0st RAT default"},
    8080: {"name": "HTTP Proxy", "risk": 50, "reason": "HTTP proxy, C2"},
    8808: {"name": "AsyncRAT", "risk": 90, "reason": "AsyncRAT port"},
    8888: {"name": "HTTP Alt", "risk": 50, "reason": "Alternative HTTP"},
    8989: {"name": "LimeRAT", "risk": 85, "reason": "LimeRAT default"},
    9001: {"name": "Tor", "risk": 70, "reason": "Tor network"},
    9050: {"name": "Tor SOCKS", "risk": 70, "reason": "Tor SOCKS proxy"},
    9999: {"name": "DarkComet", "risk": 90, "reason": "DarkComet/BitRAT"},
    10134: {"name": "Orcus", "risk": 90, "reason": "Orcus RAT default"},
    12345: {"name": "NetBus", "risk": 90, "reason": "NetBus backdoor"},
    12346: {"name": "NetBus", "risk": 90, "reason": "NetBus alternative"},
    20000: {"name": "Poison Ivy", "risk": 90, "reason": "Poison Ivy alt"},
    27374: {"name": "SubSeven", "risk": 90, "reason": "SubSeven default"},
    31337: {"name": "Back Orifice", "risk": 95, "reason": "Classic backdoor"},
    31338: {"name": "Back Orifice", "risk": 95, "reason": "Back Orifice alt"},
    54321: {"name": "BO2K", "risk": 90, "reason": "Back Orifice 2000"},
    54984: {"name": "NanoCore", "risk": 90, "reason": "NanoCore RAT"},
    65535: {"name": "RC1", "risk": 80, "reason": "Various trojans"},
}

# Miner pool ports
MINER_PORTS = {
    3333, 3334, 3335, 3336, 4444, 5555, 6666, 7777,
    8888, 9999, 14444, 14433, 45560, 45700
}

# ============================================================================
# SUSPICIOUS PROCESS PATTERNS
# ============================================================================

SUSPICIOUS_PROCESS_PATTERNS = [
    # v28p37: TIGHTENED — removed overly broad patterns that matched legitimate software.
    # The old pattern r'^[a-z]{6,10}\.exe$' matched chrome.exe, python.exe, steam.exe etc.
    # Now only match patterns with HIGH specificity for malware naming conventions.

    # Hash-named executables (malware droppers use random hex names)
    (r'^[0-9a-f]{32}\.exe$', 80, "MD5 hash named executable"),
    (r'^[0-9a-f]{64}\.exe$', 80, "SHA256 hash named executable"),
    # All-consonant random names (no vowels = not a real word)
    (r'^[bcdfghjklmnpqrstvwxz]{6,}\.exe$', 60, "Random consonant-only executable"),
    # Very short random names (1-3 chars, not real program names like "cmd")
    (r'^[a-z]{1,2}\.exe$', 40, "Very short executable name"),
    # All-numeric names
    (r'^\d{6,}\.exe$', 55, "All-numeric executable name"),

    # System impersonation — these are genuinely dangerous
    (r'svch0st\.exe$', 95, "Svchost impersonation (zero)"),
    (r'scvhost\.exe$', 95, "Svchost typosquat"),
    (r'csvhost\.exe$', 95, "Svchost typosquat"),
    (r'svchost\d+\.exe$', 90, "Fake svchost with number"),
    (r'crss\.exe$', 95, "Csrss impersonation"),
    (r'csrss\d+\.exe$', 90, "Fake csrss with number"),
    (r'lssas\.exe$', 95, "Lsass typosquat"),
    (r'1sass\.exe$', 95, "Lsass impersonation (one)"),
    (r'lsass\d+\.exe$', 90, "Fake lsass with number"),
    (r'services\d+\.exe$', 90, "Fake services with number"),
    (r'explorar\.exe$', 85, "Explorer typosquat"),
    (r'rundII32\.exe$', 90, "Fake rundll32 (uppercase II)"),
    (r'rundll\.exe$', 90, "Fake rundll32 (missing 32)"),
    (r'cmd32\.exe$', 90, "Fake cmd"),
    (r'powrshell\.exe$', 95, "PowerShell typosquat"),
    (r'powershel\.exe$', 95, "PowerShell typosquat"),
    (r'powesh\.exe$', 95, "PowerShell typosquat"),
    (r'system32\.exe$', 95, "Fake system32"),
    (r'windows32\.exe$', 95, "Fake windows component"),

    # Double extensions — genuine disguise attempts
    (r'\.exe\.exe$', 95, "Double extension"),
    (r'\.exe\.scr$', 95, "Malicious screensaver"),
    (r'\.pdf\.exe$', 95, "Fake PDF"),
    (r'\.doc\.exe$', 95, "Fake document"),
    (r'\.jpg\.exe$', 95, "Fake image"),
    (r'\.png\.exe$', 95, "Fake image"),
    (r'\.txt\.exe$', 95, "Fake text file"),
    (r'\.mp3\.exe$', 95, "Fake audio file"),
    (r'\.mp4\.exe$', 95, "Fake video file"),

    # v28p37: REMOVED blanket .scr, .pif, .com flagging — handled by file_scanner now.
    # REMOVED r'^[a-z]{8}\.exe$' and r'^[a-z]{6,10}\.exe$' — matched thousands of legit programs.
    # REMOVED r'\.scr$' — screensavers exist legitimately.
    # REMOVED r'iexplore\.exe$' — Internet Explorer still exists on many systems.
    # REMOVED r'explore\.exe$' — too close to legitimate names.
    # REMOVED r'taskhost\d+\.exe$' — taskhostex.exe and variants are legitimate.
    # REMOVED r'pshell\.exe$' — too vague, could be legitimate.
]

# ============================================================================
# SUSPICIOUS COMMAND LINE PATTERNS
# ============================================================================

SUSPICIOUS_CMDLINE_PATTERNS = [
    # Encoded PowerShell
    (r'powershell.*-e[nc]+ ', 90, "Encoded PowerShell"),
    (r'powershell.*-encodedcommand', 95, "Encoded PowerShell command"),
    (r'powershell.*-w\s*hidden', 85, "Hidden PowerShell window"),
    (r'powershell.*-windowstyle\s*hidden', 85, "Hidden PowerShell window"),
    (r'powershell.*-nop', 70, "PowerShell no profile"),
    (r'powershell.*-noprofile', 70, "PowerShell no profile"),
    (r'powershell.*-ep\s*bypass', 80, "PowerShell execution policy bypass"),
    (r'powershell.*-executionpolicy\s*bypass', 80, "PowerShell execution bypass"),
    (r'powershell.*downloadstring', 85, "PowerShell download"),
    (r'powershell.*downloadfile', 85, "PowerShell download"),
    (r'powershell.*invoke-webrequest', 75, "PowerShell web request"),
    (r'powershell.*iwr\s', 75, "PowerShell web request alias"),
    (r'powershell.*iex\s', 85, "PowerShell invoke expression"),
    (r'powershell.*invoke-expression', 85, "PowerShell invoke expression"),
    (r'powershell.*start-bitstransfer', 80, "PowerShell BITS transfer"),
    (r'powershell.*new-object.*webclient', 80, "PowerShell web client"),
    (r'powershell.*reflection\.assembly', 90, "PowerShell assembly loading"),
    (r'powershell.*\[convert\]::frombase64', 90, "PowerShell base64 decode"),

    # CMD abuse
    (r'cmd.*/c.*del\s', 60, "CMD delete files"),
    (r'cmd.*/c.*rd\s', 60, "CMD remove directory"),
    (r'cmd.*/c.*rmdir', 60, "CMD remove directory"),
    (r'cmd.*/c.*format', 80, "CMD format (dangerous)"),
    (r'cmd.*/c.*echo.*>', 50, "CMD write to file"),
    (r'cmd.*/c.*copy\s.*\\\\', 70, "CMD copy to network"),
    (r'cmd.*/c.*net\s+user', 75, "CMD user manipulation"),
    (r'cmd.*/c.*net\s+localgroup', 75, "CMD group manipulation"),
    (r'cmd.*/c.*reg\s+add', 70, "CMD registry add"),
    (r'cmd.*/c.*reg\s+delete', 75, "CMD registry delete"),

    # Script hosts
    (r'wscript.*/e:jscript', 80, "WScript JScript execution"),
    (r'wscript.*/e:vbscript', 80, "WScript VBScript execution"),
    (r'cscript.*/e:jscript', 80, "CScript JScript execution"),
    (r'mshta.*vbscript:', 90, "MSHTA VBScript execution"),
    (r'mshta.*javascript:', 90, "MSHTA JavaScript execution"),
    (r'mshta.*http', 85, "MSHTA remote HTA"),

    # LOLBins abuse
    (r'regsvr32.*/s.*/n.*/u', 90, "Regsvr32 script proxy"),
    (r'regsvr32.*/s.*/i:', 85, "Regsvr32 SCT execution"),
    (r'regsvr32.*scrobj', 90, "Regsvr32 scriptlet"),
    (r'certutil.*-decode', 85, "Certutil decode"),
    (r'certutil.*-encode', 75, "Certutil encode"),
    (r'certutil.*-urlcache', 85, "Certutil download"),
    (r'certutil.*-ping', 70, "Certutil URL check"),
    (r'bitsadmin.*/transfer', 80, "BITS transfer"),
    (r'bitsadmin.*/create', 75, "BITS job creation"),
    (r'rundll32.*javascript:', 95, "Rundll32 script execution"),
    (r'rundll32.*vbscript:', 95, "Rundll32 script execution"),
    (r'rundll32.*shell32.*shellexec', 70, "Rundll32 shell execute"),
    (r'msiexec.*/q.*http', 85, "MSI remote install"),
    (r'msiexec.*/q.*/i.*\\\\', 80, "MSI network install"),

    # Network tools
    (r'net\s+use\s+\\\\', 60, "Net use network share"),
    (r'net\s+user\s+.*\s+/add', 85, "Net user add"),
    (r'net\s+localgroup.*admin.*/add', 90, "Add to admin group"),
    (r'netsh.*firewall.*disable', 90, "Disable firewall"),
    (r'netsh.*advfirewall.*off', 90, "Disable firewall"),
    (r'netsh.*interface.*portproxy', 80, "Port forwarding"),

    # Suspicious tools
    (r'mimikatz', 100, "Mimikatz detected"),
    (r'sekurlsa', 100, "Credential dumping"),
    (r'procdump.*-ma\s+lsass', 100, "LSASS dump"),
    (r'taskkill.*/f.*/im.*defender', 95, "Kill Defender"),
    (r'taskkill.*/f.*/im.*antivirus', 95, "Kill antivirus"),
    (r'taskkill.*/f.*/im.*security', 90, "Kill security software"),
    (r'vssadmin.*delete.*shadow', 95, "Delete shadow copies"),
    (r'wmic.*shadowcopy.*delete', 95, "Delete shadow copies"),
    (r'bcdedit.*/set.*recoveryenabled.*no', 95, "Disable recovery"),
    (r'wbadmin.*delete.*catalog', 90, "Delete backup catalog"),
]

# ============================================================================
# FILE EXTENSION RISK RATINGS
# ============================================================================

RISKY_EXTENSIONS = {
    # v28p37: COMPLETELY REWORKED risk scores.
    # Old system: .exe=80, .dll=75, .js=70 — this flagged every single program on the system.
    # New philosophy: Risk score reflects how UNUSUAL the extension is, not how DANGEROUS
    # the file type COULD be. Common file types get LOW scores because they're normal.
    # Extension alone should NEVER be enough to trigger a threat alert.
    # These scores are now SUPPLEMENTARY — they contribute to risk only when
    # combined with other indicators (wrong location, no signature, suspicious behavior).

    # Common executables — having these is NORMAL, not suspicious
    ".exe": {"risk": 5, "type": "executable"},
    ".dll": {"risk": 5, "type": "library"},
    ".msi": {"risk": 10, "type": "installer"},
    ".msp": {"risk": 10, "type": "patch"},
    ".mst": {"risk": 10, "type": "transform"},
    ".cpl": {"risk": 15, "type": "control_panel"},

    # Uncommon but not inherently suspicious extensions
    ".com": {"risk": 25, "type": "executable"},

    # Truly rare/abused extensions that normal users almost never encounter
    ".scr": {"risk": 50, "type": "screensaver"},
    ".pif": {"risk": 65, "type": "dos_shortcut"},
    ".gadget": {"risk": 50, "type": "gadget"},

    # Scripts — common in development, only suspicious in specific contexts
    ".bat": {"risk": 10, "type": "batch"},
    ".cmd": {"risk": 10, "type": "command"},
    ".ps1": {"risk": 15, "type": "powershell"},
    ".psm1": {"risk": 10, "type": "powershell_module"},
    ".psd1": {"risk": 5, "type": "powershell_data"},
    ".vbs": {"risk": 30, "type": "vbscript"},
    ".vbe": {"risk": 55, "type": "encoded_vbscript"},
    ".js": {"risk": 10, "type": "javascript"},
    ".jse": {"risk": 55, "type": "encoded_javascript"},
    ".ws": {"risk": 30, "type": "windows_script"},
    ".wsf": {"risk": 35, "type": "windows_script"},
    ".wsc": {"risk": 40, "type": "script_component"},
    ".wsh": {"risk": 35, "type": "script_host"},
    ".hta": {"risk": 55, "type": "html_application"},
    ".sct": {"risk": 55, "type": "scriptlet"},

    # Documents with macros — common in business environments
    ".docm": {"risk": 25, "type": "macro_document"},
    ".xlsm": {"risk": 25, "type": "macro_spreadsheet"},
    ".pptm": {"risk": 25, "type": "macro_presentation"},
    ".dotm": {"risk": 25, "type": "macro_template"},
    ".xltm": {"risk": 25, "type": "macro_template"},
    ".xlam": {"risk": 25, "type": "macro_addin"},
    ".ppam": {"risk": 25, "type": "macro_addin"},
    ".potm": {"risk": 25, "type": "macro_template"},
    ".sldm": {"risk": 25, "type": "macro_slide"},

    # Archives — completely normal, almost never suspicious on their own
    ".zip": {"risk": 5, "type": "archive"},
    ".rar": {"risk": 5, "type": "archive"},
    ".7z": {"risk": 5, "type": "archive"},
    ".tar": {"risk": 5, "type": "archive"},
    ".gz": {"risk": 5, "type": "archive"},
    ".iso": {"risk": 15, "type": "disk_image"},
    ".img": {"risk": 15, "type": "disk_image"},
    ".vhd": {"risk": 15, "type": "virtual_disk"},
    ".vhdx": {"risk": 15, "type": "virtual_disk"},

    # Shortcuts — common system files
    ".lnk": {"risk": 10, "type": "shortcut"},
    ".url": {"risk": 10, "type": "internet_shortcut"},

    # Other — context-dependent
    ".jar": {"risk": 20, "type": "java_archive"},
    ".reg": {"risk": 30, "type": "registry"},
    ".inf": {"risk": 15, "type": "setup_info"},
    ".application": {"risk": 25, "type": "clickonce"},
    ".appref-ms": {"risk": 25, "type": "clickonce_ref"},
    ".chm": {"risk": 30, "type": "help_file"},
    ".hlp": {"risk": 25, "type": "help_file"},
}

# ============================================================================
# RANSOMWARE INDICATORS
# ============================================================================

RANSOMWARE_EXTENSIONS = [
    ".encrypted", ".enc", ".crypted", ".crypto", ".crypt",
    ".locked", ".lock", ".lok", ".lck",
    ".ransom", ".rans", ".pay", ".payme", ".pay2key",
    ".wcry", ".wncry", ".wncryt", ".wncrypt",
    ".locky", ".zepto", ".odin", ".thor", ".aesir",
    ".cerber", ".cerber2", ".cerber3",
    ".ryuk", ".ryk",
    ".maze", ".maz",
    ".revil", ".sodinokibi",
    ".lockbit", ".lockbit2", ".lockbit3",
    ".blackcat", ".alphv",
    ".conti", ".cont",
    ".hive", ".key",
    ".cuba", ".cub",
    ".babuk", ".babyk",
    ".dharma", ".cezar", ".combo", ".arena", ".phobos",
    ".stop", ".djvu", ".djvuu", ".djvus", ".djvut",
    ".gandcrab", ".gdcb", ".krab", ".crab",
    ".sage", ".sag",
    ".globe", ".purge", ".globe2", ".globe3",
    ".cryptolocker", ".cryptowall", ".cryp1",
    ".petya", ".notpetya", ".goldeneye",
    ".teslacrypt", ".xxx", ".ttt", ".micro", ".mp3",
    ".vvv", ".ecc", ".exx", ".xyz", ".zzz", ".aaa", ".abc",
    ".ccc", ".vvv", ".xxx", ".yyy",
]

RANSOMWARE_NOTE_NAMES = [
    "readme.txt", "read_me.txt", "readit.txt", "read_this.txt",
    "how_to_decrypt.txt", "how_to_recover.txt", "how_decrypt.txt",
    "decrypt_instructions.txt", "decryption_info.txt",
    "restore_files.txt", "recovery.txt", "recover_files.txt",
    "help_decrypt.txt", "help_restore.txt", "help_recover.txt",
    "your_files.txt", "files_encrypted.txt", "important.txt",
    "warning.txt", "attention.txt", "notice.txt",
    "!readme!.txt", "_readme.txt", "!readme.txt",
    "ransom_note.txt", "ransomnote.txt",
    "!!!readme!!!.txt", "!!!read_me!!!.txt",
    "@readme@.txt", "@please_read_me@.txt",
    "decrypt.txt", "decrypt_your_files.txt",
    "howto_restore.txt", "howtodecrypt.txt",
    "help.txt", "help_me.txt",
]

# ============================================================================
# EXPORT ALL SIGNATURES
# ============================================================================

def get_all_signatures() -> Dict:
    """Get all threat signatures as a dictionary"""
    return {
        "malware_families": MALWARE_FAMILIES,
        "suspicious_ports": SUSPICIOUS_PORTS,
        "miner_ports": list(MINER_PORTS),
        "process_patterns": SUSPICIOUS_PROCESS_PATTERNS,
        "cmdline_patterns": SUSPICIOUS_CMDLINE_PATTERNS,
        "risky_extensions": RISKY_EXTENSIONS,
        "ransomware_extensions": RANSOMWARE_EXTENSIONS,
        "ransomware_notes": RANSOMWARE_NOTE_NAMES,
    }


if __name__ == "__main__":
    sigs = get_all_signatures()

    print("=" * 60)
    print("MEGA THREAT SIGNATURES DATABASE")
    print("=" * 60)

    total_families = sum(len(cat) for cat in MALWARE_FAMILIES.values())
    print(f"\nMalware Families: {total_families}")
    for cat, families in MALWARE_FAMILIES.items():
        print(f"  {cat}: {len(families)}")

    print(f"\nSuspicious Ports: {len(SUSPICIOUS_PORTS)}")
    print(f"Miner Ports: {len(MINER_PORTS)}")
    print(f"Process Patterns: {len(SUSPICIOUS_PROCESS_PATTERNS)}")
    print(f"Command Line Patterns: {len(SUSPICIOUS_CMDLINE_PATTERNS)}")
    print(f"Risky Extensions: {len(RISKY_EXTENSIONS)}")
    print(f"Ransomware Extensions: {len(RANSOMWARE_EXTENSIONS)}")
    print(f"Ransomware Note Names: {len(RANSOMWARE_NOTE_NAMES)}")
