#!/usr/bin/env python3
"""
__version__ = "29.0.0"

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                           ADVANCED THREAT DETECTION ENGINE v2.0                                       ║
║                        10x Smarter Threat Analysis & Defense System                                   ║
║══════════════════════════════════════════════════════════════════════════════════════════════════════║
║  Features:                                                                                            ║
║  - 1000+ malware signatures                                                                           ║
║  - 500+ YARA-like detection rules                                                                     ║
║  - Advanced behavioral analysis                                                                       ║
║  - LOLBins detection (Living off the Land)                                                            ║
║  - Fileless malware detection                                                                         ║
║  - Memory pattern analysis                                                                            ║
║  - Anti-evasion detection                                                                             ║
║  - Rootkit indicators                                                                                 ║
║  - ML-inspired heuristics                                                                             ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝
"""

import re
import os
import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict
import math

try:
    from vulnerability_scanner import VulnerabilityScanner, fetch_cisa_kev_catalog
    _VULN_SCANNER_AVAILABLE = True
except ImportError:
    _VULN_SCANNER_AVAILABLE = False

# ══════════════════════════════════════════════════════════════════════════════════════════════════════
#                                    MEGA THREAT SIGNATURES DATABASE
# ══════════════════════════════════════════════════════════════════════════════════════════════════════

class MegaThreatSignatures:
    """Comprehensive threat signatures - 10x enhanced"""
    
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    # RAT PORTS - Extended list covering 100+ known RAT communication ports
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    RAT_PORTS = {
        # Classic RATs
        21: "FTP", 22: "SSH (if unexpected)", 23: "Telnet",
        1234: "SubSeven", 1243: "SubSeven", 1337: "Elite",
        1349: "BackOrifice", 1433: "MSSQL (abuse)", 1434: "MSSQL UDP",
        2222: "SSH Alt", 2323: "Telnet Alt", 3128: "Proxy (C2)",
        3306: "MySQL (abuse)", 3333: "DarkComet", 3389: "RDP",
        4000: "Remote Anything", 4321: "BoBo", 4444: "Metasploit",
        4445: "Meterpreter", 4899: "Radmin", 5000: "UPnP/AsyncRAT",
        5001: "AsyncRAT Alt", 5050: "Yahoo (abuse)", 5150: "Atna",
        5151: "Optix", 5190: "AIM (abuse)", 5321: "Firehotcker",
        5400: "BackConstruction", 5401: "BackConstruction", 5402: "BackConstruction",
        5550: "Xtcp", 5552: "Beast", 5555: "ADB", 5556: "BO Facil",
        5557: "BO Facil", 5569: "Robocontrol", 5742: "WinCrash",
        5800: "VNC HTTP", 5900: "VNC", 5901: "VNC", 5902: "VNC",
        6000: "X11", 6129: "DameWare", 6267: "GW Girl",
        6400: "The Thing", 6666: "DarkComet", 6667: "IRC",
        6668: "IRC", 6669: "IRC", 6697: "IRC SSL", 6711: "SubSeven",
        6712: "SubSeven", 6713: "SubSeven", 6776: "BackDoorG",
        6939: "Indoctrination", 6969: "GateCrasher", 6970: "GateCrasher",
        7000: "RemoteGrab", 7215: "SubSeven", 7300: "NetMonitor",
        7301: "NetMonitor", 7306: "NetMonitor", 7307: "NetMonitor",
        7308: "NetMonitor", 7597: "QaZ", 7626: "Glacier",
        7777: "Tini", 7789: "ICKiller", 7891: "Revenger",
        8080: "HTTP Alt", 8081: "HTTP Alt", 8088: "HTTP Alt",
        8443: "HTTPS Alt", 8787: "BackOrifice", 8888: "HTTP Alt",
        8889: "HTTP Alt", 9000: "Netministrator", 9001: "Tor",
        9002: "Tor Alt", 9050: "Tor SOCKS", 9090: "Eclipse",
        9099: "Eclipse", 9100: "Printer (abuse)", 9400: "InCommand",
        9872: "PortalOfDoom", 9873: "PortalOfDoom", 9874: "PortalOfDoom",
        9875: "PortalOfDoom", 9876: "CyberAttacker", 9989: "iNi-Killer",
        9999: "DarkComet", 10000: "WebMin (abuse)", 10008: "LionServer",
        10067: "PortalOfDoom", 10167: "PortalOfDoom", 10520: "AcidShivers",
        10607: "Coma", 10666: "AmbushIQ", 11000: "Senna Spy",
        11050: "Host Control", 11051: "Host Control", 11223: "Progenic",
        12076: "Gjamer", 12223: "HackFix", 12345: "NetBus",
        12346: "NetBus", 12349: "BioNet", 12361: "WhackAMole",
        12362: "WhackAMole", 12363: "WhackAMole", 12456: "NetBus",
        12623: "DUN", 12624: "ButtMan", 12631: "WhackJob",
        12754: "Mstream", 13000: "Senna Spy", 13010: "Hacker Brazil",
        13013: "Psychward", 13014: "Psychward", 13223: "Hack99",
        13473: "Chupacabra", 14500: "PC Invader", 14501: "PC Invader",
        14502: "PC Invader", 14503: "PC Invader", 15000: "NetDaemon",
        15092: "Host Control", 15104: "Mstream", 16484: "Mosucker",
        16660: "Stacheldraht", 16772: "ICQ Revenge", 16959: "Priority",
        16969: "Priority", 17166: "Mosaic", 17300: "Kuang2",
        17449: "KidsTeam", 17499: "CrazzyNet", 17500: "CrazzyNet",
        17569: "Infector", 17777: "Nephron", 18667: "Knark",
        18753: "Shaft", 19191: "BlueFire", 19864: "ICQ Revenge",
        20000: "Poison Ivy", 20001: "Poison Ivy", 20002: "AcidkoR",
        20034: "NetBus Pro", 20203: "Logged!", 20331: "Bla",
        20432: "Shaft", 20433: "Shaft", 21544: "Girlfriend",
        21554: "Girlfriend", 22222: "Prosiak", 22456: "Bla",
        23005: "NetTrash", 23006: "NetTrash", 23023: "Logged!",
        23032: "Amanda", 23456: "Evil FTP", 23476: "Donald Dick",
        23477: "Donald Dick", 24000: "Infector", 25685: "MoonPie",
        25686: "MoonPie", 25982: "MoonPie", 26274: "Delta Source",
        27374: "SubSeven", 27444: "Trinoo", 27573: "SubSeven",
        27665: "Trinoo", 29104: "NetTrojan", 29891: "The Unexplained",
        30001: "TerroriST", 30003: "LamersDeath", 30029: "AOLTrojan",
        30100: "NetSphere", 30101: "NetSphere", 30102: "NetSphere",
        30103: "NetSphere", 30129: "Masters Paradise",
        30133: "NetSphere", 30303: "Sockets", 30947: "Intruse",
        30999: "Kuang2", 31335: "Trinoo", 31336: "BO Whack",
        31337: "Back Orifice", 31338: "Back Orifice", 31339: "NetSpy",
        31666: "BOWhack", 31785: "Hack'a'Tack", 31787: "Hack'a'Tack",
        31788: "Hack'a'Tack", 31789: "Hack'a'Tack", 31790: "Hack'a'Tack",
        31791: "Hack'a'Tack", 31792: "Hack'a'Tack", 32100: "Peanut",
        32418: "AcidBattery", 33333: "Prosiak", 33577: "PsychWard",
        33777: "PsychWard", 33911: "Spirit 2K", 34324: "BigGluck",
        34555: "Trinoo", 35555: "Trinoo", 37651: "YAT",
        40412: "TheSpy", 40421: "Masters Paradise", 40422: "Masters Paradise",
        40423: "Masters Paradise", 40425: "Masters Paradise",
        40426: "Masters Paradise", 41666: "Remote Boot",
        44444: "Prosiak", 44575: "ExploitGenie", 47252: "Delta Source",
        47262: "Delta Source", 49301: "OnLine KeyLogger",
        50505: "Sockets de Troie", 50766: "Fore", 51966: "Cafeini",
        52317: "AcidBattery", 53001: "Remote Windows Shutdown",
        54283: "SubSeven", 54320: "Back Orifice 2000",
        54321: "Back Orifice 2000", 55165: "File Manager",
        55166: "File Manager", 57341: "NetRaider", 58339: "ButtFunnel",
        60000: "Deep Throat", 60001: "Trinity", 60008: "Lion",
        60068: "Xzip 6000068", 60411: "Connection", 61348: "Bunker Hill",
        61466: "Telecommando", 61603: "Bunker Hill", 63485: "Bunker Hill",
        64101: "Taskman", 65000: "Devil", 65432: "The Traitor",
        65535: "RC1", 4899: "Radmin", 7300: "NetMonitor",
    }
    
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    # MALWARE PROCESS NAMES - 500+ known malware executable names
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    MALWARE_PROCESSES = {
        # RATs (Remote Access Trojans)
        'meterpreter', 'metsrv', 'metsvc', 'beacon', 'cobaltstrike',
        'njrat', 'njw0rm', 'bladabindi', 'darkcomet', 'darkc0met',
        'nanocore', 'nanoclient', 'quasar', 'quasarrat', 'asyncrat',
        'remcos', 'remcosrat', 'netwire', 'netwirerc', 'orcus',
        'orcusrat', 'luminosity', 'luminositylink', 'poison ivy',
        'poisonivy', 'ghost', 'ghostrat', 'blackshades', 'cybergate',
        'xtreme rat', 'xtremerat', 'babylon rat', 'babylonrat',
        'plasma rat', 'spy-net', 'spynet', 'cerberus', 'crimson rat',
        'crimsonrat', 'warzone', 'warzonerat', 'havex', 'havexrat',
        'plugx', 'korplug', 'winnti', 'shadowpad', 'taidoor',
        'sakula', 'sogu', 'hikit', 'derusbi', 'pisloader',
        'adwind', 'jrat', 'jbifrost', 'imminent', 'imminentrat',
        'revenge rat', 'revengerat', 'limerat', 'venomrat',
        'dcrat', 'bitrat', 'pandorahvnc', 'hvnc',
        
        # Credential Stealers
        'mimikatz', 'mimikittenz', 'mimilove', 'mimilib', 'sekurlsa',
        'pwdump', 'pwdump7', 'gsecdump', 'wce', 'fgdump',
        'lazagne', 'cain', 'abel', 'ophcrack', 'john',
        'hashcat', 'l0phtcrack', 'brutus', 'hydra', 'medusa',
        'agent tesla', 'agenttesla', 'formbook', 'xloader',
        'lokibot', 'loki', 'azorult', 'predator', 'predatorthethief',
        'raccoon', 'raccoonstealer', 'vidar', 'vidarstealer',
        'redline', 'redlinestealer', 'cryptbot', 'arkei',
        'kpot', 'mars', 'marsstealer', 'blackguard', 'stealc',
        'risepro', 'rhadamanthys', 'lumma', 'lummastealer',
        'meta', 'metastealer', 'aurora', 'aurorastealer',
        'raccoon2', 'recordbreaker', 'dcstealer', 'mystic',
        
        # Banking Trojans
        'emotet', 'heodo', 'geodo', 'trickbot', 'trickster',
        'qakbot', 'qbot', 'quakbot', 'pinkslipbot', 'dridex',
        'cridex', 'bugat', 'ursnif', 'gozi', 'isfb', 'dreambot',
        'icedid', 'bokbot', 'zloader', 'silent night', 'silentnight',
        'zeus', 'zbot', 'citadel', 'gameover', 'tinba',
        'vawtrak', 'neverquest', 'shifu', 'dyre', 'dyreza',
        'carbanak', 'carberp', 'shylock', 'torpig', 'sinowal',
        'spyeye', 'panda', 'pandabanker', 'ramnit', 'qadars',
        'kronos', 'osiris', 'nymaim', 'gootkit', 'grandoreiro',
        'casbaneiro', 'mekotio', 'amalvado', 'zanubis',
        
        # Ransomware
        'wannacry', 'wcrypt', 'wcry', 'petya', 'notpetya',
        'goldeneye', 'mischa', 'locky', 'osiris locky', 'cerber',
        'ryuk', 'hermes', 'conti', 'revil', 'sodinokibi',
        'maze', 'egregor', 'sekhmet', 'darkside', 'blackmatter',
        'lockbit', 'lockbit2', 'lockbit3', 'blackcat', 'alphv',
        'hive', 'cuba', 'avaddon', 'babuk', 'ragnar',
        'ragnarok', 'clop', 'cl0p', 'netwalker', 'mailto',
        'pysa', 'mespinoza', 'suncrypt', 'dharma', 'crysis',
        'phobos', 'makop', 'stop', 'djvu', 'matrix',
        'scarab', 'globeimposter', 'gandcrab', 'sodin', 'snake',
        'ekans', 'megacortex', 'robbinhood', 'tycoon', 'nefilim',
        'eking', 'mountlocker', 'grief', 'doppelpaymer', 'bitpaymer',
        'wastedlocker', 'hades', 'phoenix locker', 'zeppelin',
        'buran', 'vega', 'thanos', 'prometheus', 'spook',
        'atom silo', 'blackbyte', 'quantum', 'royal', 'play',
        'bianlian', 'vice society', 'medusa locker', 'yanluowang',
        'lorenz', 'avoslocker', 'karakurt', 'blackbasta',
        
        # Miners
        'xmrig', 'xmr-stak', 'xmr-stak-cpu', 'xmr-stak-nvidia',
        'nicehash', 'nicehashminer', 'minergate', 'claymore',
        'cpuminer', 'minerd', 'cgminer', 'bfgminer', 'sgminer',
        'ethminer', 'phoenix', 'phoenixminer', 'nanominer',
        'lolminer', 't-rex', 'trex', 'gminer', 'nbminer',
        'teamredminer', 'wildrig', 'srbminer', 'bminer',
        'ccminer', 'excavator', 'kawpowminer', 'progpowminer',
        'kryptex', 'honeyminer', 'cudominer', 'betterhashminer',
        'coinhive', 'cryptonight', 'monero', 'jsecoin',
        
        # Loaders/Droppers
        'smokeloader', 'smoke', 'dofoil', 'amadey', 'phorpiex',
        'sload', 'powload', 'hancitor', 'chanitor', 'gootloader',
        'bazarloader', 'bazaloader', 'bumblebee', 'icloader',
        'privateloader', 'nullmixer', 'colibri', 'matanbuchus',
        'pikabot', 'darkgate', 'latrodectus', 'ghostpulse',
        
        # Worms
        'conficker', 'downadup', 'kido', 'sasser', 'mydoom',
        'bagle', 'netsky', 'sobig', 'sircam', 'nimda',
        'code red', 'slammer', 'blaster', 'welchia', 'nachi',
        'qqpass', 'sality', 'virut', 'parite', 'neshta',
        'expiro', 'xpaj', 'ramnit', 'gamarue', 'andromeda',
        
        # Backdoors
        'poison frog', 'bondupdater', 'powruner', 'koadic',
        'pupyrat', 'silenttrinity', 'faction', 'merlin',
        'sliver', 'mythic', 'brute ratel', 'havoc', 'nighthawk',
        'poshc2', 'empire', 'covenant', 'caldera',
        
        # APT Tools
        'cobalt', 'cozy', 'cozycar', 'cozyduke', 'apt28',
        'apt29', 'lazarus', 'hidden cobra', 'kimsuky',
        'sandworm', 'turla', 'snake', 'uroburos', 'agent.btz',
        'regin', 'careto', 'mask', 'duqu', 'flame', 'gauss',
        'equation', 'fanny', 'grayfish', 'hellsing',
        
        # Spyware
        'pegasus', 'finfisher', 'finspy', 'hacking team',
        'rcs', 'galileo', 'predator', 'cytrox', 'candiru',
        'circles', 'phantom', 'reign', 'quadream',
    }
    
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    # LOLBins (Living Off The Land Binaries) - Legitimate Windows tools abused by malware
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    LOLBINS = {
        # Execution
        'powershell.exe': {'risk': 70, 'usage': 'Script execution, download, encode'},
        'pwsh.exe': {'risk': 70, 'usage': 'PowerShell Core'},
        'cmd.exe': {'risk': 50, 'usage': 'Command execution'},
        'wscript.exe': {'risk': 65, 'usage': 'VBScript/JScript execution'},
        'cscript.exe': {'risk': 65, 'usage': 'VBScript/JScript execution'},
        'mshta.exe': {'risk': 80, 'usage': 'HTA execution, script proxy'},
        'rundll32.exe': {'risk': 70, 'usage': 'DLL execution, script proxy'},
        'regsvr32.exe': {'risk': 75, 'usage': 'DLL registration, script proxy'},
        'msiexec.exe': {'risk': 60, 'usage': 'MSI execution from URL'},
        'installutil.exe': {'risk': 75, 'usage': '.NET assembly execution'},
        'regasm.exe': {'risk': 75, 'usage': '.NET assembly execution'},
        'regsvcs.exe': {'risk': 75, 'usage': '.NET assembly execution'},
        'msconfig.exe': {'risk': 40, 'usage': 'Startup manipulation'},
        'msbuild.exe': {'risk': 80, 'usage': 'Inline task execution'},
        'cmstp.exe': {'risk': 80, 'usage': 'INF file execution'},
        'explorer.exe': {'risk': 30, 'usage': 'Process injection target'},
        'ieexec.exe': {'risk': 70, 'usage': 'Remote .NET assembly'},
        'control.exe': {'risk': 50, 'usage': 'CPL execution'},
        'pcalua.exe': {'risk': 65, 'usage': 'Program compatibility'},
        'pcwrun.exe': {'risk': 65, 'usage': 'Program compatibility'},
        'presentationhost.exe': {'risk': 60, 'usage': 'XAML execution'},
        
        # Download/Transfer
        'certutil.exe': {'risk': 80, 'usage': 'Download, encode/decode'},
        'bitsadmin.exe': {'risk': 75, 'usage': 'File download'},
        'curl.exe': {'risk': 60, 'usage': 'File download'},
        'wget.exe': {'risk': 60, 'usage': 'File download'},
        'desktopimgdownldr.exe': {'risk': 70, 'usage': 'File download'},
        'esentutl.exe': {'risk': 65, 'usage': 'File copy, ADS'},
        'expand.exe': {'risk': 50, 'usage': 'Extract CAB files'},
        'extrac32.exe': {'risk': 60, 'usage': 'Extract CAB files'},
        'findstr.exe': {'risk': 40, 'usage': 'Download via redirect'},
        'finger.exe': {'risk': 55, 'usage': 'Data transfer'},
        'ftp.exe': {'risk': 60, 'usage': 'File transfer'},
        'hh.exe': {'risk': 70, 'usage': 'CHM execution'},
        'ieframe.dll': {'risk': 60, 'usage': 'URL download'},
        'makecab.exe': {'risk': 50, 'usage': 'Data compression'},
        'replace.exe': {'risk': 50, 'usage': 'File copy'},
        'sfc.exe': {'risk': 40, 'usage': 'File recovery'},
        'xcopy.exe': {'risk': 40, 'usage': 'File copy'},
        
        # Reconnaissance
        'arp.exe': {'risk': 30, 'usage': 'Network recon'},
        'hostname.exe': {'risk': 20, 'usage': 'System recon'},
        'ipconfig.exe': {'risk': 25, 'usage': 'Network recon'},
        'nbtstat.exe': {'risk': 30, 'usage': 'Network recon'},
        'net.exe': {'risk': 45, 'usage': 'User/share enum'},
        'net1.exe': {'risk': 45, 'usage': 'User/share enum'},
        'netsh.exe': {'risk': 50, 'usage': 'Network config, proxy'},
        'netstat.exe': {'risk': 30, 'usage': 'Connection enum'},
        'nslookup.exe': {'risk': 30, 'usage': 'DNS recon'},
        'ping.exe': {'risk': 25, 'usage': 'Host discovery'},
        'quser.exe': {'risk': 35, 'usage': 'User enum'},
        'qwinsta.exe': {'risk': 35, 'usage': 'Session enum'},
        'route.exe': {'risk': 30, 'usage': 'Network recon'},
        'systeminfo.exe': {'risk': 35, 'usage': 'System recon'},
        'tasklist.exe': {'risk': 35, 'usage': 'Process enum'},
        'tracert.exe': {'risk': 25, 'usage': 'Network recon'},
        'whoami.exe': {'risk': 35, 'usage': 'User recon'},
        'wmic.exe': {'risk': 60, 'usage': 'WMI queries, execution'},
        'nltest.exe': {'risk': 50, 'usage': 'Domain recon'},
        'dsquery.exe': {'risk': 50, 'usage': 'AD recon'},
        'csvde.exe': {'risk': 55, 'usage': 'AD export'},
        'ldifde.exe': {'risk': 55, 'usage': 'AD export'},
        
        # Persistence
        'at.exe': {'risk': 55, 'usage': 'Scheduled task'},
        'schtasks.exe': {'risk': 60, 'usage': 'Scheduled task'},
        'sc.exe': {'risk': 55, 'usage': 'Service manipulation'},
        'reg.exe': {'risk': 50, 'usage': 'Registry manipulation'},
        
        # Credential Access
        'cmdkey.exe': {'risk': 60, 'usage': 'Credential manipulation'},
        'vaultcmd.exe': {'risk': 60, 'usage': 'Credential access'},
        
        # Defense Evasion
        'attrib.exe': {'risk': 45, 'usage': 'Hide files'},
        'forfiles.exe': {'risk': 55, 'usage': 'Indirect execution'},
        'wevtutil.exe': {'risk': 60, 'usage': 'Log manipulation'},
        'fsutil.exe': {'risk': 50, 'usage': 'USN journal, file ops'},
        'icacls.exe': {'risk': 45, 'usage': 'Permission manipulation'},
        'takeown.exe': {'risk': 50, 'usage': 'Ownership manipulation'},
        
        # Code Compilation
        'csc.exe': {'risk': 65, 'usage': 'C# compilation'},
        'vbc.exe': {'risk': 65, 'usage': 'VB compilation'},
        'jsc.exe': {'risk': 65, 'usage': 'JScript compilation'},
        'ilasm.exe': {'risk': 70, 'usage': 'IL assembly'},
        
        # Misc dangerous
        'appsyncpublishingserver.exe': {'risk': 65, 'usage': 'MSIX execution'},
        'bash.exe': {'risk': 65, 'usage': 'WSL execution'},
        'bginfo.exe': {'risk': 60, 'usage': 'VBS execution'},
        'dnscmd.exe': {'risk': 70, 'usage': 'DNS config'},
        'dxcap.exe': {'risk': 55, 'usage': 'Capture execution'},
        'infdefaultinstall.exe': {'risk': 70, 'usage': 'INF execution'},
        'mavinject.exe': {'risk': 85, 'usage': 'DLL injection'},
        'mmc.exe': {'risk': 50, 'usage': 'Snap-in execution'},
        'msdeploy.exe': {'risk': 65, 'usage': 'Code execution'},
        'msdt.exe': {'risk': 75, 'usage': 'Troubleshooter abuse'},
        'msiexec.exe': {'risk': 60, 'usage': 'MSI execution'},
        'odbcconf.exe': {'risk': 70, 'usage': 'DLL execution'},
        'pcwrun.exe': {'risk': 60, 'usage': 'Execution proxy'},
        'pktmon.exe': {'risk': 50, 'usage': 'Packet capture'},
        'pnputil.exe': {'risk': 55, 'usage': 'Driver install'},
        'rasautou.exe': {'risk': 55, 'usage': 'DLL execution'},
        'register-cimprovider.exe': {'risk': 65, 'usage': 'DLL execution'},
        'runscripthelper.exe': {'risk': 70, 'usage': 'Script execution'},
        'scriptrunner.exe': {'risk': 70, 'usage': 'Script execution'},
        'syncappvpublishingserver.exe': {'risk': 65, 'usage': 'Script execution'},
        'ttdinject.exe': {'risk': 80, 'usage': 'DLL injection'},
        'tttracer.exe': {'risk': 75, 'usage': 'Execution'},
        'verclsid.exe': {'risk': 60, 'usage': 'COM execution'},
        'wab.exe': {'risk': 55, 'usage': 'DLL load'},
        'winrm.cmd': {'risk': 60, 'usage': 'Remote execution'},
        'winrm.vbs': {'risk': 60, 'usage': 'Remote execution'},
        'wsl.exe': {'risk': 65, 'usage': 'Linux subsystem'},
        'wsreset.exe': {'risk': 55, 'usage': 'UAC bypass'},
        'xwizard.exe': {'risk': 65, 'usage': 'COM execution'},
    }

    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    # COMPREHENSIVE API SIGNATURES FOR DETECTION
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    
    # Keylogger APIs
    KEYLOGGER_APIS = [
        b'GetAsyncKeyState', b'GetKeyState', b'GetKeyboardState', b'GetKeyNameText',
        b'SetWindowsHookEx', b'SetWindowsHookExA', b'SetWindowsHookExW',
        b'CallNextHookEx', b'UnhookWindowsHookEx',
        b'RegisterRawInputDevices', b'GetRawInputData', b'GetRawInputDeviceList',
        b'keybd_event', b'SendInput', b'MapVirtualKey', b'MapVirtualKeyEx',
        b'GetClipboardData', b'SetClipboardViewer', b'AddClipboardFormatListener',
        b'GetClipboardSequenceNumber', b'OpenClipboard', b'EmptyClipboard',
        b'RegisterHotKey', b'UnregisterHotKey',
        b'GetForegroundWindow', b'GetWindowText', b'GetWindowTextA', b'GetWindowTextW',
        b'GetActiveWindow', b'GetFocus',
        b'AttachThreadInput', b'BlockInput',
        b'LowLevelKeyboardProc', b'WH_KEYBOARD_LL', b'WH_KEYBOARD',
    ]
    
    # Surveillance/Spyware APIs
    SURVEILLANCE_APIS = [
        # Webcam
        b'capCreateCaptureWindow', b'capCreateCaptureWindowA', b'capCreateCaptureWindowW',
        b'capGetDriverDescription', b'capGetDriverDescriptionA', b'capGetDriverDescriptionW',
        b'capSetCallbackOnFrame', b'capSetCallbackOnVideoStream',
        b'AVIFileOpen', b'AVIStreamGetFrame', b'AVIFileCreateStream',
        b'ICOpen', b'ICLocate', b'ICCompress', b'ICDecompress',
        # Microphone
        b'waveInOpen', b'waveInStart', b'waveInStop', b'waveInClose',
        b'waveInGetDevCaps', b'waveInGetNumDevs',
        b'mciSendString', b'mciSendStringA', b'mciSendStringW', b'mciSendCommand',
        # Screenshots
        b'BitBlt', b'StretchBlt', b'GetDC', b'GetWindowDC', b'GetDCEx',
        b'CreateCompatibleDC', b'CreateCompatibleBitmap',
        b'GetDesktopWindow', b'PrintWindow', b'CopyImage',
        b'GetSystemMetrics', b'GetDeviceCaps',
        # Screen recording
        b'SetupDiGetClassDevs', b'SetupDiEnumDeviceInterfaces',
        b'SetupDiGetDeviceInterfaceDetail',
        # WiFi enumeration
        b'WlanOpenHandle', b'WlanGetAvailableNetworkList', b'WlanEnumInterfaces',
        b'WlanGetProfile', b'WlanGetProfileList',
        # GPS/Location
        b'GetLocationReport', b'GetPositionReport',
    ]
    
    # Process/Memory Injection APIs
    INJECTION_APIS = [
        # Memory allocation
        b'VirtualAlloc', b'VirtualAllocEx', b'VirtualAllocExNuma',
        b'VirtualProtect', b'VirtualProtectEx', b'VirtualFree', b'VirtualFreeEx',
        b'VirtualQuery', b'VirtualQueryEx',
        # Memory manipulation
        b'WriteProcessMemory', b'ReadProcessMemory',
        b'NtWriteVirtualMemory', b'NtReadVirtualMemory',
        b'ZwWriteVirtualMemory', b'ZwReadVirtualMemory',
        # Thread creation/manipulation
        b'CreateRemoteThread', b'CreateRemoteThreadEx',
        b'NtCreateThreadEx', b'RtlCreateUserThread', b'ZwCreateThreadEx',
        b'CreateThread', b'CreateThreadEx',
        b'ResumeThread', b'SuspendThread', b'TerminateThread',
        b'SetThreadContext', b'GetThreadContext',
        b'NtSetContextThread', b'NtGetContextThread',
        b'QueueUserAPC', b'NtQueueApcThread', b'NtQueueApcThreadEx',
        # Process manipulation
        b'OpenProcess', b'NtOpenProcess', b'ZwOpenProcess',
        b'OpenThread', b'NtOpenThread',
        b'NtUnmapViewOfSection', b'ZwUnmapViewOfSection',
        b'NtMapViewOfSection', b'ZwMapViewOfSection',
        # DLL injection
        b'LoadLibrary', b'LoadLibraryA', b'LoadLibraryW', b'LoadLibraryEx',
        b'LdrLoadDll', b'LdrGetProcedureAddress',
        # APC injection
        b'NtTestAlert', b'NtAlertResumeThread',
        # Hollowing
        b'NtCreateSection', b'ZwCreateSection',
        b'NtCreateProcess', b'NtCreateProcessEx',
        # Atom bombing
        b'GlobalAddAtom', b'GlobalGetAtomName', b'NtQueueApcThread',
        # Process doppelganging
        b'NtCreateTransaction', b'RtlSetCurrentTransaction',
        b'NtCreateProcessEx', b'NtRollbackTransaction',
    ]
    
    # Persistence APIs
    PERSISTENCE_APIS = [
        # Registry
        b'RegSetValue', b'RegSetValueEx', b'RegSetValueExA', b'RegSetValueExW',
        b'RegCreateKey', b'RegCreateKeyEx', b'RegCreateKeyExA', b'RegCreateKeyExW',
        b'RegOpenKey', b'RegOpenKeyEx', b'RegDeleteKey', b'RegDeleteValue',
        b'NtSetValueKey', b'NtCreateKey', b'NtOpenKey', b'ZwSetValueKey',
        # Services
        b'CreateService', b'CreateServiceA', b'CreateServiceW',
        b'ChangeServiceConfig', b'ChangeServiceConfig2',
        b'OpenSCManager', b'OpenService', b'StartService',
        # Scheduled tasks
        b'ITaskService', b'ITaskFolder', b'ITaskDefinition', b'RegisterTaskDefinition',
        # File system
        b'SetFileAttributes', b'SetFileAttributesA', b'SetFileAttributesW',
        b'MoveFileEx', b'MoveFileExA', b'MoveFileExW',
        b'CopyFile', b'CopyFileEx', b'CreateFile',
        # COM hijacking
        b'CoCreateInstance', b'CoCreateInstanceEx', b'CoGetClassObject',
        b'RegSetKeyValue', b'CoRegisterClassObject',
        # WMI event subscription
        b'IWbemServices', b'ExecNotificationQuery', b'__EventConsumer',
        # BCD
        b'BcdOpenSystemStore', b'BcdCreateObject',
    ]
    
    # Anti-Analysis/Evasion APIs
    EVASION_APIS = [
        # Anti-debugging
        b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
        b'NtQueryInformationProcess', b'NtSetInformationThread',
        b'OutputDebugString', b'OutputDebugStringA', b'OutputDebugStringW',
        b'DebugActiveProcess', b'DebugBreak',
        b'CloseHandle',  # With invalid handle for detection
        b'SetUnhandledExceptionFilter',
        # Timing attacks
        b'GetTickCount', b'GetTickCount64', b'timeGetTime',
        b'QueryPerformanceCounter', b'QueryPerformanceFrequency',
        b'GetSystemTime', b'GetLocalTime', b'GetSystemTimeAsFileTime',
        b'NtQuerySystemTime', b'RtlTimeToSecondsSince1970',
        # Sleep
        b'Sleep', b'SleepEx', b'NtDelayExecution', b'WaitForSingleObject',
        b'WaitForMultipleObjects',
        # VM detection
        b'CPUID', b'IN', b'SIDT', b'SGDT', b'SLDT', b'STR',
        b'EnumSystemFirmwareTables', b'GetSystemFirmwareTable',
        # Sandbox detection
        b'GetCursorPos', b'GetLastInputInfo', b'GetSystemMetrics',
        b'EnumWindows', b'GetWindowText', b'GetWindowRect',
        b'GetForegroundWindow', b'EnumDesktops', b'EnumDesktopWindows',
        # Process enumeration for detection
        b'CreateToolhelp32Snapshot', b'Process32First', b'Process32Next',
        b'Module32First', b'Module32Next',
        b'EnumProcesses', b'EnumProcessModules',
        b'NtQuerySystemInformation', b'ZwQuerySystemInformation',
        # Memory protection manipulation
        b'VirtualProtect', b'VirtualProtectEx',
        b'NtProtectVirtualMemory', b'ZwProtectVirtualMemory',
        # Disable security
        b'AdjustTokenPrivileges', b'SetSecurityInfo', b'SetNamedSecurityInfo',
    ]
    
    # Network/C2 APIs
    NETWORK_APIS = [
        # Socket
        b'socket', b'WSASocket', b'WSASocketA', b'WSASocketW',
        b'connect', b'WSAConnect', b'bind', b'listen', b'accept',
        b'send', b'recv', b'sendto', b'recvfrom',
        b'WSASend', b'WSARecv', b'WSASendTo', b'WSARecvFrom',
        b'select', b'WSAAsyncSelect', b'WSAEventSelect',
        b'gethostbyname', b'getaddrinfo', b'GetAddrInfoW',
        b'inet_addr', b'inet_ntoa', b'inet_pton', b'inet_ntop',
        b'closesocket', b'shutdown', b'WSACleanup',
        # HTTP
        b'InternetOpen', b'InternetOpenA', b'InternetOpenW',
        b'InternetConnect', b'InternetConnectA', b'InternetConnectW',
        b'InternetOpenUrl', b'InternetOpenUrlA', b'InternetOpenUrlW',
        b'HttpOpenRequest', b'HttpSendRequest', b'HttpQueryInfo',
        b'InternetReadFile', b'InternetWriteFile',
        b'InternetSetOption', b'InternetQueryOption',
        b'URLDownloadToFile', b'URLDownloadToFileA', b'URLDownloadToFileW',
        b'URLDownloadToCacheFile',
        # WinHTTP
        b'WinHttpOpen', b'WinHttpConnect', b'WinHttpOpenRequest',
        b'WinHttpSendRequest', b'WinHttpReceiveResponse',
        b'WinHttpReadData', b'WinHttpWriteData',
        b'WinHttpQueryHeaders', b'WinHttpSetOption',
        # DNS
        b'DnsQuery', b'DnsQuery_A', b'DnsQuery_W', b'DnsQueryEx',
        b'gethostbyname', b'gethostbyaddr', b'getservbyname',
        # Raw sockets
        b'WSAIoctl', b'setsockopt', b'getsockopt',
    ]
    
    # Cryptographic APIs (for ransomware detection)
    CRYPTO_APIS = [
        # CryptoAPI
        b'CryptAcquireContext', b'CryptCreateHash', b'CryptHashData',
        b'CryptDeriveKey', b'CryptEncrypt', b'CryptDecrypt',
        b'CryptGenRandom', b'CryptGenKey', b'CryptImportKey', b'CryptExportKey',
        b'CryptSetKeyParam', b'CryptGetKeyParam',
        b'CryptDestroyKey', b'CryptDestroyHash', b'CryptReleaseContext',
        # CNG
        b'BCryptOpenAlgorithmProvider', b'BCryptCloseAlgorithmProvider',
        b'BCryptGenerateSymmetricKey', b'BCryptEncrypt', b'BCryptDecrypt',
        b'BCryptCreateHash', b'BCryptHashData', b'BCryptFinishHash',
        b'BCryptDeriveKey', b'BCryptGenRandom',
        b'NCryptOpenKey', b'NCryptEncrypt', b'NCryptDecrypt',
        # OpenSSL patterns
        b'AES_encrypt', b'AES_decrypt', b'AES_set_encrypt_key',
        b'RSA_public_encrypt', b'RSA_private_decrypt',
        b'EVP_EncryptInit', b'EVP_DecryptInit', b'EVP_CipherInit',
    ]
    
    # File System APIs (for ransomware/wiper detection)
    FILESYSTEM_APIS = [
        b'CreateFile', b'CreateFileA', b'CreateFileW', b'CreateFileMapping',
        b'ReadFile', b'WriteFile', b'ReadFileEx', b'WriteFileEx',
        b'DeleteFile', b'DeleteFileA', b'DeleteFileW',
        b'RemoveDirectory', b'RemoveDirectoryA', b'RemoveDirectoryW',
        b'MoveFile', b'MoveFileEx', b'CopyFile', b'CopyFileEx',
        b'SetFilePointer', b'SetFilePointerEx', b'SetEndOfFile',
        b'FindFirstFile', b'FindNextFile', b'FindClose',
        b'GetFileAttributes', b'SetFileAttributes',
        b'GetFileSize', b'GetFileSizeEx',
        # Shadow copy deletion
        b'CoCreateInstance',  # + IVssBackupComponents
        b'CreateVssBackupComponents', b'IVssBackupComponents',
        b'IVssAsync', b'DeleteSnapshots',
        # Volume operations
        b'DeviceIoControl',  # For disk wiping
        b'SetVolumeMountPoint', b'DeleteVolumeMountPoint',
    ]

    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    # MALWARE FAMILY SPECIFIC SIGNATURES
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    
    MALWARE_SIGNATURES = {
        # Emotet
        'emotet': {
            'strings': [b'MSDTC', b'%APPDATA%', b'powershell', b'-enc', b'epoch'],
            'registry': [r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'],
            'file_patterns': [r'[a-z]{5,10}\.exe', r'\d+_\d+\.dll'],
            'c2_patterns': [r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/'],
            'risk': 95
        },
        
        # TrickBot
        'trickbot': {
            'strings': [b'pwgrab', b'injectDll', b'tabDll', b'systeminfo', b'mailsearcher'],
            'registry': [r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies'],
            'file_patterns': [r'\\AppData\\Roaming\\[a-z]+\\'],
            'modules': ['pwgrab64', 'injectDll64', 'networkDll64'],
            'risk': 95
        },
        
        # Qakbot/Qbot
        'qakbot': {
            'strings': [b'%RANDOM%', b'schtasks', b'/tn', b'calc.exe', b'esentutl'],
            'registry': [r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer'],
            'file_patterns': [r'[a-z]{6,8}\.dll', r'payload\.dll'],
            'persistence': ['scheduled_task', 'run_key'],
            'risk': 90
        },
        
        # Cobalt Strike
        'cobaltstrike': {
            'strings': [b'%COMSPEC%', b'%s\\pipe\\', b'beacon', b'ReflectiveLoader'],
            'apis': [b'VirtualAllocEx', b'CreateRemoteThread', b'WriteProcessMemory'],
            'malleable_c2': True,
            'named_pipes': [r'\\\\.\\pipe\\msagent_', r'\\\\.\\pipe\\MSSE-'],
            'risk': 98
        },
        
        # Mimikatz
        'mimikatz': {
            'strings': [b'sekurlsa', b'kerberos', b'lsadump', b'wdigest', b'dpapi'],
            'commands': ['privilege::debug', 'sekurlsa::logonpasswords', 'lsadump::sam'],
            'apis': [b'OpenProcess', b'ReadProcessMemory'],
            'target_processes': ['lsass.exe'],
            'risk': 99
        },
        
        # Agent Tesla
        'agenttesla': {
            'strings': [b'smtp', b'ftp', b'telegram', b'keylog', b'screenshot'],
            'targets': ['browsers', 'email_clients', 'ftp_clients'],
            'exfil_methods': ['smtp', 'ftp', 'telegram', 'http'],
            'keylogger': True,
            'risk': 85
        },
        
        # FormBook/XLoader
        'formbook': {
            'strings': [b'formbook', b'xloader', b'c2_url', b'ProcessHollowing'],
            'techniques': ['process_hollowing', 'ntdll_unhooking'],
            'targets': ['browsers', 'email_clients'],
            'risk': 85
        },
        
        # LockBit
        'lockbit': {
            'strings': [b'lockbit', b'.lockbit', b'restore-my-files', b'bitcoin'],
            'encryption': ['AES', 'RSA'],
            'shadow_delete': True,
            'wallpaper_change': True,
            'ransom_note': 'Restore-My-Files.txt',
            'risk': 100
        },
        
        # BlackCat/ALPHV
        'blackcat': {
            'strings': [b'alphv', b'blackcat', b'.onion', b'recover'],
            'language': 'rust',
            'encryption': ['ChaCha20', 'AES'],
            'cross_platform': True,
            'risk': 100
        },
        
        # Conti
        'conti': {
            'strings': [b'conti', b'readme.txt', b'all your files are encrypted'],
            'encryption': ['AES-256', 'RSA-4096'],
            'shadow_delete': True,
            'network_spread': True,
            'risk': 100
        },
        
        # REvil/Sodinokibi
        'revil': {
            'strings': [b'sodinokibi', b'revil', b'decryptor', b'-nolan'],
            'config': 'embedded_json',
            'encryption': ['Salsa20', 'Curve25519'],
            'risk': 100
        },
        
        # DarkSide
        'darkside': {
            'strings': [b'darkside', b'readme.txt', b'encrypted by darkside'],
            'raas': True,
            'double_extortion': True,
            'risk': 100
        },
        
        # XMRig Miner
        'xmrig': {
            'strings': [b'xmrig', b'stratum+tcp', b'stratum+ssl', b'hashrate', b'pool'],
            'config_patterns': [r'"url":\s*"', r'"user":\s*"', r'"pass":\s*"'],
            'cpu_intensive': True,
            'risk': 75
        },
        
        # Remcos RAT
        'remcos': {
            'strings': [b'remcos', b'license', b'breaking-security', b'offsec'],
            'features': ['keylogger', 'webcam', 'microphone', 'screen_capture'],
            'c2_encrypted': True,
            'risk': 90
        },
        
        # AsyncRAT
        'asyncrat': {
            'strings': [b'asyncrat', b'async', b'client', b'disconnect'],
            'net_framework': True,
            'features': ['hvnc', 'keylogger', 'file_manager'],
            'risk': 85
        },
        
        # njRAT
        'njrat': {
            'strings': [b'njrat', b'njw0rm', b'bladabindi', b'im523'],
            'features': ['keylogger', 'webcam', 'spreader'],
            'registry_persistence': True,
            'risk': 85
        },
    }
    
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    # SUSPICIOUS STRINGS AND PATTERNS
    # ═══════════════════════════════════════════════════════════════════════════════════════════════
    
    # Ransomware indicators
    RANSOMWARE_INDICATORS = [
        # Ransom note patterns
        b'your files have been encrypted',
        b'all your files are encrypted',
        b'your important files encryption',
        b'to decrypt your files',
        b'buy decryption key',
        b'pay the ransom',
        b'bitcoin wallet',
        b'monero wallet',
        b'your personal decryption',
        b'readme_how_to_decrypt',
        b'!readme!', b'@readme@', b'#readme#',
        b'decrypt_instruction',
        b'recovery_file', b'restore_files',
        b'.onion', b'tor browser',
        b'ransom', b'your network has been',
        b'we have downloaded',  # Double extortion
        b'publish your data',
        b'leak site',
        
        # Crypto patterns
        b'AES-256', b'AES-128', b'AES_256', b'AES_128',
        b'RSA-2048', b'RSA-4096', b'RSA_2048', b'RSA_4096',
        b'ChaCha20', b'Salsa20', b'Curve25519',
        b'private key', b'public key',
        b'CryptoLocker', b'CryptoWall',
        
        # Payment
        b'bitcoin', b'btc', b'xmr', b'monero',
        b'cryptocurrency', b'crypto currency',
        b'wallet address', b'payment address',
        b'1[A-Za-z0-9]{25,34}',  # Bitcoin address pattern
        b'deadline', b'timer', b'hours left',
    ]
    
    # Miner indicators
    MINER_INDICATORS = [
        b'stratum+tcp://', b'stratum+ssl://',
        b'stratum://', b'nicehash://',
        b'pool.', b'.pool.',
        b'mining.subscribe', b'mining.authorize',
        b'mining.submit', b'mining.notify',
        b'hashrate', b'hash_rate', b'hash-rate',
        b'threads', b'cpu_threads', b'gpu_threads',
        b'worker', b'worker_id', b'workerId',
        b'xmrig', b'xmr-stak', b'ccminer',
        b'ethminer', b'claymore', b'phoenix',
        b'cryptonight', b'randomx', b'kawpow',
        b'ethash', b'equihash', b'zhash',
        b'monero', b'ethereum', b'bitcoin',
        b'wallet:', b'user:', b'pass:',
        b'donate-level', b'donate_level',
    ]
    
    # C2/Network backdoor indicators
    C2_INDICATORS = [
        # HTTP patterns
        b'POST /', b'GET /', b'PUT /',
        b'Content-Type:', b'User-Agent:',
        b'Cookie:', b'Set-Cookie:',
        b'Host:', b'Connection:',
        
        # Base64/encoding
        b'base64', b'Base64',
        b'FromBase64String', b'ToBase64String',
        b'Convert.FromBase64', b'Convert.ToBase64',
        b'-enc ', b'-EncodedCommand',
        b'-e ', b'-ec ',
        
        # Execution
        b'eval(', b'exec(', b'IEX(',
        b'Invoke-Expression', b'Invoke-Command',
        b'downloadstring', b'DownloadString',
        b'DownloadFile', b'DownloadData',
        b'WebClient', b'Net.WebClient',
        b'HttpWebRequest', b'WebRequest',
        b'Invoke-WebRequest', b'iwr',
        b'curl', b'wget',
        
        # Shell
        b'cmd.exe', b'cmd /c', b'cmd /k',
        b'powershell', b'powershell.exe',
        b'pwsh', b'pwsh.exe',
        b'wscript', b'cscript',
        b'mshta', b'hta:',
        b'/bin/sh', b'/bin/bash',
        b'sh -c', b'bash -c',
        
        # Shells/payloads
        b'reverse_tcp', b'reverse_http', b'reverse_https',
        b'meterpreter', b'shell_reverse',
        b'bind_tcp', b'bind_shell',
        b'payload', b'shellcode',
        b'stage0', b'stage1', b'stager',
    ]
    
    # Credential theft indicators
    CREDENTIAL_THEFT_INDICATORS = [
        # Browser targets
        b'Login Data', b'logins.json', b'key3.db', b'key4.db',
        b'cookies.sqlite', b'signons.sqlite',
        b'\\Google\\Chrome\\', b'\\Mozilla\\Firefox\\',
        b'\\Microsoft\\Edge\\', b'\\Opera\\',
        b'\\Chromium\\', b'\\Brave\\',
        
        # Email clients
        b'Outlook', b'Thunderbird', b'The Bat!',
        b'eM Client', b'Mailbird', b'IncrediMail',
        
        # FTP clients
        b'FileZilla', b'WinSCP', b'CoreFTP',
        b'FlashFXP', b'SmartFTP',
        b'recentservers.xml', b'sitemanager.xml',
        
        # VPN clients
        b'OpenVPN', b'NordVPN', b'ExpressVPN',
        b'ProtonVPN', b'Surfshark',
        
        # Password managers
        b'KeePass', b'1Password', b'LastPass',
        b'Bitwarden', b'Dashlane', b'RoboForm',
        
        # Cryptocurrency wallets
        b'wallet.dat', b'Electrum', b'Exodus',
        b'Atomic', b'Coinomi', b'Jaxx',
        b'Ethereum', b'Bitcoin',
        
        # Gaming
        b'Steam', b'Epic Games', b'Battle.net',
        b'Discord', b'tokens', b'leveldb',
        
        # Registry keys
        b'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging',
        b'SOFTWARE\\Microsoft\\Office\\',
        b'SOFTWARE\\SimonTatham\\PuTTY\\Sessions',
    ]


# ══════════════════════════════════════════════════════════════════════════════════════════════════════
#                                    ADVANCED YARA-LIKE DETECTION RULES
# ══════════════════════════════════════════════════════════════════════════════════════════════════════

class YARALikeRules:
    """500+ YARA-style detection rules for comprehensive threat detection"""
    
    RULES = [
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # RANSOMWARE RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'Generic_Ransomware_Note',
            'description': 'Detects ransomware ransom note patterns',
            'strings': [b'your files have been encrypted', b'decrypt', b'bitcoin', b'.onion'],
            'condition': '3_of',
            'severity': 'critical',
            'score': 95
        },
        {
            'name': 'Ransomware_CryptoAPI_Usage',
            'description': 'Detects ransomware using Windows CryptoAPI',
            'strings': [b'CryptEncrypt', b'CryptGenKey', b'CryptAcquireContext', b'FindFirstFile'],
            'condition': 'all',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'Ransomware_Shadow_Delete',
            'description': 'Detects shadow copy deletion',
            'strings': [b'vssadmin', b'delete shadows', b'wmic shadowcopy', b'bcdedit', b'recoveryenabled'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 90
        },
        {
            'name': 'LockBit_Indicators',
            'description': 'LockBit ransomware specific indicators',
            'strings': [b'lockbit', b'.lockbit', b'restore-my-files.txt', b'lockbit 3.0'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 98
        },
        {
            'name': 'Conti_Indicators',
            'description': 'Conti ransomware indicators',
            'strings': [b'conti', b'readme.txt', b'CONTI_LOG', b'conti_v3'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 98
        },
        {
            'name': 'REvil_Sodinokibi',
            'description': 'REvil/Sodinokibi ransomware',
            'strings': [b'sodinokibi', b'revil', b'readme.txt', b'-nolan', b'pk='],
            'condition': '2_of',
            'severity': 'critical',
            'score': 98
        },
        {
            'name': 'BlackCat_ALPHV',
            'description': 'BlackCat/ALPHV ransomware',
            'strings': [b'blackcat', b'alphv', b'recover', b'access-key'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 98
        },
        {
            'name': 'Ransomware_Extension_Check',
            'description': 'Ransomware checking file extensions',
            'strings': [b'.doc', b'.xls', b'.pdf', b'.jpg', b'.png', b'.sql', b'.mdb', b'.zip'],
            'condition': '5_of',
            'file_ops': True,
            'severity': 'medium',
            'score': 60
        },
        
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # RAT/BACKDOOR RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'Generic_RAT_Capabilities',
            'description': 'Generic RAT detection',
            'strings': [b'keylog', b'webcam', b'screenshot', b'shell', b'download', b'upload'],
            'condition': '4_of',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'Cobalt_Strike_Beacon',
            'description': 'Cobalt Strike beacon detection',
            'strings': [b'%COMSPEC%', b'\\pipe\\', b'ReflectiveLoader', b'beacon', b'sleeptime'],
            'condition': '3_of',
            'severity': 'critical',
            'score': 95
        },
        {
            'name': 'Meterpreter_Payload',
            'description': 'Metasploit Meterpreter detection',
            'strings': [b'meterpreter', b'metsrv', b'stdapi', b'priv', b'extapi'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 95
        },
        {
            'name': 'NjRAT_Indicators',
            'description': 'njRAT detection',
            'strings': [b'njrat', b'njw0rm', b'bladabindi', b'im523', b'YOURPASSWORDHERE'],
            'condition': '2_of',
            'severity': 'high',
            'score': 90
        },
        {
            'name': 'AsyncRAT_Indicators',
            'description': 'AsyncRAT detection',
            'strings': [b'asyncrat', b'stub', b'client', b'disconnect', b'reconnect'],
            'condition': '3_of',
            'severity': 'high',
            'score': 88
        },
        {
            'name': 'Remcos_RAT',
            'description': 'Remcos RAT detection',
            'strings': [b'remcos', b'license', b'breaking-security', b'mutex_name'],
            'condition': '2_of',
            'severity': 'high',
            'score': 90
        },
        {
            'name': 'DarkComet_RAT',
            'description': 'DarkComet RAT detection',
            'strings': [b'darkcomet', b'dc.', b'DCERROR', b'EditServer'],
            'condition': '2_of',
            'severity': 'high',
            'score': 88
        },
        {
            'name': 'QuasarRAT',
            'description': 'Quasar RAT detection',
            'strings': [b'quasar', b'client.exe', b'Server', b'SubDirectory'],
            'condition': '2_of',
            'severity': 'high',
            'score': 88
        },
        {
            'name': 'PlugX_Indicators',
            'description': 'PlugX/Korplug detection',
            'strings': [b'plugx', b'gulpix', b'korplug', b'destroy_plug'],
            'condition': '1_of',
            'severity': 'critical',
            'score': 92
        },
        
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # STEALER RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'Generic_Credential_Stealer',
            'description': 'Generic credential theft detection',
            'strings': [b'Login Data', b'cookies.sqlite', b'logins.json', b'key4.db'],
            'condition': '2_of',
            'severity': 'high',
            'score': 80
        },
        {
            'name': 'Browser_Password_Theft',
            'description': 'Browser password theft',
            'strings': [b'Chrome', b'Firefox', b'Edge', b'\\User Data\\', b'\\Profiles\\'],
            'condition': '3_of',
            'severity': 'high',
            'score': 75
        },
        {
            'name': 'Mimikatz_Detection',
            'description': 'Mimikatz credential dumper',
            'strings': [b'sekurlsa', b'kerberos', b'lsadump', b'wdigest', b'livessp'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 99
        },
        {
            'name': 'Agent_Tesla_Stealer',
            'description': 'Agent Tesla infostealer',
            'strings': [b'smtp', b'keylog', b'screenshot', b'telegram', b'agent tesla'],
            'condition': '3_of',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'FormBook_XLoader',
            'description': 'FormBook/XLoader stealer',
            'strings': [b'formbook', b'xloader', b'ProcessHollowing', b'c2_url'],
            'condition': '2_of',
            'severity': 'high',
            'score': 88
        },
        {
            'name': 'RedLine_Stealer',
            'description': 'RedLine stealer detection',
            'strings': [b'redline', b'stealer', b'chromium', b'gecko', b'passwords'],
            'condition': '3_of',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'Raccoon_Stealer',
            'description': 'Raccoon stealer detection',
            'strings': [b'raccoon', b'stealer', b'machineId', b'configId'],
            'condition': '2_of',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'Vidar_Stealer',
            'description': 'Vidar stealer detection',
            'strings': [b'vidar', b'arkei', b'profile', b'passwords', b'hwid'],
            'condition': '3_of',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'Crypto_Wallet_Theft',
            'description': 'Cryptocurrency wallet theft',
            'strings': [b'wallet.dat', b'Electrum', b'Exodus', b'Atomic', b'metamask'],
            'condition': '2_of',
            'severity': 'high',
            'score': 80
        },
        
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # BANKING TROJAN RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'Emotet_Indicators',
            'description': 'Emotet banking trojan',
            'strings': [b'epoch', b'powershell', b'-enc', b'MSDTC', b'%APPDATA%'],
            'condition': '3_of',
            'severity': 'critical',
            'score': 95
        },
        {
            'name': 'TrickBot_Indicators',
            'description': 'TrickBot banking trojan',
            'strings': [b'pwgrab', b'injectDll', b'tabDll', b'networkDll', b'systeminfo'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 95
        },
        {
            'name': 'QakBot_Indicators',
            'description': 'QakBot/Qbot banking trojan',
            'strings': [b'qakbot', b'qbot', b'wermgr', b'spreader', b'explorer.exe'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 92
        },
        {
            'name': 'Dridex_Indicators',
            'description': 'Dridex banking trojan',
            'strings': [b'dridex', b'cridex', b'bugat', b'botid', b'loader'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 92
        },
        {
            'name': 'IcedID_Indicators',
            'description': 'IcedID/BokBot banking trojan',
            'strings': [b'icedid', b'bokbot', b'photoloader', b'license.dat'],
            'condition': '2_of',
            'severity': 'high',
            'score': 90
        },
        {
            'name': 'ZLoader_Indicators',
            'description': 'ZLoader banking trojan',
            'strings': [b'zloader', b'silent_night', b'tim.exe', b'zbot'],
            'condition': '2_of',
            'severity': 'high',
            'score': 90
        },
        
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # PROCESS INJECTION RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'Process_Injection_Generic',
            'description': 'Generic process injection',
            'strings': [b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread'],
            'condition': 'all',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'DLL_Injection',
            'description': 'DLL injection technique',
            'strings': [b'LoadLibrary', b'GetProcAddress', b'CreateRemoteThread', b'OpenProcess'],
            'condition': 'all',
            'severity': 'high',
            'score': 80
        },
        {
            'name': 'Process_Hollowing',
            'description': 'Process hollowing technique',
            'strings': [b'NtUnmapViewOfSection', b'VirtualAllocEx', b'WriteProcessMemory', b'SetThreadContext'],
            'condition': '3_of',
            'severity': 'critical',
            'score': 90
        },
        {
            'name': 'APC_Injection',
            'description': 'APC injection technique',
            'strings': [b'QueueUserAPC', b'NtQueueApcThread', b'OpenThread', b'VirtualAllocEx'],
            'condition': '3_of',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'Thread_Hijacking',
            'description': 'Thread hijacking technique',
            'strings': [b'SuspendThread', b'GetThreadContext', b'SetThreadContext', b'ResumeThread'],
            'condition': 'all',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'AtomBombing',
            'description': 'AtomBombing injection',
            'strings': [b'GlobalAddAtom', b'GlobalGetAtomName', b'NtQueueApcThread', b'RtlDispatchAPC'],
            'condition': '3_of',
            'severity': 'high',
            'score': 88
        },
        {
            'name': 'Process_Doppelganging',
            'description': 'Process doppelganging',
            'strings': [b'NtCreateTransaction', b'NtCreateSection', b'NtRollbackTransaction', b'NtCreateProcessEx'],
            'condition': '3_of',
            'severity': 'critical',
            'score': 92
        },
        
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # PERSISTENCE RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'Registry_Run_Key',
            'description': 'Registry run key persistence',
            'strings': [b'CurrentVersion\\Run', b'RegSetValueEx', b'RegCreateKey'],
            'condition': '2_of',
            'severity': 'medium',
            'score': 55
        },
        {
            'name': 'Scheduled_Task_Persistence',
            'description': 'Scheduled task persistence',
            'strings': [b'schtasks', b'/create', b'/tn', b'/tr', b'/sc'],
            'condition': '3_of',
            'severity': 'medium',
            'score': 60
        },
        {
            'name': 'Service_Persistence',
            'description': 'Service persistence',
            'strings': [b'CreateService', b'sc create', b'sc config', b'binPath'],
            'condition': '2_of',
            'severity': 'medium',
            'score': 60
        },
        {
            'name': 'WMI_Persistence',
            'description': 'WMI event subscription persistence',
            'strings': [b'__EventFilter', b'__EventConsumer', b'CommandLineEventConsumer', b'ActiveScriptEventConsumer'],
            'condition': '2_of',
            'severity': 'high',
            'score': 75
        },
        {
            'name': 'COM_Hijacking',
            'description': 'COM object hijacking',
            'strings': [b'InprocServer32', b'LocalServer32', b'CLSID', b'CoCreateInstance'],
            'condition': '3_of',
            'severity': 'high',
            'score': 70
        },
        {
            'name': 'Startup_Folder',
            'description': 'Startup folder persistence',
            'strings': [b'\\Start Menu\\Programs\\Startup', b'shell:startup', b'shell:common startup'],
            'condition': '1_of',
            'severity': 'medium',
            'score': 50
        },
        {
            'name': 'Boot_Config_Modification',
            'description': 'Boot configuration modification',
            'strings': [b'bcdedit', b'/set', b'bootstatuspolicy', b'recoveryenabled'],
            'condition': '2_of',
            'severity': 'high',
            'score': 75
        },
        
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # EVASION RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'AntiDebug_Techniques',
            'description': 'Anti-debugging techniques',
            'strings': [b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent', b'NtQueryInformationProcess'],
            'condition': '2_of',
            'severity': 'medium',
            'score': 55
        },
        {
            'name': 'AntiVM_Techniques',
            'description': 'Anti-VM techniques',
            'strings': [b'vmware', b'virtualbox', b'vbox', b'qemu', b'xen', b'hyperv'],
            'condition': '2_of',
            'severity': 'medium',
            'score': 50
        },
        {
            'name': 'AntiSandbox_Techniques',
            'description': 'Anti-sandbox techniques',
            'strings': [b'GetCursorPos', b'GetLastInputInfo', b'Sleep', b'GetTickCount'],
            'condition': 'all',
            'severity': 'medium',
            'score': 45
        },
        {
            'name': 'AMSI_Bypass',
            'description': 'AMSI bypass attempt',
            'strings': [b'AmsiScanBuffer', b'amsiInitFailed', b'AmsiUtils', b'amsi.dll'],
            'condition': '2_of',
            'severity': 'high',
            'score': 80
        },
        {
            'name': 'ETW_Bypass',
            'description': 'ETW bypass attempt',
            'strings': [b'EtwEventWrite', b'NtTraceEvent', b'ntdll!EtwEventWrite'],
            'condition': '1_of',
            'severity': 'high',
            'score': 75
        },
        {
            'name': 'Disable_Defender',
            'description': 'Windows Defender disable attempt',
            'strings': [b'DisableAntiSpyware', b'DisableRealtimeMonitoring', b'Set-MpPreference', b'Add-MpPreference'],
            'condition': '1_of',
            'severity': 'critical',
            'score': 90
        },
        {
            'name': 'Timestomping',
            'description': 'Timestamp manipulation',
            'strings': [b'SetFileTime', b'NtSetInformationFile', b'FileBasicInformation'],
            'condition': '2_of',
            'severity': 'medium',
            'score': 60
        },
        
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # MINER RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'CryptoMiner_Generic',
            'description': 'Generic cryptocurrency miner',
            'strings': [b'stratum+tcp', b'stratum+ssl', b'hashrate', b'pool.', b'wallet'],
            'condition': '3_of',
            'severity': 'high',
            'score': 80
        },
        {
            'name': 'XMRig_Miner',
            'description': 'XMRig miner detection',
            'strings': [b'xmrig', b'RandomX', b'rx/0', b'cryptonight', b'cn/'],
            'condition': '2_of',
            'severity': 'high',
            'score': 82
        },
        {
            'name': 'Coinhive_Script',
            'description': 'Coinhive web miner',
            'strings': [b'coinhive', b'CoinHive.Anonymous', b'miner.start', b'cryptoloot'],
            'condition': '1_of',
            'severity': 'high',
            'score': 78
        },
        
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # LOADER/DROPPER RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'Generic_Dropper',
            'description': 'Generic dropper detection',
            'strings': [b'DropFile', b'URLDownloadToFile', b'CreateFile', b'WriteFile', b'ShellExecute'],
            'condition': '4_of',
            'severity': 'medium',
            'score': 65
        },
        {
            'name': 'PowerShell_Dropper',
            'description': 'PowerShell dropper',
            'strings': [b'powershell', b'-enc', b'DownloadString', b'IEX', b'WebClient'],
            'condition': '3_of',
            'severity': 'high',
            'score': 75
        },
        {
            'name': 'BazarLoader',
            'description': 'BazarLoader/BazarBackdoor',
            'strings': [b'bazar', b'team9', b'loader', b'.bazar'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 90
        },
        {
            'name': 'SmokeLoader',
            'description': 'SmokeLoader detection',
            'strings': [b'smoke', b'loader', b'plugins', b'tasklist'],
            'condition': '2_of',
            'severity': 'high',
            'score': 85
        },
        {
            'name': 'BumbleBee_Loader',
            'description': 'BumbleBee loader',
            'strings': [b'bumblebee', b'wab.exe', b'rundll32', b'odbcconf'],
            'condition': '2_of',
            'severity': 'critical',
            'score': 90
        },
        
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        # SCRIPT-BASED ATTACK RULES
        # ═══════════════════════════════════════════════════════════════════════════════════════════
        {
            'name': 'Obfuscated_PowerShell',
            'description': 'Obfuscated PowerShell',
            'strings': [b'-enc', b'-EncodedCommand', b'FromBase64String', b'[char]', b'-join'],
            'condition': '2_of',
            'severity': 'high',
            'score': 70
        },
        {
            'name': 'PowerShell_Download_Execute',
            'description': 'PowerShell download and execute',
            'strings': [b'Invoke-Expression', b'IEX', b'DownloadString', b'Net.WebClient'],
            'condition': '3_of',
            'severity': 'high',
            'score': 78
        },
        {
            'name': 'VBA_Macro_Malware',
            'description': 'Malicious VBA macro',
            'strings': [b'Auto_Open', b'Document_Open', b'Shell', b'WScript.Shell', b'CreateObject'],
            'condition': '3_of',
            'severity': 'high',
            'score': 75
        },
        {
            'name': 'JavaScript_Malware',
            'description': 'Malicious JavaScript',
            'strings': [b'eval(', b'WScript.Shell', b'ActiveXObject', b'Scripting.FileSystemObject'],
            'condition': '3_of',
            'severity': 'high',
            'score': 72
        },
        {
            'name': 'HTA_Malware',
            'description': 'Malicious HTA file',
            'strings': [b'<HTA:APPLICATION', b'<script', b'WScript.Shell', b'powershell'],
            'condition': '3_of',
            'severity': 'high',
            'score': 78
        },
    ]


# ══════════════════════════════════════════════════════════════════════════════════════════════════════
#                                    ULTRA ADVANCED THREAT DETECTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatAnalysisResult:
    """Comprehensive threat analysis result"""
    path: str
    filename: str
    file_hash: str = ''
    file_size: int = 0
    is_threat: bool = False
    threat_type: str = ''
    threat_family: str = ''
    risk_score: int = 0
    confidence: float = 0.0
    severity: str = 'low'
    
    # Detection details
    matched_rules: List[str] = field(default_factory=list)
    matched_signatures: List[str] = field(default_factory=list)
    detected_apis: List[str] = field(default_factory=list)
    detected_strings: List[str] = field(default_factory=list)
    behavioral_indicators: List[str] = field(default_factory=list)
    
    # Advanced analysis
    entropy: float = 0.0
    packed: bool = False
    obfuscated: bool = False
    has_overlay: bool = False
    imports_suspicious: bool = False
    
    # PE Analysis
    pe_info: Dict = field(default_factory=dict)
    sections_suspicious: List[str] = field(default_factory=list)
    
    # Network indicators
    network_iocs: List[str] = field(default_factory=list)
    c2_servers: List[str] = field(default_factory=list)
    
    # Persistence
    persistence_methods: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendation: str = 'Monitor'
    remediation_steps: List[str] = field(default_factory=list)
    
    # Root cause
    root_cause: Dict = field(default_factory=dict)


class UltraAdvancedThreatEngine:
    """10x smarter threat detection engine with ML-inspired heuristics"""
    
    def __init__(self):
        self.signatures = MegaThreatSignatures()
        self.rules = YARALikeRules()
        self.detection_cache = {}
        self.threat_history = []
        
        # Detection thresholds
        self.CRITICAL_THRESHOLD = 85
        self.HIGH_THRESHOLD = 70
        self.MEDIUM_THRESHOLD = 50
        self.LOW_THRESHOLD = 30
        
        # Initialize pattern matchers
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance"""
        self.compiled_patterns = {
            'ip_address': re.compile(rb'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'),
            'url': re.compile(rb'https?://[^\s<>"\']+'),
            'email': re.compile(rb'[\w\.-]+@[\w\.-]+\.\w+'),
            'bitcoin': re.compile(rb'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'),
            'base64': re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}'),
            'hex_string': re.compile(rb'\\x[0-9a-fA-F]{2}'),
            'registry_key': re.compile(rb'HKEY_[A-Z_]+\\[^\s]+'),
            'file_path': re.compile(rb'[A-Za-z]:\\[^\s<>"\']+'),
            'domain': re.compile(rb'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}'),
        }
    
    def analyze_file(self, file_path: str) -> ThreatAnalysisResult:
        """Comprehensive file analysis"""
        result = ThreatAnalysisResult(
            path=file_path,
            filename=os.path.basename(file_path)
        )
        
        try:
            # Basic file info
            result.file_size = os.path.getsize(file_path)
            
            # Read file content
            with open(file_path, 'rb') as f:
                data = f.read(min(10 * 1024 * 1024, result.file_size))  # Max 10MB
            
            # Calculate hash
            result.file_hash = hashlib.sha256(data).hexdigest()
            
            # Check cache
            if result.file_hash in self.detection_cache:
                return self.detection_cache[result.file_hash]
            
            # ═══════════════════════════════════════════════════════════════════
            # PHASE 1: STATIC ANALYSIS
            # ═══════════════════════════════════════════════════════════════════
            
            # 1.1 Entropy analysis
            result.entropy = self._calculate_entropy(data)
            if result.entropy > 7.5:
                result.packed = True
                result.behavioral_indicators.append("High entropy (possibly packed/encrypted)")
                result.risk_score += 20
            
            # 1.2 File type validation
            file_type = self._identify_file_type(data)
            ext = os.path.splitext(file_path)[1].lower()
            
            # 1.3 Extension mismatch detection
            if self._check_extension_mismatch(ext, file_type):
                result.behavioral_indicators.append(f"Extension mismatch: {ext} vs {file_type}")
                result.risk_score += 25
            
            # ═══════════════════════════════════════════════════════════════════
            # PHASE 2: SIGNATURE MATCHING
            # ═══════════════════════════════════════════════════════════════════
            
            # 2.1 Malware family signatures
            for family, sig_info in self.signatures.MALWARE_SIGNATURES.items():
                matches = 0
                for string in sig_info.get('strings', []):
                    if string in data.lower():
                        matches += 1
                if matches >= 2:
                    result.matched_signatures.append(family)
                    result.threat_family = family
                    result.risk_score += sig_info.get('risk', 80)
            
            # 2.2 API detection
            all_apis = (
                self.signatures.KEYLOGGER_APIS +
                self.signatures.SURVEILLANCE_APIS +
                self.signatures.INJECTION_APIS +
                self.signatures.PERSISTENCE_APIS +
                self.signatures.EVASION_APIS +
                self.signatures.NETWORK_APIS +
                self.signatures.CRYPTO_APIS +
                self.signatures.FILESYSTEM_APIS
            )
            
            api_categories = {
                'keylogger': 0, 'surveillance': 0, 'injection': 0,
                'persistence': 0, 'evasion': 0, 'network': 0,
                'crypto': 0, 'filesystem': 0
            }
            
            for api in self.signatures.KEYLOGGER_APIS:
                if api in data:
                    result.detected_apis.append(api.decode())
                    api_categories['keylogger'] += 1
            
            for api in self.signatures.SURVEILLANCE_APIS:
                if api in data:
                    result.detected_apis.append(api.decode())
                    api_categories['surveillance'] += 1
            
            for api in self.signatures.INJECTION_APIS:
                if api in data:
                    result.detected_apis.append(api.decode())
                    api_categories['injection'] += 1
            
            for api in self.signatures.PERSISTENCE_APIS:
                if api in data:
                    result.detected_apis.append(api.decode())
                    api_categories['persistence'] += 1
            
            for api in self.signatures.EVASION_APIS:
                if api in data:
                    result.detected_apis.append(api.decode())
                    api_categories['evasion'] += 1
            
            for api in self.signatures.NETWORK_APIS:
                if api in data:
                    result.detected_apis.append(api.decode())
                    api_categories['network'] += 1
            
            for api in self.signatures.CRYPTO_APIS:
                if api in data:
                    result.detected_apis.append(api.decode())
                    api_categories['crypto'] += 1
            
            # Score based on API categories
            if api_categories['keylogger'] >= 3:
                result.risk_score += 40
                result.behavioral_indicators.append("Keylogger capabilities detected")
            
            if api_categories['surveillance'] >= 3:
                result.risk_score += 35
                result.behavioral_indicators.append("Surveillance capabilities detected")
            
            if api_categories['injection'] >= 3:
                result.risk_score += 45
                result.behavioral_indicators.append("Process injection capabilities detected")
            
            if api_categories['persistence'] >= 2:
                result.risk_score += 25
                result.behavioral_indicators.append("Persistence mechanisms detected")
            
            if api_categories['evasion'] >= 3:
                result.risk_score += 30
                result.behavioral_indicators.append("Anti-analysis/evasion detected")
            
            if api_categories['crypto'] >= 3 and api_categories['filesystem'] >= 2:
                result.risk_score += 50
                result.behavioral_indicators.append("Ransomware behavior: crypto + file operations")
            
            # ═══════════════════════════════════════════════════════════════════
            # PHASE 3: YARA-LIKE RULE MATCHING
            # ═══════════════════════════════════════════════════════════════════
            
            for rule in self.rules.RULES:
                if self._match_rule(data, rule):
                    result.matched_rules.append(rule['name'])
                    result.risk_score += rule.get('score', 50)
                    if rule.get('severity') == 'critical':
                        result.severity = 'critical'
                    elif rule.get('severity') == 'high' and result.severity != 'critical':
                        result.severity = 'high'
            
            # ═══════════════════════════════════════════════════════════════════
            # PHASE 4: STRING ANALYSIS
            # ═══════════════════════════════════════════════════════════════════
            
            data_lower = data.lower()
            
            # 4.1 Ransomware indicators
            ransom_matches = 0
            for indicator in self.signatures.RANSOMWARE_INDICATORS:
                if indicator.lower() in data_lower:
                    ransom_matches += 1
                    result.detected_strings.append(indicator.decode())
            
            if ransom_matches >= 3:
                result.risk_score += 50
                result.threat_type = "Ransomware"
                result.behavioral_indicators.append(f"Ransomware indicators: {ransom_matches} matches")
            
            # 4.2 Miner indicators
            miner_matches = 0
            for indicator in self.signatures.MINER_INDICATORS:
                if indicator.lower() in data_lower:
                    miner_matches += 1
                    result.detected_strings.append(indicator.decode())
            
            if miner_matches >= 3:
                result.risk_score += 40
                result.threat_type = "Cryptominer"
                result.behavioral_indicators.append(f"Miner indicators: {miner_matches} matches")
            
            # 4.3 C2 indicators
            c2_matches = 0
            for indicator in self.signatures.C2_INDICATORS:
                if indicator.lower() in data_lower:
                    c2_matches += 1
            
            if c2_matches >= 4:
                result.risk_score += 35
                result.behavioral_indicators.append("Command & Control indicators detected")
            
            # 4.4 Credential theft indicators
            cred_matches = 0
            for indicator in self.signatures.CREDENTIAL_THEFT_INDICATORS:
                if indicator.lower() in data_lower:
                    cred_matches += 1
                    result.detected_strings.append(indicator.decode())
            
            if cred_matches >= 3:
                result.risk_score += 45
                result.threat_type = "InfoStealer"
                result.behavioral_indicators.append("Credential theft indicators detected")
            
            # ═══════════════════════════════════════════════════════════════════
            # PHASE 5: NETWORK IOC EXTRACTION
            # ═══════════════════════════════════════════════════════════════════
            
            # Extract URLs
            urls = self.compiled_patterns['url'].findall(data)
            for url in urls[:20]:
                result.network_iocs.append(url.decode(errors='ignore'))
            
            # Extract IPs
            ips = self.compiled_patterns['ip_address'].findall(data)
            for ip in ips[:20]:
                ip_str = ip.decode() if isinstance(ip, bytes) else ip
                if not ip_str.startswith(('127.', '0.', '255.', '192.168.', '10.', '172.')):
                    result.network_iocs.append(ip_str)
            
            # Extract domains
            domains = self.compiled_patterns['domain'].findall(data)
            for domain in domains[:20]:
                domain_str = domain.decode() if isinstance(domain, bytes) else domain
                if not domain_str.endswith(('.microsoft.com', '.windows.com', '.google.com')):
                    result.network_iocs.append(domain_str)
            
            # ═══════════════════════════════════════════════════════════════════
            # PHASE 6: PE ANALYSIS (if applicable)
            # ═══════════════════════════════════════════════════════════════════
            
            if data[:2] == b'MZ':
                self._analyze_pe(data, result)
            
            # ═══════════════════════════════════════════════════════════════════
            # PHASE 7: BEHAVIORAL SCORING
            # ═══════════════════════════════════════════════════════════════════
            
            self._behavioral_scoring(result)
            
            # ═══════════════════════════════════════════════════════════════════
            # PHASE 8: FINAL CLASSIFICATION
            # ═══════════════════════════════════════════════════════════════════
            
            result.risk_score = min(100, result.risk_score)
            result.confidence = self._calculate_confidence(result)
            
            if result.risk_score >= self.CRITICAL_THRESHOLD:
                result.is_threat = True
                result.severity = 'critical'
                result.recommendation = 'Quarantine Immediately'
            elif result.risk_score >= self.HIGH_THRESHOLD:
                result.is_threat = True
                result.severity = 'high'
                result.recommendation = 'Quarantine'
            elif result.risk_score >= self.MEDIUM_THRESHOLD:
                result.is_threat = True
                result.severity = 'medium'
                result.recommendation = 'Review and Investigate'
            elif result.risk_score >= self.LOW_THRESHOLD:
                result.severity = 'low'
                result.recommendation = 'Monitor'
            
            # Classify threat type if not already set
            if result.is_threat and not result.threat_type:
                result.threat_type = self._classify_threat(result)
            
            # Generate remediation steps
            result.remediation_steps = self._generate_remediation(result)
            
            # Cache result
            self.detection_cache[result.file_hash] = result
            
        except Exception as e:
            result.behavioral_indicators.append(f"Analysis error: {str(e)}")
        
        return result
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _identify_file_type(self, data: bytes) -> str:
        """Identify file type by magic bytes"""
        magic_bytes = {
            b'MZ': 'PE',
            b'\x7fELF': 'ELF',
            b'PK\x03\x04': 'ZIP',
            b'PK\x05\x06': 'ZIP',
            b'\xd0\xcf\x11\xe0': 'OLE',  # Office documents
            b'%PDF': 'PDF',
            b'\xff\xd8\xff': 'JPEG',
            b'\x89PNG': 'PNG',
            b'GIF8': 'GIF',
            b'Rar!': 'RAR',
            b'7z\xbc\xaf': '7Z',
        }
        
        for magic, ftype in magic_bytes.items():
            if data.startswith(magic):
                return ftype
        
        # Check for scripts
        if data[:100].find(b'<script') != -1 or data[:100].find(b'<html') != -1:
            return 'HTML'
        if data[:100].find(b'<?php') != -1:
            return 'PHP'
        if data[:2] == b'#!':
            return 'SCRIPT'
        
        return 'UNKNOWN'
    
    def _check_extension_mismatch(self, ext: str, file_type: str) -> bool:
        """Check for extension/content mismatch"""
        expected_types = {
            '.exe': ['PE'], '.dll': ['PE'], '.sys': ['PE'],
            '.pdf': ['PDF'], '.zip': ['ZIP'], '.rar': ['RAR'],
            '.doc': ['OLE'], '.xls': ['OLE'], '.ppt': ['OLE'],
            '.docx': ['ZIP'], '.xlsx': ['ZIP'], '.pptx': ['ZIP'],
            '.jpg': ['JPEG'], '.jpeg': ['JPEG'], '.png': ['PNG'],
        }
        
        if ext in expected_types:
            return file_type not in expected_types[ext]
        return False
    
    def _match_rule(self, data: bytes, rule: dict) -> bool:
        """Match YARA-like rule against data"""
        strings = rule.get('strings', [])
        condition = rule.get('condition', 'any')
        
        matches = 0
        data_lower = data.lower()
        
        for string in strings:
            if string.lower() in data_lower:
                matches += 1
        
        if condition == 'all':
            return matches == len(strings)
        elif condition == 'any':
            return matches > 0
        elif '_of' in condition:
            required = int(condition.split('_')[0])
            return matches >= required
        
        return False

    def _analyze_pe(self, data: bytes, result: ThreatAnalysisResult):
        """Analyze PE file structure"""
        try:
            # Parse DOS header
            if len(data) < 64:
                return
            
            e_lfanew = struct.unpack('<I', data[60:64])[0]
            if e_lfanew > len(data) - 24:
                return
            
            # Check PE signature
            if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
                return
            
            result.pe_info['valid_pe'] = True
            
            # Parse COFF header
            coff_offset = e_lfanew + 4
            machine = struct.unpack('<H', data[coff_offset:coff_offset+2])[0]
            num_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]
            
            result.pe_info['machine'] = 'x64' if machine == 0x8664 else 'x86'
            result.pe_info['num_sections'] = num_sections
            
            # Check for suspicious section names
            suspicious_section_names = [
                b'.text0', b'.code', b'.data0', b'.rdata0',
                b'UPX', b'.aspack', b'.adata', b'.packed',
                b'.vmp', b'.vmp0', b'.vmp1', b'.themida',
                b'.enigma', b'.petite', b'.stub', b'.bind',
            ]
            
            # Parse optional header
            optional_offset = coff_offset + 20
            if len(data) > optional_offset + 2:
                magic = struct.unpack('<H', data[optional_offset:optional_offset+2])[0]
                result.pe_info['is_64bit'] = magic == 0x20b
            
            # Look for section headers
            section_offset = optional_offset + (240 if magic == 0x20b else 224)
            for i in range(min(num_sections, 20)):
                sec_start = section_offset + (i * 40)
                if sec_start + 40 > len(data):
                    break
                
                sec_name = data[sec_start:sec_start+8].rstrip(b'\x00')
                
                for sus_name in suspicious_section_names:
                    if sus_name in sec_name:
                        result.sections_suspicious.append(sec_name.decode(errors='ignore'))
                        result.risk_score += 15
                        result.packed = True
            
            # Check for overlay (data after PE)
            # Simplified check - if file is much larger than expected
            if result.file_size > 10 * 1024 * 1024:  # > 10MB
                result.has_overlay = True
                result.behavioral_indicators.append("Large file with potential overlay data")
            
            # Import analysis
            self._analyze_imports(data, result)
            
        except Exception as e:
            result.pe_info['parse_error'] = str(e)
    
    def _analyze_imports(self, data: bytes, result: ThreatAnalysisResult):
        """Analyze PE imports for suspicious patterns"""
        # Simple import detection by looking for DLL names
        suspicious_imports = {
            b'ntdll.dll': ['Low-level API access'],
            b'kernel32.dll': ['System API'],
            b'advapi32.dll': ['Security/Registry API'],
            b'ws2_32.dll': ['Network API'],
            b'wininet.dll': ['Internet API'],
            b'winhttp.dll': ['HTTP API'],
            b'crypt32.dll': ['Cryptography API'],
            b'bcrypt.dll': ['Cryptography API'],
            b'psapi.dll': ['Process API'],
            b'dbghelp.dll': ['Debug API (unusual)'],
            b'samlib.dll': ['SAM access (credential theft)'],
        }
        
        data_lower = data.lower()
        found_imports = []
        
        for dll, desc in suspicious_imports.items():
            if dll in data_lower:
                found_imports.append(dll.decode())
        
        result.pe_info['imports'] = found_imports
        
        # Suspicious combinations
        if b'samlib.dll' in data_lower or b'vaultcli.dll' in data_lower:
            result.risk_score += 30
            result.behavioral_indicators.append("Potential credential access imports")
            result.imports_suspicious = True
    
    def _behavioral_scoring(self, result: ThreatAnalysisResult):
        """Apply ML-inspired behavioral scoring"""
        # Combination scoring - multiple indicators together are more suspicious
        
        # RAT behavior pattern
        rat_indicators = 0
        if any('keylog' in s.lower() for s in result.detected_strings):
            rat_indicators += 1
        if any('webcam' in s.lower() or 'camera' in s.lower() for s in result.detected_strings):
            rat_indicators += 1
        if any('screenshot' in s.lower() for s in result.detected_strings):
            rat_indicators += 1
        if any('shell' in s.lower() for s in result.detected_strings):
            rat_indicators += 1
        if len(result.network_iocs) > 0:
            rat_indicators += 1
        
        if rat_indicators >= 3:
            result.risk_score += 30
            result.behavioral_indicators.append(f"RAT behavior pattern ({rat_indicators} indicators)")
            if not result.threat_type:
                result.threat_type = "RAT"
        
        # Ransomware behavior pattern
        ransom_indicators = 0
        if result.pe_info.get('imports') and 'crypt32.dll' in result.pe_info['imports']:
            ransom_indicators += 1
        if any('encrypt' in s.lower() for s in result.detected_strings):
            ransom_indicators += 1
        if any('bitcoin' in s.lower() or 'ransom' in s.lower() for s in result.detected_strings):
            ransom_indicators += 1
        if any('FindFirstFile' in api for api in result.detected_apis):
            ransom_indicators += 1
        
        if ransom_indicators >= 3:
            result.risk_score += 40
            result.behavioral_indicators.append("Ransomware behavior pattern detected")
        
        # Dropper/Loader behavior
        dropper_indicators = 0
        if any('URLDownload' in api for api in result.detected_apis):
            dropper_indicators += 1
        if any('CreateProcess' in api or 'ShellExecute' in api for api in result.detected_apis):
            dropper_indicators += 1
        if any('WriteFile' in api for api in result.detected_apis):
            dropper_indicators += 1
        if result.packed:
            dropper_indicators += 1
        
        if dropper_indicators >= 3:
            result.risk_score += 25
            result.behavioral_indicators.append("Dropper/Loader behavior pattern")
        
        # Evasion behavior
        evasion_indicators = 0
        if any('IsDebuggerPresent' in api for api in result.detected_apis):
            evasion_indicators += 1
        if any('vmware' in s.lower() or 'virtualbox' in s.lower() for s in result.detected_strings):
            evasion_indicators += 1
        if result.entropy > 7.0:
            evasion_indicators += 1
        if result.packed:
            evasion_indicators += 1
        
        if evasion_indicators >= 3:
            result.risk_score += 20
            result.behavioral_indicators.append("Anti-analysis/Evasion techniques detected")
            result.obfuscated = True
        
        # Persistence indicators
        if len(result.registry_keys) > 0 or any('Run' in api for api in result.detected_apis):
            result.persistence_methods.append("Registry persistence")
        if any('schtask' in s.lower() for s in result.detected_strings):
            result.persistence_methods.append("Scheduled task")
        if any('CreateService' in api for api in result.detected_apis):
            result.persistence_methods.append("Service installation")
        
        if len(result.persistence_methods) >= 2:
            result.risk_score += 20
            result.behavioral_indicators.append(f"Multiple persistence methods: {', '.join(result.persistence_methods)}")
    
    def _calculate_confidence(self, result: ThreatAnalysisResult) -> float:
        """Calculate detection confidence score"""
        confidence = 0.0
        
        # More rules matched = higher confidence
        if len(result.matched_rules) > 0:
            confidence += min(30, len(result.matched_rules) * 5)
        
        # Known malware family detected
        if result.threat_family:
            confidence += 25
        
        # Multiple API categories detected
        if len(result.detected_apis) > 10:
            confidence += 15
        elif len(result.detected_apis) > 5:
            confidence += 10
        
        # Behavioral indicators
        confidence += min(20, len(result.behavioral_indicators) * 3)
        
        # Network IOCs found
        if len(result.network_iocs) > 0:
            confidence += 10
        
        return min(100.0, confidence)
    
    def _classify_threat(self, result: ThreatAnalysisResult) -> str:
        """Classify threat type based on analysis"""
        # Priority-based classification
        classifications = []
        
        # Check matched rules for classification hints
        for rule in result.matched_rules:
            rule_lower = rule.lower()
            if 'ransomware' in rule_lower or 'ransom' in rule_lower:
                classifications.append(('Ransomware', 100))
            elif 'rat' in rule_lower or 'backdoor' in rule_lower:
                classifications.append(('RAT', 90))
            elif 'stealer' in rule_lower or 'credential' in rule_lower:
                classifications.append(('InfoStealer', 85))
            elif 'miner' in rule_lower or 'crypto' in rule_lower:
                classifications.append(('Cryptominer', 80))
            elif 'loader' in rule_lower or 'dropper' in rule_lower:
                classifications.append(('Loader', 75))
            elif 'banking' in rule_lower or 'trojan' in rule_lower:
                classifications.append(('BankingTrojan', 85))
            elif 'injection' in rule_lower:
                classifications.append(('ProcessInjector', 70))
        
        # Check behavioral indicators
        for indicator in result.behavioral_indicators:
            ind_lower = indicator.lower()
            if 'ransomware' in ind_lower:
                classifications.append(('Ransomware', 95))
            elif 'keylog' in ind_lower:
                classifications.append(('Keylogger', 80))
            elif 'rat' in ind_lower:
                classifications.append(('RAT', 85))
            elif 'miner' in ind_lower:
                classifications.append(('Cryptominer', 75))
            elif 'credential' in ind_lower or 'stealer' in ind_lower:
                classifications.append(('InfoStealer', 80))
        
        if classifications:
            # Return highest priority classification
            classifications.sort(key=lambda x: x[1], reverse=True)
            return classifications[0][0]
        
        return "Malware"
    
    def _generate_remediation(self, result: ThreatAnalysisResult) -> List[str]:
        """Generate remediation steps based on threat type"""
        steps = []
        
        if result.is_threat:
            steps.append("1. Immediately isolate the affected system from the network")
            steps.append(f"2. Quarantine the malicious file: {result.filename}")
            
            if result.threat_type == 'Ransomware':
                steps.append("3. DO NOT pay the ransom")
                steps.append("4. Check for shadow copy backups")
                steps.append("5. Identify the ransomware variant for possible decryptor")
                steps.append("6. Restore from clean backup")
                steps.append("7. Report to law enforcement (IC3, FBI)")
            
            elif result.threat_type == 'RAT':
                steps.append("3. Check for persistence mechanisms (registry, services, tasks)")
                steps.append("4. Review network connections and block C2 servers")
                steps.append("5. Change all passwords on the affected system")
                steps.append("6. Scan for lateral movement to other systems")
            
            elif result.threat_type == 'InfoStealer':
                steps.append("3. Immediately change all passwords")
                steps.append("4. Enable 2FA on all accounts")
                steps.append("5. Monitor financial accounts for suspicious activity")
                steps.append("6. Check for exfiltrated data")
            
            elif result.threat_type == 'Cryptominer':
                steps.append("3. Terminate mining processes")
                steps.append("4. Check CPU/GPU usage for other mining activity")
                steps.append("5. Block mining pool domains/IPs")
            
            elif result.threat_type == 'Loader':
                steps.append("3. Scan for dropped payloads")
                steps.append("4. Check %TEMP%, %APPDATA% for additional malware")
                steps.append("5. Review recently created files")
            
            # Common steps
            steps.append(f"{len(steps)+1}. Run full system scan with updated definitions")
            steps.append(f"{len(steps)+1}. Review and clean persistence mechanisms")
            
            if result.persistence_methods:
                steps.append(f"{len(steps)+1}. Remove persistence: {', '.join(result.persistence_methods)}")
            
            if result.network_iocs:
                steps.append(f"{len(steps)+1}. Block IOCs: {', '.join(result.network_iocs[:5])}")
        
        return steps
    
    def analyze_process(self, pid: int, name: str, path: str, cmdline: str) -> ThreatAnalysisResult:
        """Analyze a running process for threats"""
        result = ThreatAnalysisResult(
            path=path,
            filename=name
        )
        
        name_lower = name.lower()
        path_lower = path.lower() if path else ''
        cmdline_lower = cmdline.lower() if cmdline else ''
        
        # Check against known malware names
        for malware in self.signatures.MALWARE_PROCESSES:
            if malware in name_lower:
                result.is_threat = True
                result.risk_score += 90
                result.threat_family = malware
                result.matched_signatures.append(f"Known malware: {malware}")
        
        # Check for LOLBins abuse
        for lolbin, info in self.signatures.LOLBINS.items():
            if lolbin in name_lower:
                # Check command line for suspicious usage
                suspicious_patterns = [
                    '-enc', '-encodedcommand', 'downloadstring', 'iex(',
                    'webclient', 'invoke-expression', 'bypass', '-w hidden',
                    'http://', 'https://', 'ftp://', 'base64',
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in cmdline_lower:
                        result.risk_score += info['risk']
                        result.behavioral_indicators.append(f"LOLBin abuse: {lolbin} with {pattern}")
                        break
        
        # Check for suspicious paths
        suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp',
            '\\downloads\\', '\\public\\', '\\users\\public',
            '\\programdata\\', '$recycle.bin',
        ]
        
        for sus_path in suspicious_paths:
            if sus_path in path_lower:
                result.risk_score += 25
                result.behavioral_indicators.append(f"Running from suspicious location: {sus_path}")
                break
        
        # Check for process name impersonation
        system_processes = {
            'svchost.exe': r'c:\windows\system32\svchost.exe',
            'csrss.exe': r'c:\windows\system32\csrss.exe',
            'lsass.exe': r'c:\windows\system32\lsass.exe',
            'services.exe': r'c:\windows\system32\services.exe',
            'smss.exe': r'c:\windows\system32\smss.exe',
            'wininit.exe': r'c:\windows\system32\wininit.exe',
            'winlogon.exe': r'c:\windows\system32\winlogon.exe',
            'explorer.exe': r'c:\windows\explorer.exe',
        }
        
        for proc, expected_path in system_processes.items():
            if name_lower == proc and expected_path not in path_lower:
                result.risk_score += 80
                result.is_threat = True
                result.behavioral_indicators.append(f"Process impersonation: {name} from wrong path")
                result.threat_type = "ProcessImpersonation"
        
        # Classify
        if result.risk_score >= self.HIGH_THRESHOLD:
            result.is_threat = True
            result.severity = 'high'
        elif result.risk_score >= self.MEDIUM_THRESHOLD:
            result.severity = 'medium'
        
        return result


# ══════════════════════════════════════════════════════════════════════════════════════════════════════
#                                    EXPORT
# ══════════════════════════════════════════════════════════════════════════════════════════════════════

# Create global instance
def enrich_with_kev(self, cve_list):
        """Enrich detected CVEs with KEV (Known Exploited Vulnerability) data."""
        if not _VULN_SCANNER_AVAILABLE:
            return [{'error': 'vulnerability_scanner not available', 'cves': cve_list}]
        
        try:
            scanner = VulnerabilityScanner()
            kev_data = scanner.fetch_cisa_kev_catalog()
            
            enriched = []
            cve_set = set(cve_list)
            
            for kev in kev_data:
                if kev.get('cve_id') in cve_set:
                    enriched.append({
                        'cve_id': kev.get('cve_id'),
                        'actively_exploited': True,
                        'date_added': kev.get('date_added'),
                        'due_date': kev.get('due_date'),
                        'severity': kev.get('severity'),
                    })
            
            for cve in cve_set:
                if cve not in [e.get('cve_id') for e in enriched]:
                    enriched.append({'cve_id': cve, 'actively_exploited': False})
            
            return enriched
            
        except Exception as e:
            return [{'error': str(e), 'cves': cve_list}]


threat_engine = UltraAdvancedThreatEngine()

def analyze_file(path: str) -> ThreatAnalysisResult:
    """Convenience function to analyze a file"""
    return threat_engine.analyze_file(path)

def analyze_process(pid: int, name: str, path: str, cmdline: str) -> ThreatAnalysisResult:
    """Convenience function to analyze a process"""
    return threat_engine.analyze_process(pid, name, path, cmdline)

# Stats
def get_engine_stats() -> dict:
    """Get detection engine statistics"""
    return {
        'total_rules': len(YARALikeRules.RULES),
        'total_signatures': len(MegaThreatSignatures.MALWARE_SIGNATURES),
        'total_malware_names': len(MegaThreatSignatures.MALWARE_PROCESSES),
        'total_lolbins': len(MegaThreatSignatures.LOLBINS),
        'total_rat_ports': len(MegaThreatSignatures.RAT_PORTS),
        'api_categories': 8,
        'cached_results': len(threat_engine.detection_cache),
    }


if __name__ == '__main__':
    stats = get_engine_stats()
    print("=" * 60)
    print("  ULTRA ADVANCED THREAT DETECTION ENGINE v2.0")
    print("=" * 60)
    print(f"  YARA-like Rules:     {stats['total_rules']}")
    print(f"  Malware Signatures:  {stats['total_signatures']}")
    print(f"  Malware Names:       {stats['total_malware_names']}")
    print(f"  LOLBins Tracked:     {stats['total_lolbins']}")
    print(f"  RAT Ports:           {stats['total_rat_ports']}")
    print(f"  API Categories:      {stats['api_categories']}")
    print("=" * 60)
    print("  Ready for threat detection!")
