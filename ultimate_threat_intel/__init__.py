"""Runtime support for Downpour's threat-feed aggregation pipeline."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Dict, Iterable, List, Optional


class ThreatCategory:
    MALWARE = "malware"
    NETWORK = "network"
    NETWORK_C2 = "network_c2"
    PHISHING = "phishing"
    EXPLOIT = "exploit"
    TECHNIQUE = "technique"
    TOOL = "tool"
    MALWARE_RANSOMWARE = "malware_ransomware"
    MALWARE_MINER = "malware_miner"
    MALWARE_STEALER = "malware_stealer"


class ThreatSeverity:
    LOW = 10
    MEDIUM = 40
    HIGH = 70
    CRITICAL = 90


@dataclass
class ThreatIndicator:
    value: str
    indicator_type: str
    category: str
    severity: int
    confidence: int
    subcategory: str = ""
    source: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatActor:
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    techniques: List[str] = field(default_factory=list)


@dataclass
class AttackPattern:
    name: str
    techniques: List[str] = field(default_factory=list)


class ThreatFeedRegistry:
    """The feed configurations consumed by :mod:`threat_feed_aggregator`."""

    FEEDS: ClassVar[Dict[str, Dict[str, Any]]] = {
        "urlhaus": {"url": "https://urlhaus.abuse.ch/downloads/csv_recent/", "type": "urlhaus", "priority": "high"},
        "feodo_tracker": {"url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", "type": "ip", "priority": "high"},
        "feodo_ip": {"url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", "type": "ip", "priority": "high"},
        "feodo_botnet_cc": {"url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", "type": "ip", "priority": "high"},
        "malware_bazaar": {"url": "https://bazaar.abuse.ch/export/csv/recent/", "type": "malwarebazaar", "priority": "high"},
        "threatfox": {"url": "https://threatfox.abuse.ch/export/json/recent/", "type": "threatfox", "priority": "high"},
        "ssl_blacklist": {"url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", "type": "ip", "priority": "medium"},
        "ssl_blacklist_ag": {"url": "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv", "type": "ip", "priority": "medium"},
        "drop": {"url": "https://www.spamhaus.org/drop/drop.txt", "type": "ip", "priority": "high"},
        "edrop": {"url": "https://www.spamhaus.org/drop/edrop.txt", "type": "ip", "priority": "high"},
        "phishtank": {"url": "https://data.phishtank.com/data/online-valid.csv", "type": "phishtank", "priority": "high"},
        "openphish": {"url": "https://openphish.com/feed.txt", "type": "url", "priority": "high"},
        "phishing_army": {"url": "https://phishing.army/download/phishing_army_blocklist.txt", "type": "domain", "priority": "high"},
        "phishing_army_ex": {"url": "https://phishing.army/download/phishing_army_blocklist_extended.txt", "type": "domain", "priority": "medium"},
        "malpedia": {"url": "https://malpedia.caad.fkie.fraunhofer.de/api/", "type": "domain", "priority": "low"},
        "malshare": {"url": "https://malshare.com/api/", "type": "domain", "priority": "low"},
        "virusshare": {"url": "https://virusshare.com/recent/", "type": "domain", "priority": "low"},
        "malware_traffic_analysis": {"url": "https://malware-traffic-analysis.net/blog/", "type": "domain", "priority": "low"},
        "foxit_cobaltstrike": {"url": "https://raw.githubusercontent.com/fox-it/cobaltstrike/master/cobaltstrike.csv", "type": "domain", "priority": "medium"},
        "hagezi_light": {"url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/light.txt", "type": "domain", "priority": "medium"},
        "stevenblack": {"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "type": "domain", "priority": "medium"},
        "adguard_dns": {"url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "type": "domain", "priority": "medium"},
        "abuseipdb": {"url": "https://www.abuseipdb.com/download/representative", "type": "ip", "priority": "medium"},
        "binary_defense": {"url": "https://www.binarydefense.com/banlist.txt", "type": "ip", "priority": "medium"},
        "cinsscore": {"url": "https://cinsscore.com/list/ci-badguys.txt", "type": "ip", "priority": "medium"},
        "blocklist_de": {"url": "https://lists.blocklist.de/lists/all.txt", "type": "ip", "priority": "medium"},
        "blocklist_de_all": {"url": "https://lists.blocklist.de/lists/all.txt", "type": "ip", "priority": "medium"},
        "official_rules": {"url": "https://github.com/Yara-Rules/rules/archive/master.zip", "type": "domain", "priority": "low"},
        "malpedia_yara": {"url": "https://malpedia.caad.fkie.fraunhofer.de/api/yara/", "type": "domain", "priority": "low"},
        "cisa_kev": {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "vulnerability", "priority": "high"},
        "nvd_cve": {"url": "https://nvd.nist.gov/feeds/json/cve/1.1/", "type": "domain", "priority": "low"},
        "exploitdb": {"url": "https://www.exploit-db.com/download.csv", "type": "domain", "priority": "low"},
        "circl_misp": {"url": "https://www.circl.lu/misp/feed/", "type": "domain", "priority": "low"},
        "misp_project": {"url": "https://www.misp-project.org/feeds/", "type": "domain", "priority": "low"},
        "alienvault_otx": {"url": "https://otx.alienvault.com/api/v1/pulses/subscribed", "type": "alienvault", "priority": "high"},
        "ibm_xforce": {"url": "https://api.xforce.ibmcloud.com/ipr/reputation", "type": "ip", "priority": "high"},
        "hybrid_analysis": {"url": "https://www.hybrid-analysis.com/feed/", "type": "domain", "priority": "medium"},
        "cisco_talos": {"url": "https://www.talosintelligence.com/documents/ip-filter-bl", "type": "ip", "priority": "high"},
        "emerging_threats": {"url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "type": "ip", "priority": "high"},
        "bambenek_consulting": {"url": "https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt", "type": "ip", "priority": "high"},
        "zeus_tracker": {"url": "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist", "type": "ip", "priority": "high"},
        "palevo_tracker": {"url": "https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist", "type": "ip", "priority": "high"},
        "ransomware_tracker": {"url": "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt", "type": "ip", "priority": "high"},
        "cybercrime_tracker": {"url": "https://cybercrime-tracker.net/ccpmgate.php", "type": "domain", "priority": "medium"},
        "malc0de": {"url": "https://malc0de.com/bl/IP_Blacklist.txt", "type": "ip", "priority": "medium"},
        "threatminer": {"url": "https://api.threatminer.org/v2/", "type": "domain", "priority": "low"},
        "fraudguard": {"url": "https://api.fraudguard.io/ip/", "type": "ip", "priority": "medium"},
        "dshield": {"url": "https://www.dshield.org/feeds/suspiciousdomains_High.txt", "type": "domain", "priority": "high"},
        "firehol": {"url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "type": "ip", "priority": "high"},
        "cleanmx": {"url": "https://clean-mx.de/rss?scope=viruses&format=csv", "type": "domain", "priority": "medium"},
        "malware_domain_list": {"url": "https://www.malwaredomainlist.com/hostslist/hosts.txt", "type": "domain", "priority": "medium"},
        "blocklist_de_apache": {"url": "https://lists.blocklist.de/lists/apache.txt", "type": "ip", "priority": "medium"},
        "blocklist_de_ssh": {"url": "https://lists.blocklist.de/lists/ssh.txt", "type": "ip", "priority": "medium"},
        "blocklist_de_ftp": {"url": "https://lists.blocklist.de/lists/ftp.txt", "type": "ip", "priority": "medium"},
        "blocklist_de_bots": {"url": "https://lists.blocklist.de/lists/bots.txt", "type": "ip", "priority": "high"},
        "blocklist_de_bruteforce": {"url": "https://lists.blocklist.de/lists/bruteforce.txt", "type": "ip", "priority": "high"},
        "spamhaus_drop": {"url": "https://www.spamhaus.org/drop/drop.txt", "type": "ip", "priority": "high"},
        "spamhaus_edrop": {"url": "https://www.spamhaus.org/drop/edrop.txt", "type": "ip", "priority": "high"},
        "spamhaus_dnsbl": {"url": "https://www.spamhaus.org/drop/drop.txt", "type": "ip", "priority": "high"},
        "ipinsights_blocklist": {"url": "https://www.ipinsights.io/blocklist.php", "type": "ip", "priority": "high"},
        "nvd_cve_modified": {"url": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz", "type": "vulnerability", "priority": "high"},
        "nvd_cve_recent": {"url": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz", "type": "vulnerability", "priority": "high"},
        "cisa_alerts": {"url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "type": "vulnerability", "priority": "high"},
        "phishunt_feed": {"url": "https://phishunt.io/feed.txt", "type": "phishing", "priority": "high"},
        "spamhaus_xbl": {"url": "https://www.spamhaus.org/drop/edrop.txt", "type": "ip", "priority": "high"},
        "spamhaus_pbl": {"url": "https://www.spamhaus.org/drop/edrop.txt", "type": "ip", "priority": "medium"},
        "misp_galaxy": {"url": "https://www.misp-project.org/galaxy/", "type": "domain", "priority": "medium"},
        "misp_warninglists": {"url": "https://www.misp-project.org/warninglists/", "type": "domain", "priority": "medium"},
        "rodanmaharjan_malicious_ip": {"url": "https://raw.githubusercontent.com/rodanmaharjan/ThreatIntelligence/main/Malicious%20IP.txt", "type": "ip", "priority": "high"},
        "rodanmaharjan_phishing_domains": {"url": "https://raw.githubusercontent.com/rodanmaharjan/ThreatIntelligence/main/Phishing_Domains.txt", "type": "domain", "priority": "high"},
        "rodanmaharjan_c2_feed": {"url": "https://raw.githubusercontent.com/rodanmaharjan/ThreatIntelligence/main/C2%20Feed.txt", "type": "ip", "priority": "high"},
        "cisa_vulnrichment": {"url": "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/", "type": "vulnerability", "priority": "high"},
        "mitre_attack_enterprise": {"url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", "type": "technique", "priority": "high"},
        "codeberg_cpdc2026_suspicious_ip": {"url": "https://codeberg.org/cpdc2026/ThreatIntelligence/raw/branch/main/edl_suspicious_ip.txt", "type": "ip", "priority": "high"},
        "codeberg_cpdc2026_suspicious_domain": {"url": "https://codeberg.org/cpdc2026/ThreatIntelligence/raw/branch/main/edl_suspicious_domain.txt", "type": "domain", "priority": "high"},
        "codeberg_cpdc2026_suspicious_ip2": {"url": "https://codeberg.org/cpdc2026/ThreatIntelligence/raw/branch/main/edl_suspicious_ip-2.txt", "type": "ip", "priority": "high"},
        "greynoise_community": {"url": "https://api.greynoise.io/v3/community/", "type": "ip", "priority": "medium"},
        "pulsedive_feed": {"url": "https://pulsedive.com/api/feed.php", "type": "ip", "priority": "medium"},
        "urlscanio_feed": {"url": "https://urlscan.io/api/v1/search/?q=*", "type": "domain", "priority": "medium"},
        "threatintel_platform": {"url": "https://threatintel.platform/", "type": "domain", "priority": "low"},
        "vt_popular_threat": {"url": "https://www.virustotal.com/api/v3/intelligence/hunting?q=type:pe+positives:5+", "type": "malware", "priority": "high"},
        "hybrid_analysis_popular": {"url": "https://www.hybrid-analysis.com/feed/", "type": "malware", "priority": "high"},
        "any_run_popular": {"url": "https://api.any.run/v1/analysis/", "type": "malware", "priority": "high"},
        "joe_sandbox_popular": {"url": "https://jbxcloud.joesecurity.org/api/", "type": "malware", "priority": "high"},
        "cape_sandbox": {"url": "https://capesandbox.com/api/v1/", "type": "malware", "priority": "medium"},
        "malshare_recent": {"url": "https://malshare.com/recent/", "type": "malware", "priority": "high"},
        "virusshare_recent": {"url": "https://virusshare.com/recent/", "type": "malware", "priority": "medium"},
        "malsign": {"url": "https://www.malsign.com/api/", "type": "malware", "priority": "medium"},
        "threatminer_malware": {"url": "https://api.threatminer.org/v2/malware.php", "type": "malware", "priority": "medium"},
        "malsynapse": {"url": "https://malsynapse.com/api/", "type": "malware", "priority": "medium"},
        "polyswarm": {"url": "https://api.polyswarm.io/v1/", "type": "malware", "priority": "medium"},
        "malsign_recent": {"url": "https://malsign.com/recent/", "type": "malware", "priority": "medium"},
        "urlscan_recent": {"url": "https://urlscan.io/api/v1/search/?q=*", "type": "url", "priority": "high"},
        "phishtank_recent": {"url": "https://data.phishtank.com/data/online-valid.csv", "type": "phishing", "priority": "high"},
        "openphish_recent": {"url": "https://openphish.com/feed.txt", "type": "phishing", "priority": "high"},
        "phishunt_recent": {"url": "https://phishunt.io/feed.txt", "type": "phishing", "priority": "high"},
        "spamhaus_phish": {"url": "https://www.spamhaus.org/drop/edrop.txt", "type": "phishing", "priority": "high"},
        "phishtank_verified": {"url": "https://data.phishtank.com/data/verified-online.csv", "type": "phishing", "priority": "high"},
        "openphish_verified": {"url": "https://openphish.com/feed-verified.txt", "type": "phishing", "priority": "high"},
        "phishing_army": {"url": "https://phishing.army/download/phishing_army_blocklist.txt", "type": "phishing", "priority": "high"},
        "phishing_army_extended": {"url": "https://phishing.army/download/phishing_army_blocklist_extended.txt", "type": "phishing", "priority": "medium"},
        "certstream": {"url": "https://certstream.calidog.io/", "type": "domain", "priority": "high"},
        "censys_certificates": {"url": "https://search.censys.io/api/v2/certificates/search", "type": "domain", "priority": "high"},
        "censys_hosts": {"url": "https://search.censys.io/api/v2/hosts/search", "type": "domain", "priority": "high"},
        "shodan_hosts": {"url": "https://api.shodan.io/shodan/host/search", "type": "domain", "priority": "high"},
        "binaryedge_hosts": {"url": "https://api.binaryedge.io/v2/query/search", "type": "domain", "priority": "high"},
        "fofa_hosts": {"url": "https://fofa.info/api/v1/search/all", "type": "domain", "priority": "high"},
        "zoomeye_hosts": {"url": "https://api.zoomeye.ai/v2/search", "type": "domain", "priority": "medium"},
        "onyphe_hosts": {"url": "https://www.onyphe.io/api/v2/simple/", "type": "domain", "priority": "medium"},
        "netlas_hosts": {"url": "https://app.netlas.io/api/", "type": "domain", "priority": "medium"},
        "criminalip_hosts": {"url": "https://api.criminalip.io/v1/banner/search", "type": "domain", "priority": "medium"},
        "hunterio_hosts": {"url": "https://api.hunter.io/v2/", "type": "domain", "priority": "medium"},
        "securitytrails_hosts": {"url": "https://api.securitytrails.com/v1/", "type": "domain", "priority": "medium"},
        "circl_lu_passive_dns": {"url": "https://www.circl.lu/pdns/query/", "type": "domain", "priority": "high"},
        "circl_lu_ssl": {"url": "https://www.circl.lu/ssl/query/", "type": "domain", "priority": "medium"},
        "dnsdb_passive_dns": {"url": "https://api.dnsdb.info/", "type": "domain", "priority": "medium"},
        "farsight_passive_dns": {"url": "https://api.dnsdb.info/dnsdb/v2/", "type": "domain", "priority": "medium"},
        "riskiq_passive_dns": {"url": "https://api.riskiq.net/", "type": "domain", "priority": "medium"},
        "spyse_passive_dns": {"url": "https://api.spyse.com/v4/data/", "type": "domain", "priority": "medium"},
        "dnstable": {"url": "https://api.dnstable.com/", "type": "domain", "priority": "medium"},
        "dnstable_api": {"url": "https://api.dnstable.com/dnsdb/v2/", "type": "domain", "priority": "medium"},
        "stix_taxii_misp": {"url": "https://misp-project.org/taxii/", "type": "misp", "priority": "medium"},
        "opencti_taxii": {"url": "https://demo.opencti.io/taxii/", "type": "misp", "priority": "medium"},
        "eclecticiq_taxii": {"url": "https://platform.eclecticiq.com/taxii/", "type": "misp", "priority": "medium"},
        "mitre_cti": {"url": "https://github.com/mitre/cti", "type": "technique", "priority": "high"},
        "mitre_attack_mobile": {"url": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json", "type": "technique", "priority": "high"},
        "mitre_attack_ics": {"url": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json", "type": "technique", "priority": "high"},
        "mitre_attack_enterprise_stix": {"url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", "type": "technique", "priority": "high"},
        "capec": {"url": "https://raw.githubusercontent.com/mitre/cti/master/capec/capec.json", "type": "technique", "priority": "high"},
        "cwe": {"url": "https://cwe.mitre.org/data/xml/", "type": "technique", "priority": "high"},
        "attack_flow": {"url": "https://github.com/center-for-threat-informed-defense/attack-flow", "type": "technique", "priority": "medium"},
        "cve_org": {"url": "https://cve.org/api/", "type": "vulnerability", "priority": "high"},
        "nvd_api": {"url": "https://services.nvd.nist.gov/rest/json/cves/2.0/", "type": "vulnerability", "priority": "high"},
        "kev_catalog": {"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "type": "vulnerability", "priority": "high"},
        "epss_scores": {"url": "https://api.first.org/data/v1/epss", "type": "vulnerability", "priority": "high"},
        "exploit_db": {"url": "https://www.exploit-db.com/download.csv", "type": "exploit", "priority": "high"},
        "metasploit_modules": {"url": "https://github.com/rapid7/metasploit-framework/tree/master/modules", "type": "exploit", "priority": "medium"},
        "nuclei_templates": {"url": "https://github.com/projectdiscovery/nuclei-templates", "type": "exploit", "priority": "high"},
        "poc_github": {"url": "https://github.com/nomi-sec/PoC-in-GitHub", "type": "exploit", "priority": "high"},
        "0day_today": {"url": "https://0day.today/", "type": "exploit", "priority": "high"},
        "packetstorm": {"url": "https://packetstormsecurity.com/files/tags/exploit/", "type": "exploit", "priority": "medium"},
        "exploit_db_github": {"url": "https://github.com/offensive-security/exploitdb", "type": "exploit", "priority": "high"},
        "cisa_alerts_rss": {"url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "type": "vulnerability", "priority": "high"},
        "cert_eu_alerts": {"url": "https://cert.europa.eu/rss.xml", "type": "vulnerability", "priority": "medium"},
        "uscert_alerts": {"url": "https://www.us-cert.gov/ncas/alerts.xml", "type": "vulnerability", "priority": "high"},
        "msrc_alerts": {"url": "https://msrc.microsoft.com/update-guide/rss", "type": "vulnerability", "priority": "high"},
        "adobe_alerts": {"url": "https://helpx.adobe.com/security/rss.xml", "type": "vulnerability", "priority": "medium"},
        "oracle_alerts": {"url": "https://www.oracle.com/security-alerts/rss.xml", "type": "vulnerability", "priority": "medium"},
        "cisco_alerts": {"url": "https://tools.cisco.com/security/center/alerts.rss", "type": "vulnerability", "priority": "high"},
        "vmware_alerts": {"url": "https://www.vmware.com/security/advisories.rss", "type": "vulnerability", "priority": "medium"},
        "dell_alerts": {"url": "https://www.dell.com/support/security/en-us/rss", "type": "vulnerability", "priority": "medium"},
        "hp_alerts": {"url": "https://support.hp.com/rss/security.xml", "type": "vulnerability", "priority": "medium"},
        "ibm_alerts": {"url": "https://www.ibm.com/security/vulnerabilities/rss.xml", "type": "vulnerability", "priority": "medium"},
        "redhat_alerts": {"url": "https://access.redhat.com/security/security-updates/rss", "type": "vulnerability", "priority": "medium"},
        "ubuntu_alerts": {"url": "https://ubuntu.com/security/notices/rss.xml", "type": "vulnerability", "priority": "medium"},
        "debian_alerts": {"url": "https://www.debian.org/security/dsa.rss", "type": "vulnerability", "priority": "medium"},
        "gentoo_alerts": {"url": "https://www.gentoo.org/security/glsa.rss", "type": "vulnerability", "priority": "medium"},
        "arch_alerts": {"url": "https://archlinux.org/feeds/security/", "type": "vulnerability", "priority": "medium"},
        "fedora_alerts": {"url": "https://fedoraproject.org/wiki/Security/Advisories/rss", "type": "vulnerability", "priority": "medium"},
        "suse_alerts": {"url": "https://www.suse.com/support/security/", "type": "vulnerability", "priority": "medium"},
            }

    @classmethod
    def get_enabled_feeds(cls) -> Dict[str, Dict[str, Any]]:
        return {name: dict(config) for name, config in cls.FEEDS.items() if config.get("enabled", True)}


class ThreatDatabase:
    """Small SQLite store shared by the feed aggregator and detection engine."""

    def __init__(self, db_path: Optional[str | Path] = None):
        self.db_path = Path(db_path or Path("downpour_data") / "ultimate_threat_intel.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._initialize()

    def _initialize(self) -> None:
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS indicators (
                    value TEXT COLLATE NOCASE NOT NULL,
                    indicator_type TEXT NOT NULL,
                    category TEXT NOT NULL,
                    subcategory TEXT NOT NULL DEFAULT '',
                    severity INTEGER NOT NULL,
                    confidence INTEGER NOT NULL,
                    source TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    tags TEXT NOT NULL DEFAULT '[]',
                    metadata TEXT NOT NULL DEFAULT '{}',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (value, indicator_type)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS feed_status (
                    feed_id TEXT PRIMARY KEY,
                    last_update TEXT NOT NULL,
                    last_success TEXT,
                    records_added INTEGER NOT NULL DEFAULT 0,
                    records_total INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL
                )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(indicator_type)")

    def add_indicators_bulk(self, indicators: Iterable[ThreatIndicator]) -> int:
        added = 0
        now = datetime.now().isoformat()
        with self.lock, sqlite3.connect(self.db_path) as conn:
            for indicator in indicators:
                value = str(indicator.value).strip()
                indicator_type = str(indicator.indicator_type).strip().lower()
                if not value or not indicator_type:
                    continue
                exists = conn.execute(
                    "SELECT 1 FROM indicators WHERE value=? AND indicator_type=?",
                    (value, indicator_type),
                ).fetchone()
                conn.execute(
                    """INSERT INTO indicators (
                        value, indicator_type, category, subcategory, severity, confidence,
                        source, description, tags, metadata, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(value, indicator_type) DO UPDATE SET
                        category=excluded.category, subcategory=excluded.subcategory,
                        severity=excluded.severity, confidence=excluded.confidence,
                        source=excluded.source, description=excluded.description,
                        tags=excluded.tags, metadata=excluded.metadata, last_seen=excluded.last_seen""",
                    (
                        value, indicator_type, str(indicator.category), str(indicator.subcategory),
                        int(indicator.severity), int(indicator.confidence), str(indicator.source),
                        str(indicator.description), json.dumps(indicator.tags, default=str),
                        json.dumps(indicator.metadata, default=str), now, now,
                    ),
                )
                added += int(exists is None)
        return added

    def check_indicator(self, value: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        with self.lock, sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """SELECT category, subcategory, severity, confidence, source, description,
                           tags, metadata, first_seen, last_seen
                    FROM indicators WHERE value=? AND indicator_type=?""",
                (str(value).strip(), str(indicator_type).strip().lower()),
            ).fetchone()
        if row is None:
            return None
        try:
            tags = json.loads(row[6])
        except (TypeError, ValueError):
            tags = []
        try:
            metadata = json.loads(row[7])
        except (TypeError, ValueError):
            metadata = {}
        return {
            "category": row[0], "subcategory": row[1], "severity": row[2],
            "confidence": row[3], "source": row[4], "description": row[5],
            "tags": tags, "metadata": metadata, "first_seen": row[8], "last_seen": row[9],
        }

    def get_statistics(self) -> Dict[str, Any]:
        with self.lock, sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            by_type = dict(conn.execute(
                "SELECT indicator_type, COUNT(*) FROM indicators GROUP BY indicator_type"
            ).fetchall())
        return {"total_indicators": total, "indicators_by_type": by_type}

    def get_indicator_sources(self, value: str, indicator_type: str) -> List[str]:
        """Get list of unique sources that have reported this indicator.
        Used for corroboration gate (TASK-013): require 2+ sources before auto-action.
        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT DISTINCT source FROM indicators WHERE value=? AND indicator_type=?",
                (str(value).strip(), str(indicator_type).strip().lower()),
            ).fetchall()
        return [row[0] for row in rows if row[0]]


_database: Optional[ThreatDatabase] = None
_database_lock = threading.Lock()


def get_database() -> ThreatDatabase:
    global _database
    with _database_lock:
        if _database is None:
            _database = ThreatDatabase()
        return _database
