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
