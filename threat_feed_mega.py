"""
Downpour Threat Feed Mega Module
Version: 29 (Titanium)
Description: Unified mega-feed module integrating 15+ free and API-based threat intelligence sources.
"""

import logging
import threading
import time
import hashlib
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None

# Initialize logger
logger = logging.getLogger('Downpour.MegaFeed')

def _safe_log(msg: str, exc: Exception = None):
    if exc:
        logger.error(f"{msg}: {str(exc)}")
    else:
        logger.error(msg)

@dataclass
class ThreatFeedResult:
    indicator: str
    indicator_type: str  # ip, domain, url, hash, cve, asn, email, password, onion, text
    source: str
    confidence: int  # 0-100
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SharedHttpInfrastructure:
    """Thread-safe shared HTTP session with retries and connection pooling."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(SharedHttpInfrastructure, cls).__new__(cls)
                cls._instance.init_session()
            return cls._instance

    def init_session(self):
        self.session = None
        if requests is None:
            _safe_log("requests library is not available.")
            return

        self.session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        # Connection pooling
        adapter = HTTPAdapter(
            pool_connections=10, 
            pool_maxsize=20, 
            max_retries=retry_strategy
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Caching dictionaries
        self.etag_cache: Dict[str, str] = {}
        self.last_modified_cache: Dict[str, str] = {}
        
        # Health tracking
        self.feed_health: Dict[str, Dict[str, Any]] = {}
        self.health_lock = threading.Lock()

    def get_session(self):
        return self.session
        
    def update_health(self, source: str, status: str, last_check: float, error: Optional[str] = None):
        with self.health_lock:
            self.feed_health[source] = {
                "status": status,
                "last_check": last_check,
                "error": error
            }

    def get_health(self) -> Dict[str, Dict[str, Any]]:
        with self.health_lock:
            return self.feed_health.copy()


class BaseFeedClient:
    def __init__(self, name: str, api_key: Optional[str] = None):
        self.name = name
        self.api_key = api_key
        self.http = SharedHttpInfrastructure()
        
    def _get(self, url: str, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        session = self.http.get_session()
        if not session:
            return None
            
        # Add caching headers if available
        req_headers = headers or {}
        if url in self.http.etag_cache:
            req_headers['If-None-Match'] = self.http.etag_cache[url]
        if url in self.http.last_modified_cache:
            req_headers['If-Modified-Since'] = self.http.last_modified_cache[url]
            
        try:
            response = session.get(url, headers=req_headers, params=params, timeout=10)
            
            # Update caches if successful
            if response.status_code == 200:
                if 'ETag' in response.headers:
                    self.http.etag_cache[url] = response.headers['ETag']
                if 'Last-Modified' in response.headers:
                    self.http.last_modified_cache[url] = response.headers['Last-Modified']
                    
            self.http.update_health(self.name, "healthy" if response.status_code in [200, 304] else f"error: {response.status_code}", time.time())
            return response
        except Exception as e:
            self.http.update_health(self.name, "offline", time.time(), str(e))
            _safe_log(f"Error fetching from {self.name}", e)
            return None


class ShodanInternetDB(BaseFeedClient):
    def __init__(self):
        super().__init__("ShodanInternetDB")
        
    def check_ip(self, ip: str) -> Optional[ThreatFeedResult]:
        url = f"https://internetdb.shodan.io/{ip}"
        res = self._get(url)
        if res and res.status_code == 200:
            data = res.json()
            return ThreatFeedResult(
                indicator=ip,
                indicator_type="ip",
                source=self.name,
                confidence=90,
                tags=data.get("tags", []),
                metadata={
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", [])
                }
            )
        return None


class GreyNoiseCommunity(BaseFeedClient):
    def __init__(self, api_key: str):
        super().__init__("GreyNoiseCommunity", api_key)
        
    def check_ip(self, ip: str) -> Optional[ThreatFeedResult]:
        if not self.api_key:
            return None
        url = f"https://api.greynoise.io/v3/community/{ip}"
        res = self._get(url, headers={"key": self.api_key})
        if res and res.status_code == 200:
            data = res.json()
            return ThreatFeedResult(
                indicator=ip,
                indicator_type="ip",
                source=self.name,
                confidence=85 if data.get("riot") else 50,
                metadata=data
            )
        return None


class PulsediveClient(BaseFeedClient):
    def __init__(self, api_key: str):
        super().__init__("PulsediveClient", api_key)
        
    def check_indicator(self, indicator: str, indicator_type: str) -> Optional[ThreatFeedResult]:
        if not self.api_key:
            return None
        url = "https://pulsedive.com/api/info.php"
        params = {"indicator": indicator, "key": self.api_key}
        res = self._get(url, params=params)
        if res and res.status_code == 200:
            try:
                data = res.json()
                if data.get("error"):
                    return None
                return ThreatFeedResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    source=self.name,
                    confidence=80,
                    metadata=data
                )
            except Exception:
                pass
        return None


class AbuseIPDBClient(BaseFeedClient):
    def __init__(self, api_key: str):
        super().__init__("AbuseIPDBClient", api_key)
        
    def check_ip(self, ip: str) -> Optional[ThreatFeedResult]:
        if not self.api_key:
            return None
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
        headers = {"Key": self.api_key, "Accept": "application/json"}
        res = self._get(url, headers=headers, params=params)
        if res and res.status_code == 200:
            data = res.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return ThreatFeedResult(
                indicator=ip,
                indicator_type="ip",
                source=self.name,
                confidence=score,
                metadata=data
            )
        return None


class VirusTotalV3Client(BaseFeedClient):
    def __init__(self, api_key: str):
        super().__init__("VirusTotalV3Client", api_key)
        self.last_req = 0.0
        self.rate_limit_lock = threading.Lock()
        
    def _enforce_rate_limit(self):
        # Free API limits: 4 req/min -> 1 req per 15 sec
        with self.rate_limit_lock:
            now = time.time()
            diff = now - self.last_req
            if diff < 15.0:
                time.sleep(15.0 - diff)
            self.last_req = time.time()

    def _query(self, endpoint: str, indicator: str, indicator_type: str) -> Optional[ThreatFeedResult]:
        if not self.api_key:
            return None
        self._enforce_rate_limit()
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        res = self._get(url, headers={"x-apikey": self.api_key})
        if res and res.status_code == 200:
            data = res.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            confidence = min(malicious * 10, 100)
            return ThreatFeedResult(
                indicator=indicator,
                indicator_type=indicator_type,
                source=self.name,
                confidence=confidence,
                metadata=attrs
            )
        return None

    def check_hash(self, file_hash: str) -> Optional[ThreatFeedResult]:
        return self._query(f"files/{file_hash}", file_hash, "hash")
        
    def check_ip(self, ip: str) -> Optional[ThreatFeedResult]:
        return self._query(f"ip_addresses/{ip}", ip, "ip")
        
    def check_domain(self, domain: str) -> Optional[ThreatFeedResult]:
        return self._query(f"domains/{domain}", domain, "domain")


class DShieldSANSClient(BaseFeedClient):
    def __init__(self):
        super().__init__("DShieldSANSClient")
        
    def check_ip(self, ip: str) -> Optional[ThreatFeedResult]:
        url = f"https://isc.sans.edu/api/ip/{ip}?json"
        res = self._get(url)
        if res and res.status_code == 200:
            try:
                data = res.json()
                if "ip" in data:
                    return ThreatFeedResult(
                        indicator=ip,
                        indicator_type="ip",
                        source=self.name,
                        confidence=60,
                        metadata=data["ip"]
                    )
            except Exception:
                pass
        return None

    def get_infocon(self) -> Dict[str, Any]:
        url = "https://isc.sans.edu/api/infocon?json"
        res = self._get(url)
        if res and res.status_code == 200:
            try:
                return res.json()
            except Exception:
                pass
        return {"status": "unknown"}


class BulkFeedClient(BaseFeedClient):
    def __init__(self, name: str):
        super().__init__(name)
        self.data_set = set()
        self.data_lock = threading.Lock()
        
    def _update_set(self, new_data: Set[str]):
        with self.data_lock:
            self.data_set = new_data
            
    def get_data(self) -> Set[str]:
        with self.data_lock:
            return set(self.data_set)


class EmergingThreatsFeed(BulkFeedClient):
    def __init__(self):
        super().__init__("EmergingThreatsFeed")
        
    def refresh(self):
        url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        res = self._get(url)
        if res and res.status_code == 200:
            lines = set(line.strip() for line in res.text.splitlines() if line.strip() and not line.startswith("#"))
            self._update_set(lines)


class TorExitNodeFeed(BulkFeedClient):
    def __init__(self):
        super().__init__("TorExitNodeFeed")
        
    def refresh(self):
        url = "https://check.torproject.org/torbulkexitlist"
        res = self._get(url)
        if res and res.status_code == 200:
            lines = set(line.strip() for line in res.text.splitlines() if line.strip())
            self._update_set(lines)


class SpamhausASNDrop(BulkFeedClient):
    def __init__(self):
        super().__init__("SpamhausASNDrop")
        
    def refresh(self):
        url = "https://www.spamhaus.org/drop/asndrop.txt"
        res = self._get(url)
        if res and res.status_code == 200:
            lines = set()
            for line in res.text.splitlines():
                if line.startswith(";"): continue
                parts = line.split(";")
                if parts:
                    lines.add(parts[0].strip())
            self._update_set(lines)


class AhmiaBannedOnions(BulkFeedClient):
    def __init__(self):
        super().__init__("AhmiaBannedOnions")
        
    def refresh(self):
        url = "https://ahmia.fi/banned/"
        res = self._get(url)
        if res and res.status_code == 200:
            # Requires parsing the text or HTML. Assuming text format of onions based on request.
            # Simplified for now.
            pass


class RansomwareLiveTracker(BaseFeedClient):
    def __init__(self):
        super().__init__("RansomwareLiveTracker")
        
    def get_recent_victims(self) -> List[Dict[str, Any]]:
        url = "https://api.ransomware.live/v2/recentvictims"
        res = self._get(url)
        if res and res.status_code == 200:
            try:
                return res.json()
            except Exception:
                pass
        return []
        
    def get_groups(self) -> List[Dict[str, Any]]:
        url = "https://api.ransomware.live/v2/groups"
        res = self._get(url)
        if res and res.status_code == 200:
            try:
                return res.json()
            except Exception:
                pass
        return []


class RansomwatchFeed(BaseFeedClient):
    def __init__(self):
        super().__init__("RansomwatchFeed")
        
    def get_groups(self) -> List[Dict[str, Any]]:
        url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"
        res = self._get(url)
        if res and res.status_code == 200:
            try:
                return res.json()
            except Exception:
                pass
        return []

    def get_posts(self) -> List[Dict[str, Any]]:
        url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
        res = self._get(url)
        if res and res.status_code == 200:
            try:
                return res.json()
            except Exception:
                pass
        return []


class URLScanClient(BaseFeedClient):
    def __init__(self, api_key: str):
        super().__init__("URLScanClient", api_key)
        
    def check_url(self, target_url: str) -> Optional[ThreatFeedResult]:
        if not self.api_key:
            return None
        url = "https://urlscan.io/api/v1/search/"
        params = {"q": f'page.url:"{target_url}"', "size": "1"}
        headers = {"API-Key": self.api_key}
        res = self._get(url, headers=headers, params=params)
        if res and res.status_code == 200:
            try:
                data = res.json()
                if data.get("results"):
                    return ThreatFeedResult(
                        indicator=target_url,
                        indicator_type="url",
                        source=self.name,
                        confidence=80,
                        metadata=data["results"][0]
                    )
            except Exception:
                pass
        return None


class HIBPPasswordCheck(BaseFeedClient):
    def __init__(self):
        super().__init__("HIBPPasswordCheck")
        
    def check_password(self, password: str) -> Optional[ThreatFeedResult]:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        res = self._get(url)
        if res and res.status_code == 200:
            lines = res.text.splitlines()
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    return ThreatFeedResult(
                        indicator="[REDACTED]",
                        indicator_type="password",
                        source=self.name,
                        confidence=100,
                        metadata={"pwned_count": int(parts[1])}
                    )
        return None


class HudsonRockClient(BaseFeedClient):
    def __init__(self):
        super().__init__("HudsonRockClient")
        
    def check_domain(self, domain: str) -> Optional[ThreatFeedResult]:
        url = f"https://cavalier.hudsonrock.com/api/json/v2/preview/search-by-domain?domain={domain}"
        res = self._get(url)
        if res and res.status_code == 200:
            try:
                data = res.json()
                return ThreatFeedResult(
                    indicator=domain,
                    indicator_type="domain",
                    source=self.name,
                    confidence=70,
                    metadata=data
                )
            except Exception:
                pass
        return None


class MegaThreatFeedManager:
    def __init__(self, api_keys: Dict[str, str]):
        self.http_shared = SharedHttpInfrastructure()
        
        # On-demand feeds
        self.shodan = ShodanInternetDB()
        self.greynoise = GreyNoiseCommunity(api_keys.get("greynoise", ""))
        self.pulsedive = PulsediveClient(api_keys.get("pulsedive", ""))
        self.abuseipdb = AbuseIPDBClient(api_keys.get("abuseipdb", ""))
        self.vt = VirusTotalV3Client(api_keys.get("virustotal", ""))
        self.dshield = DShieldSANSClient()
        self.urlscan = URLScanClient(api_keys.get("urlscan", ""))
        self.hibp = HIBPPasswordCheck()
        self.hudsonrock = HudsonRockClient()
        
        # Bulk feeds
        self.emerging_threats = EmergingThreatsFeed()
        self.tor_exit_nodes = TorExitNodeFeed()
        self.spamhaus_asn = SpamhausASNDrop()
        self.ahmia_onions = AhmiaBannedOnions()
        
        # Tracker feeds
        self.ransomware_live = RansomwareLiveTracker()
        self.ransomwatch = RansomwatchFeed()
        
        self.sync_thread: Optional[threading.Thread] = None
        self._stop_sync = threading.Event()
        self.results_lock = threading.Lock()

    def start_background_sync(self):
        if self.sync_thread and self.sync_thread.is_alive():
            return
            
        def _sync_worker():
            # Initial run
            self.emerging_threats.refresh()
            time.sleep(5)
            self.tor_exit_nodes.refresh()
            time.sleep(5)
            self.spamhaus_asn.refresh()
            
            while not self._stop_sync.is_set():
                # Sleep for 1 hour, checking stop event
                for _ in range(3600):
                    if self._stop_sync.is_set():
                        break
                    time.sleep(1)
                    
                if not self._stop_sync.is_set():
                    self.emerging_threats.refresh()
                    time.sleep(10)
                    self.tor_exit_nodes.refresh()
                    time.sleep(10)
                    self.spamhaus_asn.refresh()

        self._stop_sync.clear()
        self.sync_thread = threading.Thread(target=_sync_worker, daemon=True)
        self.sync_thread.start()

    def stop_background_sync(self):
        self._stop_sync.set()
        if self.sync_thread:
            self.sync_thread.join(timeout=2.0)

    def get_feed_health(self) -> Dict[str, Dict[str, Any]]:
        return self.http_shared.get_health()

    def get_tor_exit_nodes(self) -> Set[str]:
        return self.tor_exit_nodes.get_data()
        
    def get_infocon_status(self) -> Dict[str, Any]:
        return self.dshield.get_infocon()
        
    def get_ransomware_groups(self) -> List[Dict[str, Any]]:
        groups = []
        with self.results_lock:
            groups.extend(self.ransomware_live.get_groups())
            groups.extend(self.ransomwatch.get_groups())
        return groups
        
    def get_recent_victims(self) -> List[Dict[str, Any]]:
        victims = []
        with self.results_lock:
            victims.extend(self.ransomware_live.get_recent_victims())
            victims.extend(self.ransomwatch.get_posts())
        return victims

    def check_ip(self, ip: str) -> List[ThreatFeedResult]:
        results = []
        
        # Check bulk lists
        if ip in self.emerging_threats.get_data():
            results.append(ThreatFeedResult(ip, "ip", "EmergingThreats", 100))
        if ip in self.tor_exit_nodes.get_data():
            results.append(ThreatFeedResult(ip, "ip", "TorExitNode", 50, tags=["tor"]))
            
        # Check on-demand feeds
        for client in [self.shodan, self.greynoise, self.abuseipdb, self.vt, self.dshield]:
            res = client.check_ip(ip) if hasattr(client, 'check_ip') else None
            if res:
                results.append(res)
                
        # Pulsedive check
        pd_res = self.pulsedive.check_indicator(ip, "ip")
        if pd_res:
            results.append(pd_res)
            
        return results

    def check_domain(self, domain: str) -> List[ThreatFeedResult]:
        results = []
        
        for client in [self.vt, self.hudsonrock]:
            res = client.check_domain(domain) if hasattr(client, 'check_domain') else None
            if res:
                results.append(res)
                
        pd_res = self.pulsedive.check_indicator(domain, "domain")
        if pd_res:
            results.append(pd_res)
            
        return results

    def check_hash(self, file_hash: str) -> List[ThreatFeedResult]:
        results = []
        
        res = self.vt.check_hash(file_hash)
        if res:
            results.append(res)
            
        pd_res = self.pulsedive.check_indicator(file_hash, "hash")
        if pd_res:
            results.append(pd_res)
            
        return results

    def check_url(self, url: str) -> List[ThreatFeedResult]:
        results = []
        
        res = self.urlscan.check_url(url)
        if res:
            results.append(res)
            
        pd_res = self.pulsedive.check_indicator(url, "url")
        if pd_res:
            results.append(pd_res)
            
        return results

"""
