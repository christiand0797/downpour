"""
Downpour Security Application - Dark Web OSINT Intelligence Module
Version: v29.70

This module provides comprehensive dark web threat intelligence capabilities,
including Tor exit node tracking, ransomware leak site monitoring, infostealer
exposure checking, and malicious onion tracking.
"""

import logging
import threading
import time
import re
import json
from datetime import datetime, timedelta, timezone
from typing import Set, List, Dict, Any, Optional
from functools import lru_cache
import functools

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None  # type: ignore

# Set up module logger
logger = logging.getLogger('Downpour.DarkWebIntel')

def _safe_log(level: int, msg: str, exc_info: bool = False) -> None:
    """Safe logging wrapper following existing code style."""
    try:
        logger.log(level, msg, exc_info=exc_info)
    except Exception:
        pass


def _get_session() -> "requests.Session":
    """Create a configured requests session with retries and headers."""
    if requests is None:
        raise RuntimeError("requests library is not installed")
    
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    session.headers.update({
        'User-Agent': 'Downpour Security Suite v29.70 (Threat Intelligence Module)'
    })
    return session


class TorExitNodeMonitor:
    """Monitors and caches active Tor exit nodes."""
    
    def __init__(self) -> None:
        self._exit_nodes: Set[str] = set()
        self._lock = threading.Lock()
        self._session = None if requests is None else _get_session()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_sync_time: Optional[float] = None
        
    def sync(self) -> int:
        """Sync Tor exit nodes from bulk exit lists."""
        if self._session is None:
            _safe_log(logging.ERROR, "Cannot sync Tor nodes: requests module missing")
            return 0
            
        nodes = set()
        
        # Try primary source
        try:
            response = self._session.get('https://check.torproject.org/torbulkexitlist', timeout=10)
            response.raise_for_status()
            for line in response.text.splitlines():
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    nodes.add(ip)
            _safe_log(logging.INFO, f"Synced {len(nodes)} Tor exit nodes from primary source")
        except Exception as e:
            _safe_log(logging.WARNING, f"Failed to sync Tor nodes from primary source: {e}")
            
            # Try fallback source
            try:
                response = self._session.get('https://www.dan.me.uk/torlist/', timeout=10)
                response.raise_for_status()
                for line in response.text.splitlines():
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        nodes.add(ip)
                _safe_log(logging.INFO, f"Synced {len(nodes)} Tor exit nodes from fallback source")
            except Exception as e2:
                _safe_log(logging.ERROR, f"Failed to sync Tor nodes from fallback source: {e2}")

        if nodes:
            with self._lock:
                self._exit_nodes = nodes
            self._last_sync_time = time.time()
            
        return len(nodes)
        
    def is_tor_exit(self, ip: str) -> bool:
        """Check if an IP address is a known Tor exit node."""
        with self._lock:
            return ip in self._exit_nodes
            
    def get_exit_node_count(self) -> int:
        """Get the current count of loaded Tor exit nodes."""
        with self._lock:
            return len(self._exit_nodes)
            
    def _refresh_loop(self) -> None:
        """Background thread loop for periodic refreshing."""
        while not self._stop_event.is_set():
            # Refresh every 6 hours
            if self._last_sync_time is None or time.time() - self._last_sync_time > 6 * 3600:
                self.sync()
            self._stop_event.wait(600)  # Check every 10 minutes
            
    def start(self) -> None:
        """Start the background refresh thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._refresh_loop, daemon=True, name="TorExitMonitorThread")
        self._thread.start()
        
    def stop(self) -> None:
        """Stop the background refresh thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


class RansomwareLeakMonitor:
    """Monitors ransomware leak sites and tracks victims."""
    
    def __init__(self) -> None:
        self._groups: List[Dict[str, Any]] = []
        self._victims: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._session = None if requests is None else _get_session()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_sync_time: Optional[float] = None
        
    def sync(self) -> None:
        """Fetch latest ransomware victims and groups."""
        if self._session is None:
            _safe_log(logging.ERROR, "Cannot sync Ransomware data: requests module missing")
            return
            
        new_groups = []
        new_victims = []
        
        # Try fetching from ransomware.live API
        try:
            r_groups = self._session.get('https://api.ransomware.live/v2/groups', timeout=15)
            if r_groups.status_code == 200:
                new_groups = r_groups.json()
                
            r_victims = self._session.get('https://api.ransomware.live/v2/recentvictims', timeout=15)
            if r_victims.status_code == 200:
                new_victims = r_victims.json()
        except Exception as e:
            _safe_log(logging.WARNING, f"Failed to sync from ransomware.live API: {e}")
            
        # Try fetching from ransomwatch as fallback/supplement
        if not new_victims:
            try:
                r_posts = self._session.get('https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json', timeout=15)
                if r_posts.status_code == 200:
                    data = r_posts.json()
                    for post in data:
                        new_victims.append({
                            'victim': post.get('post_title', ''),
                            'group_name': post.get('group_name', ''),
                            'published': post.get('published', '')
                        })
            except Exception as e:
                _safe_log(logging.ERROR, f"Failed to sync from ransomwatch: {e}")

        with self._lock:
            if new_groups:
                self._groups = new_groups
            if new_victims:
                # Sort victims by publication date, newest first
                try:
                    self._victims = sorted(new_victims, key=lambda x: x.get('published', ''), reverse=True)
                except Exception:
                    self._victims = new_victims
                    
        self._last_sync_time = time.time()
        _safe_log(logging.INFO, f"Ransomware data synced: {len(self._groups)} groups, {len(self._victims)} victims")

    def get_active_groups(self) -> List[Dict[str, Any]]:
        """Get list of active ransomware groups."""
        with self._lock:
            # We filter for groups that might have an 'onion' URL or specific status if available
            # Just returning all parsed groups here, standardized if possible
            results = []
            for g in self._groups:
                results.append({
                    'name': g.get('name', 'Unknown'),
                    'onion': g.get('locations', [{}])[0].get('fqdn', '') if g.get('locations') else '',
                    'status': 'Active',
                    'victim_count': g.get('victim_count', 0)
                })
            return results

    def get_recent_victims(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent ransomware victims."""
        with self._lock:
            return self._victims[:limit]
            
    def search_organization(self, name: str) -> List[Dict[str, Any]]:
        """Fuzzy match victim posts for a specific organization name."""
        name_lower = name.lower()
        results = []
        with self._lock:
            for v in self._victims:
                victim_name = str(v.get('post_title', v.get('victim', ''))).lower()
                if name_lower in victim_name:
                    results.append(v)
        return results
        
    def get_group_count(self) -> int:
        """Get the number of tracked groups."""
        with self._lock:
            return len(self._groups)
            
    def get_victim_count_24h(self) -> int:
        """Get the number of victims published in the last 24 hours."""
        count = 0
        now = datetime.now(timezone.utc)
        time_24h_ago = now - timedelta(hours=24)
        
        with self._lock:
            for v in self._victims:
                pub = v.get('published', '')
                if pub:
                    try:
                        # Attempt to parse common ISO formats
                        if pub.endswith('Z'):
                            pub = pub[:-1] + '+00:00'
                        pub_time = datetime.fromisoformat(pub)
                        if pub_time.tzinfo is None:
                            pub_time = pub_time.replace(tzinfo=timezone.utc)
                        if pub_time >= time_24h_ago:
                            count += 1
                    except ValueError:
                        pass
        return count
        
    def _refresh_loop(self) -> None:
        """Background thread loop for periodic refreshing."""
        while not self._stop_event.is_set():
            # Refresh every 30 minutes
            if self._last_sync_time is None or time.time() - self._last_sync_time > 30 * 60:
                self.sync()
            self._stop_event.wait(300)  # Check every 5 minutes
            
    def start(self) -> None:
        """Start the background refresh thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._refresh_loop, daemon=True, name="RansomwareMonitorThread")
        self._thread.start()
        
    def stop(self) -> None:
        """Stop the background refresh thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


class RateLimiter:
    """Simple rate limiter."""
    def __init__(self, interval_seconds: float):
        self.interval = interval_seconds
        self.last_called = 0.0
        self.lock = threading.Lock()
        
    def wait(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_called
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
            self.last_called = time.time()


class InfostealerExposureChecker:
    """Checks domains for infostealer exposure."""
    
    def __init__(self) -> None:
        self._session = None if requests is None else _get_session()
        self._rate_limiter = RateLimiter(5.0) # 1 request per 5 seconds
        self._checked_count = 0
        self._lock = threading.Lock()
        
    @lru_cache(maxsize=100)
    def _fetch_domain_data(self, domain: str) -> Dict[str, Any]:
        """Fetch domain data with caching."""
        if self._session is None:
            return {'error': 'requests module missing'}
            
        self._rate_limiter.wait()
        
        url = f'https://cavalier.hudsonrock.com/api/json/v2/preview/search-by-domain?domain={domain}'
        try:
            response = self._session.get(url, timeout=10)
            if response.status_code == 200:
                with self._lock:
                    self._checked_count += 1
                return response.json()
            elif response.status_code == 404:
                return {'employee_count': 0, 'client_count': 0, 'stealer_families': [], 'status': 'not_found'}
            else:
                return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            _safe_log(logging.ERROR, f"Error checking domain {domain} for infostealers: {e}")
            return {'error': str(e)}

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check a domain for infostealer infections."""
        # Using lru_cache wrapped method
        result = self._fetch_domain_data(domain)
        
        # Standardize the output format
        out = {
            'domain': domain,
            'employee_count': result.get('employees', 0) if isinstance(result.get('employees'), int) else result.get('employee_count', 0),
            'client_count': result.get('users', 0) if isinstance(result.get('users'), int) else result.get('client_count', 0),
            'stealer_families': result.get('stealers', []) if isinstance(result.get('stealers'), list) else result.get('stealer_families', []),
            'status': result.get('status', 'success' if 'error' not in result else 'error')
        }
        if 'error' in result:
            out['error'] = result['error']
            
        return out
        
    def get_checked_count(self) -> int:
        with self._lock:
            return self._checked_count


class MaliciousOnionTracker:
    """Tracks banned/malicious onion addresses."""
    
    def __init__(self) -> None:
        self._banned_onions: Set[str] = set()
        self._lock = threading.Lock()
        self._session = None if requests is None else _get_session()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_sync_time: Optional[float] = None
        
    def sync(self) -> int:
        """Fetch banned onions from Ahmia."""
        if self._session is None:
            return 0
            
        try:
            response = self._session.get('https://ahmia.fi/banned/', timeout=15)
            response.raise_for_status()
            
            # Very basic extraction: looking for 56 char md5/sha1/v3 hashes or onion addresses
            # Typically ahmia lists md5 hashes of banned addresses
            onions = set()
            for match in re.finditer(r'([a-fA-F0-9]{32,64}|[a-z2-7]{16,56}\.onion)', response.text):
                val = match.group(1).lower()
                onions.add(val)
                
            with self._lock:
                self._banned_onions = onions
            self._last_sync_time = time.time()
            _safe_log(logging.INFO, f"Synced {len(onions)} malicious onion identifiers")
            return len(onions)
            
        except Exception as e:
            _safe_log(logging.ERROR, f"Failed to sync malicious onions: {e}")
            return 0
            
    def is_malicious_onion(self, address: str) -> bool:
        """Check if an address or hash is in the banned list."""
        address = address.lower()
        if address.endswith('.onion'):
            address = address[:-6]
            
        with self._lock:
            return address in self._banned_onions or f"{address}.onion" in self._banned_onions
            
    def get_tracked_count(self) -> int:
        with self._lock:
            return len(self._banned_onions)

    def _refresh_loop(self) -> None:
        """Background thread loop for periodic refreshing."""
        while not self._stop_event.is_set():
            # Refresh every 24 hours
            if self._last_sync_time is None or time.time() - self._last_sync_time > 24 * 3600:
                self.sync()
            self._stop_event.wait(3600)  # Check every hour
            
    def start(self) -> None:
        """Start the background refresh thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._refresh_loop, daemon=True, name="MaliciousOnionMonitorThread")
        self._thread.start()
        
    def stop(self) -> None:
        """Stop the background refresh thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


class DarkWebIntelManager:
    """Orchestrator for all Dark Web intelligence capabilities."""
    
    def __init__(self) -> None:
        self.tor_monitor = TorExitNodeMonitor()
        self.ransomware_monitor = RansomwareLeakMonitor()
        self.infostealer_checker = InfostealerExposureChecker()
        self.onion_tracker = MaliciousOnionTracker()
        self._running = False
        
    def start(self) -> None:
        """Launch all background sync threads."""
        if self._running:
            return
            
        _safe_log(logging.INFO, "Starting Dark Web Intel Manager...")
        self.tor_monitor.start()
        self.ransomware_monitor.start()
        self.onion_tracker.start()
        self._running = True
        
    def stop(self) -> None:
        """Cleanly shut down all background threads."""
        _safe_log(logging.INFO, "Stopping Dark Web Intel Manager...")
        self.tor_monitor.stop()
        self.ransomware_monitor.stop()
        self.onion_tracker.stop()
        self._running = False
        
    def get_dashboard_summary(self) -> Dict[str, int]:
        """Return a summary of dark web intel stats."""
        return {
            'tor_exit_count': self.tor_monitor.get_exit_node_count(),
            'ransomware_groups_active': self.ransomware_monitor.get_group_count(),
            'victims_last_24h': self.ransomware_monitor.get_victim_count_24h(),
            'infostealer_domains_checked': self.infostealer_checker.get_checked_count(),
            'malicious_onions_tracked': self.onion_tracker.get_tracked_count()
        }
        
    def check_ip_dark_web(self, ip: str) -> Dict[str, Any]:
        """Check if an IP has any dark web associations."""
        is_tor = self.tor_monitor.is_tor_exit(ip)
        return {
            'ip': ip,
            'is_tor_exit': is_tor,
            'risk_level': 'High' if is_tor else 'Unknown',
            'details': 'Tor exit node' if is_tor else 'No known dark web association'
        }
        
    def get_ransomware_ticker(self) -> List[str]:
        """Get formatted strings of latest victims for UI ticker display."""
        recent = self.ransomware_monitor.get_recent_victims(limit=10)
        ticker_items = []
        for v in recent:
            victim = v.get('post_title', v.get('victim', 'Unknown'))
            group = v.get('group_name', 'Unknown Group')
            date_str = v.get('published', '')
            if date_str:
                try:
                    # Simple date formatting for ticker
                    date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    date_str = date_obj.strftime("%Y-%m-%d")
                except ValueError:
                    date_str = date_str[:10]
                    
            ticker_items.append(f"[{group}] claimed {victim} ({date_str})")
            
        if not ticker_items:
            return ["No recent ransomware activity found."]
            
        return ticker_items

