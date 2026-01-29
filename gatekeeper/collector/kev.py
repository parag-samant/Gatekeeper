"""
CISA Known Exploited Vulnerabilities (KEV) catalog client.

Fetches and parses the KEV catalog JSON feed to identify
vulnerabilities with known active exploitation.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Set, Any

import requests
import backoff
import structlog

from ..config import Config
from .models import KEVEntry

logger = structlog.get_logger(__name__)


class KEVClient:
    """
    Client for the CISA KEV catalog.
    
    The KEV catalog is a JSON feed of vulnerabilities with known
    active exploitation, maintained by CISA.
    """
    
    DEFAULT_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self, config: Config):
        """
        Initialize the KEV client.
        
        Args:
            config: Application configuration.
        """
        self.config = config
        self.feed_url = config.kev_feed_url or self.DEFAULT_FEED_URL
        
        # Session for requests
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Gatekeeper-CVE-Advisory/1.0",
            "Accept": "application/json"
        })
        
        # Cache for KEV data
        self._cache: Optional[Dict[str, KEVEntry]] = None
        self._cache_time: Optional[datetime] = None
        self._cache_ttl = timedelta(hours=1)  # Cache for 1 hour
        
        logger.info("kev_client_initialized", feed_url=self.feed_url)
    
    @backoff.on_exception(
        backoff.expo,
        (requests.RequestException, requests.Timeout),
        max_tries=3,
        max_time=120
    )
    def _fetch_catalog(self) -> Dict:
        """
        Fetch the KEV catalog from CISA.
        
        Returns:
            Raw JSON response data.
        
        Raises:
            requests.RequestException: On request failure after retries.
        """
        logger.debug("kev_fetch_started", url=self.feed_url)
        
        response = self.session.get(self.feed_url, timeout=60)
        response.raise_for_status()
        
        data = response.json()
        logger.info(
            "kev_fetch_completed",
            catalog_version=data.get("catalogVersion"),
            count=data.get("count")
        )
        
        return data
    
    def _load_cache(self) -> Dict[str, KEVEntry]:
        """Load and cache the KEV catalog."""
        now = datetime.now(timezone.utc)
        
        # Return cached data if still valid
        if (self._cache is not None and 
            self._cache_time is not None and 
            now - self._cache_time < self._cache_ttl):
            return self._cache
        
        # Fetch fresh data
        try:
            data = self._fetch_catalog()
        except requests.RequestException as e:
            logger.error("kev_fetch_failed", error=str(e))
            # Return existing cache if available
            if self._cache is not None:
                logger.warning("kev_using_stale_cache")
                return self._cache
            return {}
        
        # Parse entries into cache
        self._cache = {}
        for vuln in data.get("vulnerabilities", []):
            try:
                entry = KEVEntry.from_kev_data(vuln)
                self._cache[entry.cve_id] = entry
            except Exception as e:
                cve_id = vuln.get("cveID", "unknown")
                logger.warning("kev_parse_error", cve_id=cve_id, error=str(e))
        
        self._cache_time = now
        logger.info("kev_cache_loaded", entries=len(self._cache))
        
        return self._cache
    
    def get_all_kev_ids(self) -> Set[str]:
        """
        Get all CVE IDs in the KEV catalog.
        
        Returns:
            Set of CVE IDs.
        """
        cache = self._load_cache()
        return set(cache.keys())
    
    def get_kev_entry(self, cve_id: str) -> Optional[KEVEntry]:
        """
        Get KEV entry for a specific CVE.
        
        Args:
            cve_id: CVE identifier.
        
        Returns:
            KEVEntry if found, None otherwise.
        """
        cache = self._load_cache()
        return cache.get(cve_id)
    
    def is_in_kev(self, cve_id: str) -> bool:
        """
        Check if a CVE is in the KEV catalog.
        
        Args:
            cve_id: CVE identifier.
        
        Returns:
            True if the CVE is in KEV.
        """
        cache = self._load_cache()
        return cve_id in cache
    
    def get_recent_additions(self, hours: int = 24) -> List[KEVEntry]:
        """
        Get KEV entries added in the last N hours.
        
        Args:
            hours: Number of hours to look back.
        
        Returns:
            List of recently added KEV entries.
        """
        cache = self._load_cache()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        recent = []
        for entry in cache.values():
            if entry.date_added is not None:
                # Make date_added timezone-aware if needed
                added_date = entry.date_added
                if added_date.tzinfo is None:
                    added_date = added_date.replace(tzinfo=timezone.utc)
                
                if added_date >= cutoff:
                    recent.append(entry)
        
        # Sort by date added (most recent first)
        recent.sort(key=lambda e: e.date_added or datetime.min, reverse=True)
        
        logger.info(
            "kev_recent_additions",
            count=len(recent),
            hours=hours
        )
        
        return recent
    
    def get_entries_by_vendor(self, vendor: str) -> List[KEVEntry]:
        """
        Get KEV entries for a specific vendor.
        
        Args:
            vendor: Vendor name (case-insensitive partial match).
        
        Returns:
            List of matching KEV entries.
        """
        cache = self._load_cache()
        vendor_lower = vendor.lower()
        
        return [
            entry for entry in cache.values()
            if vendor_lower in entry.vendor_project.lower()
        ]
    
    def get_entries_with_ransomware(self) -> List[KEVEntry]:
        """
        Get KEV entries known to be used in ransomware campaigns.
        
        Returns:
            List of KEV entries with known ransomware use.
        """
        cache = self._load_cache()
        
        return [
            entry for entry in cache.values()
            if entry.known_ransomware_use.lower() == "known"
        ]
    
    def get_catalog_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the KEV catalog.
        
        Returns:
            Dict with catalog statistics.
        """
        cache = self._load_cache()
        
        ransomware_count = len([
            e for e in cache.values()
            if e.known_ransomware_use.lower() == "known"
        ])
        
        # Count by year
        by_year: Dict[int, int] = {}
        for entry in cache.values():
            if entry.date_added:
                year = entry.date_added.year
                by_year[year] = by_year.get(year, 0) + 1
        
        return {
            "total_entries": len(cache),
            "ransomware_associated": ransomware_count,
            "by_year": by_year
        }
    
    def clear_cache(self):
        """Clear the KEV cache to force a refresh."""
        self._cache = None
        self._cache_time = None
        logger.info("kev_cache_cleared")
    
    def close(self):
        """Close the HTTP session."""
        self.session.close()
