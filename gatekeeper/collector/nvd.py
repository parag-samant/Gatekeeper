"""
NVD (National Vulnerability Database) API client.

Provides rate-limited access to the NVD CVE API for fetching
vulnerability data within specified time windows.
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Iterator, Dict, Any
from urllib.parse import urlencode

import requests
import backoff
import structlog

from ..config import Config
from .models import CVE

logger = structlog.get_logger(__name__)


class NVDRateLimiter:
    """
    Rate limiter for NVD API requests.
    
    Without API key: 5 requests per 30 seconds
    With API key: 50 requests per 30 seconds
    """
    
    def __init__(self, requests_per_window: int = 5, window_seconds: int = 30):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.request_times: List[float] = []
    
    def wait_if_needed(self):
        """Wait if necessary to comply with rate limits."""
        now = time.time()
        
        # Remove requests outside the window
        self.request_times = [
            t for t in self.request_times 
            if now - t < self.window_seconds
        ]
        
        # If at limit, wait until oldest request exits window
        if len(self.request_times) >= self.requests_per_window:
            oldest = self.request_times[0]
            wait_time = self.window_seconds - (now - oldest) + 0.1
            if wait_time > 0:
                logger.debug("rate_limit_wait", wait_seconds=wait_time)
                time.sleep(wait_time)
                # Clean up again after waiting
                now = time.time()
                self.request_times = [
                    t for t in self.request_times 
                    if now - t < self.window_seconds
                ]
        
        # Record this request
        self.request_times.append(time.time())


class NVDClient:
    """
    Client for the NVD CVE API.
    
    Provides methods to fetch CVEs by date range with automatic
    pagination and rate limiting.
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    DEFAULT_PAGE_SIZE = 100  # Conservative page size for reliability
    MAX_PAGE_SIZE = 2000
    
    def __init__(self, config: Config):
        """
        Initialize the NVD client.
        
        Args:
            config: Application configuration.
        """
        self.config = config
        self.api_key = config.nvd_api_key
        
        # Set up rate limiter based on API key presence
        requests_per_window = 50 if self.api_key else 5
        self.rate_limiter = NVDRateLimiter(
            requests_per_window=requests_per_window,
            window_seconds=30
        )
        
        # Set up session
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Gatekeeper-CVE-Advisory/1.0",
            "Accept": "application/json"
        })
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
        
        logger.info(
            "nvd_client_initialized",
            has_api_key=bool(self.api_key),
            rate_limit=requests_per_window
        )
    
    @backoff.on_exception(
        backoff.expo,
        (requests.RequestException, requests.Timeout),
        max_tries=5,
        max_time=300
    )
    def _make_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make a rate-limited request to the NVD API.
        
        Args:
            params: Query parameters.
        
        Returns:
            JSON response data.
        
        Raises:
            requests.RequestException: On request failure after retries.
        """
        self.rate_limiter.wait_if_needed()
        
        url = f"{self.BASE_URL}?{urlencode(params)}"
        logger.debug("nvd_request", url=url)
        
        response = self.session.get(url, timeout=60)
        response.raise_for_status()
        
        return response.json()
    
    def _format_datetime(self, dt: datetime) -> str:
        """Format datetime for NVD API."""
        # NVD expects ISO 8601 format with timezone
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    def fetch_cves_by_date(
        self,
        start_date: datetime,
        end_date: datetime,
        use_modified_date: bool = True,
        min_cvss: Optional[float] = None
    ) -> Iterator[CVE]:
        """
        Fetch CVEs within a date range.
        
        Args:
            start_date: Start of date range.
            end_date: End of date range.
            use_modified_date: If True, use lastModified date; else use published date.
            min_cvss: Minimum CVSS score filter (applied after fetch).
        
        Yields:
            CVE objects matching the criteria.
        """
        params = {
            "resultsPerPage": self.DEFAULT_PAGE_SIZE,
            "startIndex": 0,
            "noRejected": ""  # Exclude rejected CVEs
        }
        
        # Add date range parameters
        if use_modified_date:
            params["lastModStartDate"] = self._format_datetime(start_date)
            params["lastModEndDate"] = self._format_datetime(end_date)
        else:
            params["pubStartDate"] = self._format_datetime(start_date)
            params["pubEndDate"] = self._format_datetime(end_date)
        
        total_results = None
        fetched = 0
        
        while True:
            try:
                data = self._make_request(params)
            except requests.RequestException as e:
                logger.error("nvd_request_failed", error=str(e))
                break
            
            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info(
                    "nvd_fetch_started",
                    total_results=total_results,
                    start_date=start_date.isoformat(),
                    end_date=end_date.isoformat()
                )
            
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                break
            
            for vuln_data in vulnerabilities:
                try:
                    cve = CVE.from_nvd_response(vuln_data)
                    
                    # Apply CVSS filter if specified
                    if min_cvss is not None:
                        if cve.highest_cvss_score < min_cvss:
                            continue
                    
                    fetched += 1
                    yield cve
                    
                except Exception as e:
                    cve_id = vuln_data.get("cve", {}).get("id", "unknown")
                    logger.warning("cve_parse_error", cve_id=cve_id, error=str(e))
            
            # Check if more pages
            results_per_page = data.get("resultsPerPage", self.DEFAULT_PAGE_SIZE)
            start_index = data.get("startIndex", 0)
            
            if start_index + results_per_page >= total_results:
                break
            
            # Next page
            params["startIndex"] = start_index + results_per_page
            logger.debug(
                "nvd_fetch_progress",
                fetched=start_index + len(vulnerabilities),
                total=total_results
            )
        
        logger.info("nvd_fetch_completed", cves_fetched=fetched, total_available=total_results)
    
    def fetch_recent_cves(
        self,
        hours: int = 24,
        min_cvss: Optional[float] = None
    ) -> List[CVE]:
        """
        Fetch CVEs modified in the last N hours.
        
        Args:
            hours: Number of hours to look back.
            min_cvss: Minimum CVSS score filter.
        
        Returns:
            List of CVE objects.
        """
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(hours=hours)
        
        return list(self.fetch_cves_by_date(
            start_date=start_date,
            end_date=end_date,
            use_modified_date=True,
            min_cvss=min_cvss
        ))
    
    def fetch_cve_by_id(self, cve_id: str) -> Optional[CVE]:
        """
        Fetch a specific CVE by ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234").
        
        Returns:
            CVE object or None if not found.
        """
        params = {"cveId": cve_id}
        
        try:
            data = self._make_request(params)
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                return CVE.from_nvd_response(vulnerabilities[0])
        except requests.RequestException as e:
            logger.error("nvd_fetch_cve_failed", cve_id=cve_id, error=str(e))
        
        return None
    
    def fetch_kev_cves(self) -> Iterator[CVE]:
        """
        Fetch all CVEs that are in the CISA KEV catalog.
        
        Yields:
            CVE objects that are in KEV.
        """
        params = {
            "hasKev": "",
            "resultsPerPage": self.DEFAULT_PAGE_SIZE,
            "startIndex": 0
        }
        
        total_results = None
        
        while True:
            try:
                data = self._make_request(params)
            except requests.RequestException as e:
                logger.error("nvd_kev_request_failed", error=str(e))
                break
            
            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info("nvd_kev_fetch_started", total_results=total_results)
            
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                break
            
            for vuln_data in vulnerabilities:
                try:
                    yield CVE.from_nvd_response(vuln_data)
                except Exception as e:
                    cve_id = vuln_data.get("cve", {}).get("id", "unknown")
                    logger.warning("cve_parse_error", cve_id=cve_id, error=str(e))
            
            # Check if more pages
            results_per_page = data.get("resultsPerPage", self.DEFAULT_PAGE_SIZE)
            start_index = data.get("startIndex", 0)
            
            if start_index + results_per_page >= total_results:
                break
            
            params["startIndex"] = start_index + results_per_page
    
    def close(self):
        """Close the HTTP session."""
        self.session.close()
