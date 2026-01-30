"""
VulnCheck Community API Client.

Provides faster CVE updates and exploit intelligence.
VulnCheck often publishes CVE data before NVD processes it.

API Documentation: https://docs.vulncheck.com/
Free tier: https://vulncheck.com/pricing
"""

from typing import Dict, List, Optional, Any
import httpx
import structlog
from backoff import on_exception, expo
from ratelimit import limits, sleep_and_retry
import os

from .models import CVE


logger = structlog.get_logger(__name__)


class VulnCheckCollector:
    """
    VulnCheck Community API client.
    
    FREE tier available with API key.
    Provides faster CVE updates than NVD and exploit context.
    """
    
    BASE_URL = "https://api.vulncheck.com/v3"
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize VulnCheck collector.
        
        Args:
            api_key: VulnCheck API key (from env if not provided)
            timeout: HTTP request timeout in seconds
        """
        self.api_key = api_key or os.getenv("VULNCHECK_API_KEY")
        self.timeout = timeout
        self.logger = logger.bind(collector="vulncheck")
        
        if not self.api_key:
            self.logger.warning("vulncheck_no_api_key", message="VulnCheck disabled")
        else:
            self.logger.info("vulncheck_collector_initialized")
    
    @property
    def headers(self) -> Dict[str, str]:
        """Get HTTP headers with API key."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json"
        }
    
    @sleep_and_retry
    @limits(calls=10, period=60)  # Conservative rate limit
    @on_exception(expo, (httpx.HTTPError, httpx.TimeoutException), max_tries=3)
    async def get_cve_info(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get CVE information from VulnCheck.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
        
        Returns:
            Dictionary with CVE data or None if not found
        """
        if not self.api_key:
            return None
        
        url = f"{self.BASE_URL}/index/vulncheck-nvd2/{cve_id}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=self.headers)
                
                if response.status_code == 404:
                    self.logger.debug(
                        "cve_not_found_in_vulncheck",
                        cve_id=cve_id
                    )
                    return None
                
                response.raise_for_status()
                data = response.json()
                
                self.logger.info(
                    "vulncheck_cve_retrieved",
                    cve_id=cve_id
                )
                
                return data.get("data", [{}])[0] if data.get("data") else None
                
        except httpx.HTTPStatusError as e:
            self.logger.warning(
                "vulncheck_http_error",
                cve_id=cve_id,
                status_code=e.response.status_code,
                error=str(e)
            )
            return None
        except Exception as e:
            self.logger.error(
                "vulncheck_request_failed",
                cve_id=cve_id,
                error=str(e)
            )
            return None
    
    @sleep_and_retry
    @limits(calls=5, period=60)
    async def check_exploit_intelligence(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Check for exploit intelligence on a CVE.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Exploit intelligence data or None
        """
        if not self.api_key:
            return None
        
        url = f"{self.BASE_URL}/index/initial-access"
        params = {"cve": cve_id}
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=self.headers, params=params)
                
                if response.status_code == 404:
                    return None
                
                response.raise_for_status()
                data = response.json()
                
                if data.get("data"):
                    self.logger.info(
                        "vulncheck_exploit_intel_found",
                        cve_id=cve_id,
                        count=len(data["data"])
                    )
                    return data
                
                return None
                
        except Exception as e:
            self.logger.warning(
                "vulncheck_exploit_check_failed",
                cve_id=cve_id,
                error=str(e)
            )
            return None
    
    async def enrich_cve(self, cve: CVE) -> CVE:
        """
        Enrich CVE with VulnCheck data.
        
        Args:
            cve: CVE object to enrich
        
        Returns:
            Enriched CVE object
        """
        if not self.api_key:
            return cve
        
        # Check for exploit intelligence
        exploit_data = await self.check_exploit_intelligence(cve.cve_id)
        
        if exploit_data and exploit_data.get("data"):
            # Mark as having known exploits
            if not hasattr(cve, 'exploit_available'):
                cve.__dict__['exploit_available'] = True
            if not hasattr(cve, 'exploit_sources'):
                cve.__dict__['exploit_sources'] = []
            
            cve.__dict__['exploit_available'] = True
            if "VulnCheck" not in cve.__dict__.get('exploit_sources', []):
                cve.__dict__['exploit_sources'].append("VulnCheck Initial Access")
            
            self.logger.info(
                "vulncheck_exploit_detected",
                cve_id=cve.cve_id,
                exploit_count=len(exploit_data["data"])
            )
        
        return cve
