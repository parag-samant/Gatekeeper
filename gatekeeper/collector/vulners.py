"""
Vulners API Client.

Provides exploit availability detection for CVEs.
Checks if public exploits exist in Exploit-DB, Metasploit, GitHub, etc.

API Documentation: https://vulners.com/api/v3/
Free tier: 500 API calls per day
"""

from typing import Dict, List, Optional, Any
import httpx
import structlog
from backoff import on_exception, expo
from ratelimit import limits, sleep_and_retry
import os

from .models import CVE


logger = structlog.get_logger(__name__)


class VulnersCollector:
    """
    Vulners API client for exploit intelligence.
    
    FREE tier: 500 API calls/day
    Detects public exploits from multiple sources.
    """
    
    BASE_URL = "https://vulners.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize Vulners collector.
        
        Args:
            api_key: Vulners API key (from env if not provided)
            timeout: HTTP request timeout in seconds
        """
        self.api_key = api_key or os.getenv("VULNERS_API_KEY")
        self.timeout = timeout
        self.logger = logger.bind(collector="vulners")
        
        if not self.api_key:
            self.logger.warning("vulners_no_api_key", message="Vulners disabled")
        else:
            self.logger.info("vulners_collector_initialized")
    
    @sleep_and_retry
    @limits(calls=8, period=60)  # Conservative: 480/hour < 500/day limit
    @on_exception(expo, (httpx.HTTPError, httpx.TimeoutException), max_tries=3)
    async def check_exploit_availability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Check if public exploits exist for a CVE.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
        
        Returns:
            Dictionary with exploit data or None if no exploits found
        """
        if not self.api_key:
            return None
        
        url = f"{self.BASE_URL}/search/id/"
        
        payload = {
            "id": cve_id,
            "apiKey": self.api_key
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)
                
                if response.status_code != 200:
                    self.logger.debug(
                        "vulners_request_failed",
                        cve_id=cve_id,
                        status_code=response.status_code
                    )
                    return None
                
                data = response.json()
                
                # Check if exploits exist
                if data.get("result") == "OK":
                    documents = data.get("data", {}).get("documents", {})
                    
                    # Look for exploit-related documents
                    exploit_types = ["exploit", "metasploit", "exploitdb", "poc", "githubexploit"]
                    exploits_found = []
                    
                    for doc_id, doc_data in documents.items():
                        doc_type = doc_data.get("type", "").lower()
                        if any(exp_type in doc_type for exp_type in exploit_types):
                            exploits_found.append({
                                "type": doc_data.get("type"),
                                "title": doc_data.get("title"),
                                "href": doc_data.get("href")
                            })
                    
                    if exploits_found:
                        self.logger.info(
                            "vulners_exploits_found",
                            cve_id=cve_id,
                            exploit_count=len(exploits_found),
                            types=[e["type"] for e in exploits_found[:3]]
                        )
                        
                        return {
                            "cve_id": cve_id,
                            "exploit_count": len(exploits_found),
                            "exploits": exploits_found
                        }
                
                return None
                
        except httpx.HTTPStatusError as e:
            self.logger.warning(
                "vulners_http_error",
                cve_id=cve_id,
                status_code=e.response.status_code,
                error=str(e)
            )
            return None
        except Exception as e:
            self.logger.error(
                "vulners_request_failed",
                cve_id=cve_id,
                error=str(e)
            )
            return None
    
    async def enrich_cve(self, cve: CVE) -> CVE:
        """
        Enrich CVE with Vulners exploit intelligence.
        
        Args:
            cve: CVE object to enrich
        
        Returns:
            Enriched CVE object
        """
        if not self.api_key:
            return cve
        
        exploit_data = await self.check_exploit_availability(cve.cve_id)
        
        if exploit_data:
            # Initialize exploit tracking fields if not present
            if not hasattr(cve, 'exploit_available'):
                cve.__dict__['exploit_available'] = False
            if not hasattr(cve, 'exploit_sources'):
                cve.__dict__['exploit_sources'] = []
            if not hasattr(cve, 'exploit_details'):
                cve.__dict__['exploit_details'] = []
            
            # Mark exploit as available
            cve.__dict__['exploit_available'] = True
            
            # Add Vulners as source
            source_names = []
            for exploit in exploit_data.get("exploits", []):
                exploit_type = exploit.get("type", "Unknown")
                if exploit_type not in source_names:
                    source_names.append(exploit_type)
            
            cve.__dict__['exploit_sources'].extend(source_names)
            cve.__dict__['exploit_details'] = exploit_data.get("exploits", [])[:5]  # Store up to 5 exploits
            
            self.logger.info(
                "vulners_enrichment_added",
                cve_id=cve.cve_id,
                exploit_sources=source_names[:3]
            )
        
        return cve
