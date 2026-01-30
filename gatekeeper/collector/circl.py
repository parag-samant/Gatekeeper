"""
CIRCL Vulnerability-Lookup API Client.

Provides enriched CVE data including:
- CAPEC attack patterns
- CWE weakness types
- Aggregated data from multiple sources
- Enhanced vulnerability context

API Documentation: https://vulnerability.lookup.circl.lu/api/
"""

from typing import Dict, List, Optional, Any
import httpx
import structlog
from backoff import on_exception, expo
from ratelimit import limits, sleep_and_retry

from .models import CVE


logger = structlog.get_logger(__name__)


class CIRCLCollector:
    """
    CIRCL Vulnerability-Lookup API client.
    
    FREE service, no authentication required.
    Aggregates CVE data from NVD, CISA KEV, GitHub Advisories, and more.
    """
    
    BASE_URL = "https://vulnerability.lookup.circl.lu/api"
    
    def __init__(self, timeout: int = 30):
        """
        Initialize CIRCL collector.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.logger = logger.bind(collector="circl")
        
        self.logger.info("circl_collector_initialized")
    
    @sleep_and_retry
    @limits(calls=10, period=60)  # Conservative rate limit
    @on_exception(expo, (httpx.HTTPError, httpx.TimeoutException), max_tries=3)
    async def get_cve_enrichment(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get enriched CVE data from CIRCL.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
        
        Returns:
            Dictionary with enriched CVE data or None if not found
        """
        url = f"{self.BASE_URL}/cve/{cve_id}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                
                if response.status_code == 404:
                    self.logger.debug(
                        "cve_not_found_in_circl",
                        cve_id=cve_id
                    )
                    return None
                
                response.raise_for_status()
                data = response.json()
                
                self.logger.info(
                    "circl_enrichment_retrieved",
                    cve_id=cve_id,
                    has_capec=bool(data.get("capec")),
                    has_cwe=bool(data.get("cwe")),
                    sources=len(data.get("references", []))
                )
                
                return data
                
        except httpx.HTTPStatusError as e:
            self.logger.warning(
                "circl_http_error",
                cve_id=cve_id,
                status_code=e.response.status_code,
                error=str(e)
            )
            return None
        except Exception as e:
            self.logger.error(
                "circl_request_failed",
                cve_id=cve_id,
                error=str(e)
            )
            return None
    
    def extract_capec_ids(self, circl_data: Dict[str, Any]) -> List[str]:
        """
        Extract CAPEC attack pattern IDs from CIRCL data.
        
        Args:
            circl_data: CIRCL API response
        
        Returns:
            List of CAPEC IDs (e.g., ["CAPEC-233", "CAPEC-100"])
        """
        capec_ids = []
        
        # CIRCL may provide CAPEC in different formats
        capec_data = circl_data.get("capec", [])
        
        if isinstance(capec_data, list):
            for item in capec_data:
                if isinstance(item, dict):
                    capec_id = item.get("id") or item.get("capec-id")
                    if capec_id:
                        # Normalize format
                        if not capec_id.startswith("CAPEC-"):
                            capec_id = f"CAPEC-{capec_id}"
                        capec_ids.append(capec_id)
                elif isinstance(item, str):
                    if not item.startswith("CAPEC-"):
                        item = f"CAPEC-{item}"
                    capec_ids.append(item)
        
        return capec_ids
    
    def extract_additional_references(self, circl_data: Dict[str, Any]) -> List[str]:
        """
        Extract additional reference URLs from CIRCL data.
        
        Args:
            circl_data: CIRCL API response
        
        Returns:
            List of reference URLs
        """
        refs = []
        
        # CIRCL aggregates from multiple sources
        references = circl_data.get("references", [])
        
        for ref in references:
            if isinstance(ref, dict):
                url = ref.get("url")
                if url and url not in refs:
                    refs.append(url)
            elif isinstance(ref, str):
                if ref not in refs:
                    refs.append(ref)
        
        return refs
    
    async def enrich_cve(self, cve: CVE) -> CVE:
        """
        Enrich a CVE object with CIRCL data.
        
        Args:
            cve: CVE object to enrich
        
        Returns:
            Enriched CVE object (modified in place)
        """
        circl_data = await self.get_cve_enrichment(cve.cve_id)
        
        if not circl_data:
            self.logger.debug(
                "no_circl_enrichment",
                cve_id=cve.cve_id
            )
            return cve
        
        # Extract CAPEC attack patterns
        capec_ids = self.extract_capec_ids(circl_data)
        if capec_ids:
            # Store in CVE object (will need to add this field to model)
            if not hasattr(cve, 'capec_ids'):
                cve.__dict__['capec_ids'] = []
            cve.__dict__['capec_ids'].extend(capec_ids)
            
            self.logger.info(
                "capec_patterns_added",
                cve_id=cve.cve_id,
                capec_count=len(capec_ids),
                patterns=capec_ids[:3]
            )
        
        # Extract additional references
        additional_refs = self.extract_additional_references(circl_data)
        if additional_refs:
            # Add to CVE references if not duplicate
            existing_urls = {ref.url for ref in cve.references}
            new_refs = [url for url in additional_refs if url not in existing_urls]
            
            if new_refs:
                from .models import Reference
                for url in new_refs[:5]:  # Limit to 5 new refs
                    cve.references.append(Reference(
                        url=url,
                        source="CIRCL",
                        tags=["circl-aggregated"]
                    ))
                
                self.logger.info(
                    "circl_references_added",
                    cve_id=cve.cve_id,
                    new_refs_count=len(new_refs)
                )
        
        return cve
    
    @sleep_and_retry
    @limits(calls=5, period=60)
    async def get_latest_cves(self, count: int = 30) -> List[Dict[str, Any]]:
        """
        Get latest CVEs with enrichment from CIRCL.
        
        Args:
            count: Number of latest CVEs to retrieve (max 30)
        
        Returns:
            List of enriched CVE data dictionaries
        """
        url = f"{self.BASE_URL}/browse"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                
                # CIRCL returns latest CVEs with enrichment
                cves = data if isinstance(data, list) else data.get("cves", [])
                
                self.logger.info(
                    "circl_latest_cves_retrieved",
                    count=len(cves[:count])
                )
                
                return cves[:count]
                
        except Exception as e:
            self.logger.error(
                "circl_latest_cves_failed",
                error=str(e)
            )
            return []
