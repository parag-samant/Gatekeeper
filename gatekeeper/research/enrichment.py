"""
CVE enrichment orchestrator.

Coordinates research activities to enrich CVE data with
additional intelligence from various OSINT sources.
"""

from datetime import datetime, timezone
from typing import List, Optional

import structlog

from ..config import Config
from ..collector.models import CVE, EnrichedCVE, ResearchResult
from ..collector.kev import KEVClient
from ..collector.circl import CIRCLCollector
from ..collector.vulncheck import VulnCheckCollector
from ..collector.vulners import VulnersCollector
from .duckduckgo import DuckDuckGoSearcher, SearchResultAggregator

logger = structlog.get_logger(__name__)


class CVEEnricher:
    """
    Orchestrates CVE enrichment with research data.
    
    Coordinates searches across multiple sources to build
    comprehensive vulnerability intelligence.
    """
    
    def __init__(self, config: Config, kev_client: Optional[KEVClient] = None):
        """
        Initialize the enricher.
        
        Args:
            config: Application configuration.
            kev_client: Optional KEV client (created if not provided).
        """
        self.config = config
        self.searcher = DuckDuckGoSearcher(config)
        self.kev_client = kev_client or KEVClient(config)
        self.circl_collector = CIRCLCollector()  # CIRCL threat intel
        self.vulncheck_collector = VulnCheckCollector()  # VulnCheck (faster updates + exploits)
        self.vulners_collector = VulnersCollector()  # Vulners (exploit detection)
        self.queries_per_cve = config.research_queries_per_cve
        
        logger.info("cve_enricher_initialized", queries_per_cve=self.queries_per_cve)
    
    def enrich(self, cve: CVE) -> EnrichedCVE:
        """
        Enrich a CVE with research data.
        
        Args:
            cve: CVE to enrich.
        
        Returns:
            EnrichedCVE with research results.
        """
        logger.info("enriching_cve", cve_id=cve.cve_id)
        
        # Check KEV status
        kev_entry = self.kev_client.get_kev_entry(cve.cve_id)
        if kev_entry:
            cve.kev_entry = kev_entry
            logger.info("cve_in_kev", cve_id=cve.cve_id)
        
        # CIRCL enrichment (attack patterns, additional context)
        import asyncio
        try:
            asyncio.run(self.circl_collector.enrich_cve(cve))
            if cve.capec_ids:
                logger.info(
                    "circl_enrichment_added",
                    cve_id=cve.cve_id,
                    capec_count=len(cve.capec_ids)
                )
        except Exception as e:
            logger.warning(
                "circl_enrichment_failed",
                cve_id=cve.cve_id,
                error=str(e)
            )
        
        # VulnCheck enrichment (exploit intelligence, faster updates)
        try:
            asyncio.run(self.vulncheck_collector.enrich_cve(cve))
        except Exception as e:
            logger.warning(
                "vulncheck_enrichment_failed",
                cve_id=cve.cve_id,
                error=str(e)
            )
        
        # Vulners enrichment (exploit availability detection)
        try:
            asyncio.run(self.vulners_collector.enrich_cve(cve))
        except Exception as e:
            logger.warning(
                "vulners_enrichment_failed",
                cve_id=cve.cve_id,
                error=str(e)
            )
        
        # Determine product name for search
        product = self._extract_product_name(cve)
        
        # Perform research
        research_results = self.searcher.search_cve(
            cve_id=cve.cve_id,
            product=product,
            queries_count=self.queries_per_cve
        )
        
        # Categorize results
        categorized = SearchResultAggregator.categorize(research_results)
        
        # Build enriched CVE
        enriched = EnrichedCVE(
            cve=cve,
            research_results=research_results,
            vendor_advisories=categorized["vendor_advisories"],
            exploit_references=categorized["exploit_references"],
            patch_references=categorized["patch_references"],
            technical_analyses=categorized["technical_analyses"],
            research_completed=True,
            research_timestamp=datetime.now(timezone.utc)
        )
        
        logger.info(
            "cve_enriched",
            cve_id=cve.cve_id,
            total_results=len(research_results),
            vendor_advisories=len(enriched.vendor_advisories),
            exploit_refs=len(enriched.exploit_references),
            in_kev=cve.is_in_kev,
            capec_ids=len(cve.capec_ids)
        )
        
        return enriched
    
    def enrich_batch(self, cves: List[CVE]) -> List[EnrichedCVE]:
        """
        Enrich a batch of CVEs.
        
        Args:
            cves: List of CVEs to enrich.
        
        Returns:
            List of EnrichedCVE objects.
        """
        logger.info("enriching_batch", count=len(cves))
        
        enriched = []
        for i, cve in enumerate(cves, 1):
            try:
                result = self.enrich(cve)
                enriched.append(result)
                logger.debug("batch_progress", current=i, total=len(cves))
            except Exception as e:
                logger.error(
                    "enrichment_failed",
                    cve_id=cve.cve_id,
                    error=str(e)
                )
                # Create minimal enriched CVE for failed enrichment
                enriched.append(EnrichedCVE(
                    cve=cve,
                    research_completed=False
                ))
        
        logger.info("batch_enrichment_completed", enriched=len(enriched))
        return enriched
    
    def _extract_product_name(self, cve: CVE) -> Optional[str]:
        """
        Extract a product name from CVE data for search queries.
        
        Args:
            cve: CVE to extract product from.
        
        Returns:
            Product name string or None.
        """
        # Try KEV entry first
        if cve.kev_entry:
            if cve.kev_entry.product:
                return cve.kev_entry.product
            if cve.kev_entry.vendor_project:
                return cve.kev_entry.vendor_project
        
        # Try to extract from CPE
        if cve.affected_products:
            # CPE format: cpe:2.3:a:vendor:product:version:...
            for cpe in cve.affected_products:
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    if vendor != "*" and product != "*":
                        return f"{vendor} {product}"
        
        # Try to extract from description
        description = cve.description
        if description:
            # Look for common patterns
            import re
            
            # Pattern: "X allows..." or "X contains..."
            match = re.search(r'^([A-Z][A-Za-z0-9\s\-]+?)\s+(allows|contains|has|is vulnerable)', description)
            if match:
                return match.group(1).strip()
        
        return None
    
    def close(self):
        """Clean up resources."""
        self.kev_client.close()
