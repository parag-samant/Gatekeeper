"""
Product and vendor filtering for CVEs.

Provides flexible filtering of CVEs based on product names, vendors,
and configurable keyword matching from filters.yaml configuration.
"""

from typing import List, Optional
import structlog

from .collector.models import CVE
from .config import ProductFilter


logger = structlog.get_logger(__name__)


class CVEFilter:
    """Filters CVEs based on product/vendor criteria from configuration."""
    
    def __init__(
        self,
        product_filters: List[ProductFilter],
        exclude_filters: Optional[List[ProductFilter]] = None
    ):
        """
        Initialize CVE filter.
        
        Args:
            product_filters: List of product filters to match (OR logic).
            exclude_filters: List of exclusion filters (optional).
        """
        self.product_filters = product_filters or []
        self.exclude_filters = exclude_filters or []
        
        logger.info(
            "cve_filter_initialized",
            product_filters=len(self.product_filters),
            exclude_filters=len(self.exclude_filters)
        )
    
    def matches_product(self, cve: CVE) -> bool:
        """
        Check if CVE matches product filtering criteria.
        
        Args:
            cve: CVE to check.
        
        Returns:
            True if CVE should be processed (matches filters), False otherwise.
        """
        # If no product filters configured, include everything
        if not self.product_filters:
            logger.debug("no_product_filters_all_included", cve_id=cve.cve_id)
            return True
        
        # Build searchable text from CVE data
        search_text = self._build_search_text(cve)
        
        # Check exclusions first (highest priority)
        if self.exclude_filters:
            for exclude_filter in self.exclude_filters:
                if self._matches_filter(search_text, exclude_filter, cve):
                    logger.debug(
                        "cve_excluded",
                        cve_id=cve.cve_id,
                        filter_keywords=exclude_filter.keywords
                    )
                    return False
        
        # Must match at least one product filter (OR logic)
        for product_filter in self.product_filters:
            if self._matches_filter(search_text, product_filter, cve):
                logger.debug(
                    "cve_matched_filter",
                    cve_id=cve.cve_id,
                    filter_keywords=product_filter.keywords,
                    filter_vendor=product_filter.vendor
                )
                return True
        
        # No filters matched
        logger.debug("cve_no_filter_match", cve_id=cve.cve_id)
        return False
    
    def _build_search_text(self, cve: CVE) -> str:
        """
        Build searchable text from CVE metadata.
        
        Combines:
        - CVE description
        - CPE product/vendor names
        - Vendor names extracted from CVE data
        
        Args:
            cve: CVE object.
        
        Returns:
            Lowercase searchable text.
        """
        parts = []
        
        # Add description
        if cve.description:
            parts.append(cve.description)
        
        # Add CPE criteria (product and vendor info)
        if cve.cpe_matches:
            for cpe in cve.cpe_matches:
                if cpe.criteria:
                    parts.append(cpe.criteria)
                if cpe.vulnerable:
                    # Extract vendor:product from CPE format
                    # CPE format: cpe:2.3:a:vendor:product:version:...
                    cpe_parts = cpe.criteria.split(":")
                    if len(cpe_parts) >= 5:
                        vendor = cpe_parts[3]
                        product = cpe_parts[4]
                        parts.extend([vendor, product])
        
        # Add extracted vendor names
        if cve.vendor_names:
            parts.extend(cve.vendor_names)
        
        # Add KEV vulnerability name if present
        if cve.kev_entry and cve.kev_entry.vulnerability_name:
            parts.append(cve.kev_entry.vulnerability_name)
        
        return " ".join(parts).lower()
    
    def _matches_filter(
        self,
        search_text: str,
        filter_config: ProductFilter,
        cve: CVE
    ) -> bool:
        """
        Check if a single filter matches the CVE.
        
        Args:
            search_text: Lowercase searchable text from CVE.
            filter_config: Filter configuration to check.
            cve: Original CVE object.
        
        Returns:
            True if filter matches.
        """
        # Vendor filtering (optional, provides additional constraint)
        if filter_config.vendor:
            vendor_lower = filter_config.vendor.lower()
            
            # Check in search text
            vendor_match = vendor_lower in search_text
            
            # Also check explicit vendor_names list
            if not vendor_match and cve.vendor_names:
                vendor_match = any(
                    vendor_lower in v.lower()
                    for v in cve.vendor_names
                )
            
            # If vendor specified but doesn't match, filter doesn't match
            if not vendor_match:
                return False
        
        # Keyword matching (required)
        if filter_config.keywords:
            keyword_match = any(
                keyword.lower() in search_text
                for keyword in filter_config.keywords
            )
            
            if not keyword_match:
                return False
        
        # Both vendor (if specified) and keywords (if specified) matched
        return True
    
    def get_matching_filters(self, cve: CVE) -> List[ProductFilter]:
        """
        Get list of all filters that match a CVE.
        
        Useful for debugging and logging which products triggered the match.
        
        Args:
            cve: CVE to check.
        
        Returns:
            List of matching ProductFilter objects.
        """
        if not self.product_filters:
            return []
        
        search_text = self._build_search_text(cve)
        matches = []
        
        for product_filter in self.product_filters:
            if self._matches_filter(search_text, product_filter, cve):
                matches.append(product_filter)
        
        return matches
