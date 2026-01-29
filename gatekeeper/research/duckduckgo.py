"""
DuckDuckGo search client for OSINT research.

Provides rate-limited web search functionality using DuckDuckGo
for gathering additional vulnerability intelligence.
"""

import time
import re
from typing import List, Optional
from urllib.parse import urlparse

import structlog
from duckduckgo_search import DDGS

from ..config import Config
from ..collector.models import ResearchResult

logger = structlog.get_logger(__name__)


# Patterns for classifying search results
VENDOR_DOMAINS = [
    "microsoft.com", "apple.com", "google.com", "oracle.com",
    "cisco.com", "vmware.com", "broadcom.com", "adobe.com",
    "fortinet.com", "paloaltonetworks.com", "juniper.net",
    "redhat.com", "canonical.com", "debian.org", "suse.com",
    "apache.org", "mozilla.org", "opensuse.org", "fedoraproject.org",
    "support.microsoft.com", "support.apple.com", "cloud.google.com",
]

EXPLOIT_DOMAINS = [
    "exploit-db.com", "packetstormsecurity.com", "rapid7.com",
    "vuldb.com", "vulners.com", "cvedetails.com",
    "sploitus.com", "0day.today", "seebug.org",
]

SECURITY_BLOG_DOMAINS = [
    "blog.qualys.com", "unit42.paloaltonetworks.com", "research.checkpoint.com",
    "securelist.com", "blog.talosintelligence.com", "blog.rapid7.com",
    "crowdstrike.com", "mandiant.com", "sentinelone.com",
    "thedfirreport.com", "bleepingcomputer.com", "thehackernews.com",
    "securityweek.com", "darkreading.com", "krebsonsecurity.com",
]

EXPLOIT_KEYWORDS = [
    "exploit", "poc", "proof of concept", "proof-of-concept",
    "payload", "shellcode", "metasploit", "nuclei template",
    "weaponized", "in the wild", "actively exploited",
]

PATCH_KEYWORDS = [
    "patch", "update", "fix", "hotfix", "remediation",
    "security update", "security bulletin", "advisory",
    "mitigation", "workaround",
]

ANALYSIS_KEYWORDS = [
    "analysis", "deep dive", "technical details", "root cause",
    "vulnerability analysis", "security research", "writeup",
    "write-up", "disclosure", "full disclosure",
]


class DuckDuckGoSearcher:
    """
    DuckDuckGo search client with rate limiting.
    
    Uses the duckduckgo-search library to perform web searches
    for vulnerability research purposes.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the searcher.
        
        Args:
            config: Application configuration.
        """
        self.config = config
        self.delay_seconds = config.duckduckgo_delay_seconds
        self.max_results = config.max_search_results_per_query
        self._last_search_time: float = 0
        
        logger.info(
            "duckduckgo_searcher_initialized",
            delay_seconds=self.delay_seconds,
            max_results=self.max_results
        )
    
    def _wait_for_rate_limit(self):
        """Wait if necessary to respect rate limits."""
        now = time.time()
        elapsed = now - self._last_search_time
        
        if elapsed < self.delay_seconds:
            wait_time = self.delay_seconds - elapsed
            logger.debug("duckduckgo_rate_limit_wait", wait_seconds=wait_time)
            time.sleep(wait_time)
        
        self._last_search_time = time.time()
    
    def _classify_result(self, url: str, title: str, snippet: str) -> dict:
        """
        Classify a search result based on URL and content.
        
        Args:
            url: Result URL.
            title: Result title.
            snippet: Result snippet.
        
        Returns:
            Dict with classification flags.
        """
        url_lower = url.lower()
        title_lower = title.lower()
        snippet_lower = snippet.lower()
        combined = f"{title_lower} {snippet_lower}"
        
        # Extract domain
        try:
            domain = urlparse(url).netloc.lower()
            # Remove www prefix
            if domain.startswith("www."):
                domain = domain[4:]
        except Exception:
            domain = ""
        
        # Check for vendor advisory
        is_vendor = any(vd in domain for vd in VENDOR_DOMAINS)
        is_vendor = is_vendor or "advisory" in combined or "security bulletin" in combined
        
        # Check for exploit reference
        is_exploit = any(ed in domain for ed in EXPLOIT_DOMAINS)
        is_exploit = is_exploit or any(kw in combined for kw in EXPLOIT_KEYWORDS)
        is_exploit = is_exploit or "github.com" in domain and ("poc" in combined or "exploit" in combined)
        
        # Check for patch info
        is_patch = any(kw in combined for kw in PATCH_KEYWORDS)
        
        # Check for technical analysis
        is_analysis = any(bd in domain for bd in SECURITY_BLOG_DOMAINS)
        is_analysis = is_analysis or any(kw in combined for kw in ANALYSIS_KEYWORDS)
        
        return {
            "is_vendor_advisory": is_vendor,
            "is_exploit_reference": is_exploit,
            "is_patch_info": is_patch,
            "is_technical_analysis": is_analysis,
        }
    
    def search(self, query: str, max_results: Optional[int] = None) -> List[ResearchResult]:
        """
        Perform a DuckDuckGo search.
        
        Args:
            query: Search query string.
            max_results: Maximum results to return (default from config).
        
        Returns:
            List of ResearchResult objects.
        """
        if max_results is None:
            max_results = self.max_results
        
        self._wait_for_rate_limit()
        
        results = []
        
        try:
            logger.debug("duckduckgo_search", query=query)
            
            with DDGS() as ddgs:
                search_results = list(ddgs.text(
                    query,
                    max_results=max_results,
                    safesearch="off"
                ))
            
            for item in search_results:
                url = item.get("href", item.get("link", ""))
                title = item.get("title", "")
                snippet = item.get("body", item.get("snippet", ""))
                
                if not url:
                    continue
                
                # Classify the result
                classification = self._classify_result(url, title, snippet)
                
                result = ResearchResult(
                    query=query,
                    title=title,
                    url=url,
                    snippet=snippet,
                    source="duckduckgo",
                    **classification
                )
                results.append(result)
            
            logger.debug(
                "duckduckgo_search_completed",
                query=query,
                results_count=len(results)
            )
            
        except Exception as e:
            logger.warning("duckduckgo_search_error", query=query, error=str(e))
        
        return results
    
    def search_cve(
        self,
        cve_id: str,
        product: Optional[str] = None,
        queries_count: int = 5
    ) -> List[ResearchResult]:
        """
        Perform multiple searches for a CVE.
        
        Args:
            cve_id: CVE identifier.
            product: Affected product name (optional).
            queries_count: Number of different queries to run.
        
        Returns:
            Combined list of ResearchResult objects (deduplicated by URL).
        """
        queries = self._build_cve_queries(cve_id, product, queries_count)
        
        all_results: List[ResearchResult] = []
        seen_urls: set = set()
        
        for query in queries:
            results = self.search(query)
            
            for result in results:
                # Deduplicate by URL
                if result.url not in seen_urls:
                    seen_urls.add(result.url)
                    all_results.append(result)
        
        logger.info(
            "cve_research_completed",
            cve_id=cve_id,
            queries_run=len(queries),
            unique_results=len(all_results)
        )
        
        return all_results
    
    def _build_cve_queries(
        self,
        cve_id: str,
        product: Optional[str],
        count: int
    ) -> List[str]:
        """
        Build search queries for a CVE.
        
        Args:
            cve_id: CVE identifier.
            product: Affected product name.
            count: Maximum number of queries.
        
        Returns:
            List of search query strings.
        """
        queries = []
        
        # Basic CVE search
        queries.append(f"{cve_id}")
        
        # Exploit/PoC search
        queries.append(f"{cve_id} exploit PoC")
        
        # Vendor advisory search
        queries.append(f"{cve_id} advisory patch")
        
        # Technical analysis search
        queries.append(f"{cve_id} technical analysis")
        
        # Detection/indicators search
        queries.append(f"{cve_id} detection indicators IOC")
        
        # Product-specific search if available
        if product:
            # Clean up product name
            product_clean = re.sub(r'[^\w\s]', ' ', product).strip()
            if product_clean:
                queries.append(f"{product_clean} {cve_id} vulnerability")
        
        # Mitigation search
        queries.append(f"{cve_id} mitigation remediation")
        
        return queries[:count]


class SearchResultAggregator:
    """
    Aggregates and categorizes search results.
    """
    
    @staticmethod
    def categorize(results: List[ResearchResult]) -> dict:
        """
        Categorize research results by type.
        
        Args:
            results: List of research results.
        
        Returns:
            Dict with categorized results.
        """
        vendor_advisories = []
        exploit_references = []
        patch_references = []
        technical_analyses = []
        other = []
        
        for result in results:
            if result.is_vendor_advisory:
                vendor_advisories.append(result)
            elif result.is_exploit_reference:
                exploit_references.append(result)
            elif result.is_patch_info:
                patch_references.append(result)
            elif result.is_technical_analysis:
                technical_analyses.append(result)
            else:
                other.append(result)
        
        return {
            "vendor_advisories": vendor_advisories,
            "exploit_references": exploit_references,
            "patch_references": patch_references,
            "technical_analyses": technical_analyses,
            "other": other,
        }
