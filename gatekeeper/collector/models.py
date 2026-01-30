"""
Data models for CVE and KEV vulnerability data.

These Pydantic models provide structured, validated representations
of vulnerability data from NVD and CISA KEV sources.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
from enum import Enum


class CVSSSeverity(str, Enum):
    """CVSS severity levels."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackVector(str, Enum):
    """CVSS attack vector values."""
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class AttackComplexity(str, Enum):
    """CVSS attack complexity values."""
    LOW = "LOW"
    HIGH = "HIGH"


class PrivilegesRequired(str, Enum):
    """CVSS privileges required values."""
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class UserInteraction(str, Enum):
    """CVSS user interaction values."""
    NONE = "NONE"
    REQUIRED = "REQUIRED"


class ImpactLevel(str, Enum):
    """CVSS impact levels."""
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class CVSSMetrics(BaseModel):
    """CVSS scoring metrics for a vulnerability."""
    
    version: str = Field(default="3.1", description="CVSS version")
    vector_string: Optional[str] = Field(default=None, description="CVSS vector string")
    base_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Base CVSS score")
    base_severity: CVSSSeverity = Field(default=CVSSSeverity.NONE, description="Qualitative severity")
    
    # Attack metrics
    attack_vector: Optional[AttackVector] = None
    attack_complexity: Optional[AttackComplexity] = None
    privileges_required: Optional[PrivilegesRequired] = None
    user_interaction: Optional[UserInteraction] = None
    
    # Impact metrics
    confidentiality_impact: Optional[ImpactLevel] = None
    integrity_impact: Optional[ImpactLevel] = None
    availability_impact: Optional[ImpactLevel] = None
    
    # Scores
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    
    @classmethod
    def from_nvd_metrics(cls, metrics_data: Dict[str, Any], version: str = "3.1") -> "CVSSMetrics":
        """Create CVSSMetrics from NVD API response data."""
        cvss_data = metrics_data.get("cvssData", {})
        
        # Map severity string to enum
        severity_str = cvss_data.get("baseSeverity", "NONE")
        try:
            severity = CVSSSeverity(severity_str.upper())
        except ValueError:
            severity = CVSSSeverity.NONE
        
        # Map attack vector
        av_str = cvss_data.get("attackVector", "")
        attack_vector = None
        if av_str:
            try:
                attack_vector = AttackVector(av_str.upper())
            except ValueError:
                pass
        
        # Map attack complexity
        ac_str = cvss_data.get("attackComplexity", "")
        attack_complexity = None
        if ac_str:
            try:
                attack_complexity = AttackComplexity(ac_str.upper())
            except ValueError:
                pass
        
        # Map privileges required
        pr_str = cvss_data.get("privilegesRequired", "")
        privileges_required = None
        if pr_str:
            try:
                privileges_required = PrivilegesRequired(pr_str.upper())
            except ValueError:
                pass
        
        # Map user interaction
        ui_str = cvss_data.get("userInteraction", "")
        user_interaction = None
        if ui_str:
            try:
                user_interaction = UserInteraction(ui_str.upper())
            except ValueError:
                pass
        
        # Map impacts
        def get_impact(key: str) -> Optional[ImpactLevel]:
            val = cvss_data.get(key, "")
            if val:
                try:
                    return ImpactLevel(val.upper())
                except ValueError:
                    pass
            return None
        
        return cls(
            version=cvss_data.get("version", version),
            vector_string=cvss_data.get("vectorString"),
            base_score=float(cvss_data.get("baseScore", 0.0)),
            base_severity=severity,
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            confidentiality_impact=get_impact("confidentialityImpact"),
            integrity_impact=get_impact("integrityImpact"),
            availability_impact=get_impact("availabilityImpact"),
            exploitability_score=metrics_data.get("exploitabilityScore"),
            impact_score=metrics_data.get("impactScore"),
        )


class Reference(BaseModel):
    """Reference URL associated with a CVE."""
    
    url: str = Field(description="Reference URL")
    source: Optional[str] = Field(default=None, description="Source identifier")
    tags: List[str] = Field(default_factory=list, description="Reference tags")


class Weakness(BaseModel):
    """Weakness (CWE) associated with a CVE."""
    
    cwe_id: str = Field(description="CWE identifier (e.g., CWE-79)")
    description: Optional[str] = Field(default=None, description="Weakness description")
    source: Optional[str] = Field(default=None, description="Source of the weakness mapping")


class CPEMatch(BaseModel):
    """
    Detailed CPE match configuration with version constraints from NVD.
    
    Provides structured access to affected product/version information
    for enterprise-grade advisory generation.
    """
    
    criteria: str = Field(description="Full CPE 2.3 string")
    vulnerable: bool = Field(default=True, description="Is this configuration vulnerable")
    
    # Version constraints from NVD
    version_start_including: Optional[str] = Field(default=None, description="Start version (inclusive)")
    version_start_excluding: Optional[str] = Field(default=None, description="Start version (exclusive)")
    version_end_including: Optional[str] = Field(default=None, description="End version (inclusive)")
    version_end_excluding: Optional[str] = Field(default=None, description="End version (exclusive)")
    
    # Parsed CPE components
    vendor: Optional[str] = Field(default=None, description="Vendor name")
    product: Optional[str] = Field(default=None, description="Product name")
    version: Optional[str] = Field(default=None, description="Specific version if not a range")
    
    @classmethod
    def from_nvd_match(cls, match_data: Dict[str, Any]) -> "CPEMatch":
        """
        Create CPEMatch from NVD cpeMatch data.
        
        Args:
            match_data: CPE match dictionary from NVD API
        
        Returns:
            Parsed CPEMatch instance
        """
        criteria = match_data.get("criteria", "")
        
        # Parse CPE 2.3 string: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        vendor, product, version = None, None, None
        if criteria:
            parts = criteria.split(":")
            if len(parts) >= 5:
                vendor = parts[3].replace("_", " ").replace("-", " ").title() if parts[3] != "*" else None
                product = parts[4].replace("_", " ").replace("-", " ").title() if parts[4] != "*" else None
                if len(parts) > 5 and parts[5] not in ("*", "-"):
                    version = parts[5]
        
        return cls(
            criteria=criteria,
            vulnerable=match_data.get("vulnerable", True),
            version_start_including=match_data.get("versionStartIncluding"),
            version_start_excluding=match_data.get("versionStartExcluding"),
            version_end_including=match_data.get("versionEndIncluding"),
            version_end_excluding=match_data.get("versionEndExcluding"),
            vendor=vendor,
            product=product,
            version=version
        )
    
    @property
    def version_range_text(self) -> str:
        """
        Generate human-readable version range text.
        
        Returns:
            Formatted version range string for display in advisories
        """
        if self.version and self.version != "*":
            return f"version {self.version}"
        
        parts = []
        
        # Start constraint
        if self.version_start_including:
            parts.append(f"from {self.version_start_including}")
        elif self.version_start_excluding:
            parts.append(f"after {self.version_start_excluding}")
        
        # End constraint
        if self.version_end_including:
            parts.append(f"to {self.version_end_including}")
        elif self.version_end_excluding:
            parts.append(f"before {self.version_end_excluding}")
        
        if parts:
            return " ".join(parts)
        
        return "all versions"
    
    @property
    def display_name(self) -> str:
        """Get vendor product name for display."""
        parts = []
        if self.vendor:
            parts.append(self.vendor)
        if self.product:
            parts.append(self.product)
        return " ".join(parts) if parts else "Unknown Product"



class KEVEntry(BaseModel):
    """CISA Known Exploited Vulnerability catalog entry."""
    
    cve_id: str = Field(description="CVE identifier")
    vendor_project: str = Field(default="", description="Vendor or project name")
    product: str = Field(default="", description="Affected product name")
    vulnerability_name: str = Field(default="", description="Vulnerability title")
    date_added: Optional[datetime] = Field(default=None, description="Date added to KEV catalog")
    short_description: str = Field(default="", description="Brief vulnerability description")
    required_action: str = Field(default="", description="Required remediation action")
    due_date: Optional[datetime] = Field(default=None, description="Remediation due date")
    known_ransomware_use: str = Field(default="Unknown", description="Known ransomware campaign use")
    notes: str = Field(default="", description="Additional notes")
    cwes: List[str] = Field(default_factory=list, description="Associated CWE identifiers")
    
    @classmethod
    def from_kev_data(cls, data: Dict[str, Any]) -> "KEVEntry":
        """Create KEVEntry from CISA KEV catalog JSON data."""
        # Parse dates
        date_added = None
        if data.get("dateAdded"):
            try:
                date_added = datetime.strptime(data["dateAdded"], "%Y-%m-%d")
            except (ValueError, TypeError):
                pass
        
        due_date = None
        if data.get("dueDate"):
            try:
                due_date = datetime.strptime(data["dueDate"], "%Y-%m-%d")
            except (ValueError, TypeError):
                pass
        
        return cls(
            cve_id=data.get("cveID", ""),
            vendor_project=data.get("vendorProject", ""),
            product=data.get("product", ""),
            vulnerability_name=data.get("vulnerabilityName", ""),
            date_added=date_added,
            short_description=data.get("shortDescription", ""),
            required_action=data.get("requiredAction", ""),
            due_date=due_date,
            known_ransomware_use=data.get("knownRansomwareCampaignUse", "Unknown"),
            notes=data.get("notes", ""),
            cwes=data.get("cwes", []),
        )


class CVE(BaseModel):
    """Complete CVE vulnerability record."""
    
    cve_id: str = Field(description="CVE identifier (e.g., CVE-2024-1234)")
    source_identifier: Optional[str] = Field(default=None, description="Source that reported the CVE")
    
    # Timestamps
    published: Optional[datetime] = Field(default=None, description="Date CVE was published")
    last_modified: Optional[datetime] = Field(default=None, description="Date CVE was last modified")
    
    # Status
    vuln_status: str = Field(default="", description="Vulnerability status in NVD")
    
    # Descriptions
    descriptions: Dict[str, str] = Field(
        default_factory=dict, 
        description="CVE descriptions by language code"
    )
    
    # Scoring
    cvss_v31: Optional[CVSSMetrics] = Field(default=None, description="CVSS v3.1 metrics")
    cvss_v30: Optional[CVSSMetrics] = Field(default=None, description="CVSS v3.0 metrics")
    cvss_v2: Optional[CVSSMetrics] = Field(default=None, description="CVSS v2.0 metrics")
    
    # Weaknesses and references
    weaknesses: List[Weakness] = Field(default_factory=list, description="Associated CWE weaknesses")
    references: List[Reference] = Field(default_factory=list, description="Reference URLs")
    
    # Affected products - NEW structured format
    cpe_matches: List[CPEMatch] = Field(default_factory=list, description="Detailed CPE match configurations")
    vendor_names: List[str] = Field(default_factory=list, description="Extracted vendor names for filtering")
    product_names: List[str] = Field(default_factory=list, description="Extracted product names for filtering")
    
    
    # Threat intelligence enrichment (from CIRCL and other feeds)
    capec_ids: List[str] = Field(default_factory=list, description="CAPEC attack pattern IDs from CIRCL")
    exploit_available: bool = Field(default=False, description="Public exploits available (VulnCheck/Vulners)")
    exploit_sources: List[str] = Field(default_factory=list, description="Sources of exploit code")
    
    # Legacy property for backward compatibility
    @property
    def affected_products(self) -> List[str]:
        """Get list of CPE criteria strings (legacy compatibility)."""
        return [cpe.criteria for cpe in self.cpe_matches]

    
    # KEV data (if present)
    kev_entry: Optional[KEVEntry] = Field(default=None, description="KEV catalog entry if listed")

    
    # Metadata
    evaluator_comment: Optional[str] = Field(default=None, description="NVD evaluator comment")
    evaluator_solution: Optional[str] = Field(default=None, description="NVD evaluator solution")
    evaluator_impact: Optional[str] = Field(default=None, description="NVD evaluator impact")
    
    @property
    def is_in_kev(self) -> bool:
        """Check if this CVE is in the CISA KEV catalog."""
        return self.kev_entry is not None
    
    @property
    def highest_cvss_score(self) -> float:
        """Get the highest CVSS score across all versions."""
        scores = []
        if self.cvss_v31:
            scores.append(self.cvss_v31.base_score)
        if self.cvss_v30:
            scores.append(self.cvss_v30.base_score)
        if self.cvss_v2:
            scores.append(self.cvss_v2.base_score)
        return max(scores) if scores else 0.0
    
    @property
    def primary_cvss(self) -> Optional[CVSSMetrics]:
        """Get the primary (preferred) CVSS metrics."""
        return self.cvss_v31 or self.cvss_v30 or self.cvss_v2
    
    @property
    def severity(self) -> str:
        """Get the qualitative severity level."""
        cvss = self.primary_cvss
        if cvss:
            return cvss.base_severity.value
        return "UNKNOWN"
    
    @property
    def description(self) -> str:
        """Get the English description or first available."""
        if "en" in self.descriptions:
            return self.descriptions["en"]
        if self.descriptions:
            return next(iter(self.descriptions.values()))
        return ""
    
    @property
    def cwe_ids(self) -> List[str]:
        """Get list of CWE IDs."""
        return [w.cwe_id for w in self.weaknesses]
    
    @property
    def vulnerability_type(self) -> str:
        """Derive vulnerability type from CWE or description."""
        # Common CWE to type mappings
        cwe_type_map = {
            "CWE-79": "Cross-Site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-94": "Code Injection",
            "CWE-78": "OS Command Injection",
            "CWE-22": "Path Traversal",
            "CWE-287": "Authentication Bypass",
            "CWE-288": "Authentication Bypass Using Alternate Path",
            "CWE-306": "Missing Authentication",
            "CWE-434": "Unrestricted File Upload",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-611": "XML External Entity (XXE)",
            "CWE-787": "Out-of-Bounds Write",
            "CWE-416": "Use After Free",
            "CWE-190": "Integer Overflow",
            "CWE-200": "Information Disclosure",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-362": "Race Condition",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-862": "Missing Authorization",
            "CWE-863": "Incorrect Authorization",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
            "CWE-119": "Buffer Overflow",
            "CWE-120": "Buffer Overflow",
            "CWE-121": "Stack-Based Buffer Overflow",
            "CWE-122": "Heap-Based Buffer Overflow",
            "CWE-125": "Out-of-Bounds Read",
            "CWE-269": "Improper Privilege Management",
            "CWE-284": "Improper Access Control",
            "CWE-400": "Resource Exhaustion (DoS)",
            "CWE-476": "NULL Pointer Dereference",
            "CWE-732": "Incorrect Permission Assignment",
            "CWE-755": "Improper Handling of Exceptional Conditions",
            "CWE-770": "Allocation of Resources Without Limits (DoS)",
            "CWE-1321": "Prototype Pollution",
        }
        
        for weakness in self.weaknesses:
            if weakness.cwe_id in cwe_type_map:
                return cwe_type_map[weakness.cwe_id]
        
        # Fallback to first CWE description or generic
        if self.weaknesses and self.weaknesses[0].description:
            return self.weaknesses[0].description
        
        # Try to detect from description
        desc_lower = self.description.lower()
        
        # Check for common vulnerability patterns in description
        desc_patterns = [
            (["remote code execution", "execute arbitrary code", "code execution"], "Remote Code Execution"),
            (["command injection", "os command"], "OS Command Injection"),
            (["sql injection"], "SQL Injection"),
            (["cross-site scripting", "xss"], "Cross-Site Scripting (XSS)"),
            (["buffer overflow", "stack overflow", "heap overflow"], "Buffer Overflow"),
            (["privilege escalation", "elevate privilege"], "Privilege Escalation"),
            (["authentication bypass", "bypass authentication"], "Authentication Bypass"),
            (["denial of service", "dos", "crash", "resource exhaustion"], "Denial of Service"),
            (["information disclosure", "sensitive information", "expose information"], "Information Disclosure"),
            (["path traversal", "directory traversal", ".."], "Path Traversal"),
            (["xml external entity", "xxe"], "XML External Entity (XXE)"),
            (["deserialization"], "Insecure Deserialization"),
            (["ssrf", "server-side request"], "Server-Side Request Forgery (SSRF)"),
            (["csrf", "cross-site request"], "Cross-Site Request Forgery (CSRF)"),
            (["use after free", "use-after-free"], "Use After Free"),
            (["integer overflow", "integer underflow"], "Integer Overflow"),
            (["null pointer", "null dereference"], "NULL Pointer Dereference"),
            (["out-of-bounds read"], "Out-of-Bounds Read"),
            (["out-of-bounds write"], "Out-of-Bounds Write"),
            (["memory corruption"], "Memory Corruption"),
            (["arbitrary file"], "Arbitrary File Access"),
            (["hardcoded", "hard-coded", "default password"], "Use of Hard-coded Credentials"),
        ]
        
        for patterns, vuln_type in desc_patterns:
            if any(p in desc_lower for p in patterns):
                return vuln_type
        
        return "Unspecified Vulnerability"
    
    @classmethod
    def from_nvd_response(cls, cve_data: Dict[str, Any]) -> "CVE":
        """Create CVE from NVD API response data."""
        cve = cve_data.get("cve", {})
        
        # Parse timestamps
        published = None
        if cve.get("published"):
            try:
                published = datetime.fromisoformat(cve["published"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        last_modified = None
        if cve.get("lastModified"):
            try:
                last_modified = datetime.fromisoformat(cve["lastModified"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        # Parse descriptions
        descriptions = {}
        for desc in cve.get("descriptions", []):
            lang = desc.get("lang", "en")
            descriptions[lang] = desc.get("value", "")
        
        # Parse CVSS metrics
        cvss_v31 = None
        cvss_v30 = None
        cvss_v2 = None
        
        metrics = cve.get("metrics", {})
        
        if metrics.get("cvssMetricV31"):
            for m in metrics["cvssMetricV31"]:
                if m.get("type") == "Primary" or cvss_v31 is None:
                    cvss_v31 = CVSSMetrics.from_nvd_metrics(m, "3.1")
        
        if metrics.get("cvssMetricV30"):
            for m in metrics["cvssMetricV30"]:
                if m.get("type") == "Primary" or cvss_v30 is None:
                    cvss_v30 = CVSSMetrics.from_nvd_metrics(m, "3.0")
        
        if metrics.get("cvssMetricV2"):
            for m in metrics["cvssMetricV2"]:
                if m.get("type") == "Primary" or cvss_v2 is None:
                    cvss_v2 = CVSSMetrics.from_nvd_metrics(m, "2.0")
        
        # Parse weaknesses
        weaknesses = []
        for weakness_data in cve.get("weaknesses", []):
            source = weakness_data.get("source")
            for desc in weakness_data.get("description", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("value", "")
                    if cwe_id and cwe_id.startswith("CWE-"):
                        weaknesses.append(Weakness(
                            cwe_id=cwe_id,
                            source=source
                        ))
        
        # Parse references
        references = []
        for ref in cve.get("references", []):
            references.append(Reference(
                url=ref.get("url", ""),
                source=ref.get("source"),
                tags=ref.get("tags", [])
            ))
        
        # Parse affected products from configurations with detailed CPE match data
        cpe_matches = []
        vendor_names_set = set()
        product_names_set = set()
        
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match_data in node.get("cpeMatch", []):
                    if match_data.get("vulnerable", True):
                        cpe_match = CPEMatch.from_nvd_match(match_data)
                        cpe_matches.append(cpe_match)
                        
                        # Extract vendor/product names for filtering
                        if cpe_match.vendor:
                            vendor_names_set.add(cpe_match.vendor)
                        if cpe_match.product:
                            product_names_set.add(cpe_match.product)

        
        return cls(
            cve_id=cve.get("id", ""),
            source_identifier=cve.get("sourceIdentifier"),
            published=published,
            last_modified=last_modified,
            vuln_status=cve.get("vulnStatus", ""),
            descriptions=descriptions,
            cvss_v31=cvss_v31,
            cvss_v30=cvss_v30,
            cvss_v2=cvss_v2,
            weaknesses=weaknesses,
            references=references,
            cpe_matches=cpe_matches,
            vendor_names=sorted(list(vendor_names_set)),
            product_names=sorted(list(product_names_set)),
            evaluator_comment=cve.get("evaluatorComment"),
            evaluator_solution=cve.get("evaluatorSolution"),
            evaluator_impact=cve.get("evaluatorImpact"),
        )


class ResearchResult(BaseModel):
    """Result from OSINT research."""
    
    query: str = Field(description="Search query used")
    title: str = Field(default="", description="Result title")
    url: str = Field(description="Result URL")
    snippet: str = Field(default="", description="Result snippet/description")
    source: str = Field(default="duckduckgo", description="Search source")
    
    # Classification
    is_vendor_advisory: bool = Field(default=False, description="Is this a vendor advisory")
    is_exploit_reference: bool = Field(default=False, description="Is this an exploit reference")
    is_patch_info: bool = Field(default=False, description="Contains patch information")
    is_technical_analysis: bool = Field(default=False, description="Contains technical analysis")


class EnrichedCVE(BaseModel):
    """CVE enriched with research data."""
    
    cve: CVE = Field(description="Original CVE data")
    
    # Research results
    research_results: List[ResearchResult] = Field(
        default_factory=list,
        description="All research results"
    )
    
    # Categorized results
    vendor_advisories: List[ResearchResult] = Field(
        default_factory=list,
        description="Vendor advisory references"
    )
    exploit_references: List[ResearchResult] = Field(
        default_factory=list,
        description="Exploit and PoC references"
    )
    patch_references: List[ResearchResult] = Field(
        default_factory=list,
        description="Patch and update references"
    )
    technical_analyses: List[ResearchResult] = Field(
        default_factory=list,
        description="Technical analysis articles"
    )
    
    # Research metadata
    research_completed: bool = Field(default=False, description="Research phase completed")
    research_timestamp: Optional[datetime] = Field(default=None, description="When research was performed")
    
    @property
    def has_active_exploitation(self) -> bool:
        """Check if there's evidence of active exploitation."""
        # KEV listing indicates active exploitation
        if self.cve.is_in_kev:
            return True
        
        # Check for exploit keywords in research
        exploit_keywords = ["actively exploited", "in the wild", "poc", "proof of concept"]
        for result in self.research_results:
            snippet_lower = result.snippet.lower()
            if any(kw in snippet_lower for kw in exploit_keywords):
                return True
        
        return False
    
    @property
    def exploitation_status(self) -> str:
        """Get exploitation status string."""
        if self.cve.is_in_kev:
            return "Active Exploitation (CISA KEV Listed)"
        if self.has_active_exploitation:
            return "Potential Active Exploitation"
        if self.exploit_references:
            return "PoC/Exploit Code Available"
        return "Theoretical/No Known Exploitation"
