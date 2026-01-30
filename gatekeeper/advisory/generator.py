"""
OpenRouter-powered advisory generator.

Uses the OpenRouter API to generate professional security
advisories from enriched CVE data. Falls back to enterprise
HTML template when AI is unavailable.
"""

import time
import hashlib
from datetime import datetime, timezone
from typing import Optional, Tuple
import html

import requests
import backoff
import structlog

from ..config import Config
from ..collector.models import EnrichedCVE
from .prompts import ADVISORY_SYSTEM_PROMPT, build_advisory_prompt

logger = structlog.get_logger(__name__)


# Color scheme for severity levels
SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#7c0a02", "text": "#ffffff", "border": "#5c0801"},
    "HIGH": {"bg": "#dc3545", "text": "#ffffff", "border": "#c82333"},
    "MEDIUM": {"bg": "#fd7e14", "text": "#ffffff", "border": "#e96b02"},
    "LOW": {"bg": "#28a745", "text": "#ffffff", "border": "#1e7e34"},
    "UNKNOWN": {"bg": "#6c757d", "text": "#ffffff", "border": "#545b62"},
}

RISK_COLORS = {
    "HIGH": {"bg": "#f8d7da", "text": "#721c24", "badge": "#dc3545"},
    "MEDIUM": {"bg": "#fff3cd", "text": "#856404", "badge": "#fd7e14"},
    "LOW": {"bg": "#d4edda", "text": "#155724", "badge": "#28a745"},
}


class AdvisoryGenerator:
    """
    AI-powered security advisory generator using OpenRouter.
    
    Uses the specified model (default: openai/gpt-oss-120b:free)
    to generate comprehensive security advisories following
    CIS MS-ISAC enterprise format. Now generates HTML output.
    """
    
    OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
    
    def __init__(self, config: Config):
        """
        Initialize the advisory generator.
        
        Args:
            config: Application configuration.
        """
        self.config = config
        self.api_key = config.openrouter_api_key
        self.model = config.openrouter_model
        self.delay_seconds = config.openrouter_delay_seconds
        self._last_request_time: float = 0
        
        # Session for requests
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/gatekeeper-cve-advisory",
            "X-Title": "Gatekeeper CVE Advisory System"
        })
        
        logger.info(
            "advisory_generator_initialized",
            model=self.model,
            delay_seconds=self.delay_seconds
        )
    
    def _wait_for_rate_limit(self):
        """Wait if necessary to respect rate limits."""
        now = time.time()
        elapsed = now - self._last_request_time
        
        if elapsed < self.delay_seconds:
            wait_time = self.delay_seconds - elapsed
            logger.debug("openrouter_rate_limit_wait", wait_seconds=wait_time)
            time.sleep(wait_time)
        
        self._last_request_time = time.time()
    
    @backoff.on_exception(
        backoff.expo,
        (requests.RequestException, requests.Timeout),
        max_tries=3,
        max_time=180
    )
    def _call_api(self, messages: list, temperature: float = 0.3) -> str:
        """
        Make a request to the OpenRouter API.
        
        Args:
            messages: Chat messages for the model.
            temperature: Sampling temperature (lower = more deterministic).
        
        Returns:
            Generated text content.
        
        Raises:
            requests.RequestException: On API error after retries.
            ValueError: If response is invalid.
        """
        self._wait_for_rate_limit()
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 4096,  # Sufficient for detailed advisory
        }
        
        logger.debug("openrouter_request", model=self.model)
        
        response = self.session.post(
            self.OPENROUTER_API_URL,
            json=payload,
            timeout=120
        )
        
        # Check for API errors
        if response.status_code != 200:
            error_detail = response.text
            logger.error(
                "openrouter_api_error",
                status_code=response.status_code,
                detail=error_detail
            )
            response.raise_for_status()
        
        data = response.json()
        
        # Extract the generated content
        choices = data.get("choices", [])
        if not choices:
            raise ValueError("No choices in API response")
        
        message = choices[0].get("message", {})
        content = message.get("content", "")
        
        if not content:
            raise ValueError("Empty content in API response")
        
        # Log usage stats if available
        usage = data.get("usage", {})
        if usage:
            logger.debug(
                "openrouter_usage",
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
                total_tokens=usage.get("total_tokens")
            )
        
        return content
    
    def generate(self, enriched_cve: EnrichedCVE) -> str:
        """
        Generate a security advisory for an enriched CVE.
        
        Args:
            enriched_cve: CVE with research data.
        
        Returns:
            Generated advisory text.
        
        Raises:
            Exception: On generation failure.
        """
        cve_id = enriched_cve.cve.cve_id
        logger.info("generating_advisory", cve_id=cve_id)
        
        # Build the prompt
        user_prompt = build_advisory_prompt(enriched_cve)
        
        messages = [
            {"role": "system", "content": ADVISORY_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            advisory = self._call_api(messages)
            logger.info(
                "advisory_generated",
                cve_id=cve_id,
                length=len(advisory)
            )
            return advisory
        except Exception as e:
            logger.error("advisory_generation_failed", cve_id=cve_id, error=str(e))
            raise
    
    def generate_with_fallback(self, enriched_cve: EnrichedCVE) -> str:
        """
        Generate advisory with fallback to template-based generation.
        
        Args:
            enriched_cve: CVE with research data.
        
        Returns:
            Generated advisory HTML.
        """
        try:
            return self.generate(enriched_cve)
        except Exception as e:
            logger.warning(
                "falling_back_to_template",
                cve_id=enriched_cve.cve.cve_id,
                error=str(e)
            )
            return self._generate_html_advisory(enriched_cve)
    
    def _generate_advisory_number(self, cve_id: str) -> str:
        """Generate a unique advisory number based on CVE ID."""
        year = datetime.now(timezone.utc).year
        # Create a hash-based number from CVE ID for consistency
        hash_num = int(hashlib.md5(cve_id.encode()).hexdigest()[:4], 16) % 1000
        return f"GK-{year}-{hash_num:03d}"
    
    def _get_mitre_attack_mapping(self, vuln_type: str) -> Tuple[str, str]:
        """Map vulnerability type to MITRE ATT&CK tactic and technique."""
        vuln_lower = vuln_type.lower()
        
        if any(x in vuln_lower for x in ['remote code', 'rce', 'command injection', 'code execution']):
            return ("Initial Access (TA0001)", "Exploit Public-Facing Application (T1190)")
        elif any(x in vuln_lower for x in ['authentication', 'auth bypass', 'credential']):
            return ("Initial Access (TA0001)", "Valid Accounts (T1078)")
        elif any(x in vuln_lower for x in ['privilege', 'escalation', 'elevation']):
            return ("Privilege Escalation (TA0004)", "Exploitation for Privilege Escalation (T1068)")
        elif any(x in vuln_lower for x in ['information disclosure', 'info leak', 'sensitive']):
            return ("Discovery (TA0007)", "System Information Discovery (T1082)")
        elif any(x in vuln_lower for x in ['denial', 'dos', 'availability']):
            return ("Impact (TA0040)", "Service Stop (T1489)")
        elif any(x in vuln_lower for x in ['sql injection', 'sqli']):
            return ("Initial Access (TA0001)", "Exploit Public-Facing Application (T1190)")
        elif any(x in vuln_lower for x in ['xss', 'cross-site', 'script']):
            return ("Execution (TA0002)", "Command and Scripting Interpreter (T1059)")
        elif any(x in vuln_lower for x in ['buffer', 'overflow', 'memory']):
            return ("Execution (TA0002)", "Exploitation for Client Execution (T1203)")
        elif any(x in vuln_lower for x in ['path traversal', 'directory', 'file']):
            return ("Discovery (TA0007)", "File and Directory Discovery (T1083)")
        else:
            return ("Initial Access (TA0001)", "Exploit Public-Facing Application (T1190)")
    
    def _calculate_risk_ratings(self, cvss, is_in_kev: bool, vuln_type: str) -> dict:
        """Calculate risk ratings for different organization types."""
        base_score = cvss.base_score if cvss else 7.0
        attack_vector = cvss.attack_vector.value if cvss and cvss.attack_vector else "NETWORK"
        
        # Base risk on CVSS score
        if base_score >= 9.0:
            base_risk = "HIGH"
        elif base_score >= 7.0:
            base_risk = "HIGH" if is_in_kev else "MEDIUM"
        elif base_score >= 4.0:
            base_risk = "MEDIUM"
        else:
            base_risk = "LOW"
        
        # Adjust for attack vector
        if attack_vector == "LOCAL":
            # Local attacks are lower risk for well-managed enterprises
            enterprise_adjustment = -1
        elif attack_vector == "PHYSICAL":
            enterprise_adjustment = -2
        else:
            enterprise_adjustment = 0
        
        risk_levels = ["LOW", "MEDIUM", "HIGH"]
        
        def adjust_risk(base: str, adjustment: int) -> str:
            idx = risk_levels.index(base)
            new_idx = max(0, min(2, idx + adjustment))
            return risk_levels[new_idx]
        
        return {
            "gov_large": base_risk,
            "gov_small": adjust_risk(base_risk, enterprise_adjustment),
            "biz_large": base_risk,
            "biz_small": base_risk,
            "home": adjust_risk(base_risk, -1) if attack_vector == "NETWORK" else "LOW"
        }
    
    def _escape(self, text: str) -> str:
        """Escape HTML special characters."""
        return html.escape(str(text)) if text else ""
    
    def _extract_product_from_description(self, description: str) -> Tuple[str, str]:
        """
        Extract vendor and product name from CVE description.
        
        Returns:
            Tuple of (vendor, product) or ("Unknown Vendor", "Unknown Product")
        """
        if not description:
            return ("Unknown Vendor", "Unknown Product")
        
        # Common patterns in CVE descriptions
        # Pattern 1: "X before version Y" or "X prior to Y"
        # Pattern 2: "vulnerability in X allows"
        # Pattern 3: "X Y.Z.W allows" (product version allows)
        # Pattern 4: "in X, a vulnerability"
        
        import re
        
        # Try to find product name at the start - usually "Product version allows"
        # or "A vulnerability in Product"
        
        # Pattern: starts with product name followed by version
        match = re.match(r'^([A-Z][A-Za-z0-9\s\-_.]+?)[\s]+(v?[\d]+\.[\d]+[^\s]*|before|prior|through)', description)
        if match:
            product = match.group(1).strip()
            # Clean up common suffixes
            product = re.sub(r'\s+(plugin|extension|module|component|package)$', '', product, flags=re.IGNORECASE)
            return (self._guess_vendor(product, description), product)
        
        # Pattern: "A vulnerability in X allows" or "An issue in X"
        match = re.search(r'(?:vulnerability|issue|flaw|bug)\s+in\s+([A-Z][A-Za-z0-9\s\-_.]+?)(?:\s+(?:v?[\d]+\.[\d]+|allows|before|prior|could|permits|enables|through))', description)
        if match:
            product = match.group(1).strip()
            return (self._guess_vendor(product, description), product)
        
        # Pattern: "X is vulnerable" or "X contains"
        match = re.search(r'^([A-Z][A-Za-z0-9\s\-_.]+?)\s+(?:is\s+vulnerable|contains|has)', description)
        if match:
            product = match.group(1).strip()
            return (self._guess_vendor(product, description), product)
        
        # Pattern: Look for common vendor products
        known_products = {
            'wordpress': 'WordPress',
            'apache': 'Apache',
            'nginx': 'Nginx',
            'microsoft': 'Microsoft',
            'linux kernel': 'Linux Kernel',
            'chrome': 'Google Chrome',
            'firefox': 'Mozilla Firefox',
            'jenkins': 'Jenkins',
            'docker': 'Docker',
            'kubernetes': 'Kubernetes',
            'redis': 'Redis',
            'mysql': 'MySQL',
            'postgresql': 'PostgreSQL',
            'mongodb': 'MongoDB',
            'oracle': 'Oracle',
            'cisco': 'Cisco',
            'fortinet': 'Fortinet',
            'palo alto': 'Palo Alto Networks',
            'vmware': 'VMware',
            'citrix': 'Citrix',
            'adobe': 'Adobe',
            'php': 'PHP',
            'python': 'Python',
            'node.js': 'Node.js',
            'nodejs': 'Node.js',
            'jquery': 'jQuery',
            'react': 'React',
            'angular': 'Angular',
            'vue': 'Vue.js',
            'laravel': 'Laravel',
            'django': 'Django',
            'spring': 'Spring Framework',
            'tomcat': 'Apache Tomcat',
            'jboss': 'JBoss',
            'weblogic': 'Oracle WebLogic',
            'websphere': 'IBM WebSphere',
            'iis': 'Microsoft IIS',
            'exchange': 'Microsoft Exchange',
            'sharepoint': 'Microsoft SharePoint',
            'office': 'Microsoft Office',
            'windows': 'Microsoft Windows',
            'macos': 'Apple macOS',
            'ios': 'Apple iOS',
            'android': 'Google Android',
            'samsung': 'Samsung',
            'huawei': 'Huawei',
            'zyxel': 'Zyxel',
            'netgear': 'Netgear',
            'tp-link': 'TP-Link',
            'd-link': 'D-Link',
            'gitlab': 'GitLab',
            'github': 'GitHub',
            'bitbucket': 'Bitbucket',
            'jira': 'Atlassian Jira',
            'confluence': 'Atlassian Confluence',
            'slack': 'Slack',
            'zoom': 'Zoom',
            'teams': 'Microsoft Teams',
        }
        
        desc_lower = description.lower()
        for key, product in known_products.items():
            if key in desc_lower:
                return (self._guess_vendor(product, description), product)
        
        return ("Unknown Vendor", "Unknown Product")
    
    def _guess_vendor(self, product: str, description: str) -> str:
        """Guess the vendor based on product name."""
        product_lower = product.lower()
        desc_lower = description.lower()
        
        vendor_mappings = {
            'wordpress': 'WordPress.org',
            'apache': 'Apache Software Foundation',
            'nginx': 'F5/Nginx',
            'linux': 'Linux',
            'chrome': 'Google',
            'firefox': 'Mozilla',
            'edge': 'Microsoft',
            'safari': 'Apple',
            'microsoft': 'Microsoft',
            'windows': 'Microsoft',
            'office': 'Microsoft',
            'exchange': 'Microsoft',
            'azure': 'Microsoft',
            'oracle': 'Oracle',
            'java': 'Oracle',
            'mysql': 'Oracle',
            'cisco': 'Cisco',
            'fortinet': 'Fortinet',
            'fortigate': 'Fortinet',
            'fortios': 'Fortinet',
            'palo alto': 'Palo Alto Networks',
            'vmware': 'VMware',
            'citrix': 'Citrix',
            'adobe': 'Adobe',
            'acrobat': 'Adobe',
            'photoshop': 'Adobe',
            'ibm': 'IBM',
            'sap': 'SAP',
            'salesforce': 'Salesforce',
            'atlassian': 'Atlassian',
            'jira': 'Atlassian',
            'confluence': 'Atlassian',
            'gitlab': 'GitLab',
            'jenkins': 'Jenkins Project',
            'docker': 'Docker Inc',
            'kubernetes': 'CNCF',
            'redis': 'Redis Ltd',
            'mongodb': 'MongoDB Inc',
            'postgresql': 'PostgreSQL Global Development Group',
            'php': 'PHP Group',
            'python': 'Python Software Foundation',
            'node': 'OpenJS Foundation',
            'jquery': 'OpenJS Foundation',
            'react': 'Meta',
            'facebook': 'Meta',
            'angular': 'Google',
            'vue': 'Vue.js',
            'laravel': 'Laravel',
            'django': 'Django Software Foundation',
            'spring': 'VMware',
            'tomcat': 'Apache Software Foundation',
            'samsung': 'Samsung',
            'huawei': 'Huawei',
            'apple': 'Apple',
            'macos': 'Apple',
            'ios': 'Apple',
            'iphone': 'Apple',
            'ipad': 'Apple',
            'android': 'Google',
            'pixel': 'Google',
            'zyxel': 'Zyxel',
            'netgear': 'Netgear',
            'tp-link': 'TP-Link',
            'd-link': 'D-Link',
            'zoom': 'Zoom Video Communications',
            'slack': 'Salesforce',
            'teams': 'Microsoft',
        }
        
        for key, vendor in vendor_mappings.items():
            if key in product_lower or key in desc_lower:
                return vendor
        
        # Try to extract from description patterns like "Vendor Product"
        # or check if the first word of product is a known vendor
        first_word = product.split()[0].lower() if product else ""
        if first_word in vendor_mappings:
            return vendor_mappings[first_word]
        
        return "Multiple Vendors" if "multiple" in desc_lower else "Unknown Vendor"
    
    def _build_affected_products_table(self, cve: "CVE") -> str:
        """
        Build detailed HTML table of affected products and versions from CPE data.
        
        Args:
            cve: CVE with parsed CPE match data
        
        Returns:
            HTML table string with vendor/product/version information
        """
        if not cve.cpe_matches:
            # Fallback for CVEs without CPE data
            vendor, product = self._extract_product_from_description(cve.description)
            if product != "Unknown Product":
                return f'''
                <table class="affected-products-table">
                    <thead>
                        <tr>
                            <th>Vendor</th>
                            <th>Product</th>
                            <th>Affected Versions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>{self._escape(vendor)}</strong></td>
                            <td>{self._escape(product)}</td>
                            <td>Check vendor advisory for exact versions</td>
                        </tr>
                    </tbody>
                </table>
                '''
            else:
                return '<p><em>Product and version information not available. Refer to vendor security advisory for details.</em></p>'
        
        # Group CPE matches by vendor/product
        products = {}
        for cpe in cve.cpe_matches:
            if cpe.vendor and cpe.product:
                key = (cpe.vendor, cpe.product)
                if key not in products:
                    products[key] = []
                version_text = cpe.version_range_text
                if version_text not in products[key]:
                    products[key].append(version_text)
        
        if not products:
            return '<p><em>Product details not available in CPE data</em></p>'
        
        # Build table HTML
        html = '''
        <table class="affected-products-table">
            <thead>
                <tr>
                    <th>Vendor</th>
                    <th>Product</th>
                    <th>Affected Versions</th>
                </tr>
            </thead>
            <tbody>
'''
        
        # Show up to 20 products (most relevant for MSP)
        for (vendor, product), versions in sorted(products.items())[:20]:
            version_list = ", ".join(versions)
            if len(version_list) > 100:
                version_list = version_list[:97] + "..."
            
            html += f'''                <tr>
                    <td><strong>{self._escape(vendor)}</strong></td>
                    <td>{self._escape(product)}</td>
                    <td><code>{self._escape(version_list)}</code></td>
                </tr>
'''
        
        html += '''            </tbody>
        </table>
'''
        
        if len(products) > 20:
            html += f'        <p style="margin-top: 10px; font-size: 13px; color: #666;"><em>Note: {len(products) - 20} additional product configurations not shown. See CVE references for complete affected product list.</em></p>\n'
        
        return html
    
    def _generate_html_advisory(self, enriched_cve: EnrichedCVE) -> str:
        """
        Generate an enterprise-grade HTML advisory when AI fails.
        Follows CIS MS-ISAC advisory format with professional styling.
        
        Args:
            enriched_cve: CVE with research data.
        
        Returns:
            HTML advisory.
        """
        cve = enriched_cve.cve
        cvss = cve.primary_cvss
        now = datetime.now(timezone.utc)
        
        # Generate advisory number
        advisory_num = self._generate_advisory_number(cve.cve_id)
        
        # Get MITRE ATT&CK mapping
        tactic, technique = self._get_mitre_attack_mapping(cve.vulnerability_type)
        
        # Calculate risk ratings
        risks = self._calculate_risk_ratings(cvss, cve.is_in_kev, cve.vulnerability_type)
        
        # Determine severity and colors
        if cvss:
            severity = cvss.base_severity.value
            cvss_score = cvss.base_score
        else:
            severity = "HIGH"
            cvss_score = 7.0
        
        sev_colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])
        
        # Build product name
        if cve.kev_entry:
            product_name = f"{self._escape(cve.kev_entry.vendor_project)} {self._escape(cve.kev_entry.product)}"
        elif cve.affected_products:
            cpe_parts = cve.affected_products[0].split(":")
            if len(cpe_parts) >= 5:
                product_name = f"{cpe_parts[3]} {cpe_parts[4]}".replace("_", " ").title()
                product_name = self._escape(product_name)
            else:
                product_name = "the affected product"
        else:
            # Try to extract from description when no CPE data available
            vendor, product = self._extract_product_from_description(cve.description)
            if product != "Unknown Product":
                product_name = f"{self._escape(vendor)} {self._escape(product)}"
            else:
                product_name = "the affected product"
        
        # Build overview
        overview = f"A vulnerability has been discovered in {product_name} which could allow for {self._escape(cve.vulnerability_type.lower())}."
        if cve.is_in_kev:
            overview += " <strong>This vulnerability is being actively exploited in the wild.</strong>"
        
        # Build impact statement
        if cvss:
            impacts = []
            if cvss.confidentiality_impact and cvss.confidentiality_impact.value == "HIGH":
                impacts.append("access sensitive information")
            if cvss.integrity_impact and cvss.integrity_impact.value == "HIGH":
                impacts.append("modify system data")
            if cvss.availability_impact and cvss.availability_impact.value == "HIGH":
                impacts.append("cause denial of service")
            if not impacts:
                impacts.append("compromise the affected system")
            impact_text = ", ".join(impacts)
        else:
            impact_text = "compromise the affected system"
        
        # Generate HTML
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Advisory: {self._escape(cve.cve_id)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{ 
            max-width: 800px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 12px; 
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }}
        .header {{ 
            background: linear-gradient(135deg, {sev_colors['bg']} 0%, {sev_colors['border']} 100%);
            color: {sev_colors['text']};
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{ font-size: 14px; text-transform: uppercase; letter-spacing: 2px; opacity: 0.9; margin-bottom: 10px; }}
        .header .cve-id {{ font-size: 28px; font-weight: bold; margin-bottom: 15px; }}
        .header .severity-badge {{ 
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
        }}
        .meta-bar {{
            display: flex;
            flex-wrap: wrap;
            background: #f8f9fa;
            padding: 15px 30px;
            border-bottom: 1px solid #e9ecef;
            gap: 20px;
        }}
        .meta-item {{ font-size: 13px; }}
        .meta-item strong {{ color: #495057; }}
        
        .kev-alert {{
            background: linear-gradient(135deg, #7c0a02 0%, #a00 100%);
            color: white;
            padding: 20px 30px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .kev-alert .icon {{ font-size: 32px; }}
        .kev-alert .text {{ flex: 1; }}
        .kev-alert h3 {{ margin-bottom: 5px; font-size: 16px; }}
        .kev-alert p {{ font-size: 13px; opacity: 0.9; }}
        
        .section {{ padding: 25px 30px; border-bottom: 1px solid #e9ecef; }}
        .section:last-child {{ border-bottom: none; }}
        .section h2 {{ 
            color: #1a5f7a;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #1a5f7a;
        }}
        .section p {{ margin-bottom: 12px; }}
        
        .cvss-box {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin: 15px 0;
        }}
        .cvss-score {{
            text-align: center;
            padding: 20px;
            background: {sev_colors['bg']};
            color: {sev_colors['text']};
            border-radius: 8px;
            min-width: 100px;
        }}
        .cvss-score .score {{ font-size: 36px; font-weight: bold; }}
        .cvss-score .label {{ font-size: 12px; text-transform: uppercase; }}
        .cvss-details {{ flex: 1; min-width: 250px; }}
        .cvss-details table {{ width: 100%; font-size: 13px; }}
        .cvss-details td {{ padding: 6px 0; }}
        .cvss-details td:first-child {{ color: #666; width: 45%; }}
        
        .risk-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        .risk-table th {{ 
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            color: #666;
            border-bottom: 2px solid #dee2e6;
        }}
        .risk-table td {{ padding: 12px; border-bottom: 1px solid #e9ecef; }}
        .risk-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        .risk-high {{ background: {RISK_COLORS['HIGH']['bg']}; color: {RISK_COLORS['HIGH']['text']}; }}
        .risk-medium {{ background: {RISK_COLORS['MEDIUM']['bg']}; color: {RISK_COLORS['MEDIUM']['text']}; }}
        .risk-low {{ background: {RISK_COLORS['LOW']['bg']}; color: {RISK_COLORS['LOW']['text']}; }}
        
        .affected-products-table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin: 15px 0; 
            font-size: 14px;
            background: white;
        }}
        .affected-products-table th {{ 
            background: #1a5f7a;
            color: white;
            padding: 12px;
            text-align: left;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }}
        .affected-products-table td {{ 
            padding: 12px; 
            border-bottom: 1px solid #e9ecef;
            vertical-align: top;
        }}
        .affected-products-table tr:hover {{
            background: #f8f9fa;
        }}
        .affected-products-table code {{
            background: #f1f3f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
            color: #1a5f7a;
        }}
        
        .affected-list {{ 
            list-style: none; 
            padding: 0;
            margin: 15px 0;
        }}
        .affected-list li {{
            padding: 10px 15px;
            background: #f8f9fa;
            margin-bottom: 8px;
            border-radius: 6px;
            border-left: 4px solid #1a5f7a;
        }}
        
        .mitre-box {{
            display: flex;
            gap: 15px;
            margin: 15px 0;
        }}
        .mitre-item {{
            flex: 1;
            background: #e7f3ff;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #1a5f7a;
        }}
        .mitre-item .label {{ font-size: 11px; color: #666; text-transform: uppercase; }}
        .mitre-item .value {{ font-weight: bold; color: #1a5f7a; margin-top: 5px; }}
        
        .recommendation {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 12px;
            border-left: 4px solid #28a745;
        }}
        .recommendation.urgent {{ border-left-color: #dc3545; background: #fff5f5; }}
        .recommendation h4 {{ color: #155724; font-size: 14px; margin-bottom: 8px; }}
        .recommendation.urgent h4 {{ color: #721c24; }}
        .recommendation p {{ font-size: 13px; color: #666; margin: 0; }}
        
        .reference-list {{
            list-style: none;
            padding: 0;
        }}
        .reference-list li {{
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }}
        .reference-list li:last-child {{ border-bottom: none; }}
        .reference-list a {{
            color: #1a5f7a;
            text-decoration: none;
            word-break: break-all;
        }}
        .reference-list a:hover {{ text-decoration: underline; }}
        .reference-label {{
            display: inline-block;
            background: #e9ecef;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            text-transform: uppercase;
            margin-right: 8px;
            color: #666;
        }}
        
        .footer {{
            background: #1a5f7a;
            color: white;
            padding: 20px 30px;
            text-align: center;
            font-size: 12px;
        }}
        .footer a {{ color: #a0d2db; }}
        
        .description {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-radius: 8px;
            font-size: 14px;
            border-left: 4px solid #6c757d;
        }}
        
        @media (max-width: 600px) {{
            body {{ padding: 10px; }}
            .section {{ padding: 20px; }}
            .meta-bar {{ flex-direction: column; gap: 10px; }}
            .cvss-box {{ flex-direction: column; }}
            .mitre-box {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Gatekeeper Security Advisory</h1>
            <div class="cve-id">{self._escape(cve.cve_id)}</div>
            <div class="severity-badge">{severity} SEVERITY</div>
        </div>
        
        <div class="meta-bar">
            <div class="meta-item"><strong>Advisory:</strong> {advisory_num}</div>
            <div class="meta-item"><strong>Published:</strong> {now.strftime('%B %d, %Y')}</div>
            <div class="meta-item"><strong>CVSS Score:</strong> {cvss_score}</div>
            <div class="meta-item"><strong>Type:</strong> {self._escape(cve.vulnerability_type)}</div>
        </div>
'''
        
        # KEV Alert Banner
        if cve.is_in_kev:
            ransomware_note = ""
            if cve.kev_entry and cve.kev_entry.known_ransomware_use == "Known":
                ransomware_note = " Associated with ransomware campaigns."
            
            html_content += f'''
        <div class="kev-alert">
            <div class="icon">⚠️</div>
            <div class="text">
                <h3>ACTIVE EXPLOITATION CONFIRMED</h3>
                <p>This vulnerability is listed in CISA's Known Exploited Vulnerabilities (KEV) catalog.{ransomware_note}</p>
            </div>
        </div>
'''
        
        # Overview Section
        html_content += f'''
        <div class="section">
            <h2>Overview</h2>
            <p>{overview}</p>
            <p>Successful exploitation could allow an attacker to <strong>{impact_text}</strong>.</p>
        </div>
'''
        
        # Systems Affected Section with detailed product/version table
        html_content += '''
        <div class="section">
            <h2>Affected Products and Versions</h2>
'''
        html_content += self._build_affected_products_table(cve)
        html_content += '''
        </div>
'''

        
        # Risk Assessment Section
        def risk_badge(level: str) -> str:
            return f'<span class="risk-badge risk-{level.lower()}">{level}</span>'
        
        html_content += f'''
        <div class="section">
            <h2>Risk Assessment</h2>
            <table class="risk-table">
                <tr>
                    <th>Entity Type</th>
                    <th>Risk Level</th>
                </tr>
                <tr>
                    <td>Large/Medium Government</td>
                    <td>{risk_badge(risks['gov_large'])}</td>
                </tr>
                <tr>
                    <td>Small Government</td>
                    <td>{risk_badge(risks['gov_small'])}</td>
                </tr>
                <tr>
                    <td>Large/Medium Business</td>
                    <td>{risk_badge(risks['biz_large'])}</td>
                </tr>
                <tr>
                    <td>Small Business</td>
                    <td>{risk_badge(risks['biz_small'])}</td>
                </tr>
                <tr>
                    <td>Home Users</td>
                    <td>{risk_badge(risks['home'])}</td>
                </tr>
            </table>
        </div>
'''
        
        # Technical Summary Section
        html_content += f'''
        <div class="section">
            <h2>Technical Summary</h2>
            
            <div class="mitre-box">
                <div class="mitre-item">
                    <div class="label">MITRE ATT&CK Tactic</div>
                    <div class="value">{self._escape(tactic)}</div>
                </div>
                <div class="mitre-item">
                    <div class="label">MITRE ATT&CK Technique</div>
                    <div class="value">{self._escape(technique)}</div>
                </div>
            </div>
            
            <div class="description">
                {self._escape(cve.description) if cve.description else "No description available."}
            </div>
'''
        
        # CVSS Details
        if cvss:
            html_content += f'''
            <div class="cvss-box">
                <div class="cvss-score">
                    <div class="score">{cvss.base_score}</div>
                    <div class="label">{severity}</div>
                </div>
                <div class="cvss-details">
                    <table>
                        <tr><td>Attack Vector</td><td><strong>{cvss.attack_vector.value if cvss.attack_vector else 'Unknown'}</strong></td></tr>
                        <tr><td>Attack Complexity</td><td><strong>{cvss.attack_complexity.value if cvss.attack_complexity else 'Unknown'}</strong></td></tr>
                        <tr><td>Privileges Required</td><td><strong>{cvss.privileges_required.value if cvss.privileges_required else 'Unknown'}</strong></td></tr>
                        <tr><td>User Interaction</td><td><strong>{cvss.user_interaction.value if cvss.user_interaction else 'Unknown'}</strong></td></tr>
                        <tr><td>Confidentiality Impact</td><td><strong>{cvss.confidentiality_impact.value if cvss.confidentiality_impact else 'Unknown'}</strong></td></tr>
                        <tr><td>Integrity Impact</td><td><strong>{cvss.integrity_impact.value if cvss.integrity_impact else 'Unknown'}</strong></td></tr>
                        <tr><td>Availability Impact</td><td><strong>{cvss.availability_impact.value if cvss.availability_impact else 'Unknown'}</strong></td></tr>
                    </table>
                </div>
            </div>
'''
            if cvss.vector_string:
                html_content += f'            <p style="font-size: 12px; color: #666;"><strong>Vector:</strong> <code>{self._escape(cvss.vector_string)}</code></p>\n'
        
        html_content += '        </div>\n'
        
        # CISA KEV Section
        if cve.is_in_kev and cve.kev_entry:
            kev = cve.kev_entry
            html_content += f'''
        <div class="section">
            <h2>CISA KEV Status</h2>
            <div style="background: #f8d7da; padding: 20px; border-radius: 8px; border-left: 4px solid #dc3545;">
                <p style="margin-bottom: 15px;"><strong>⚠️ This vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog.</strong></p>
                <table style="width: 100%; font-size: 14px;">
                    <tr><td style="padding: 8px 0; width: 160px; color: #666;">Date Added</td><td><strong>{kev.date_added.strftime('%B %d, %Y') if kev.date_added else 'Unknown'}</strong></td></tr>
                    <tr><td style="padding: 8px 0; color: #666;">Due Date</td><td><strong style="color: #dc3545;">{kev.due_date.strftime('%B %d, %Y') if kev.due_date else 'Unknown'}</strong></td></tr>
                    <tr><td style="padding: 8px 0; color: #666;">Ransomware Use</td><td><strong>{kev.known_ransomware_use}</strong></td></tr>
                </table>
                {f'<p style="margin-top: 15px; font-size: 13px;"><strong>Required Action:</strong> {self._escape(kev.required_action)}</p>' if kev.required_action else ''}
            </div>
        </div>
'''
        
        # Recommendations Section
        html_content += '''
        <div class="section">
            <h2>Recommendations</h2>
'''
        
        if cve.kev_entry and cve.kev_entry.required_action:
            html_content += f'''
            <div class="recommendation urgent">
                <h4>⚡ Immediate Action Required</h4>
                <p>{self._escape(cve.kev_entry.required_action)}</p>
            </div>
'''
        else:
            html_content += '''
            <div class="recommendation urgent">
                <h4>⚡ Apply Security Updates</h4>
                <p>Apply appropriate updates provided by the vendor to vulnerable systems immediately after appropriate testing.</p>
            </div>
'''
        
        html_content += '''
            <div class="recommendation">
                <h4>Safeguard 7.1: Vulnerability Management Process</h4>
                <p>Establish and maintain a documented vulnerability management process for enterprise assets.</p>
            </div>
            <div class="recommendation">
                <h4>Safeguard 7.2: Remediation Process</h4>
                <p>Establish and maintain a risk-based remediation strategy with monthly or more frequent reviews.</p>
            </div>
            <div class="recommendation">
                <h4>Safeguard 7.4: Automated Patch Management</h4>
                <p>Perform application updates through automated patch management on a monthly or more frequent basis.</p>
            </div>
'''
        
        if cvss and cvss.attack_vector and cvss.attack_vector.value == "NETWORK":
            html_content += '''
            <div class="recommendation">
                <h4>Safeguard 12.1: Network Infrastructure</h4>
                <p>Ensure network infrastructure is kept up-to-date with the latest stable release of software.</p>
            </div>
'''
        
        html_content += '''
            <div class="recommendation">
                <h4>Compensating Controls</h4>
                <p>If immediate patching is not possible: implement network segmentation, apply strict access controls, increase monitoring, and consider taking vulnerable systems offline.</p>
            </div>
        </div>
'''
        
        # References Section
        html_content += f'''
        <div class="section">
            <h2>References</h2>
            <ul class="reference-list">
                <li>
                    <span class="reference-label">NVD</span>
                    <a href="https://nvd.nist.gov/vuln/detail/{self._escape(cve.cve_id)}" target="_blank">
                        https://nvd.nist.gov/vuln/detail/{self._escape(cve.cve_id)}
                    </a>
                </li>
'''
        
        # Add vendor advisories
        if enriched_cve.vendor_advisories:
            for ref in enriched_cve.vendor_advisories[:3]:
                html_content += f'''                <li>
                    <span class="reference-label">Vendor</span>
                    <a href="{self._escape(ref.url)}" target="_blank">{self._escape(ref.url)}</a>
                </li>
'''
        
        # Add other references
        if cve.references:
            seen_urls = set()
            count = 0
            for ref in cve.references:
                if ref.url not in seen_urls and count < 5:
                    html_content += f'''                <li>
                    <span class="reference-label">Reference</span>
                    <a href="{self._escape(ref.url)}" target="_blank">{self._escape(ref.url)}</a>
                </li>
'''
                    seen_urls.add(ref.url)
                    count += 1
        
        html_content += '''            </ul>
        </div>
'''
        
        # Footer
        html_content += f'''
        <div class="footer">
            <p><strong>Gatekeeper CVE Advisory System</strong></p>
            <p style="margin-top: 8px; opacity: 0.8;">
                Generated on {now.strftime('%Y-%m-%d %H:%M:%S')} UTC<br>
                This advisory was generated using template-based formatting.
            </p>
        </div>
    </div>
</body>
</html>'''
        
        return html_content
    
    def close(self):
        """Close the HTTP session."""
        self.session.close()
