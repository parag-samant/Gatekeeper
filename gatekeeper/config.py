"""
Configuration module for Gatekeeper CVE Advisory System.

Loads configuration from environment variables and .env file,
validates required settings, and provides typed access to configuration values.
"""

import os
import sys
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, field
from dotenv import load_dotenv


@dataclass
class ProductFilter:
    """Product/vendor filter criteria."""
    keywords: List[str] = field(default_factory=list)
    vendor: Optional[str] = None
    description: Optional[str] = None


@dataclass
class Config:
    """Application configuration loaded from environment variables."""
    
    # Gmail SMTP Configuration
    gmail_user: str = ""
    gmail_app_password: str = ""
    
    # OpenRouter API Configuration
    openrouter_api_key: str = ""
    openrouter_model: str = "openai/gpt-oss-120b:free"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    
    # Recipient Configuration
    recipient_email: str = ""
    
    # NVD API Configuration
    nvd_api_key: Optional[str] = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # CISA KEV Configuration
    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    # Scheduler Configuration
    run_interval_hours: int = 12
    
    # Database Configuration
    database_path: str = "./data/gatekeeper.db"
    
    # Logging Configuration
    log_level: str = "INFO"
    log_file: str = "./logs/gatekeeper.log"
    
    # Filtering Configuration
    min_cvss_score: float = 8.0  # Default to critical/high
    lookback_hours: int = 24
    filter_config_path: str = "./filters.yaml"
    product_filters: List[ProductFilter] = field(default_factory=list)
    exclude_filters: List[ProductFilter] = field(default_factory=list)
    
    # Rate Limiting Configuration
    nvd_requests_per_window: int = 5  # Without API key
    nvd_window_seconds: int = 30
    duckduckgo_delay_seconds: float = 2.0
    openrouter_delay_seconds: float = 3.0
    
    # Research Configuration
    max_search_results_per_query: int = 10
    research_queries_per_cve: int = 5
    
    def __post_init__(self):
        """Adjust rate limits if NVD API key is provided."""
        if self.nvd_api_key:
            self.nvd_requests_per_window = 50


def load_config(env_path: Optional[str] = None) -> Config:
    """
    Load configuration from environment variables and optional .env file.
    
    Args:
        env_path: Optional path to .env file. If not provided, searches
                  current directory and parent directories.
    
    Returns:
        Config object with loaded values.
    
    Raises:
        ValueError: If required configuration values are missing.
    """
    # Load .env file if it exists
    if env_path:
        load_dotenv(env_path)
    else:
        # Try to find .env in current directory or parent
        env_file = Path(".env")
        if env_file.exists():
            load_dotenv(env_file)
        else:
            # Try parent directories
            for parent in Path.cwd().parents:
                env_file = parent / ".env"
                if env_file.exists():
                    load_dotenv(env_file)
                    break
    
    config = Config(
        # Gmail
        gmail_user=os.getenv("GMAIL_USER", ""),
        gmail_app_password=os.getenv("GMAIL_APP_PASSWORD", ""),
        
        # OpenRouter
        openrouter_api_key=os.getenv("OPENROUTER_API_KEY", ""),
        openrouter_model=os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free"),
        
        # Recipient
        recipient_email=os.getenv("RECIPIENT_EMAIL", ""),
        
        # NVD
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
        
        # Scheduler
        run_interval_hours=int(os.getenv("RUN_INTERVAL_HOURS", "12")),
        
        # Database
        database_path=os.getenv("DATABASE_PATH", "./data/gatekeeper.db"),
        
        # Logging
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_file=os.getenv("LOG_FILE", "./logs/gatekeeper.log"),
        
        # Filtering
        min_cvss_score=float(os.getenv("MIN_CVSS_SCORE", "8.0")),
        lookback_hours=int(os.getenv("LOOKBACK_HOURS", "24")),
        filter_config_path=os.getenv("FILTER_CONFIG_PATH", "./filters.yaml"),
    )
    
    # Load product filters from YAML if file exists
    product_filters, exclude_filters = load_product_filters(config.filter_config_path)
    config.product_filters = product_filters
    config.exclude_filters = exclude_filters
    
    return config


def load_product_filters(config_path: str) -> tuple:
    """
    Load product filters from YAML configuration file.
    
    Args:
        config_path: Path to filters.yaml file.
    
    Returns:
        Tuple of (product_filters, exclude_filters) lists.
    """
    filter_path = Path(config_path)
    
    # If file doesn't exist, return empty filters
    if not filter_path.exists():
        return [], []
    
    try:
        import yaml
        
        with open(filter_path) as f:
            data = yaml.safe_load(f) or {}
        
        # Load product filters
        product_filters = []
        for filter_data in data.get('product_filters', []):
            product_filters.append(ProductFilter(
                keywords=filter_data.get('keywords', []),
                vendor=filter_data.get('vendor'),
                description=filter_data.get('description')
            ))
        
        # Load exclude filters
        exclude_filters = []
        for filter_data in data.get('exclude_filters', []):
            exclude_filters.append(ProductFilter(
                keywords=filter_data.get('keywords', []),
                vendor=filter_data.get('vendor'),
                description=filter_data.get('description')
            ))
        
        return product_filters, exclude_filters
        
    except Exception as e:
        print(f"Warning: Failed to load product filters from {config_path}: {e}", file=sys.stderr)
        # Log error type for troubleshooting
        print(f"  Error type: {e.__class__.__name__}", file=sys.stderr)
        return [], []


def validate_config(config: Config) -> list[str]:
    """
    Validate that required configuration values are present.
    
    Args:
        config: Configuration object to validate.
    
    Returns:
        List of validation error messages. Empty if valid.
    """
    errors = []
    
    if not config.gmail_user:
        errors.append("GMAIL_USER is required")
    if not config.gmail_app_password:
        errors.append("GMAIL_APP_PASSWORD is required")
    if not config.openrouter_api_key:
        errors.append("OPENROUTER_API_KEY is required")
    if not config.recipient_email:
        errors.append("RECIPIENT_EMAIL is required")
    
    # Validate email format (basic check)
    if config.gmail_user and "@" not in config.gmail_user:
        errors.append("GMAIL_USER must be a valid email address")
    if config.recipient_email and "@" not in config.recipient_email:
        errors.append("RECIPIENT_EMAIL must be a valid email address")
    
    # Validate numeric ranges
    if config.min_cvss_score < 0 or config.min_cvss_score > 10:
        errors.append("MIN_CVSS_SCORE must be between 0 and 10")
    if config.run_interval_hours < 1:
        errors.append("RUN_INTERVAL_HOURS must be at least 1")
    if config.lookback_hours < 1:
        errors.append("LOOKBACK_HOURS must be at least 1")
    
    return errors


# Global config instance (lazy loaded)
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance, loading if necessary."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reset_config():
    """Reset the global configuration instance (useful for testing)."""
    global _config
    _config = None
