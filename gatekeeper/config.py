"""
Configuration module for Gatekeeper CVE Advisory System.

Loads configuration from environment variables and .env file,
validates required settings, and provides typed access to configuration values.
"""

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from dotenv import load_dotenv


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
    min_cvss_score: float = 7.0
    lookback_hours: int = 24
    
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
        min_cvss_score=float(os.getenv("MIN_CVSS_SCORE", "7.0")),
        lookback_hours=int(os.getenv("LOOKBACK_HOURS", "24")),
    )
    
    return config


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
