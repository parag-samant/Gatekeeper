"""
Gatekeeper CVE Advisory System - One-Shot Execution Mode

This module provides a single-run execution mode for GitHub Actions
and other environments where a continuous scheduler is not appropriate.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any

import structlog

from .config import Config, load_config, validate_config
from .main import GatekeeperOrchestrator, configure_logging


def run_single_workflow() -> Dict[str, Any]:
    """
    Execute a single workflow run without scheduling.
    
    Designed for GitHub Actions and other cron-based execution environments.
    
    Returns:
        Dict with run statistics.
    
    Raises:
        SystemExit: On configuration errors or critical failures.
    """
    print("=" * 60)
    print("  Gatekeeper CVE Advisory System - Single Run")
    print("  GitHub Actions Compatible Mode")
    print("=" * 60)
    print()
    
    # Load configuration
    config = load_config()
    
    # Validate configuration
    errors = validate_config(config)
    if errors:
        print("❌ Configuration errors:")
        for error in errors:
            print(f"  - {error}")
        print()
        print("Please configure GitHub Secrets properly.")
        sys.exit(1)
    
    # Ensure directories exist
    Path(config.database_path).parent.mkdir(parents=True, exist_ok=True)
    Path(config.log_file).parent.mkdir(parents=True, exist_ok=True)
    
    # Configure logging
    logger = configure_logging(config)
    logger.info("single_run_started", version="1.0.0", mode="github_actions")
    
    orchestrator = None
    try:
        # Create orchestrator
        orchestrator = GatekeeperOrchestrator(config, logger)
        
        # Run workflow once
        logger.info("executing_workflow")
        stats = orchestrator.run_workflow()
        
        # Cleanup
        orchestrator.cleanup()
        
        # Log summary
        logger.info(
            "single_run_completed",
            collected=stats["cves_collected"],
            new=stats["cves_new"],
            processed=stats["cves_processed"],
            emailed=stats["cves_emailed"],
            errors=stats["errors"]
        )
        
        # Print summary for GitHub Actions output
        print()
        print("=" * 60)
        print("  Run Summary")
        print("=" * 60)
        print(f"CVEs Collected: {stats['cves_collected']}")
        print(f"New CVEs: {stats['cves_new']}")
        print(f"Advisories Generated: {stats['cves_processed']}")
        print(f"Emails Sent: {stats['cves_emailed']}")
        print(f"Errors: {stats['errors']}")
        print("=" * 60)
        print()
        
        # Set GitHub Actions output if available
        if github_output := os.getenv("GITHUB_OUTPUT"):
            try:
                with open(github_output, "a") as f:
                    f.write(f"cves_collected={stats['cves_collected']}\n")
                    f.write(f"cves_new={stats['cves_new']}\n")
                    f.write(f"cves_processed={stats['cves_processed']}\n")
                    f.write(f"cves_emailed={stats['cves_emailed']}\n")
                    f.write(f"errors={stats['errors']}\n")
                logger.info("github_output_written", path=github_output)
            except Exception as e:
                logger.warning("github_output_write_failed", error=str(e))
        
        # Exit with appropriate code
        if stats["errors"] > 0 and stats["cves_emailed"] == 0:
            logger.error("run_failed_no_emails_sent")
            sys.exit(1)
        elif stats["errors"] > 0:
            logger.warning("run_completed_with_errors")
            sys.exit(0)  # Partial success
        else:
            logger.info("run_successful")
            sys.exit(0)
    
    except Exception as e:
        logger.error("run_failed", error=str(e), exc_info=True)
        print(f"\n❌ Fatal error: {str(e)}")
        # Ensure cleanup on exception
        if orchestrator is not None:
            try:
                orchestrator.cleanup()
            except Exception as cleanup_error:
                logger.error("cleanup_failed", error=str(cleanup_error))
        sys.exit(1)


def main():
    """Entry point for one-shot execution."""
    run_single_workflow()


if __name__ == "__main__":
    main()
