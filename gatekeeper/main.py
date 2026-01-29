"""
Gatekeeper CVE Advisory System - Main Entry Point

Provides the main orchestration loop and scheduler for the
automated threat intelligence advisory system.
"""

import sys
import signal
import uuid
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import structlog
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED

from .config import Config, load_config, validate_config
from .collector.nvd import NVDClient
from .collector.kev import KEVClient
from .collector.models import CVE, EnrichedCVE
from .deduplication.store import CVEStore, compute_advisory_hash
from .research.enrichment import CVEEnricher
from .advisory.generator import AdvisoryGenerator
from .delivery.email import EmailSender


def configure_logging(config: Config) -> structlog.BoundLogger:
    """
    Configure structured logging.
    
    Args:
        config: Application configuration.
    
    Returns:
        Configured logger.
    """
    # Set log level
    log_level = getattr(logging, config.log_level.upper(), logging.INFO)
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.dev.ConsoleRenderer() if sys.stdout.isatty() else structlog.processors.JSONRenderer()
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(config.log_file, encoding="utf-8")
        ]
    )
    
    return structlog.get_logger("gatekeeper")


class GatekeeperOrchestrator:
    """
    Main orchestrator for the CVE advisory workflow.
    
    Coordinates all components to collect, enrich, generate,
    and deliver security advisories.
    """
    
    def __init__(self, config: Config, logger: structlog.BoundLogger):
        """
        Initialize the orchestrator.
        
        Args:
            config: Application configuration.
            logger: Configured logger instance.
        """
        self.config = config
        self.logger = logger
        
        # Initialize components
        self.store = CVEStore(config.database_path)
        self.nvd_client = NVDClient(config)
        self.kev_client = KEVClient(config)
        self.enricher = CVEEnricher(config, self.kev_client)
        self.generator = AdvisoryGenerator(config)
        self.email_sender = EmailSender(config)
        
        self.logger.info("orchestrator_initialized")
    
    def run_workflow(self) -> dict:
        """
        Execute the full advisory workflow.
        
        Returns:
            Dict with run statistics.
        """
        run_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        
        self.logger.info("workflow_started", run_id=run_id)
        self.store.start_run(run_id)
        
        stats = {
            "run_id": run_id,
            "cves_collected": 0,
            "cves_new": 0,
            "cves_processed": 0,
            "cves_emailed": 0,
            "errors": 0,
            "error_messages": []
        }
        
        try:
            # Step 1: Collect CVEs
            self.logger.info("step_1_collecting_cves")
            cves = self._collect_cves()
            stats["cves_collected"] = len(cves)
            self.store.update_run(run_id, cves_collected=len(cves))
            
            if not cves:
                self.logger.info("no_cves_found")
                self.store.end_run(run_id, status="completed")
                return stats
            
            # Step 2: Filter and deduplicate
            self.logger.info("step_2_filtering_cves", count=len(cves))
            new_cves = self._filter_new_cves(cves)
            stats["cves_new"] = len(new_cves)
            self.store.update_run(run_id, cves_new=len(new_cves))
            
            if not new_cves:
                self.logger.info("no_new_cves")
                self.store.end_run(run_id, status="completed")
                return stats
            
            # Step 3: Process each CVE
            self.logger.info("step_3_processing_cves", count=len(new_cves))
            
            for i, cve in enumerate(new_cves, 1):
                self.logger.info(
                    "processing_cve",
                    cve_id=cve.cve_id,
                    progress=f"{i}/{len(new_cves)}"
                )
                
                try:
                    success = self._process_single_cve(cve)
                    if success:
                        stats["cves_processed"] += 1
                        stats["cves_emailed"] += 1
                    else:
                        stats["errors"] += 1
                except Exception as e:
                    self.logger.error(
                        "cve_processing_error",
                        cve_id=cve.cve_id,
                        error=str(e)
                    )
                    stats["errors"] += 1
                    stats["error_messages"].append(f"{cve.cve_id}: {str(e)}")
                    self.store.mark_error(cve.cve_id, str(e))
            
            self.store.update_run(
                run_id,
                cves_processed=stats["cves_processed"],
                cves_emailed=stats["cves_emailed"]
            )
            
        except Exception as e:
            self.logger.error("workflow_error", error=str(e))
            stats["errors"] += 1
            stats["error_messages"].append(f"Workflow error: {str(e)}")
            self.store.end_run(run_id, status="failed", errors=str(e))
            return stats
        
        # Determine final status
        duration = time.time() - start_time
        if stats["errors"] == 0:
            status = "completed"
        elif stats["cves_emailed"] > 0:
            status = "partial"
        else:
            status = "failed"
        
        self.store.end_run(
            run_id,
            status=status,
            errors="; ".join(stats["error_messages"]) if stats["error_messages"] else None
        )
        
        self.logger.info(
            "workflow_completed",
            run_id=run_id,
            status=status,
            collected=stats["cves_collected"],
            new=stats["cves_new"],
            processed=stats["cves_processed"],
            emailed=stats["cves_emailed"],
            errors=stats["errors"],
            duration_seconds=round(duration, 1)
        )
        
        # Send summary email if any CVEs were processed
        if stats["cves_collected"] > 0:
            self.email_sender.send_summary_email(
                run_id=run_id,
                cves_processed=stats["cves_processed"],
                cves_emailed=stats["cves_emailed"],
                errors=stats["errors"],
                duration_seconds=duration
            )
        
        return stats
    
    def _collect_cves(self) -> List[CVE]:
        """
        Collect CVEs from all sources.
        
        Returns:
            List of CVE objects.
        """
        cves = []
        seen_ids = set()
        
        # Collect from NVD
        try:
            self.logger.info("collecting_from_nvd", hours=self.config.lookback_hours)
            nvd_cves = self.nvd_client.fetch_recent_cves(
                hours=self.config.lookback_hours,
                min_cvss=self.config.min_cvss_score
            )
            for cve in nvd_cves:
                if cve.cve_id not in seen_ids:
                    seen_ids.add(cve.cve_id)
                    cves.append(cve)
            self.logger.info("nvd_collection_complete", count=len(nvd_cves))
        except Exception as e:
            self.logger.error("nvd_collection_error", error=str(e))
        
        # Collect recent KEV additions
        try:
            self.logger.info("collecting_recent_kev")
            recent_kevs = self.kev_client.get_recent_additions(hours=self.config.lookback_hours)
            
            for kev_entry in recent_kevs:
                if kev_entry.cve_id not in seen_ids:
                    # Fetch full CVE data from NVD for KEV entries
                    cve = self.nvd_client.fetch_cve_by_id(kev_entry.cve_id)
                    if cve:
                        cve.kev_entry = kev_entry
                        seen_ids.add(cve.cve_id)
                        cves.append(cve)
            
            self.logger.info("kev_collection_complete", new_entries=len(recent_kevs))
        except Exception as e:
            self.logger.error("kev_collection_error", error=str(e))
        
        # Enrich with KEV data for non-KEV CVEs
        kev_ids = self.kev_client.get_all_kev_ids()
        for cve in cves:
            if cve.cve_id in kev_ids and not cve.kev_entry:
                cve.kev_entry = self.kev_client.get_kev_entry(cve.cve_id)
        
        self.logger.info("collection_complete", total=len(cves))
        return cves
    
    def _filter_new_cves(self, cves: List[CVE]) -> List[CVE]:
        """
        Filter out previously processed CVEs.
        
        Args:
            cves: List of collected CVEs.
        
        Returns:
            List of new (unprocessed) CVEs.
        """
        new_cves = []
        
        for cve in cves:
            if not self.store.is_processed(cve.cve_id):
                # Mark as seen
                self.store.mark_seen(
                    cve_id=cve.cve_id,
                    kev_status=cve.is_in_kev,
                    cvss_score=cve.highest_cvss_score,
                    severity=cve.severity,
                    title=cve.kev_entry.vulnerability_name if cve.kev_entry else None
                )
                new_cves.append(cve)
            else:
                self.logger.debug("cve_already_processed", cve_id=cve.cve_id)
        
        return new_cves
    
    def _process_single_cve(self, cve: CVE) -> bool:
        """
        Process a single CVE through the full pipeline.
        
        Args:
            cve: CVE to process.
        
        Returns:
            True if successfully processed and emailed.
        """
        cve_id = cve.cve_id
        
        # Step 1: Enrich with research
        self.logger.debug("enriching_cve", cve_id=cve_id)
        enriched = self.enricher.enrich(cve)
        
        # Step 2: Generate advisory (HTML format)
        self.logger.debug("generating_advisory", cve_id=cve_id)
        advisory_html = self.generator.generate_with_fallback(enriched)
        
        # Step 3: Store advisory hash
        advisory_hash = compute_advisory_hash(advisory_html)
        self.store.mark_processed(cve_id, advisory_hash)
        
        # Step 4: Send email (HTML with plain text fallback)
        self.logger.debug("sending_email", cve_id=cve_id)
        plain_text_fallback = f"Security Advisory for {cve_id}\n\nPlease view this email in an HTML-capable email client for the full advisory.\n\nCVSS Score: {cve.highest_cvss_score or 'N/A'}\nSeverity: {cve.severity}\nKEV Status: {'Listed' if cve.is_in_kev else 'Not Listed'}\n\nFor details, visit: https://nvd.nist.gov/vuln/detail/{cve_id}"
        success = self.email_sender.send_advisory(enriched, advisory_html, plain_text_fallback)
        
        if success:
            self.store.mark_emailed(cve_id)
            return True
        else:
            self.store.mark_error(cve_id, "Email delivery failed")
            return False
    
    def cleanup(self):
        """Clean up resources."""
        self.nvd_client.close()
        self.kev_client.close()
        self.enricher.close()
        self.generator.close()
        self.store.close()
        self.logger.info("orchestrator_cleanup_complete")


def run_scheduled_workflow(orchestrator: GatekeeperOrchestrator):
    """Wrapper function for scheduled execution."""
    try:
        orchestrator.run_workflow()
    except Exception as e:
        orchestrator.logger.error("scheduled_run_failed", error=str(e))


def main():
    """Main entry point."""
    print("=" * 60)
    print("  Gatekeeper CVE Advisory System")
    print("  Automated Threat Intelligence & Advisory Generation")
    print("=" * 60)
    print()
    
    # Load configuration
    config = load_config()
    
    # Validate configuration
    errors = validate_config(config)
    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"  - {error}")
        print()
        print("Please check your .env file and try again.")
        sys.exit(1)
    
    # Ensure directories exist
    Path(config.database_path).parent.mkdir(parents=True, exist_ok=True)
    Path(config.log_file).parent.mkdir(parents=True, exist_ok=True)
    
    # Configure logging
    logger = configure_logging(config)
    logger.info("gatekeeper_starting", version="1.0.0")
    
    # Create orchestrator
    orchestrator = GatekeeperOrchestrator(config, logger)
    
    # Set up signal handlers for graceful shutdown
    shutdown_flag = False
    
    def signal_handler(signum, frame):
        nonlocal shutdown_flag
        if shutdown_flag:
            logger.warning("forced_shutdown")
            sys.exit(1)
        shutdown_flag = True
        logger.info("shutdown_requested")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create scheduler
    scheduler = BlockingScheduler()
    
    def job_listener(event):
        if event.exception:
            logger.error("job_failed", exception=str(event.exception))
    
    scheduler.add_listener(job_listener, EVENT_JOB_ERROR)
    
    # Add the scheduled job
    scheduler.add_job(
        run_scheduled_workflow,
        trigger=IntervalTrigger(hours=config.run_interval_hours),
        args=[orchestrator],
        id="cve_advisory_job",
        name="CVE Advisory Generation",
        replace_existing=True,
        max_instances=1
    )
    
    logger.info(
        "scheduler_configured",
        interval_hours=config.run_interval_hours,
        min_cvss=config.min_cvss_score,
        lookback_hours=config.lookback_hours
    )
    
    # Run immediately on startup
    logger.info("running_initial_workflow")
    try:
        orchestrator.run_workflow()
    except Exception as e:
        logger.error("initial_workflow_failed", error=str(e))
    
    # Start the scheduler
    logger.info("starting_scheduler")
    print()
    print(f"Scheduler started. Running every {config.run_interval_hours} hours.")
    print("Press Ctrl+C to stop.")
    print()
    
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("shutting_down")
    finally:
        scheduler.shutdown(wait=False)
        orchestrator.cleanup()
        logger.info("gatekeeper_stopped")


if __name__ == "__main__":
    main()
