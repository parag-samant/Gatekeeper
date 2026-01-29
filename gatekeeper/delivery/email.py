"""
Gmail SMTP email sender for advisory delivery.

Provides reliable email delivery of security advisories
using Gmail's SMTP service with app password authentication.
Now supports HTML-formatted emails with professional styling.
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Tuple
from datetime import datetime, timezone

import backoff
import structlog

from ..config import Config
from ..collector.models import EnrichedCVE

logger = structlog.get_logger(__name__)


class EmailSender:
    """
    Gmail SMTP email sender for security advisories.
    
    Uses Gmail's SMTP server with TLS encryption and app
    password authentication for secure email delivery.
    Supports both HTML and plain text email formats.
    """
    
    GMAIL_SMTP_HOST = "smtp.gmail.com"
    GMAIL_SMTP_PORT_TLS = 587  # STARTTLS
    GMAIL_SMTP_PORT_SSL = 465  # SSL/TLS
    
    def __init__(self, config: Config):
        """
        Initialize the email sender.
        
        Args:
            config: Application configuration with Gmail credentials.
        """
        self.config = config
        self.gmail_user = config.gmail_user
        self.gmail_password = config.gmail_app_password
        self.recipient = config.recipient_email
        
        # SSL context
        self.ssl_context = ssl.create_default_context()
        
        logger.info(
            "email_sender_initialized",
            from_address=self.gmail_user,
            to_address=self.recipient
        )
    
    def _build_subject(self, cve: EnrichedCVE) -> str:
        """
        Build the email subject line.
        
        Args:
            cve: Enriched CVE data.
        
        Returns:
            Formatted subject line.
        """
        cve_id = cve.cve.cve_id
        
        # Get short title
        if cve.cve.kev_entry and cve.cve.kev_entry.vulnerability_name:
            title = cve.cve.kev_entry.vulnerability_name
            # Truncate if too long
            if len(title) > 60:
                title = title[:57] + "..."
        else:
            title = cve.cve.vulnerability_type
        
        # Add KEV indicator if applicable
        kev_indicator = " [KEV]" if cve.cve.is_in_kev else ""
        
        # Add severity if available
        severity = cve.cve.severity
        severity_indicator = f" [{severity}]" if severity and severity != "UNKNOWN" else ""
        
        return f"[Security Advisory] {cve_id}{kev_indicator}{severity_indicator} - {title}"
    
    def _build_message(
        self,
        cve: EnrichedCVE,
        advisory_html: str,
        advisory_text: str
    ) -> MIMEMultipart:
        """
        Build the email message with both HTML and plain text versions.
        
        Args:
            cve: Enriched CVE data.
            advisory_html: Advisory HTML content.
            advisory_text: Advisory plain text content (fallback).
        
        Returns:
            MIME message object.
        """
        msg = MIMEMultipart("alternative")
        msg["Subject"] = self._build_subject(cve)
        msg["From"] = self.gmail_user
        msg["To"] = self.recipient
        msg["X-Priority"] = "1" if cve.cve.is_in_kev else "3"  # High priority for KEV
        msg["X-Mailer"] = "Gatekeeper CVE Advisory System"
        msg["X-CVE-ID"] = cve.cve.cve_id
        
        if cve.cve.is_in_kev:
            msg["X-KEV-Status"] = "Listed"
        
        # Add plain text version first (fallback)
        msg.attach(MIMEText(advisory_text, "plain", "utf-8"))
        
        # Add HTML version (preferred)
        msg.attach(MIMEText(advisory_html, "html", "utf-8"))
        
        return msg
    
    @backoff.on_exception(
        backoff.expo,
        (smtplib.SMTPException, OSError),
        max_tries=3,
        max_time=120
    )
    def _send_smtp(self, msg: MIMEMultipart) -> bool:
        """
        Send email via SMTP with retry.
        
        Args:
            msg: MIME message to send.
        
        Returns:
            True if sent successfully.
        
        Raises:
            smtplib.SMTPException: On SMTP error after retries.
        """
        logger.debug("smtp_connecting", host=self.GMAIL_SMTP_HOST)
        
        # Use STARTTLS (port 587)
        with smtplib.SMTP(self.GMAIL_SMTP_HOST, self.GMAIL_SMTP_PORT_TLS, timeout=30) as server:
            server.ehlo()
            server.starttls(context=self.ssl_context)
            server.ehlo()
            server.login(self.gmail_user, self.gmail_password)
            server.send_message(msg)
        
        return True
    
    def send_advisory(
        self,
        cve: EnrichedCVE,
        advisory_html: str,
        advisory_text: str = ""
    ) -> bool:
        """
        Send a security advisory email.
        
        Args:
            cve: Enriched CVE data.
            advisory_html: Advisory HTML content.
            advisory_text: Advisory plain text content (optional fallback).
        
        Returns:
            True if sent successfully, False otherwise.
        """
        cve_id = cve.cve.cve_id
        logger.info("sending_advisory_email", cve_id=cve_id)
        
        # If no plain text provided, create a simple fallback
        if not advisory_text:
            advisory_text = f"Security Advisory for {cve_id}\n\nPlease view this email in an HTML-capable email client for full formatting."
        
        try:
            msg = self._build_message(cve, advisory_html, advisory_text)
            self._send_smtp(msg)
            
            logger.info(
                "advisory_email_sent",
                cve_id=cve_id,
                subject=msg["Subject"],
                to=self.recipient
            )
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(
                "smtp_authentication_failed",
                cve_id=cve_id,
                error=str(e)
            )
            return False
            
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(
                "smtp_recipients_refused",
                cve_id=cve_id,
                recipient=self.recipient,
                error=str(e)
            )
            return False
            
        except smtplib.SMTPException as e:
            logger.error(
                "smtp_error",
                cve_id=cve_id,
                error=str(e)
            )
            return False
            
        except Exception as e:
            logger.error(
                "email_send_failed",
                cve_id=cve_id,
                error=str(e)
            )
            return False
    
    def send_test_email(self) -> bool:
        """
        Send a test email to verify configuration.
        
        Returns:
            True if test email sent successfully.
        """
        logger.info("sending_test_email")
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "[Gatekeeper] Test Email - Configuration Verified"
        msg["From"] = self.gmail_user
        msg["To"] = self.recipient
        
        now = datetime.now(timezone.utc)
        
        text_body = f"""
Gatekeeper CVE Advisory System - Test Email
============================================

This is a test email to verify your email configuration is working correctly.

Configuration Details:
- From: {self.gmail_user}
- To: {self.recipient}
- Timestamp: {now.isoformat()}Z

If you received this email, your Gatekeeper system is configured correctly
to send security advisories.

-- 
Gatekeeper CVE Advisory System
"""
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #1a5f7a 0%, #2d8659 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 30px; }}
        .success-badge {{ background: #d4edda; color: #155724; padding: 15px; border-radius: 6px; text-align: center; margin-bottom: 20px; }}
        .details {{ background: #f8f9fa; padding: 20px; border-radius: 6px; }}
        .details table {{ width: 100%; border-collapse: collapse; }}
        .details td {{ padding: 8px 0; }}
        .details td:first-child {{ color: #666; width: 120px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Gatekeeper CVE Advisory System</h1>
        </div>
        <div class="content">
            <div class="success-badge">
                <strong>Configuration Verified Successfully</strong>
            </div>
            <p>This is a test email to confirm your email configuration is working correctly.</p>
            <div class="details">
                <table>
                    <tr><td><strong>From:</strong></td><td>{self.gmail_user}</td></tr>
                    <tr><td><strong>To:</strong></td><td>{self.recipient}</td></tr>
                    <tr><td><strong>Timestamp:</strong></td><td>{now.strftime('%Y-%m-%d %H:%M:%S')} UTC</td></tr>
                </table>
            </div>
            <p style="margin-top: 20px;">If you received this email, your Gatekeeper system is configured correctly to send security advisories.</p>
        </div>
        <div class="footer">
            Gatekeeper CVE Advisory System
        </div>
    </div>
</body>
</html>
"""
        
        msg.attach(MIMEText(text_body.strip(), "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))
        
        try:
            self._send_smtp(msg)
            logger.info("test_email_sent", to=self.recipient)
            return True
        except Exception as e:
            logger.error("test_email_failed", error=str(e))
            return False
    
    def send_summary_email(
        self,
        run_id: str,
        cves_processed: int,
        cves_emailed: int,
        errors: int,
        duration_seconds: float
    ) -> bool:
        """
        Send a run summary email.
        
        Args:
            run_id: Unique run identifier.
            cves_processed: Number of CVEs processed.
            cves_emailed: Number of advisories sent.
            errors: Number of errors encountered.
            duration_seconds: Run duration in seconds.
        
        Returns:
            True if sent successfully.
        """
        logger.info("sending_summary_email", run_id=run_id)
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Gatekeeper] Run Summary - {cves_emailed} Advisories Sent"
        msg["From"] = self.gmail_user
        msg["To"] = self.recipient
        
        now = datetime.now(timezone.utc)
        
        if errors == 0:
            status = "SUCCESS"
            status_color = "#28a745"
            status_bg = "#d4edda"
        elif cves_emailed > 0:
            status = "PARTIAL"
            status_color = "#ffc107"
            status_bg = "#fff3cd"
        else:
            status = "FAILED"
            status_color = "#dc3545"
            status_bg = "#f8d7da"
        
        text_body = f"""
Gatekeeper CVE Advisory System - Run Summary
=============================================

Run ID:          {run_id}
Status:          {status}
Timestamp:       {now.isoformat()}Z

Results:
--------
CVEs Processed:  {cves_processed}
Advisories Sent: {cves_emailed}
Errors:          {errors}
Duration:        {duration_seconds:.1f} seconds

{"Note: Check logs for error details." if errors > 0 else ""}

-- 
Gatekeeper CVE Advisory System
"""
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #1a5f7a 0%, #2d8659 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 30px; }}
        .status-badge {{ background: {status_bg}; color: {status_color}; padding: 15px; border-radius: 6px; text-align: center; margin-bottom: 20px; font-weight: bold; font-size: 18px; }}
        .stats {{ display: flex; flex-wrap: wrap; gap: 15px; margin: 20px 0; }}
        .stat-box {{ flex: 1; min-width: 120px; background: #f8f9fa; padding: 20px; border-radius: 6px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #1a5f7a; }}
        .stat-label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
        .details {{ margin-top: 20px; }}
        .details table {{ width: 100%; border-collapse: collapse; }}
        .details td {{ padding: 10px; border-bottom: 1px solid #eee; }}
        .details td:first-child {{ color: #666; width: 140px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }}
        .error-note {{ background: #fff3cd; color: #856404; padding: 10px 15px; border-radius: 4px; margin-top: 15px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Gatekeeper Run Summary</h1>
        </div>
        <div class="content">
            <div class="status-badge">{status}</div>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value">{cves_processed}</div>
                    <div class="stat-label">CVEs Processed</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{cves_emailed}</div>
                    <div class="stat-label">Advisories Sent</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value" style="color: {'#dc3545' if errors > 0 else '#28a745'}">{errors}</div>
                    <div class="stat-label">Errors</div>
                </div>
            </div>
            
            <div class="details">
                <table>
                    <tr><td><strong>Run ID:</strong></td><td><code>{run_id}</code></td></tr>
                    <tr><td><strong>Duration:</strong></td><td>{duration_seconds:.1f} seconds</td></tr>
                    <tr><td><strong>Timestamp:</strong></td><td>{now.strftime('%Y-%m-%d %H:%M:%S')} UTC</td></tr>
                </table>
            </div>
            
            {"<div class='error-note'>Check logs for error details.</div>" if errors > 0 else ""}
        </div>
        <div class="footer">
            Gatekeeper CVE Advisory System
        </div>
    </div>
</body>
</html>
"""
        
        msg.attach(MIMEText(text_body.strip(), "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))
        
        try:
            self._send_smtp(msg)
            logger.info("summary_email_sent", run_id=run_id)
            return True
        except Exception as e:
            logger.error("summary_email_failed", run_id=run_id, error=str(e))
            return False
