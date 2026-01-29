# GitHub Actions Deployment Guide

## Automated CVE Monitoring with GitHub Actions

This guide explains how to deploy Gatekeeper to run automatically on GitHub infrastructure every 12 hours, with no server required.

---

## Quick Setup

### 1. Fork/Use This Repository

Ensure you have this repository on your GitHub account (public or private).

### 2. Configure GitHub Secrets

Go to your repository: **Settings → Secrets and variables → Actions → New repository secret**

Add the following secrets:

| Secret Name | Description | Required |
|-------------|-------------|----------|
| `GMAIL_USER` | Your Gmail address | ✅ Yes |
| `GMAIL_APP_PASSWORD` | Gmail App Password ([create here](https://myaccount.google.com/apppasswords)) | ✅ Yes |
| `OPENROUTER_API_KEY` | OpenRouter API key ([get free key](https://openrouter.ai/keys)) | ✅ Yes |
| `RECIPIENT_EMAIL` | Email to receive advisories | ✅ Yes |
| `NVD_API_KEY` | NVD API key ([get here](https://nvd.nist.gov/developers/request-an-api-key)) | ⚠️ Optional |

**IMPORTANT:** Never commit actual credentials to the repository!

### 3. Enable GitHub Actions

1. Go to **Actions** tab in your repository
2. If prompted, enable workflows
3. You should see two workflows:
   - **CVE Advisory Monitor** (runs every 12 hours)
   - **Manual CVE Monitor Run** (on-demand)

### 4. Test Manual Run

1. Go to **Actions** tab
2. Select **Manual CVE Monitor Run**
3. Click **Run workflow**
4. Monitor the run in real-time

### 5. Verify Automated Schedule

The workflow will run automatically:
- **00:00 UTC** (12:00 AM)
- **12:00 UTC** (12:00 PM)

You'll receive CVE advisory emails at these times if new vulnerabilities are found.

---

## How It Works

```
GitHub Actions Cron (Every 12h)
         ↓
  Download database (if exists)
         ↓
  Run Gatekeeper once
         ↓
  Collect CVEs from NVD & KEV
         ↓
  Research & Generate Advisories
         ↓
  Send Emails
         ↓
  Upload database for next run
```

---

## Database Persistence

- **Storage:** GitHub Actions Artifacts
- **Retention:** 90 days
- **What's stored:** SQLite database with processed CVE IDs
- **Security:** Only contains CVE IDs and timestamps (no credentials)

The database is automatically downloaded before each run and uploaded after, ensuring continuity across runs.

---

## Monitoring

### View Run History

1. Go to **Actions** tab
2. See all workflow runs with status
3. Click any run to view detailed logs

### Email Notifications

GitHub can email you on workflow failures:
1. Go to **Settings → Notifications**
2. Enable **Actions** notifications

### Run Summary

Each run creates a summary showing:
- CVEs collected
- New CVEs processed
- Advisories generated
- Emails sent
- Any errors

---

## Cost & Limits

### Free Tier (Public Repository)
- ✅ **Unlimited minutes**
- ✅ No cost
- ✅ All features available

### Free Tier (Private Repository)
- ⚠️ 2,000 minutes/month
- Each run: ~5-15 minutes
- **Enough for:** ~130-400 runs/month
- **With 2 runs/day:** 60 runs/month (well within limit)

### GitHub Actions Limits
- ✅ Max 6 hours per job (Gatekeeper runs in <30 minutes typically)
- ✅ 1000 API requests/hour (Gatekeeper uses <100/run)

---

## Troubleshooting

### No Emails Received

1. Check workflow run logs in Actions tab
2. Verify Gmail App Password is correct
3. Ensure 2FA is enabled on Gmail account
4. Check recipient email is correct

### Workflow Fails

1. Click failed workflow run
2. Expand failed step
3. Check error message
4. Common issues:
   - Missing GitHub Secrets
   - Invalid Gmail App Password
   - Network/API issues (will retry next run)

### Database Not Persisting

- First run won't have a database (expected)
- Subsequent runs should download previous database
- Check "Upload database artifact" step succeeded

### Manual Run Not Working

- Ensure all GitHub Secrets are configured
- Check workflow permissions are enabled
- Review run logs for specific errors

---

## Customization

### Change Schedule

Edit `.github/workflows/cve-monitor.yml`:

```yaml
schedule:
  - cron: '0 */6 * * *'  # Every 6 hours
  # or
  - cron: '0 0 * * *'    # Once daily at midnight
```

[Cron syntax helper](https://crontab.guru/)

### Change Parameters

Edit workflow file environment variables:

```yaml
env:
  MIN_CVSS_SCORE: '8.0'  # Only critical/high
  LOOKBACK_HOURS: '48'   # Look back 2 days
```

### Add Notification Channels

Extend the workflow to add Slack, Discord, etc.:

```yaml
- name: Send to Slack
  if: steps.monitor.outputs.cves_emailed > 0
  uses: slackapi/slack-github-action@v1
  # ... slack configuration
```

---

## Security Best Practices

✅ **Do:**
- Use GitHub Secrets for all credentials
- Keep repository private if concerned about logs
- Rotate API keys periodically
- Review workflow run logs

❌ **Don't:**
- Commit `.env` file
- Hardcode credentials in workflow files
- Share GitHub Actions logs publicly (may contain debug info)

---

## Comparison: GitHub Actions vs Docker

| Feature | GitHub Actions | Docker (Self-Hosted) |
|---------|----------------|---------------------|
| **Cost** | Free (public) | Server costs |
| **Maintenance** | None | Server maintenance |
| **Uptime** | GitHub handles | You manage |
| **Database** | Artifacts (90 days) | Persistent storage |
| **Logs** | 30-90 days | Forever (if desired) |
| **Flexibility** | Limited | Full control |

**Recommendation:** Use GitHub Actions for simplicity, Docker for production environments with compliance requirements.

---

## Migration from Docker

If you were running via Docker locally:

1. Stop the Docker container:
   ```bash
   docker-compose down
   ```

2. Optional: Migrate database to GitHub:
   - Your local database is in `./data/gatekeeper.db`
   - Upload this manually in first GitHub Actions run (advanced)

3. GitHub Actions will handle everything from now on

You can always switch back to Docker by following the README instructions.

---

## Support

- **GitHub Issues:** Report bugs or feature requests
- **Discussions:** Ask questions or share tips
- **Documentation:** See main README.md

---

## Advanced: Workflow Outputs

Access run statistics programmatically:

```yaml
- name: Get stats
  run: |
    echo "CVEs: ${{ steps.monitor.outputs.cves_collected }}"
    echo "New: ${{ steps.monitor.outputs.cves_new }}"
```

Use these for custom integrations, dashboards, or alerts.
