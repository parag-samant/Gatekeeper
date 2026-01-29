# Gatekeeper

Automated CVE threat intelligence system that collects, enriches, and delivers enterprise-grade security advisories.

## Overview

Gatekeeper continuously monitors the NVD (National Vulnerability Database) and CISA KEV (Known Exploited Vulnerabilities) catalog for high-severity vulnerabilities, performs automated OSINT research, and generates professional security advisories delivered via email.

**NEW: GitHub Actions Support** - Run automatically every 12 hours on GitHub infrastructure with zero server costs! See [GitHub Actions Guide](GITHUB_ACTIONS.md).


### Key Features

- **Automated Collection**: Fetches CVE data from NVD API every 12 hours
- **CISA KEV Integration**: Cross-references with actively exploited vulnerabilities  
- **Intelligent Filtering**: Processes only High/Critical severity (CVSS >= 7.0)
- **Deduplication**: SQLite-backed state management prevents duplicate alerts
- **OSINT Enrichment**: DuckDuckGo search for threat context and exploits
- **AI-Generated Advisories**: Uses OpenRouter API for professional advisory generation
- **Enterprise Format**: CIS MS-ISAC style advisories with MITRE ATT&CK mapping
- **Email Delivery**: Individual advisory emails via Gmail SMTP

## Advisory Format

Generated advisories follow the CIS MS-ISAC format and include:

| Section | Description |
|---------|-------------|
| Advisory Number | Unique ID (GK-YYYY-NNN) |
| Overview | Executive summary |
| Threat Intelligence | Exploitation status, ransomware associations |
| Systems Affected | Impacted products/versions |
| Risk Assessment | Ratings by organization type |
| Technical Summary | MITRE ATT&CK mapping, CVSS details |
| CISA KEV Status | KEV details if listed |
| Recommendations | CIS Controls Safeguards |
| Detection Guidance | Monitoring and IOC guidance |
| References | CVE, vendor, and additional sources |

## Quick Start

### Choose Your Deployment Method

#### Option 1: GitHub Actions (Recommended - No Server Required)

Runs automatically every 12 hours on GitHub infrastructure.

1. Fork/clone this repository
2. Add GitHub Secrets (Settings → Secrets → Actions):
   - `GMAIL_USER`, `GMAIL_APP_PASSWORD`
   - `OPENROUTER_API_KEY`, `RECIPIENT_EMAIL`
3. Enable GitHub Actions
4. Done! See [Full GitHub Actions Guide](GITHUB_ACTIONS.md)

#### Option 2: Local/Server Deployment

### Prerequisites


- Python 3.12+
- Gmail account with App Password ([generate here](https://myaccount.google.com/apppasswords))
- OpenRouter API key ([get free key](https://openrouter.ai/keys))

### Installation

```bash
# Clone or navigate to directory
cd /path/to/Gatekeeper

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your credentials
```

### Configuration

Edit `.env` with your credentials:

```env
# Gmail SMTP
GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx

# OpenRouter API
OPENROUTER_API_KEY=sk-or-v1-your-key-here

# Recipient
RECIPIENT_EMAIL=security-team@company.com

# Optional: NVD API key for higher rate limits
NVD_API_KEY=your-nvd-key
```

### Run Locally

```bash
# Activate virtual environment
source venv/bin/activate

# Run the system
python -m gatekeeper.main
```

The system will:
1. Run immediately on startup
2. Schedule subsequent runs every 12 hours
3. Continue running until stopped (Ctrl+C)

## Docker Deployment

### Build and Run

```bash
# Build the image
docker-compose build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Docker Compose Configuration

The included `docker-compose.yml` provides:
- Automatic restart on failure
- Persistent storage for database and logs
- Resource limits (1 CPU, 512MB RAM)
- Health checks every 5 minutes
- Log rotation (10MB max, 3 files)

## Project Structure

```
gatekeeper/
├── __init__.py
├── main.py                    # Entry point with APScheduler
├── config.py                  # Configuration loader
├── collector/
│   ├── models.py              # Pydantic data models
│   ├── nvd.py                 # NVD API client
│   └── kev.py                 # CISA KEV feed client
├── deduplication/
│   └── store.py               # SQLite state management
├── research/
│   ├── duckduckgo.py          # DuckDuckGo search client
│   └── enrichment.py          # CVE enrichment orchestrator
├── advisory/
│   ├── generator.py           # Advisory generation
│   └── prompts.py             # AI system prompts
└── delivery/
    └── email.py               # Gmail SMTP sender
```

## Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `GMAIL_USER` | - | Gmail address for sending |
| `GMAIL_APP_PASSWORD` | - | Gmail app password |
| `OPENROUTER_API_KEY` | - | OpenRouter API key |
| `RECIPIENT_EMAIL` | - | Email to receive advisories |
| `NVD_API_KEY` | - | Optional NVD API key |
| `RUN_INTERVAL_HOURS` | 12 | Hours between runs |
| `MIN_CVSS_SCORE` | 7.0 | Minimum CVSS to process |
| `LOOKBACK_HOURS` | 24 | Hours to look back for CVEs |
| `DATABASE_PATH` | ./data/gatekeeper.db | SQLite database path |
| `LOG_LEVEL` | INFO | Logging verbosity |
| `LOG_FILE` | ./logs/gatekeeper.log | Log file path |

## Data Sources

### NVD API
- Official NIST vulnerability database
- Rate limits: 5 req/30s (50 req/30s with API key)
- Provides CVSS scores, descriptions, references

### CISA KEV Catalog
- Known exploited vulnerabilities list
- Updated frequently by CISA
- Provides exploitation dates, remediation deadlines

## AI Models

Gatekeeper uses OpenRouter to access various AI models for advisory generation:

- Default: `openai/gpt-oss-120b:free` (free tier)
- Falls back to template generation if AI is unavailable

To use other models, update the `OPENROUTER_MODEL` in your `.env`:

```env
OPENROUTER_MODEL=anthropic/claude-3-haiku
```

## Monitoring

### Check Database Stats

```bash
sqlite3 data/gatekeeper.db "SELECT * FROM run_logs ORDER BY started_at DESC LIMIT 5;"
```

### View Processing Stats

```bash
sqlite3 data/gatekeeper.db "SELECT 
  COUNT(*) as total,
  SUM(CASE WHEN emailed_at IS NOT NULL THEN 1 ELSE 0 END) as emailed,
  SUM(CASE WHEN error_message IS NOT NULL THEN 1 ELSE 0 END) as failed
FROM processed_cves;"
```

### Tail Logs

```bash
tail -f logs/gatekeeper.log
```

## Troubleshooting

### Email Not Sending

1. Verify Gmail App Password is correct (16 characters with spaces)
2. Ensure 2FA is enabled on your Google account
3. Check that "Less secure app access" is not blocking

### Rate Limiting

- **NVD**: Get an API key for 10x higher limits
- **OpenRouter**: Free tier has 50 requests/day limit
- **DuckDuckGo**: Built-in rate limiting handles this

### High Memory Usage

Adjust Docker limits in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      memory: 256M  # Reduce if needed
```

## License

MIT License - See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Acknowledgments

- [NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Known Exploited Vulnerabilities
- [CIS](https://www.cisecurity.org/) - Advisory format inspiration
- [OpenRouter](https://openrouter.ai/) - AI model access
