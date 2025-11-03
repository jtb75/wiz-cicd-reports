# Wiz CI/CD Reporting Tool

Production-ready Python application for generating comprehensive security reports from Wiz CI/CD pipeline scans.

**Features:** Interactive dashboards, CSV exports, risk scoring, automatic retries, tag filtering, and more!

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Credentials

Create a `.env` file with your Wiz credentials:

```bash
WIZ_CLIENT_ID=your_client_id_here
WIZ_CLIENT_SECRET=your_secret_here
```

### 3. Run Scripts

```bash
# Quick example with time filtering
python basic_usage.py              # Last 30 days
python basic_usage.py -t 7d        # Last 7 days
python basic_usage.py -t 24h       # Last 24 hours
python basic_usage.py --debug      # Enable debug logging

# Generate CSV reports
python generate_reports.py
python generate_reports.py -t 7d

# Generate interactive HTML dashboard
python generate_dashboard.py
python generate_dashboard.py -t 7d

# Generate multi-tab dashboard (RECOMMENDED)
python generate_dashboard_multitab.py

# Fetch raw scan data
python get_cicd_scan_data.py
```

## Files

```
wiz-cicd-reports/
├── basic_usage.py                    # Quick start example
├── generate_reports.py               # Generate CSV reports
├── generate_dashboard.py             # Single-page HTML dashboard
├── generate_dashboard_multitab.py    # Multi-tab dashboard (NEW!)
├── get_cicd_scan_data.py             # Fetch raw data
├── .env                              # Your credentials (create this)
│
├── wiz_cicd/                         # Reusable module
│   ├── __init__.py                   # Package exports & logging config
│   ├── reporter.py                   # WizCICDReporter class
│   ├── processor.py                  # Data processing functions
│   ├── queries.py                    # GraphQL queries
│   └── version.py                    # Version info
│
└── tests/                            # Test suite (56 tests, 93% coverage)
    ├── __init__.py
    ├── conftest.py                   # Test fixtures
    ├── test_wiz_reporter.py          # Reporter class tests
    ├── test_data_processor.py        # Data processing tests
    └── test_logging.py               # Logging config tests
```

## Using the Module in Your Own Projects

### Option 1: Copy the Module

Just copy the `wiz_cicd/` folder to your project:

```bash
cp -r wiz_cicd/ /path/to/your/project/
```

Then import and use:

```python
from wiz_cicd import WizCICDReporter

reporter = WizCICDReporter(client_id, client_secret)
scans = reporter.fetch_all_scans()
reporter.generate_csv_reports()
```

### Option 2: Import from This Directory

Add this directory to your Python path:

```python
import sys
sys.path.append('/path/to/cicd-reports')

from wiz_cicd import WizCICDReporter
```

## Features

### 🎯 Core Capabilities
- **Automatic pagination** - Handles large datasets efficiently
- **Retry logic** - Exponential backoff for transient failures
- **Rate limit handling** - Respects API rate limits automatically
- **Token auto-refresh** - Automatic token renewal for long-running operations
- **Comprehensive logging** - Configurable log levels (DEBUG, INFO, WARNING, etc.)
- **Tag filtering** - Filter by environment, team, or any custom tags
- **Time filtering** - Query last 1d, 7d, 30d, or custom hours/days

### 📊 Multi-Tab Dashboard (NEW!)

**Executive Summary Tab:**
- High-level KPI cards (Total Scans, Pass/Fail/Warn rates)
- 6 interactive charts (verdicts, findings, severity, trends)
- **Top 10 Riskiest Applications** table with risk scoring
- Clickable drill-down to detailed view
- PDF export

**Detailed Reporting Tab:**
- Filter by tag and scan type
- Resource sidebar with live filtering
- Expandable scan history per resource
- Detailed finding breakdown (6 types × 5 severities)
- Timeline visualization per resource

**Features:**
- Secret type breakdown tracking (Cloud Keys, DB Connections, Git Credentials, etc.)
- Risk scoring: Critical×5 + High×3.5 + Medium×2 + Low×1
- Interactive filtering with dynamic chart updates
- Export to PDF

### WizCICDReporter Class

```python
from wiz_cicd import WizCICDReporter, configure_logging

# Optional: Configure logging
configure_logging(level='INFO')  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Initialize (with optional retry config)
reporter = WizCICDReporter(client_id, client_secret, max_retries=3)

# Authenticate (automatic token management)
token, dc = reporter.authenticate()

# Fetch all scans (with automatic pagination & retries)
scans = reporter.fetch_all_scans()

# Fetch with time filter
from wiz_cicd import create_time_filter_variables
variables = create_time_filter_variables(days=7)  # Last 7 days
scans = reporter.fetch_all_scans(variables=variables)

# Get statistics
verdict_stats = reporter.get_verdict_stats()
finding_stats = reporter.get_finding_stats()
daily_trends = reporter.get_daily_trends()  # Includes secret type breakdown

# Tag filtering
tags = reporter.extract_tags()
filtered = reporter.filter_scans_by_tag(tag_key="environment", tag_value="production")

# Generate reports
files = reporter.generate_csv_reports(output_dir="output")
reporter.print_summary()
```

### Production Features

**Reliability:**
- ✅ Automatic retry with exponential backoff (1s, 2s, 4s...)
- ✅ Rate limit handling (respects Retry-After headers)
- ✅ Token auto-refresh (60-second buffer before expiry)
- ✅ Comprehensive error handling and logging

**Performance:**
- ✅ Smart caching (avoids redundant calculations)
- ✅ Efficient pagination (handles 1000+ scans)
- ✅ Connection pooling and timeouts (180s default)

### Available Functions

```python
from wiz_cicd import (
    parse_scan_data,
    calculate_verdict_stats,
    calculate_finding_type_stats,
    calculate_daily_trends
)

# Parse raw scan data
parsed = parse_scan_data(raw_scans)

# Calculate statistics
verdict_stats = calculate_verdict_stats(parsed)
finding_stats = calculate_finding_type_stats(parsed)
trends = calculate_daily_trends(parsed)
```

## Reports Generated

### CSV Reports

- **executive_summary_TIMESTAMP.csv** - Pass/fail/warn statistics and finding totals
- **daily_trends_TIMESTAMP.csv** - Daily trending data
- **detailed_scans_TIMESTAMP.csv** - Full scan details (all fields)

### HTML Dashboards

**Single-Page Dashboard** (`generate_dashboard.py`):
- **dashboard_TIMESTAMP.html** - Interactive charts with tag filtering
  - Verdict distribution, findings by type, severity breakdown
  - Daily trends, tag filtering dropdown

**Multi-Tab Dashboard** (`generate_dashboard_multitab.py`) - RECOMMENDED:
- **Executive Summary Tab:**
  - KPI cards (Total, Passed, Failed, Warned)
  - Top 10 Riskiest Applications with risk scores
  - 6 interactive charts (verdict distribution, findings by type/severity, trends)
  - Secret Types Detected Over Time chart
  - PDF export functionality

- **Detailed Reporting Tab:**
  - Filter by tag and scan type (checkbox dropdown)
  - Resource sidebar with live search
  - Expandable scan history per resource
  - Detailed finding breakdown per scan
  - Timeline visualization

## Advanced Usage

### Configure Logging

```python
from wiz_cicd import configure_logging

# Set log level
configure_logging(level='DEBUG')  # See detailed API calls and retries
configure_logging(level='INFO')   # See progress messages
configure_logging(level='WARNING')  # Only warnings and errors (default)

# Custom format
configure_logging(
    level='DEBUG',
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
```

### Time Filtering

```python
from wiz_cicd import create_time_filter_variables

# Last 7 days
variables = create_time_filter_variables(days=7)

# Last 24 hours
variables = create_time_filter_variables(hours=24)

# Fetch with custom time range
scans = reporter.fetch_all_scans(variables=variables)
```

### Configure Retry Behavior

```python
# Default: 3 retries with exponential backoff
reporter = WizCICDReporter(client_id, client_secret)

# Custom retry count
reporter = WizCICDReporter(client_id, client_secret, max_retries=5)

# Retry logic automatically handles:
# - Transient network errors (exponential backoff: 1s, 2s, 4s...)
# - Rate limiting (429 errors - respects Retry-After header)
# - Token expiration (auto-refresh when needed)
```

### Customization

**Change Default Time Period:**

Edit `wiz_cicd/queries.py`:

```python
"timestamp": {
    "inLast": {
        "amount": 30,  # Change to 7, 60, 90, etc.
        "unit": "DurationFilterValueUnitDays"
    }
}
```

**Add Custom Filters:**

Edit the `filterBy` section in `wiz_cicd/queries.py` to add resource filters, tag filters, etc.

## Testing

Comprehensive test suite with 93% coverage:

```bash
# Run all tests
pytest tests/

# With coverage report
pytest tests/ --cov=wiz_cicd --cov-report=term-missing

# With HTML coverage report
pytest tests/ --cov=wiz_cicd --cov-report=html

# 56 tests covering:
# - Retry logic and exponential backoff
# - Token expiry and auto-refresh
# - Rate limit handling
# - Data parsing and statistics
# - Tag filtering operations
# - Logging configuration
```

**Test Coverage:**
- `wiz_cicd/__init__.py`: 100%
- `wiz_cicd/processor.py`: 99%
- `wiz_cicd/reporter.py`: 95%
- **Overall: 93%**

## Dependencies

- **requests** - HTTP library for API calls
- **python-dotenv** - Load credentials from .env file
- **pytest** (optional) - For running tests

## What Gets Created

When you run the scripts, an `output/` directory is created with your reports. This is gitignored and local to each user.

## Architecture

```
Scripts (top level)
    ↓
WizCICDReporter (wiz_cicd/reporter.py)
    ↓
├─→ Data Processor (wiz_cicd/processor.py)
├─→ GraphQL Queries (wiz_cicd/queries.py)
└─→ Wiz API
```

**Simple, self-contained, copy-and-use!**

## Support

For issues or questions, see the inline code documentation in `wiz_cicd/` files.
