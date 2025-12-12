# Wiz CI/CD Reporting Tool

Python tool for generating security reports from Wiz CI/CD pipeline scans.

## Setup

```bash
pip install -r requirements.txt
```

Create `.env` with your Wiz credentials:
```
WIZ_CLIENT_ID=your_client_id
WIZ_CLIENT_SECRET=your_secret
```

## Usage

### Generate HTML Dashboard
```bash
python generate_dashboard_multitab.py              # Last 30 days
python generate_dashboard_multitab.py -t 7d        # Last 7 days
python generate_dashboard_multitab.py -t 24h       # Last 24 hours
python generate_dashboard_multitab.py --icons unicode  # Use Unicode icons
```

### Generate CSV Reports
```bash
python generate_reports.py
python generate_reports.py -t 7d
```

### Options
| Flag | Description |
|------|-------------|
| `-t`, `--time-range` | Time range: `30d`, `7d`, `24h`, `6h`, etc. |
| `--icons` | Icon style: `ascii` (default), `unicode`, `html` |
| `-o`, `--output-dir` | Output directory (default: `output/`) |

## Output

**HTML Dashboard** - Interactive multi-tab dashboard with:
- Executive summary with KPIs and charts
- Top 10 riskiest applications with risk scoring
- Detailed reporting with filtering by tag and scan type
- PDF export

**CSV Reports:**
- `executive_summary_TIMESTAMP.csv` - Pass/fail/warn statistics
- `daily_trends_TIMESTAMP.csv` - Daily trending data
- `detailed_scans_TIMESTAMP.csv` - Full scan details

## Using as a Module

```python
from wiz_cicd import WizCICDReporter, create_time_filter_variables

reporter = WizCICDReporter(client_id, client_secret)
reporter.authenticate()

# Fetch scans (last 7 days)
variables = create_time_filter_variables(days=7)
scans = reporter.fetch_all_scans(variables=variables)

# Get statistics
verdict_stats = reporter.get_verdict_stats()
finding_stats = reporter.get_finding_stats()

# Generate reports
reporter.generate_csv_reports(output_dir="output")
```

## Project Structure

```
wiz-cicd-reports/
├── generate_dashboard_multitab.py   # HTML dashboard generator
├── generate_reports.py              # CSV report generator
├── wiz_cicd/                        # Reusable module
│   ├── reporter.py                  # WizCICDReporter class
│   ├── processor.py                 # Data processing
│   ├── queries.py                   # GraphQL queries
│   └── icons.py                     # Icon style definitions
└── tests/                           # Test suite
```

## Testing

```bash
pytest tests/
pytest tests/ --cov=wiz_cicd
```
