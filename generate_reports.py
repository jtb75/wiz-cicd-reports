#!/usr/bin/env python3
"""
Generate executive reports from Wiz CI/CD scan data.

This script generates various reports including:
- Executive summary (CSV)
- Daily trends (CSV)
- Detailed scans (CSV)

Usage:
    python generate_reports.py              # Default: last 30 days
    python generate_reports.py -t 7d        # Last 7 days
    python generate_reports.py -t 24h       # Last 24 hours
    python generate_reports.py --debug      # Enable debug logging
"""

import os
import sys
import argparse
from pathlib import Path
from dotenv import load_dotenv

from wiz_cicd import WizCICDReporter, create_time_filter_variables, configure_logging

# Load environment variables
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

CLIENT_ID = os.environ.get("WIZ_CLIENT_ID")
CLIENT_SECRET = os.environ.get("WIZ_CLIENT_SECRET")


def parse_time_range(time_str):
    """Parse time range string."""
    time_str = time_str.lower().strip()
    if time_str.endswith('h'):
        hours = int(time_str[:-1])
        return (None, hours, f"Last {hours} hour{'s' if hours != 1 else ''}")
    elif time_str.endswith('d'):
        days = int(time_str[:-1])
        return (days, None, f"Last {days} day{'s' if days != 1 else ''}")
    else:
        days = int(time_str)
        return (days, None, f"Last {days} day{'s' if days != 1 else ''}")


def main():
    """Main function"""

    # Parse arguments
    parser = argparse.ArgumentParser(description='Generate Wiz CI/CD CSV reports')
    parser.add_argument('--time-range', '-t', type=str, default='30d',
                       help='Time range (e.g., 1d, 7d, 24h). Default: 30d')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    parser.add_argument('--log-level', type=str, default='WARNING',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Set logging level (default: WARNING)')
    args = parser.parse_args()

    # Configure logging
    log_level = 'DEBUG' if args.debug else args.log_level
    configure_logging(level=log_level)

    if not CLIENT_ID or not CLIENT_SECRET:
        print("\nERROR: Missing credentials.")
        print(f"Please ensure WIZ_CLIENT_ID and WIZ_CLIENT_SECRET are set in: {env_path}")
        return 1

    # Parse time range
    try:
        days, hours, time_desc = parse_time_range(args.time_range)
    except ValueError:
        print(f"ERROR: Invalid time range: {args.time_range}")
        return 1

    print("="*80)
    print("WIZ CI/CD SCAN REPORT GENERATOR")
    print("="*80)
    print(f"Time Range: {time_desc}")
    print()

    # Initialize reporter
    print("Initializing Wiz CI/CD Reporter...")
    reporter = WizCICDReporter(CLIENT_ID, CLIENT_SECRET)

    # Authenticate
    print("Authenticating with Wiz API...")
    token, dc = reporter.authenticate()
    print(f"  [OK] Successfully authenticated (Data Center: {dc})")
    print()

    # Fetch data with time filter
    print(f"Fetching CI/CD scan data ({time_desc})...")
    variables = create_time_filter_variables(days=days, hours=hours)
    scans = reporter.fetch_all_scans(variables=variables)
    print()

    # Generate reports
    print("Generating CSV reports...")
    files = reporter.generate_csv_reports()
    for report_type, filename in files.items():
        print(f"  [OK] {report_type}: {filename}")
    print()

    # Print summary
    reporter.print_summary()

    print("\n[OK] All reports generated successfully!")
    return 0


if __name__ == '__main__':
    exit(main())
