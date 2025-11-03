#!/usr/bin/env python3
"""
Script to query Wiz API for CI/CD scan data and print results.

Requirements:
    pip install requests python-dotenv

Usage:
    python get_cicd_scan_data.py              # Default: last 30 days
    python get_cicd_scan_data.py -t 7d        # Last 7 days
    python get_cicd_scan_data.py -t 24h       # Last 24 hours
"""

import json
import os
import sys
import argparse
from pathlib import Path
from dotenv import load_dotenv

from wiz_cicd import WizCICDReporter, create_time_filter_variables

# Load environment variables from .env file in the current directory
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

# Get credentials from environment variables (loaded from .env file)
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
    parser = argparse.ArgumentParser(description='Fetch Wiz CI/CD scan data')
    parser.add_argument('--time-range', '-t', type=str, default='30d',
                       help='Time range (e.g., 1d, 7d, 24h). Default: 30d')
    args = parser.parse_args()

    # Check credentials
    if not CLIENT_ID or not CLIENT_SECRET:
        print("\nERROR: Missing credentials.")
        print(f"Please ensure WIZ_CLIENT_ID and WIZ_CLIENT_SECRET are set in: {env_path}")
        print("\nExpected format in .env file:")
        print("WIZ_CLIENT_ID=your_client_id_here")
        print("WIZ_CLIENT_SECRET=your_client_secret_here")
        sys.exit(1)

    # Parse time range
    try:
        days, hours, time_desc = parse_time_range(args.time_range)
    except ValueError:
        print(f"ERROR: Invalid time range: {args.time_range}")
        return 1

    print(f"Time Range: {time_desc}")
    print("Authenticating with Wiz API...")
    reporter = WizCICDReporter(CLIENT_ID, CLIENT_SECRET)
    token, dc = reporter.authenticate()
    print(f"Successfully authenticated (Data Center: {dc})")
    print()

    print(f"Fetching CI/CD scan data ({time_desc})...")
    variables = create_time_filter_variables(days=days, hours=hours)
    all_scans = reporter.fetch_all_scans(variables=variables)

    # Print the JSON output
    print("\n" + "="*80)
    print("RESULTS:")
    print("="*80)
    print(json.dumps(all_scans, indent=2))
    print("="*80)

    print("\nDone!")


if __name__ == '__main__':
    main()
