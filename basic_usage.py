#!/usr/bin/env python3
"""
Basic usage example for wiz-cicd-reports package.

This demonstrates the core functionality of the package.

Usage:
    python basic_usage.py              # Default: last 30 days
    python basic_usage.py -t 7d        # Last 7 days
    python basic_usage.py -t 24h       # Last 24 hours
    python basic_usage.py --debug      # Enable debug logging
"""

import os
import argparse
from pathlib import Path
from dotenv import load_dotenv

# Load credentials from .env file (in same directory as script)
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

# Import from wiz_cicd package
from wiz_cicd import WizCICDReporter, create_time_filter_variables, configure_logging

def parse_time_range(time_str):
    """Parse time range string like '1d', '7d', '24h'."""
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
    """Demonstrate basic usage."""

    # Parse arguments
    parser = argparse.ArgumentParser(description='Basic Wiz CI/CD reporting example')
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

    # Get credentials
    client_id = os.environ.get("WIZ_CLIENT_ID")
    client_secret = os.environ.get("WIZ_CLIENT_SECRET")

    if not client_id or not client_secret:
        print("ERROR: Set WIZ_CLIENT_ID and WIZ_CLIENT_SECRET in .env file")
        return 1

    # Parse time range
    try:
        days, hours, time_desc = parse_time_range(args.time_range)
    except ValueError:
        print(f"ERROR: Invalid time range: {args.time_range}")
        return 1

    print("=" * 60)
    print("Wiz CI/CD Reports - Basic Usage Example")
    print("=" * 60)
    print(f"Time Range: {time_desc}")
    print()

    # Initialize reporter
    print("1. Initialize WizCICDReporter...")
    reporter = WizCICDReporter(client_id, client_secret)

    # Authenticate
    print("2. Authenticate with Wiz API...")
    token, dc = reporter.authenticate()
    print(f"   ✓ Authenticated (Data Center: {dc})")
    print()

    # Fetch scans with time filter
    print(f"3. Fetch CI/CD scan data ({time_desc})...")
    variables = create_time_filter_variables(days=days, hours=hours)
    scans = reporter.fetch_all_scans(variables=variables)
    print()

    # Get statistics
    print("4. Calculate statistics...")
    verdict_stats = reporter.get_verdict_stats()
    finding_stats = reporter.get_finding_stats()
    print("   ✓ Statistics calculated")
    print()

    # Print summary
    print("5. Display summary:")
    print("-" * 60)
    reporter.print_summary()
    print()

    # Extract tags
    print("6. Extract tags...")
    tags = reporter.extract_tags()
    print(f"   ✓ Found {len(tags)} unique tag keys")
    for key, values in list(tags.items())[:3]:  # Show first 3
        print(f"     - {key}: {len(values)} values")
    print()

    # Generate reports
    print("7. Generate CSV reports...")
    files = reporter.generate_csv_reports(output_dir="output")
    for report_type, filepath in files.items():
        print(f"   ✓ {report_type}: {filepath}")
    print()

    print("=" * 60)
    print("✓ Example complete!")
    print("=" * 60)

    return 0


if __name__ == '__main__':
    exit(main())
