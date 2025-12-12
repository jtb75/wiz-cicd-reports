"""
WizCICDReporter - Class-based interface for Wiz CI/CD scan reporting.

This module provides a clean, reusable interface for fetching, analyzing,
and reporting on Wiz CI/CD pipeline scan data.
"""

import base64
import json
import csv
import os
import time
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import requests

from .queries import WIZ_CODE_ANALYZER_QUERY, WIZ_CODE_ANALYZER_VARIABLES
from .processor import (
    parse_scan_data,
    calculate_verdict_stats,
    calculate_finding_type_stats,
    calculate_daily_trends
)
from .icons import get_console_icon

# Configure module logger
logger = logging.getLogger(__name__)


class WizCICDReporter:
    """
    Main class for interacting with Wiz API and generating CI/CD scan reports.

    Example usage:
        reporter = WizCICDReporter(client_id, client_secret)
        scans = reporter.fetch_all_scans()
        reporter.generate_html_dashboard()
        reporter.generate_csv_reports()
    """

    def __init__(self, client_id: str, client_secret: str, max_retries: int = 3):
        """
        Initialize the reporter with Wiz API credentials.

        Args:
            client_id: Wiz service account client ID
            client_secret: Wiz service account client secret
            max_retries: Maximum number of retry attempts for API calls (default: 3)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.token_expiry = None
        self.dc = None
        self.max_retries = max_retries
        self.headers_auth = {"Content-Type": "application/x-www-form-urlencoded"}
        self.headers = {"Content-Type": "application/json"}

        # Cached data
        self._raw_scans = None
        self._parsed_scans = None
        self._verdict_stats = None
        self._finding_stats = None
        self._daily_trends = None
        self._tag_index = None

    def authenticate(self) -> Tuple[str, str]:
        """
        Authenticate with Wiz API and retrieve access token.

        Returns:
            Tuple of (token, data_center)

        Raises:
            ValueError: If authentication fails
        """
        logger.info("Authenticating with Wiz API...")

        auth_payload = {
            'grant_type': 'client_credentials',
            'audience': 'wiz-api',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

        def _authenticate():
            response = requests.post(
                url="https://auth.app.wiz.io/oauth/token",
                headers=self.headers_auth,
                data=auth_payload,
                timeout=180
            )
            response.raise_for_status()
            return response

        try:
            response = self._retry_with_backoff(_authenticate)
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed after retries: {str(e)}")
            raise ValueError(f"Authentication failed: {str(e)}")

        response_json = response.json()
        token = response_json.get('access_token')
        expires_in = response_json.get('expires_in', 3600)  # Default 1 hour

        if not token:
            error_msg = f"Could not retrieve token: {response_json.get('message')}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Decode JWT to extract data center and expiry
        token_payload = token.split(".")[1]
        padded = self._pad_base64(token_payload)
        decoded = json.loads(base64.standard_b64decode(padded))
        dc = decoded["dc"]

        self.token = token
        self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
        self.dc = dc
        self.headers["Authorization"] = f"Bearer {token}"

        logger.info(f"Successfully authenticated (Data Center: {dc}, expires in {expires_in}s)")

        return token, dc

    @staticmethod
    def _pad_base64(data: str) -> str:
        """Add padding to base64 string if needed."""
        missing_padding = len(data) % 4
        if missing_padding:
            data += "=" * (4 - missing_padding)
        return data

    def _is_token_valid(self) -> bool:
        """
        Check if the current token is valid and not expired.

        Returns:
            True if token is valid and not expired, False otherwise
        """
        if not self.token or not self.token_expiry:
            return False

        # Add 60 second buffer to refresh before actual expiry
        return datetime.now() < (self.token_expiry - timedelta(seconds=60))

    def _retry_with_backoff(self, func, *args, **kwargs):
        """
        Execute a function with exponential backoff retry logic.

        Args:
            func: Function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            Function result

        Raises:
            Exception: If all retry attempts fail
        """
        last_exception = None

        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except requests.exceptions.RequestException as e:
                last_exception = e

                # Don't retry on 4xx errors (except 429 rate limit)
                if hasattr(e, 'response') and e.response is not None:
                    status_code = e.response.status_code

                    # Handle rate limiting
                    if status_code == 429:
                        retry_after = int(e.response.headers.get('Retry-After', 60))
                        logger.warning(f"Rate limited. Waiting {retry_after} seconds before retry...")
                        time.sleep(retry_after)
                        continue

                    # Don't retry client errors (except 429)
                    if 400 <= status_code < 500:
                        logger.error(f"Client error {status_code}: {str(e)}")
                        raise

                # Calculate backoff time: 2^attempt seconds
                if attempt < self.max_retries - 1:
                    backoff_time = 2 ** attempt
                    logger.warning(
                        f"Request failed (attempt {attempt + 1}/{self.max_retries}): {str(e)}. "
                        f"Retrying in {backoff_time} seconds..."
                    )
                    time.sleep(backoff_time)
                else:
                    logger.error(f"All {self.max_retries} retry attempts failed: {str(e)}")

        raise last_exception

    def query_api(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a GraphQL query against the Wiz API.

        Args:
            query: GraphQL query string
            variables: Query variables

        Returns:
            API response as dictionary

        Raises:
            ValueError: If query fails
        """
        # Check if token is valid, refresh if needed
        if not self._is_token_valid():
            logger.info("Token expired or invalid, re-authenticating...")
            self.authenticate()

        data = {"variables": variables, "query": query}

        def _query():
            response = requests.post(
                url=f"https://api.{self.dc}.app.wiz.io/graphql",
                json=data,
                headers=self.headers,
                timeout=180
            )
            response.raise_for_status()
            return response

        try:
            response = self._retry_with_backoff(_query)
        except requests.exceptions.RequestException as e:
            logger.error(f"API query failed after retries: {str(e)}")
            raise ValueError(f"API query failed: {str(e)}")

        return response.json()

    def fetch_all_scans(
        self,
        variables: Optional[Dict[str, Any]] = None,
        verbose: bool = True,
        icon_style: str = 'ascii'
    ) -> List[Dict[str, Any]]:
        """
        Fetch all CI/CD scans with automatic pagination.

        Args:
            variables: Query variables (uses default if None)
            verbose: Print progress messages
            icon_style: Icon style for console output ('ascii', 'unicode', 'html')

        Returns:
            List of scan dictionaries
        """
        if variables is None:
            variables = WIZ_CODE_ANALYZER_VARIABLES.copy()
        else:
            variables = variables.copy()

        all_events = []
        has_next_page = True
        page_count = 0

        logger.info("Fetching CI/CD scan data...")
        if verbose:
            print("Fetching CI/CD scan data...")

        while has_next_page:
            page_count += 1
            logger.debug(f"Fetching page {page_count}...")
            if verbose:
                print(f"  Page {page_count}...", end="", flush=True)

            result = self.query_api(WIZ_CODE_ANALYZER_QUERY, variables)

            # Handle errors but continue if we have data
            if 'errors' in result:
                error_messages = [err.get('message', 'Unknown error') for err in result.get('errors', [])]
                logger.warning(f"API returned errors: {error_messages}")
                if verbose:
                    print(f" [API warnings]", end="")
                if 'data' not in result or not result.get('data', {}).get('cloudEvents'):
                    logger.warning("No data returned, stopping pagination")
                    if verbose:
                        print(" [stopping - no data]")
                    break

            cloud_events = result.get('data', {}).get('cloudEvents', {})
            nodes = cloud_events.get('nodes', [])

            logger.debug(f"Page {page_count} returned {len(nodes)} scans")
            if verbose:
                print(f" {len(nodes)} scans")

            all_events.extend(nodes)

            # Check pagination
            page_info = cloud_events.get('pageInfo', {})
            has_next_page = page_info.get('hasNextPage', False)

            if has_next_page:
                variables['after'] = page_info.get('endCursor')
                logger.debug(f"Has next page, cursor: {page_info.get('endCursor')}")

        logger.info(f"Successfully retrieved {len(all_events)} total scans")
        if verbose:
            ok_icon = get_console_icon('ok', icon_style)
            print(f"{ok_icon} Retrieved {len(all_events)} total scans\n")

        # Cache the raw scans
        self._raw_scans = all_events

        return all_events

    def get_parsed_scans(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Get parsed scan data. Uses cached data if available.

        Args:
            force_refresh: Force re-parsing of data

        Returns:
            List of parsed scan dictionaries
        """
        if self._parsed_scans is None or force_refresh:
            if self._raw_scans is None:
                self.fetch_all_scans()
            self._parsed_scans = parse_scan_data(self._raw_scans)

        return self._parsed_scans

    def get_verdict_stats(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Get verdict statistics (pass/fail/warn)."""
        if self._verdict_stats is None or force_refresh:
            parsed = self.get_parsed_scans(force_refresh)
            self._verdict_stats = calculate_verdict_stats(parsed)
        return self._verdict_stats

    def get_finding_stats(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Get finding type statistics."""
        if self._finding_stats is None or force_refresh:
            parsed = self.get_parsed_scans(force_refresh)
            self._finding_stats = calculate_finding_type_stats(parsed)
        return self._finding_stats

    def get_daily_trends(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """Get daily trend data."""
        if self._daily_trends is None or force_refresh:
            parsed = self.get_parsed_scans(force_refresh)
            self._daily_trends = calculate_daily_trends(parsed)
        return self._daily_trends

    def extract_tags(self, force_refresh: bool = False) -> Dict[str, set]:
        """
        Extract all unique tag key/value pairs from scans.

        Returns:
            Dictionary mapping tag keys to sets of values
        """
        if self._tag_index is not None and not force_refresh:
            return self._tag_index

        if self._raw_scans is None:
            self.fetch_all_scans()

        tag_index = {}

        for scan in self._raw_scans:
            extra = scan.get('extraDetails') or {}
            tags = extra.get('tags') or []

            for tag in tags:
                if not isinstance(tag, dict):
                    continue

                key = tag.get('key')
                value = tag.get('value')

                if key and value:
                    if key not in tag_index:
                        tag_index[key] = set()
                    tag_index[key].add(value)

        # Convert sets to sorted lists for easier use
        self._tag_index = {k: sorted(v) for k, v in tag_index.items()}

        return self._tag_index

    def filter_scans_by_tag(
        self,
        tag_key: Optional[str] = None,
        tag_value: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Filter scans by tag key and/or value.

        Args:
            tag_key: Tag key to filter by (optional)
            tag_value: Tag value to filter by (optional)

        Returns:
            Filtered list of raw scan dictionaries
        """
        if self._raw_scans is None:
            self.fetch_all_scans()

        if tag_key is None and tag_value is None:
            return self._raw_scans

        filtered = []

        for scan in self._raw_scans:
            extra = scan.get('extraDetails') or {}
            tags = extra.get('tags') or []

            for tag in tags:
                if not isinstance(tag, dict):
                    continue

                key = tag.get('key')
                value = tag.get('value')

                # Check if this tag matches the filter
                key_match = (tag_key is None or key == tag_key)
                value_match = (tag_value is None or value == tag_value)

                if key_match and value_match:
                    filtered.append(scan)
                    break  # Don't add the same scan multiple times

        return filtered

    def generate_csv_reports(self, output_dir: str = "output") -> Dict[str, str]:
        """
        Generate all CSV reports.

        Args:
            output_dir: Directory to save reports

        Returns:
            Dictionary mapping report type to filename
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        parsed = self.get_parsed_scans()
        verdict_stats = self.get_verdict_stats()
        finding_stats = self.get_finding_stats()
        daily_trends = self.get_daily_trends()

        files = {}

        # Executive summary
        filename = f"{output_dir}/executive_summary_{timestamp}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['EXECUTIVE SUMMARY - SCAN VERDICTS'])
            writer.writerow(['Metric', 'Value', 'Percentage'])
            writer.writerow(['Total Scans', verdict_stats['total_scans'], '100%'])
            writer.writerow(['Passed', verdict_stats['passed'], f"{verdict_stats['pass_rate']:.1f}%"])
            writer.writerow(['Failed', verdict_stats['failed'], f"{verdict_stats['fail_rate']:.1f}%"])
            writer.writerow(['Warned', verdict_stats['warned'], f"{verdict_stats['warn_rate']:.1f}%"])
            writer.writerow([])
            writer.writerow(['FINDINGS BY TYPE'])
            writer.writerow(['Finding Type', 'Total', 'Critical', 'High', 'Medium', 'Low'])
            for finding_type, stats in finding_stats.items():
                writer.writerow([
                    finding_type.capitalize(),
                    stats['total'],
                    stats['critical'],
                    stats['high'],
                    stats['medium'],
                    stats['low']
                ])
        files['executive_summary'] = filename

        # Daily trends
        filename = f"{output_dir}/daily_trends_{timestamp}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Date', 'Total Scans', 'Passed', 'Failed', 'Warned',
                           'Total Findings', 'Critical', 'High', 'Medium', 'Low'])
            for day in daily_trends:
                writer.writerow([
                    day['date'],
                    day['total_scans'],
                    day['passed'],
                    day['failed'],
                    day['warned'],
                    day['total_findings'],
                    day['critical'],
                    day['high'],
                    day['medium'],
                    day['low']
                ])
        files['daily_trends'] = filename

        # Detailed scans
        filename = f"{output_dir}/detailed_scans_{timestamp}.csv"
        if parsed:
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=parsed[0].keys())
                writer.writeheader()
                writer.writerows(parsed)
        files['detailed_scans'] = filename

        return files

    def print_summary(self):
        """Print executive summary to console."""
        verdict_stats = self.get_verdict_stats()
        finding_stats = self.get_finding_stats()

        print("="*80)
        print("EXECUTIVE SUMMARY")
        print("="*80)
        print(f"Total Scans:  {verdict_stats['total_scans']}")
        print(f"  Passed:     {verdict_stats['passed']:4d} ({verdict_stats['pass_rate']:.1f}%)")
        print(f"  Failed:     {verdict_stats['failed']:4d} ({verdict_stats['fail_rate']:.1f}%)")
        print(f"  Warned:     {verdict_stats['warned']:4d} ({verdict_stats['warn_rate']:.1f}%)")
        print()
        print("Findings by Type:")
        for finding_type, stats in finding_stats.items():
            if stats['total'] > 0:
                print(f"  {finding_type.capitalize():15} Total: {stats['total']:5d}  "
                      f"(C:{stats['critical']:4d} H:{stats['high']:4d} "
                      f"M:{stats['medium']:4d} L:{stats['low']:4d})")
        print("="*80)
