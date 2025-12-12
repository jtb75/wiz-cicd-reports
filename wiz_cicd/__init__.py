"""
Wiz CI/CD Reporting Package

A comprehensive Python package for fetching, analyzing, and reporting on
Wiz CI/CD pipeline scan data.

Example usage:
    from wiz_cicd import WizCICDReporter, configure_logging

    # Optional: Configure logging
    configure_logging(level='INFO')

    reporter = WizCICDReporter(client_id, client_secret)
    scans = reporter.fetch_all_scans()
    reporter.generate_csv_reports()
"""

import logging

__version__ = "1.0.0"
__author__ = "Wiz Security"
__license__ = "MIT"

# Import main classes and functions for public API
from .reporter import WizCICDReporter
from .processor import (
    parse_scan_data,
    calculate_verdict_stats,
    calculate_finding_type_stats,
    calculate_daily_trends
)
from .queries import create_time_filter_variables
from .icons import get_icons, get_console_icon, get_scan_type_icon, get_js_icon_object


def configure_logging(level: str = 'INFO', format: str = None):
    """
    Configure logging for the wiz_cicd package.

    Args:
        level: Logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        format: Custom log format string (optional)

    Example:
        configure_logging(level='DEBUG')
    """
    if format is None:
        format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=format,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Set level for wiz_cicd logger
    logger = logging.getLogger('wiz_cicd')
    logger.setLevel(getattr(logging, level.upper()))


# Define public API
__all__ = [
    "WizCICDReporter",
    "parse_scan_data",
    "calculate_verdict_stats",
    "calculate_finding_type_stats",
    "calculate_daily_trends",
    "create_time_filter_variables",
    "configure_logging",
    "get_icons",
    "get_console_icon",
    "get_scan_type_icon",
    "get_js_icon_object",
    "__version__",
]
