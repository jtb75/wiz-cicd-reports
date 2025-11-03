"""
Data processing module for Wiz CI/CD scan data.

This module provides functions to parse and analyze scan data from the Wiz API.
"""

from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any


def parse_scan_data(scans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Parse raw scan data into a flat structure for analysis.

    Args:
        scans: List of scan dictionaries from Wiz API

    Returns:
        List of parsed scan records
    """
    parsed_scans = []

    for scan in scans:
        extra = scan.get('extraDetails') or {}
        analytics = extra.get('analytics') or {}
        status = extra.get('status') or {}
        subject = scan.get('subjectResource') or {}
        actor = scan.get('actor') or {}
        cli_details = extra.get('cliDetails') or {}

        # Calculate total findings by type
        vuln_analytics = analytics.get('vulnerabilityScanResultAnalytics') or {}
        secret_analytics = analytics.get('secretScanResultAnalytics') or {}
        iac_analytics = analytics.get('iacScanResultAnalytics') or {}
        sast_analytics = analytics.get('sastScanResultAnalytics') or {}
        data_analytics = analytics.get('dataScanResultAnalytics') or {}
        malware_details = extra.get('malwareDetails', {})
        malware_analytics = (malware_details.get('analytics') if malware_details else None) or {}

        parsed = {
            # Scan metadata
            'scan_id': scan.get('id'),
            'timestamp': scan.get('timestamp'),
            'date': scan.get('timestamp', '').split('T')[0] if scan.get('timestamp') else None,
            'cloud_platform': scan.get('cloudPlatform', ''),
            'origin': scan.get('origin'),

            # Resource info
            'resource_name': subject.get('name'),
            'resource_type': subject.get('type'),
            'resource_id': subject.get('id'),

            # Actor info
            'actor_name': actor.get('name'),
            'actor_email': actor.get('email'),
            'actor_type': actor.get('type'),

            # Status
            'scan_state': status.get('state'),
            'verdict': status.get('verdict'),

            # CLI details
            'cli_version': cli_details.get('clientVersion'),
            'scan_origin_type': cli_details.get('scanOriginResourceType'),

            # Vulnerability findings
            'vuln_critical': vuln_analytics.get('criticalCount', 0),
            'vuln_high': vuln_analytics.get('highCount', 0),
            'vuln_medium': vuln_analytics.get('mediumCount', 0),
            'vuln_low': vuln_analytics.get('lowCount', 0),
            'vuln_info': vuln_analytics.get('infoCount', 0),
            'vuln_total': sum([
                vuln_analytics.get('criticalCount', 0),
                vuln_analytics.get('highCount', 0),
                vuln_analytics.get('mediumCount', 0),
                vuln_analytics.get('lowCount', 0),
                vuln_analytics.get('infoCount', 0)
            ]),

            # Secret findings
            'secret_critical': secret_analytics.get('criticalCount', 0),
            'secret_high': secret_analytics.get('highCount', 0),
            'secret_medium': secret_analytics.get('mediumCount', 0),
            'secret_low': secret_analytics.get('lowCount', 0),
            'secret_info': secret_analytics.get('infoCount', 0),
            'secret_total': secret_analytics.get('totalCount', 0),

            # Secret type breakdown
            'secret_cloud_keys': secret_analytics.get('cloudKeyCount', 0),
            'secret_db_connections': secret_analytics.get('dbConnectionStringCount', 0),
            'secret_git_credentials': secret_analytics.get('gitCredentialCount', 0),
            'secret_passwords': secret_analytics.get('passwordCount', 0),
            'secret_private_keys': secret_analytics.get('privateKeyCount', 0),
            'secret_saas_api_keys': secret_analytics.get('saasAPIKeyCount', 0),

            # IaC findings
            'iac_critical': iac_analytics.get('criticalCount', 0) if iac_analytics else 0,
            'iac_high': iac_analytics.get('highCount', 0) if iac_analytics else 0,
            'iac_medium': iac_analytics.get('mediumCount', 0) if iac_analytics else 0,
            'iac_low': iac_analytics.get('lowCount', 0) if iac_analytics else 0,
            'iac_info': iac_analytics.get('infoCount', 0) if iac_analytics else 0,
            'iac_total': sum([
                iac_analytics.get('criticalCount', 0) if iac_analytics else 0,
                iac_analytics.get('highCount', 0) if iac_analytics else 0,
                iac_analytics.get('mediumCount', 0) if iac_analytics else 0,
                iac_analytics.get('lowCount', 0) if iac_analytics else 0,
                iac_analytics.get('infoCount', 0) if iac_analytics else 0
            ]),

            # SAST findings
            'sast_critical': sast_analytics.get('criticalCount', 0),
            'sast_high': sast_analytics.get('highCount', 0),
            'sast_medium': sast_analytics.get('mediumCount', 0),
            'sast_low': sast_analytics.get('lowCount', 0),
            'sast_info': sast_analytics.get('infoCount', 0),
            'sast_total': sum([
                sast_analytics.get('criticalCount', 0),
                sast_analytics.get('highCount', 0),
                sast_analytics.get('mediumCount', 0),
                sast_analytics.get('lowCount', 0),
                sast_analytics.get('infoCount', 0)
            ]),

            # Sensitive data findings
            'data_critical': data_analytics.get('criticalCount', 0),
            'data_high': data_analytics.get('highCount', 0),
            'data_medium': data_analytics.get('mediumCount', 0),
            'data_low': data_analytics.get('lowCount', 0),
            'data_info': data_analytics.get('infoCount', 0),
            'data_total': sum([
                data_analytics.get('criticalCount', 0),
                data_analytics.get('highCount', 0),
                data_analytics.get('mediumCount', 0),
                data_analytics.get('lowCount', 0),
                data_analytics.get('infoCount', 0)
            ]),

            # Malware findings
            'malware_critical': malware_analytics.get('criticalCount', 0),
            'malware_high': malware_analytics.get('highCount', 0),
            'malware_medium': malware_analytics.get('mediumCount', 0),
            'malware_low': malware_analytics.get('lowCount', 0),
            'malware_info': malware_analytics.get('infoCount', 0),
            'malware_total': malware_analytics.get('totalCount', 0) if malware_analytics.get('totalCount') else sum([
                malware_analytics.get('criticalCount', 0),
                malware_analytics.get('highCount', 0),
                malware_analytics.get('mediumCount', 0),
                malware_analytics.get('lowCount', 0),
                malware_analytics.get('infoCount', 0)
            ]),

            # Overall totals
            'total_critical': sum([
                vuln_analytics.get('criticalCount', 0),
                secret_analytics.get('criticalCount', 0),
                iac_analytics.get('criticalCount', 0) if iac_analytics else 0,
                sast_analytics.get('criticalCount', 0),
                data_analytics.get('criticalCount', 0),
                malware_analytics.get('criticalCount', 0)
            ]),
            'total_high': sum([
                vuln_analytics.get('highCount', 0),
                secret_analytics.get('highCount', 0),
                iac_analytics.get('highCount', 0) if iac_analytics else 0,
                sast_analytics.get('highCount', 0),
                data_analytics.get('highCount', 0),
                malware_analytics.get('highCount', 0)
            ]),
            'total_medium': sum([
                vuln_analytics.get('mediumCount', 0),
                secret_analytics.get('mediumCount', 0),
                iac_analytics.get('mediumCount', 0) if iac_analytics else 0,
                sast_analytics.get('mediumCount', 0),
                data_analytics.get('mediumCount', 0),
                malware_analytics.get('mediumCount', 0)
            ]),
            'total_low': sum([
                vuln_analytics.get('lowCount', 0),
                secret_analytics.get('lowCount', 0),
                iac_analytics.get('lowCount', 0) if iac_analytics else 0,
                sast_analytics.get('lowCount', 0),
                data_analytics.get('lowCount', 0),
                malware_analytics.get('lowCount', 0)
            ]),
        }

        parsed_scans.append(parsed)

    return parsed_scans


def calculate_verdict_stats(parsed_scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate pass/fail/warn statistics."""
    total = len(parsed_scans)

    verdict_counts = defaultdict(int)
    for scan in parsed_scans:
        verdict = scan.get('verdict', 'UNKNOWN')
        verdict_counts[verdict] += 1

    return {
        'total_scans': total,
        'passed': verdict_counts.get('PASSED_BY_POLICY', 0),
        'failed': verdict_counts.get('FAILED_BY_POLICY', 0),
        'warned': verdict_counts.get('WARN_BY_POLICY', 0),
        'pass_rate': (verdict_counts.get('PASSED_BY_POLICY', 0) / total * 100) if total > 0 else 0,
        'fail_rate': (verdict_counts.get('FAILED_BY_POLICY', 0) / total * 100) if total > 0 else 0,
        'warn_rate': (verdict_counts.get('WARN_BY_POLICY', 0) / total * 100) if total > 0 else 0
    }


def calculate_finding_type_stats(parsed_scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate statistics by finding type."""
    stats = {
        'vulnerabilities': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'secrets': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'iac': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'sast': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'data': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'malware': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
    }

    for scan in parsed_scans:
        type_mapping = {
            'vuln': 'vulnerabilities',
            'secret': 'secrets',
            'iac': 'iac',
            'sast': 'sast',
            'data': 'data',
            'malware': 'malware'
        }

        for finding_type, type_key in type_mapping.items():
            stats[type_key]['total'] += scan.get(f'{finding_type}_total', 0)
            stats[type_key]['critical'] += scan.get(f'{finding_type}_critical', 0)
            stats[type_key]['high'] += scan.get(f'{finding_type}_high', 0)
            stats[type_key]['medium'] += scan.get(f'{finding_type}_medium', 0)
            stats[type_key]['low'] += scan.get(f'{finding_type}_low', 0)

    return stats


def calculate_daily_trends(parsed_scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate daily trends for verdicts and findings."""
    daily_data = defaultdict(lambda: {
        'date': None,
        'total_scans': 0,
        'passed': 0,
        'failed': 0,
        'warned': 0,
        'total_findings': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        # Secret type breakdown
        'secret_cloud_keys': 0,
        'secret_db_connections': 0,
        'secret_git_credentials': 0,
        'secret_passwords': 0,
        'secret_private_keys': 0,
        'secret_saas_api_keys': 0
    })

    for scan in parsed_scans:
        date = scan.get('date')
        if not date:
            continue

        daily_data[date]['date'] = date
        daily_data[date]['total_scans'] += 1

        verdict = scan.get('verdict', '')
        if verdict == 'PASSED_BY_POLICY':
            daily_data[date]['passed'] += 1
        elif verdict == 'FAILED_BY_POLICY':
            daily_data[date]['failed'] += 1
        elif verdict == 'WARN_BY_POLICY':
            daily_data[date]['warned'] += 1

        daily_data[date]['critical'] += scan.get('total_critical', 0)
        daily_data[date]['high'] += scan.get('total_high', 0)
        daily_data[date]['medium'] += scan.get('total_medium', 0)
        daily_data[date]['low'] += scan.get('total_low', 0)
        daily_data[date]['total_findings'] += (
            scan.get('total_critical', 0) +
            scan.get('total_high', 0) +
            scan.get('total_medium', 0) +
            scan.get('total_low', 0)
        )

        # Accumulate secret types
        daily_data[date]['secret_cloud_keys'] += scan.get('secret_cloud_keys', 0)
        daily_data[date]['secret_db_connections'] += scan.get('secret_db_connections', 0)
        daily_data[date]['secret_git_credentials'] += scan.get('secret_git_credentials', 0)
        daily_data[date]['secret_passwords'] += scan.get('secret_passwords', 0)
        daily_data[date]['secret_private_keys'] += scan.get('secret_private_keys', 0)
        daily_data[date]['secret_saas_api_keys'] += scan.get('secret_saas_api_keys', 0)

    # Convert to sorted list
    trend_list = sorted(daily_data.values(), key=lambda x: x['date'])

    return trend_list
