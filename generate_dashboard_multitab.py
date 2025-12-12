#!/usr/bin/env python3
"""
Generate multi-tab HTML dashboard from Wiz CI/CD scan data.

This script generates an interactive HTML dashboard with three tabs:
1. Executive Summary - High-level charts and statistics
2. Application View - Grouped by tag combinations (e.g., environment + team)
3. Resource View - Detailed list of all scanned resources

Usage:
    python generate_dashboard_multitab.py
"""

import json
import html
import os
import argparse
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict

from wiz_cicd import WizCICDReporter, create_time_filter_variables

# Load environment variables
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

CLIENT_ID = os.environ.get("WIZ_CLIENT_ID")
CLIENT_SECRET = os.environ.get("WIZ_CLIENT_SECRET")


def group_scans_by_tags(scans_with_tags, primary_tag='wiz:environment', secondary_tag='wiz:team'):
    """
    Group scans by tag combinations to create application-level view.

    Args:
        scans_with_tags: List of scans with their tags
        primary_tag: Primary grouping tag (can be tag name or scan field like 'resource_type')
        secondary_tag: Secondary grouping tag (can be tag name or scan field)

    Returns:
        Dictionary of grouped scan statistics
    """
    groups = defaultdict(lambda: {
        'scans': [],
        'total_scans': 0,
        'passed': 0,
        'failed': 0,
        'warned': 0,
        'total_critical': 0,
        'total_high': 0,
        'total_medium': 0,
        'total_low': 0,
        'tags': {}
    })

    for scan in scans_with_tags:
        # Build tags dictionary from scan tags
        tags_dict = {tag['key']: tag['value'] for tag in scan.get('tags', []) if isinstance(tag, dict)}

        # Get primary value - check tags first, then scan fields
        if primary_tag in tags_dict:
            primary_val = tags_dict[primary_tag]
        elif primary_tag in scan:
            primary_val = scan.get(primary_tag, 'untagged')
        else:
            primary_val = 'untagged'

        # Get secondary value - check tags first, then scan fields
        if secondary_tag in tags_dict:
            secondary_val = tags_dict[secondary_tag]
        elif secondary_tag in scan:
            secondary_val = scan.get(secondary_tag, 'untagged')
        else:
            secondary_val = 'untagged'

        # Create group key from tag combination
        group_key = f"{primary_val} / {secondary_val}"

        # Add scan to group
        groups[group_key]['scans'].append(scan)
        groups[group_key]['total_scans'] += 1
        groups[group_key]['tags'] = {primary_tag: primary_val, secondary_tag: secondary_val}

        # Update verdict counts
        verdict = scan.get('verdict', '')
        if verdict == 'PASSED_BY_POLICY':
            groups[group_key]['passed'] += 1
        elif verdict == 'FAILED_BY_POLICY':
            groups[group_key]['failed'] += 1
        elif verdict == 'WARN_BY_POLICY':
            groups[group_key]['warned'] += 1

        # Update finding counts
        groups[group_key]['total_critical'] += scan.get('total_critical', 0)
        groups[group_key]['total_high'] += scan.get('total_high', 0)
        groups[group_key]['total_medium'] += scan.get('total_medium', 0)
        groups[group_key]['total_low'] += scan.get('total_low', 0)

    return dict(groups)


def generate_html_dashboard(reporter: WizCICDReporter, output_dir="output", time_range_desc="Last 30 days"):
    """Generate multi-tab HTML dashboard."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"{output_dir}/dashboard_multitab_{timestamp}.html"

    # Store time range for PDF export
    global report_time_range
    report_time_range = time_range_desc

    # Get statistics
    verdict_stats = reporter.get_verdict_stats()
    finding_stats = reporter.get_finding_stats()
    daily_trends = reporter.get_daily_trends()

    # Get tag index for filtering
    tag_index = reporter.extract_tags()

    # Get raw scans with tags
    raw_scans = reporter._raw_scans
    parsed_scans = reporter.get_parsed_scans()

    # Create a mapping of scan_id to tags
    scan_tags = {}
    for scan in raw_scans:
        scan_id = scan.get('id')
        extra = scan.get('extraDetails') or {}
        tags = extra.get('tags') or []
        scan_tags[scan_id] = tags

    # Embed the parsed scans with tags
    scans_with_tags = []
    for scan in parsed_scans:
        scan_copy = scan.copy()
        scan_copy['tags'] = scan_tags.get(scan['scan_id'], [])
        scans_with_tags.append(scan_copy)

    # Create tag filters (key:value pairs) for the detailed reporting view
    # Build list of all unique tag key:value combinations
    tag_filters = set()
    has_untagged_scans = False

    for scan in scans_with_tags:
        scan_tags = scan.get('tags', [])
        if not scan_tags or scan_tags is None or len(scan_tags) == 0:
            has_untagged_scans = True
        else:
            for tag in scan_tags:
                if isinstance(tag, dict) and tag.get('key') and tag.get('value'):
                    tag_filters.add(f"{tag['key']}: {tag['value']}")

    # Sort tag filters alphabetically
    tag_filters = sorted(tag_filters)

    # Add "Untagged" option if there are scans without tags
    if has_untagged_scans:
        tag_filters.insert(0, 'Untagged')

    # Keep application_groups for backward compatibility but make it simple
    # Just create a group per tag filter
    application_groups = {}
    for tag_filter in tag_filters:
        application_groups[tag_filter] = {
            'scans': [],
            'total_scans': 0,
            'passed': 0,
            'failed': 0,
            'warned': 0,
            'total_critical': 0,
            'total_high': 0,
            'total_medium': 0,
            'total_low': 0,
            'tags': {}
        }

    # Helper function to add scan to a group
    def add_scan_to_group(group, scan):
        group['scans'].append(scan)
        group['total_scans'] += 1

        # Update verdicts
        if scan.get('verdict') == 'PASSED_BY_POLICY':
            group['passed'] += 1
        elif scan.get('verdict') == 'FAILED_BY_POLICY':
            group['failed'] += 1
        elif scan.get('verdict') == 'WARN_BY_POLICY':
            group['warned'] += 1

        # Update findings
        group['total_critical'] += scan.get('total_critical', 0)
        group['total_high'] += scan.get('total_high', 0)
        group['total_medium'] += scan.get('total_medium', 0)
        group['total_low'] += scan.get('total_low', 0)

    # Assign scans to their tag filter groups
    for scan in scans_with_tags:
        scan_tags = scan.get('tags', [])

        if not scan_tags or scan_tags is None or len(scan_tags) == 0:
            # Scan has no tags - add to "Untagged" group
            if 'Untagged' not in application_groups:
                application_groups['Untagged'] = {
                    'scans': [],
                    'total_scans': 0,
                    'passed': 0,
                    'failed': 0,
                    'warned': 0,
                    'total_critical': 0,
                    'total_high': 0,
                    'total_medium': 0,
                    'total_low': 0,
                    'tags': {}
                }
            add_scan_to_group(application_groups['Untagged'], scan)
        else:
            # Scan has tags - add to each applicable tag filter group
            for tag in scan_tags:
                if isinstance(tag, dict) and tag.get('key') and tag.get('value'):
                    tag_filter = f"{tag['key']}: {tag['value']}"
                    if tag_filter in application_groups:
                        add_scan_to_group(application_groups[tag_filter], scan)

    # Pre-compute JSON strings outside f-string for Python <3.12 compatibility
    # (backslashes not allowed in f-string expressions before 3.12)
    escape_script_close = '<\\/'
    all_scans_json = json.dumps(json.dumps(scans_with_tags).replace('</', escape_script_close))
    app_groups_json = json.dumps(json.dumps(application_groups).replace('</', escape_script_close))
    daily_trends_json = json.dumps(json.dumps(daily_trends).replace('</', escape_script_close))
    finding_stats_json = json.dumps(json.dumps(finding_stats).replace('</', escape_script_close))
    verdict_stats_json = json.dumps(json.dumps(verdict_stats).replace('</', escape_script_close))

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wiz CI/CD Multi-Tab Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
            integrity="sha384-e6nUZLBkQ86NJ6TVVKAeSaK8jWa3NhkYWZFomE39AvDbQWeie9PlQqM3pmYW5d1g"
            crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/jspdf@2.5.1/dist/jspdf.umd.min.js"
            integrity="sha384-JcnsjUPPylna1s1fvi1u12X5qjY5OL56iySh75FdtrwhO/SWXgMjoVqcKyIIWOLk"
            crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/jspdf-autotable@3.8.2/dist/jspdf.plugin.autotable.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f7fa;
            padding: 0;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1600px;
            margin: 0 auto;
        }}

        .header {{
            background: #00438F;
            padding: 24px 40px;
            margin-bottom: 0;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border-bottom: 3px solid #D8273F;
        }}

        .header h1 {{
            color: #ffffff;
            font-size: 28px;
            margin-bottom: 6px;
            font-weight: 600;
        }}

        .header .subtitle {{
            color: #cbd5e1;
            font-size: 13px;
        }}

        /* Tab Navigation */
        .tab-navigation {{
            background: white;
            border-bottom: 1px solid #e5e7eb;
            padding: 0 40px;
            margin-bottom: 0;
            display: flex;
            gap: 0;
            justify-content: space-between;
            align-items: center;
        }}

        .tab-buttons {{
            display: flex;
            gap: 0;
        }}

        .tab-export {{
            display: flex;
            gap: 10px;
            align-items: center;
        }}

        .tab-button {{
            padding: 16px 32px;
            background: transparent;
            border: none;
            border-bottom: 3px solid transparent;
            font-size: 14px;
            font-weight: 600;
            color: #64748b;
            cursor: pointer;
            transition: all 0.2s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .tab-button:hover {{
            color: #1e293b;
            background: #f8fafc;
        }}

        .tab-button.active {{
            color: #D8273F;
            background: white;
            border-bottom-color: #D8273F;
        }}

        .tab-content {{
            display: none;
        }}

        .tab-content.active {{
            display: block;
            padding: 30px 40px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}

        .stat-card {{
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 4px;
            padding: 20px;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
            transition: box-shadow 0.2s ease;
        }}

        .stat-card:hover {{
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }}

        .stat-card h3 {{
            color: #64748b;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 12px;
        }}

        .stat-card .value {{
            font-size: 32px;
            font-weight: 700;
            color: #1e293b;
            margin-bottom: 4px;
            line-height: 1;
        }}

        .stat-card .percentage {{
            font-size: 13px;
            color: #64748b;
        }}

        .stat-card.passed .value {{ color: #059669; }}
        .stat-card.failed .value {{ color: #dc2626; }}
        .stat-card.warned .value {{ color: #d97706; }}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }}

        .chart-card {{
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 4px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }}

        .chart-card h2 {{
            color: #1e293b;
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 2px solid #f1f5f9;
        }}

        .chart-container {{
            position: relative;
            height: 280px;
        }}

        .full-width {{
            grid-column: 1 / -1;
        }}

        .full-width .chart-container {{
            height: 320px;
        }}

        /* Application/Resource Table Styles */
        .table-card {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow-x: auto;
        }}

        .table-card h2 {{
            color: #1f2937;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
        }}

        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}

        .data-table th {{
            background: #f8fafc;
            color: #1e293b;
            font-weight: 700;
            text-align: left;
            padding: 10px 12px;
            border-bottom: 2px solid #e5e7eb;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .data-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #f1f5f9;
            color: #334155;
        }}

        .data-table tbody tr:hover {{
            background: #f8fafc;
        }}

        .data-table tbody tr:first-child {{
            background: #fef3c7;
        }}

        .data-table tbody tr:first-child:hover {{
            background: #fde68a;
        }}

        /* Matrix table specific styles */
        .matrix-table tbody tr {{
            background: white;
        }}

        .matrix-table tbody tr:hover {{
            background: #f8fafc;
        }}

        .matrix-table tbody tr:last-child {{
            background: #f1f5f9;
            border-top: 2px solid #cbd5e1;
        }}

        .matrix-table tbody tr:last-child:hover {{
            background: #e2e8f0;
        }}

        .matrix-table th {{
            background: #f8fafc;
        }}

        .matrix-table td:first-child {{
            font-weight: 600;
            color: #1e293b;
        }}

        .matrix-table td:last-child {{
            background: #f8fafc;
            border-left: 2px solid #e5e7eb;
        }}

        /* Expandable table styles */
        .expandable-table tbody tr.scan-row {{
            cursor: pointer;
            transition: background 0.2s ease;
        }}

        .expandable-table tbody tr.scan-row:hover {{
            background: #f8fafc;
        }}

        .expandable-table tbody tr.scan-row.expanded {{
            background: #fef3c7;
        }}

        .expandable-table tbody tr.detail-row {{
            display: none;
            background: #fffbeb;
        }}

        .expandable-table tbody tr.detail-row.show {{
            display: table-row;
        }}

        .expandable-table tbody tr.detail-row td {{
            padding: 0;
            border-bottom: 2px solid #e5e7eb;
        }}

        .expand-icon {{
            display: inline-block;
            transition: transform 0.2s ease;
            font-weight: bold;
            color: #64748b;
        }}

        .scan-row.expanded .expand-icon {{
            transform: rotate(90deg);
        }}

        .detail-content {{
            padding: 16px;
        }}

        .detail-matrix {{
            width: 100%;
            font-size: 12px;
        }}

        .detail-matrix th {{
            background: #f1f5f9;
            padding: 6px 8px;
            font-size: 10px;
            text-align: center;
        }}

        .detail-matrix td {{
            padding: 6px 8px;
            text-align: center;
            border: 1px solid #e5e7eb;
        }}

        .detail-matrix td:first-child {{
            text-align: left;
            font-weight: 600;
            background: #f8fafc;
        }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 2px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}

        .badge.passed {{
            background: #059669;
            color: white;
        }}

        .badge.failed {{
            background: #dc2626;
            color: white;
        }}

        .badge.warned {{
            background: #d97706;
            color: white;
        }}

        .badge.critical {{
            background: #dc2626;
            color: white;
        }}

        .badge.high {{
            background: #ea580c;
            color: white;
        }}

        .badge.medium {{
            background: #2563eb;
            color: white;
        }}

        .badge.low {{
            background: #059669;
            color: white;
        }}

        .footer {{
            background: #00438F;
            padding: 16px 40px;
            text-align: center;
            color: #cbd5e1;
            font-size: 11px;
            border-top: 1px solid #D8273F;
            margin-top: 0;
        }}

        .search-box {{
            margin-bottom: 15px;
        }}

        .search-box input {{
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #cbd5e1;
            border-radius: 4px;
            font-size: 13px;
        }}

        .search-box input:focus {{
            outline: none;
            border-color: #3b82f6;
        }}

        .severity-cell {{
            white-space: nowrap;
        }}

        .severity-count {{
            margin-right: 8px;
        }}

        /* Tab 4: Resource Drill-Down Styles */
        .drill-down-container {{
            display: flex;
            gap: 0;
            height: calc(100vh - 300px);
            min-height: 600px;
        }}

        .app-filter-bar {{
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 4px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }}

        .app-filter-bar h3 {{
            color: #1e293b;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }}

        .app-filter-controls {{
            display: flex;
            gap: 10px;
            align-items: flex-end;
        }}

        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .filter-group > label {{
            color: #1e293b;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .app-filter-bar input {{
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #cbd5e1;
            border-radius: 4px;
            font-size: 14px;
            background: white;
            transition: all 0.2s ease;
        }}

        /* Custom checkbox dropdown */
        .checkbox-dropdown {{
            position: relative;
            min-width: 35ch;
        }}

        .dropdown-button {{
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #cbd5e1;
            border-radius: 4px;
            font-size: 13px;
            background: white;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.2s ease;
        }}

        .dropdown-button:hover {{
            border-color: #94a3b8;
        }}

        .dropdown-button.open {{
            border-color: #00438F;
            box-shadow: 0 0 0 3px rgba(0, 67, 143, 0.1);
        }}

        .dropdown-arrow {{
            font-size: 10px;
            color: #64748b;
            transition: transform 0.2s ease;
        }}

        .dropdown-button.open .dropdown-arrow {{
            transform: rotate(180deg);
        }}

        .dropdown-panel {{
            display: none;
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            margin-top: 4px;
            background: white;
            border: 1px solid #cbd5e1;
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 1000;
            max-height: 300px;
            overflow-y: auto;
            overflow-x: hidden;
            width: 100%;
        }}

        .dropdown-panel.show {{
            display: block;
        }}

        .dropdown-item {{
            padding: 12px 14px;
            display: flex !important;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            transition: background 0.2s ease;
            background: white;
            user-select: none;
            color: #1e293b;
            font-size: 14px;
        }}

        .dropdown-item span {{
            display: inline-block !important;
            visibility: visible !important;
            opacity: 1 !important;
        }}

        .dropdown-item:hover {{
            background: #f8fafc !important;
        }}

        .dropdown-item input[type="checkbox"] {{
            width: 18px;
            height: 18px;
            cursor: pointer;
            flex-shrink: 0;
        }}

        .dropdown-item .scan-type-icon {{
            font-size: 18px !important;
            flex-shrink: 0;
            display: inline-block !important;
            visibility: visible !important;
            opacity: 1 !important;
            width: auto !important;
            height: auto !important;
        }}

        .dropdown-item .scan-type-text {{
            flex: 1;
            font-size: 14px !important;
            color: #1e293b !important;
            display: inline-block !important;
            visibility: visible !important;
            opacity: 1 !important;
            line-height: 1.5 !important;
            font-weight: 500 !important;
        }}

        .dropdown-item label {{
            flex: 1;
            cursor: pointer;
            font-size: 14px !important;
            color: #1e293b !important;
            margin: 0 !important;
            padding: 0 !important;
            text-transform: none !important;
            letter-spacing: 0 !important;
            font-weight: 500 !important;
            display: inline-block !important;
            background: transparent !important;
            border: none !important;
            visibility: visible !important;
            opacity: 1 !important;
            line-height: 1.5 !important;
            white-space: nowrap !important;
        }}

        .app-filter-bar input:focus {{
            outline: none;
            border-color: #00438F;
            box-shadow: 0 0 0 3px rgba(0, 67, 143, 0.1);
        }}

        .reset-button {{
            padding: 10px 20px;
            border: 1px solid #cbd5e1;
            border-radius: 4px;
            background: white;
            color: #64748b;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            white-space: nowrap;
        }}

        .reset-button:hover {{
            background: #f8fafc;
            border-color: #94a3b8;
            color: #1e293b;
        }}

        .resource-sidebar {{
            width: 280px;
            min-width: 280px;
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 4px;
            padding: 16px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            overflow-y: auto;
            transition: all 0.3s ease;
        }}

        .resource-sidebar.collapsed {{
            width: 48px;
            min-width: 48px;
            padding: 10px;
        }}

        .sidebar-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid #e5e7eb;
        }}

        .sidebar-header h3 {{
            color: #1e293b;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .sidebar-toggle {{
            background: #f8fafc;
            border: 1px solid #e5e7eb;
            border-radius: 3px;
            padding: 4px 8px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s ease;
            color: #64748b;
        }}

        .sidebar-toggle:hover {{
            background: #e5e7eb;
            color: #1e293b;
        }}

        .resource-sidebar.collapsed .sidebar-header h3,
        .resource-sidebar.collapsed .resource-search {{
            display: none;
        }}

        .resource-search {{
            margin-bottom: 15px;
        }}

        .resource-search input {{
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #cbd5e1;
            border-radius: 4px;
            font-size: 13px;
        }}

        .resource-search input:focus {{
            outline: none;
            border-color: #00438F;
        }}

        .resource-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}

        .resource-item {{
            padding: 10px 12px;
            margin-bottom: 6px;
            border-radius: 3px;
            cursor: pointer;
            transition: all 0.2s ease;
            border: 1px solid #e5e7eb;
            background: white;
        }}

        .resource-item:hover {{
            background: #f8fafc;
            border-color: #cbd5e1;
        }}

        .resource-item.active {{
            background: #00438F;
            color: white;
            border-color: #00438F;
        }}

        .resource-item {{
            display: flex;
            align-items: flex-start;
            gap: 8px;
        }}

        .resource-icon {{
            font-size: 18px;
            flex-shrink: 0;
            margin-top: 2px;
        }}

        .resource-info {{
            flex: 1;
            min-width: 0;
        }}

        .resource-item .resource-name {{
            font-weight: 600;
            font-size: 13px;
            display: block;
            margin-bottom: 4px;
            word-wrap: break-word;
            word-break: break-all;
            overflow-wrap: break-word;
            hyphens: auto;
            line-height: 1.3;
        }}

        .resource-item .resource-meta {{
            font-size: 12px;
            opacity: 0.8;
        }}

        .resource-sidebar.collapsed .resource-item {{
            padding: 12px 8px;
            justify-content: center;
            position: relative;
        }}

        .resource-sidebar.collapsed .resource-info {{
            display: none;
        }}

        .resource-sidebar.collapsed .resource-icon {{
            font-size: 20px;
        }}

        .resource-detail-pane {{
            flex: 1;
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 4px;
            padding: 24px;
            margin-left: 16px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            overflow-y: auto;
        }}

        .detail-header {{
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}

        .detail-header h2 {{
            color: #1e293b;
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 8px;
        }}

        .detail-header .meta {{
            color: #64748b;
            font-size: 13px;
        }}

        .detail-section {{
            margin-bottom: 30px;
        }}

        .detail-section h3 {{
            color: #1e293b;
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid #f1f5f9;
        }}

        .scan-summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }}

        .summary-item {{
            background: #f8fafc;
            padding: 16px;
            border-radius: 3px;
            border: 1px solid #e5e7eb;
        }}

        .summary-item .label {{
            color: #64748b;
            font-size: 10px;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }}

        .summary-item .value {{
            color: #1e293b;
            font-size: 22px;
            font-weight: 700;
            line-height: 1;
        }}

        .empty-state {{
            text-align: center;
            padding: 60px 20px;
            color: #6b7280;
        }}

        .empty-state h3 {{
            font-size: 18px;
            margin-bottom: 10px;
        }}

        .historical-chart {{
            background: #f9fafb;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
            margin-top: 20px;
        }}

        .historical-chart .chart-container {{
            height: 250px;
        }}

        /* Export buttons */
        .export-controls {{
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            justify-content: flex-end;
        }}

        .export-button {{
            padding: 8px 18px;
            border: 1px solid #e5e7eb;
            border-radius: 3px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}

        .export-button.csv {{
            background: white;
            color: #059669;
            border-color: #059669;
        }}

        .export-button.csv:hover {{
            background: #059669;
            color: white;
        }}

        .export-button.pdf {{
            background: #D8273F;
            color: white;
            border-color: #D8273F;
        }}

        .export-button.pdf:hover {{
            background: #b91c30;
            border-color: #b91c30;
        }}

        .export-button:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}

        /* Top 10 Riskiest Section */
        .top-risky-section {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        .top-risky-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 15px;
        }}

        .top-risky-header h2 {{
            color: #1f2937;
            font-size: 20px;
            font-weight: 600;
            margin: 0;
        }}

        .risk-legend {{
            font-size: 12px;
            color: #64748b;
        }}

        .top-risky-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}

        .top-risky-table thead th {{
            background: #f8fafc;
            color: #475569;
            font-weight: 700;
            padding: 12px 16px;
            text-align: left;
            border-bottom: 2px solid #e2e8f0;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .top-risky-table tbody tr {{
            border-bottom: 1px solid #f1f5f9;
            transition: all 0.2s ease;
            cursor: pointer;
        }}

        .top-risky-table tbody tr:hover {{
            background: #f8fafc;
            transform: scale(1.01);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }}

        .top-risky-table tbody tr.rank-1 {{
            background: #fef2f2;
            border-left: 4px solid #dc2626;
        }}

        .top-risky-table tbody tr.rank-2 {{
            background: #fff7ed;
            border-left: 4px solid #ea580c;
        }}

        .top-risky-table tbody tr.rank-3 {{
            background: #fffbeb;
            border-left: 4px solid #f59e0b;
        }}

        .top-risky-table tbody td {{
            padding: 14px 16px;
            color: #1e293b;
        }}

        .top-risky-table .rank-cell {{
            font-size: 18px;
            font-weight: 700;
            color: #94a3b8;
            text-align: center;
        }}

        .top-risky-table tr.rank-1 .rank-cell {{ color: #dc2626; }}
        .top-risky-table tr.rank-2 .rank-cell {{ color: #ea580c; }}
        .top-risky-table tr.rank-3 .rank-cell {{ color: #f59e0b; }}

        .top-risky-table .name-cell {{
            font-weight: 600;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .top-risky-table .score-cell {{
            font-size: 20px;
            font-weight: 700;
            color: #1e293b;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Wiz CI/CD Pipeline Security Dashboard</h1>
            <p class="subtitle">Multi-Tab Report - {time_range_desc} - Generated on {report_date}</p>
        </div>

        <!-- Tab Navigation -->
        <div class="tab-navigation">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="switchTab('executive')">
                    Executive Summary
                </button>
                <button class="tab-button" onclick="switchTab('detailed')">
                    Detailed Reporting
                </button>
            </div>
            <div class="tab-export">
                <button class="export-button pdf" id="tabExportBtn" onclick="exportCurrentTab()">
                    Export as PDF
                </button>
            </div>
        </div>

        <!-- Tab 1: Executive Summary -->
        <div id="executive-tab" class="tab-content active">
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Scans</h3>
                    <div class="value">{verdict_stats['total_scans']}</div>
                    <div class="percentage">{time_range_desc}</div>
                </div>

                <div class="stat-card passed">
                    <h3>Passed</h3>
                    <div class="value">{verdict_stats['passed']}</div>
                    <div class="percentage">{verdict_stats['pass_rate']:.1f}% of total</div>
                </div>

                <div class="stat-card failed">
                    <h3>Failed</h3>
                    <div class="value">{verdict_stats['failed']}</div>
                    <div class="percentage">{verdict_stats['fail_rate']:.1f}% of total</div>
                </div>

                <div class="stat-card warned">
                    <h3>Warned</h3>
                    <div class="value">{verdict_stats['warned']}</div>
                    <div class="percentage">{verdict_stats['warn_rate']:.1f}% of total</div>
                </div>
            </div>

            <!-- Top 10 Riskiest -->
            <div class="top-risky-section">
                <div class="top-risky-header">
                    <h2 id="topRiskyTitle">Top 10 Riskiest Applications</h2>
                    <div class="risk-legend">
                        <span style="font-size: 12px; color: #64748b;">Risk Score: Critical*5 + High*3.5 + Medium*2 + Low*1</span>
                    </div>
                </div>
                <div class="table-container">
                    <table class="top-risky-table">
                        <thead>
                            <tr>
                                <th style="width: 60px; text-align: center;">Rank</th>
                                <th>Application / Resource</th>
                                <th style="width: 90px; text-align: center;">Critical</th>
                                <th style="width: 90px; text-align: center;">High</th>
                                <th style="width: 90px; text-align: center;">Medium</th>
                                <th style="width: 90px; text-align: center;">Low</th>
                                <th style="width: 130px; text-align: center;">Last Scanned</th>
                                <th style="width: 110px; text-align: center;">Verdict</th>
                                <th style="width: 110px; text-align: center;">Risk Score</th>
                            </tr>
                        </thead>
                        <tbody id="topRiskyTableBody">
                            <!-- Will be populated by JavaScript -->
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="charts-grid">
                <div class="chart-card">
                    <h2>Scan Verdicts Distribution</h2>
                    <div class="chart-container">
                        <canvas id="verdictChart"></canvas>
                    </div>
                </div>

                <div class="chart-card">
                    <h2>Findings by Type</h2>
                    <div class="chart-container">
                        <canvas id="findingTypeChart"></canvas>
                    </div>
                </div>

                <div class="chart-card">
                    <h2>Findings by Severity</h2>
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>

                <div class="chart-card">
                    <h2>Finding Type Breakdown</h2>
                    <div class="chart-container">
                        <canvas id="findingBreakdownChart"></canvas>
                    </div>
                </div>

                <div class="chart-card full-width">
                    <h2>Daily Scan Verdicts Trend</h2>
                    <div class="chart-container">
                        <canvas id="verdictTrendChart"></canvas>
                    </div>
                </div>

                <div class="chart-card full-width">
                    <h2>Secret Types Detected Over Time</h2>
                    <div class="chart-container">
                        <canvas id="secretTypesTrendChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab 2: Detailed Reporting -->
        <div id="detailed-tab" class="tab-content">
            <!-- App/Tag Filter Bar -->
            <div class="app-filter-bar">
                <h3>Filters</h3>
                <div class="app-filter-controls">
                    <div class="filter-group" style="flex: 1;">
                        <label>Filter by Tag</label>
                        <input type="text"
                               id="appFilterSearch"
                               placeholder="Search tags..."
                               list="appList"
                               onchange="handleAppSelection()"
                               oninput="handleAppInput()">
                        <datalist id="appList">
                            <option value="">All Applications</option>
                        </datalist>
                    </div>
                    <div class="filter-group">
                        <label>Scan Type</label>
                        <div class="checkbox-dropdown">
                            <div class="dropdown-button" onclick="toggleScanTypeDropdown()">
                                <span id="scanTypeLabel">All Types (5)</span>
                                <span class="dropdown-arrow">v</span>
                            </div>
                            <div class="dropdown-panel" id="scanTypePanel">
                                <div class="dropdown-item" onclick="document.getElementById('type_CONTAINER_IMAGE').click();" style="cursor: pointer; display: block !important; padding: 12px 14px; background: white;">
                                    <input type="checkbox" id="type_CONTAINER_IMAGE" value="CONTAINER_IMAGE" checked onchange="updateScanTypeFilter()" onclick="event.stopPropagation();" style="width: 18px; height: 18px; margin-right: 10px; vertical-align: middle;">
                                    <span style="font-size: 14px; color: #1e293b; font-weight: 500; vertical-align: middle;">Container Image</span>
                                </div>
                                <div class="dropdown-item" onclick="document.getElementById('type_DIRECTORY').click();" style="cursor: pointer; display: block !important; padding: 12px 14px; background: white;">
                                    <input type="checkbox" id="type_DIRECTORY" value="DIRECTORY" checked onchange="updateScanTypeFilter()" onclick="event.stopPropagation();" style="width: 18px; height: 18px; margin-right: 10px; vertical-align: middle;">
                                    <span style="font-size: 14px; color: #1e293b; font-weight: 500; vertical-align: middle;">Directory</span>
                                </div>
                                <div class="dropdown-item" onclick="document.getElementById('type_IAC').click();" style="cursor: pointer; display: block !important; padding: 12px 14px; background: white;">
                                    <input type="checkbox" id="type_IAC" value="IAC" checked onchange="updateScanTypeFilter()" onclick="event.stopPropagation();" style="width: 18px; height: 18px; margin-right: 10px; vertical-align: middle;">
                                    <span style="font-size: 14px; color: #1e293b; font-weight: 500; vertical-align: middle;">IaC</span>
                                </div>
                                <div class="dropdown-item" onclick="document.getElementById('type_VIRTUAL_MACHINE_IMAGE').click();" style="cursor: pointer; display: block !important; padding: 12px 14px; background: white;">
                                    <input type="checkbox" id="type_VIRTUAL_MACHINE_IMAGE" value="VIRTUAL_MACHINE_IMAGE" checked onchange="updateScanTypeFilter()" onclick="event.stopPropagation();" style="width: 18px; height: 18px; margin-right: 10px; vertical-align: middle;">
                                    <span style="font-size: 14px; color: #1e293b; font-weight: 500; vertical-align: middle;">VM Image</span>
                                </div>
                                <div class="dropdown-item" onclick="document.getElementById('type_VIRTUAL_MACHINE').click();" style="cursor: pointer; display: block !important; padding: 12px 14px; background: white;">
                                    <input type="checkbox" id="type_VIRTUAL_MACHINE" value="VIRTUAL_MACHINE" checked onchange="updateScanTypeFilter()" onclick="event.stopPropagation();" style="width: 18px; height: 18px; margin-right: 10px; vertical-align: middle;">
                                    <span style="font-size: 14px; color: #1e293b; font-weight: 500; vertical-align: middle;">Virtual Machine</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="filter-group">
                        <label>&nbsp;</label>
                        <button class="reset-button" onclick="resetAllFilters()">
                            Reset All
                        </button>
                    </div>
                </div>
            </div>

            <!-- Main Drill-Down Container -->
            <div class="drill-down-container">
                <!-- Left Sidebar: Resource List -->
                <div class="resource-sidebar" id="resourceSidebar">
                    <div class="sidebar-header">
                        <h3>Resources</h3>
                        <button class="sidebar-toggle" onclick="toggleSidebar()">&lt;</button>
                    </div>

                    <div class="resource-search">
                        <input type="text" id="resourceSidebarSearch"
                               placeholder="Search resources..."
                               onkeyup="searchSidebarResources()">
                    </div>

                    <ul class="resource-list" id="resourceSidebarList">
                        <!-- Populated dynamically -->
                    </ul>
                </div>

                <!-- Right Pane: Resource Details -->
                <div class="resource-detail-pane" id="resourceDetailPane">
                    <div class="empty-state">
                        <h3>Select a Resource</h3>
                        <p>Choose a resource from the list to view scan details and historical trends</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="footer">
            Generated by Wiz CI/CD Report Generator | Data sourced from Wiz API
        </div>
    </div>

    <script>
        // Embedded scan data (properly escaped to prevent XSS)
        const allScans = JSON.parse({all_scans_json});
        const applicationGroups = JSON.parse({app_groups_json});
        const dailyTrends = JSON.parse({daily_trends_json});
        const findingStats = JSON.parse({finding_stats_json});
        const verdictStats = JSON.parse({verdict_stats_json});
        const reportTimeRange = {json.dumps(time_range_desc)};

        let charts = {{}};

        // Tab switching
        function switchTab(tabName) {{
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {{
                tab.classList.remove('active');
            }});
            document.querySelectorAll('.tab-button').forEach(btn => {{
                btn.classList.remove('active');
            }});

            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');

            // Update export button based on active tab
            updateExportButton(tabName);

            // Initialize charts/tables if needed
            if (tabName === 'executive' && Object.keys(charts).length === 0) {{
                initializeExecutiveCharts();
            }} else if (tabName === 'detailed') {{
                initializeDetailedReporting();
            }}
        }}

        // Update export button text based on active tab
        function updateExportButton(tabName) {{
            const btn = document.getElementById('tabExportBtn');
            if (!btn) return;

            if (tabName === 'detailed' && !selectedResourceId) {{
                btn.disabled = true;
                btn.title = 'Select a resource to export';
            }} else {{
                btn.disabled = false;
                btn.title = '';
            }}
        }}

        // Export current tab
        function exportCurrentTab() {{
            const activeTab = document.querySelector('.tab-content.active');
            if (!activeTab) return;

            if (activeTab.id === 'executive-tab') {{
                exportExecutivePDF();
            }} else if (activeTab.id === 'detailed-tab') {{
                exportDetailedPDF();
            }}
        }}

        // Risk Scoring Functions
        function calculateRiskScore(scan) {{
            const critical = scan.total_critical || 0;
            const high = scan.total_high || 0;
            const medium = scan.total_medium || 0;
            const low = scan.total_low || 0;

            return (critical * 5) + (high * 3.5) + (medium * 2) + (low * 1);
        }}

        function getLatestScanPerApp(scans) {{
            // Group scans by tag combinations (app identifier)
            const appMap = new Map();

            scans.forEach(scan => {{
                const tags = scan.tags || [];
                if (tags.length === 0) {{
                    // Use resource name if no tags
                    const appKey = `Untagged: ${{scan.resource_name || 'Unknown'}}`;
                    if (!appMap.has(appKey) || scan.timestamp > appMap.get(appKey).timestamp) {{
                        appMap.set(appKey, {{ ...scan, appName: appKey }});
                    }}
                }} else {{
                    // Create app name from all tags
                    const tagStr = tags.map(t => `${{t.key}}: ${{t.value}}`).sort().join(' | ');
                    if (!appMap.has(tagStr) || scan.timestamp > appMap.get(tagStr).timestamp) {{
                        appMap.set(tagStr, {{ ...scan, appName: tagStr }});
                    }}
                }}
            }});

            return Array.from(appMap.values());
        }}

        function getLatestScanPerResource(scans) {{
            // Group scans by resource name
            const resourceMap = new Map();

            scans.forEach(scan => {{
                const resourceKey = scan.resource_name || scan.resource_id || 'Unknown';
                if (!resourceMap.has(resourceKey) || scan.timestamp > resourceMap.get(resourceKey).timestamp) {{
                    resourceMap.set(resourceKey, {{ ...scan, resourceKey }});
                }}
            }});

            return Array.from(resourceMap.values());
        }}

        function drillDownToApp(appName) {{
            // Switch to detailed tab
            switchTab('detailed');

            // Set the filter to this app
            const input = document.getElementById('appFilterSearch');
            input.value = appName;
            currentAppFilter = appName;

            // Apply filters
            applyFilters();

            // Scroll to top
            window.scrollTo({{ top: 0, behavior: 'smooth' }});
        }}

        function updateTopRisky() {{
            const tbody = document.getElementById('topRiskyTableBody');

            // Always show top 10 apps on Executive tab
            const items = getLatestScanPerApp(allScans);
            const nameField = 'appName';

            // Calculate risk scores and sort
            items.forEach(item => {{
                item.riskScore = calculateRiskScore(item);
            }});

            items.sort((a, b) => b.riskScore - a.riskScore);
            const top10 = items.slice(0, 10);

            // Render table
            tbody.innerHTML = '';

            if (top10.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: #94a3b8; padding: 20px;">No data available</td></tr>';
                return;
            }}

            top10.forEach((item, index) => {{
                const rank = index + 1;
                const rankClass = rank <= 3 ? `rank-${{rank}}` : '';
                const name = item[nameField] || item.resource_name || 'Unknown';
                const score = item.riskScore;

                const critical = item.total_critical || 0;
                const high = item.total_high || 0;
                const medium = item.total_medium || 0;
                const low = item.total_low || 0;

                const verdictClass = item.verdict === 'PASSED_BY_POLICY' ? 'passed' :
                                    item.verdict === 'FAILED_BY_POLICY' ? 'failed' : 'warned';
                const verdictText = item.verdict ? item.verdict.replace('_BY_POLICY', '') : 'N/A';

                // Format last scanned timestamp
                const lastScanned = item.timestamp ? new Date(item.timestamp).toLocaleString('en-US', {{
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                }}) : 'N/A';

                // Escape name for JavaScript string
                const escapedName = name.replace(/'/g, "\\'").replace(/"/g, '&quot;');

                const row = `
                    <tr class="${{rankClass}}" onclick="drillDownToApp('${{escapedName}}')" title="Click to view details in Detailed tab">
                        <td class="rank-cell">#${{rank}}</td>
                        <td class="name-cell">${{name}} <span style="color: #94a3b8; font-size: 12px; margin-left: 8px;">&gt;</span></td>
                        <td style="text-align: center;"><span class="badge critical">${{critical}}</span></td>
                        <td style="text-align: center;"><span class="badge high">${{high}}</span></td>
                        <td style="text-align: center;"><span class="badge medium">${{medium}}</span></td>
                        <td style="text-align: center;"><span class="badge low">${{low}}</span></td>
                        <td style="text-align: center; font-size: 12px; color: #64748b;">${{lastScanned}}</td>
                        <td style="text-align: center;"><span class="badge ${{verdictClass}}">${{verdictText}}</span></td>
                        <td class="score-cell">${{score}}</td>
                    </tr>
                `;

                tbody.innerHTML += row;
            }});
        }}

        // Initialize executive charts
        function initializeExecutiveCharts() {{
            // Verdict Chart
            const verdictCtx = document.getElementById('verdictChart').getContext('2d');
            charts.verdict = new Chart(verdictCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Passed', 'Failed', 'Warned'],
                    datasets: [{{
                        data: [verdictStats.passed, verdictStats.failed, verdictStats.warned],
                        backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ position: 'bottom' }} }}
                }}
            }});

            // Finding Type Chart
            const findingLabels = [];
            const findingTotals = [];
            Object.entries(findingStats).forEach(([type, data]) => {{
                if (data.total > 0) {{
                    findingLabels.push(type.charAt(0).toUpperCase() + type.slice(1));
                    findingTotals.push(data.total);
                }}
            }});

            const findingTypeCtx = document.getElementById('findingTypeChart').getContext('2d');
            charts.findingType = new Chart(findingTypeCtx, {{
                type: 'bar',
                data: {{
                    labels: findingLabels,
                    datasets: [{{
                        label: 'Total Findings',
                        data: findingTotals,
                        backgroundColor: '#3b82f6',
                        borderRadius: 6
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ display: false }} }},
                    scales: {{ y: {{ beginAtZero: true }} }}
                }}
            }});

            // Severity Chart
            const totalCritical = Object.values(findingStats).reduce((sum, f) => sum + f.critical, 0);
            const totalHigh = Object.values(findingStats).reduce((sum, f) => sum + f.high, 0);
            const totalMedium = Object.values(findingStats).reduce((sum, f) => sum + f.medium, 0);
            const totalLow = Object.values(findingStats).reduce((sum, f) => sum + f.low, 0);

            const severityCtx = document.getElementById('severityChart').getContext('2d');
            charts.severity = new Chart(severityCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        data: [totalCritical, totalHigh, totalMedium, totalLow],
                        backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ position: 'bottom' }} }}
                }}
            }});

            // Finding Breakdown Chart
            const breakdownCtx = document.getElementById('findingBreakdownChart').getContext('2d');
            charts.breakdown = new Chart(breakdownCtx, {{
                type: 'bar',
                data: {{
                    labels: findingLabels,
                    datasets: [
                        {{
                            label: 'Critical',
                            data: findingLabels.map(label => {{
                                const key = label.toLowerCase();
                                return findingStats[key]?.critical || 0;
                            }}),
                            backgroundColor: '#ef4444'
                        }},
                        {{
                            label: 'High',
                            data: findingLabels.map(label => {{
                                const key = label.toLowerCase();
                                return findingStats[key]?.high || 0;
                            }}),
                            backgroundColor: '#f59e0b'
                        }},
                        {{
                            label: 'Medium',
                            data: findingLabels.map(label => {{
                                const key = label.toLowerCase();
                                return findingStats[key]?.medium || 0;
                            }}),
                            backgroundColor: '#3b82f6'
                        }},
                        {{
                            label: 'Low',
                            data: findingLabels.map(label => {{
                                const key = label.toLowerCase();
                                return findingStats[key]?.low || 0;
                            }}),
                            backgroundColor: '#10b981'
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ position: 'bottom' }} }},
                    scales: {{
                        x: {{ stacked: true }},
                        y: {{ stacked: true, beginAtZero: true }}
                    }}
                }}
            }});

            // Daily Verdict Trend
            const dates = dailyTrends.map(d => d.date);
            const verdictTrendCtx = document.getElementById('verdictTrendChart').getContext('2d');
            charts.verdictTrend = new Chart(verdictTrendCtx, {{
                type: 'line',
                data: {{
                    labels: dates,
                    datasets: [
                        {{
                            label: 'Passed',
                            data: dailyTrends.map(d => d.passed),
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'Failed',
                            data: dailyTrends.map(d => d.failed),
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'Warned',
                            data: dailyTrends.map(d => d.warned),
                            borderColor: '#f59e0b',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            tension: 0.4,
                            fill: true
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ position: 'bottom' }} }},
                    scales: {{ y: {{ beginAtZero: true }} }}
                }}
            }});

            // Secret Types Trend Chart
            const secretTypesTrendCtx = document.getElementById('secretTypesTrendChart').getContext('2d');
            charts.secretTypesTrend = new Chart(secretTypesTrendCtx, {{
                type: 'line',
                data: {{
                    labels: dates,
                    datasets: [
                        {{
                            label: 'Cloud Keys',
                            data: dailyTrends.map(d => d.secret_cloud_keys || 0),
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'DB Connections',
                            data: dailyTrends.map(d => d.secret_db_connections || 0),
                            borderColor: '#f59e0b',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'Git Credentials',
                            data: dailyTrends.map(d => d.secret_git_credentials || 0),
                            borderColor: '#8b5cf6',
                            backgroundColor: 'rgba(139, 92, 246, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'Passwords',
                            data: dailyTrends.map(d => d.secret_passwords || 0),
                            borderColor: '#ec4899',
                            backgroundColor: 'rgba(236, 72, 153, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'Private Keys',
                            data: dailyTrends.map(d => d.secret_private_keys || 0),
                            borderColor: '#06b6d4',
                            backgroundColor: 'rgba(6, 182, 212, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'SaaS API Keys',
                            data: dailyTrends.map(d => d.secret_saas_api_keys || 0),
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            tension: 0.4,
                            fill: true
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ position: 'bottom' }},
                        tooltip: {{
                            mode: 'index',
                            intersect: false
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            stacked: false,
                            title: {{
                                display: true,
                                text: 'Number of Secrets Detected'
                            }}
                        }},
                        x: {{
                            title: {{
                                display: true,
                                text: 'Date'
                            }}
                        }}
                    }},
                    interaction: {{
                        mode: 'nearest',
                        axis: 'x',
                        intersect: false
                    }}
                }}
            }});

            // Initialize Top 10 Riskiest
            updateTopRisky();
        }}

        // Executive Summary PDF Export
        function exportExecutivePDF() {{
            if (!window.jspdf) {{
                alert('PDF library not loaded. Please refresh the page and try again.');
                return;
            }}

            try {{
                const {{ jsPDF }} = window.jspdf;
                const doc = new jsPDF();
                let pageNum = 1;

                // Page 1: Title & Statistics
                doc.setFontSize(20);
                doc.setFont(undefined, 'bold');
                doc.text('Wiz CI/CD Pipeline Security Dashboard', 14, 20);

                doc.setFontSize(13);
                doc.text('Executive Summary Report', 14, 30);

                doc.setFontSize(10);
                doc.setFont(undefined, 'normal');
                doc.text(`Generated: ${{new Date().toLocaleString()}}`, 14, 38);
                doc.setFont(undefined, 'bold');
                doc.text(`Report Period: ${{reportTimeRange}}`, 14, 45);
                doc.setFont(undefined, 'normal');

                // Scan Summary
                doc.setFontSize(13);
                doc.setFont(undefined, 'bold');
                doc.text('Scan Summary', 14, 58);

                const stats = [
                    ['Total Scans', verdictStats.total_scans],
                    ['Passed', `${{verdictStats.passed}} (${{verdictStats.pass_rate.toFixed(1)}}%)`],
                    ['Failed', `${{verdictStats.failed}} (${{verdictStats.fail_rate.toFixed(1)}}%)`],
                    ['Warned', `${{verdictStats.warned}} (${{verdictStats.warn_rate.toFixed(1)}}%)`]
                ];

                doc.autoTable({{
                    body: stats,
                    startY: 64,
                    theme: 'grid',
                    styles: {{ fontSize: 10 }},
                    headStyles: {{ fillColor: [0, 67, 143] }},
                    columnStyles: {{
                        0: {{ fontStyle: 'bold', cellWidth: 60 }},
                        1: {{ cellWidth: 60 }}
                    }}
                }});

                // Findings by Type
                let currentY = doc.lastAutoTable.finalY + 12;
                doc.setFontSize(13);
                doc.setFont(undefined, 'bold');
                doc.text('Findings by Type', 14, currentY);

                const findingData = Object.entries(findingStats).map(([type, data]) => [
                    type.charAt(0).toUpperCase() + type.slice(1),
                    data.total,
                    data.critical,
                    data.high,
                    data.medium,
                    data.low
                ]);

                doc.autoTable({{
                    head: [['Type', 'Total', 'Critical', 'High', 'Medium', 'Low']],
                    body: findingData,
                    startY: currentY + 8,
                    theme: 'striped',
                    styles: {{ fontSize: 9 }},
                    headStyles: {{ fillColor: [0, 67, 143] }}
                }});

                // Top 10 Riskiest Applications
                currentY = doc.lastAutoTable.finalY + 12;
                doc.setFontSize(13);
                doc.setFont(undefined, 'bold');
                doc.text('Top 10 Riskiest Applications', 14, currentY);
                doc.setFontSize(8);
                doc.setFont(undefined, 'normal');
                doc.text('Risk Score: Critical*5 + High*3.5 + Medium*2 + Low*1', 14, currentY + 6);

                // Get top 10 data
                const top10Items = getLatestScanPerApp(allScans);
                top10Items.forEach(item => {{
                    item.riskScore = calculateRiskScore(item);
                }});
                top10Items.sort((a, b) => b.riskScore - a.riskScore);
                const top10 = top10Items.slice(0, 10);

                const top10Data = top10.map((item, index) => {{
                    const name = item.appName || item.resource_name || 'Unknown';
                    const lastScanned = item.timestamp ? new Date(item.timestamp).toLocaleDateString('en-US', {{
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                    }}) : 'N/A';
                    const verdict = item.verdict ? item.verdict.replace('_BY_POLICY', '') : 'N/A';

                    return [
                        `#${{index + 1}}`,
                        name.substring(0, 45) + (name.length > 45 ? '...' : ''),
                        item.total_critical || 0,
                        item.total_high || 0,
                        item.total_medium || 0,
                        item.total_low || 0,
                        lastScanned,
                        verdict,
                        item.riskScore.toFixed(1)
                    ];
                }});

                doc.autoTable({{
                    head: [['Rank', 'Application', 'C', 'H', 'M', 'L', 'Last Scanned', 'Verdict', 'Risk']],
                    body: top10Data,
                    startY: currentY + 12,
                    theme: 'striped',
                    styles: {{ fontSize: 8, cellPadding: 3, overflow: 'linebreak' }},
                    headStyles: {{ fillColor: [0, 67, 143], fontSize: 8, halign: 'center' }},
                    columnStyles: {{
                        0: {{ cellWidth: 15, halign: 'center' }},
                        1: {{ cellWidth: 'auto' }},
                        2: {{ cellWidth: 15, halign: 'center', fillColor: [254, 242, 242] }},
                        3: {{ cellWidth: 15, halign: 'center', fillColor: [255, 247, 237] }},
                        4: {{ cellWidth: 15, halign: 'center', fillColor: [239, 246, 255] }},
                        5: {{ cellWidth: 15, halign: 'center', fillColor: [240, 253, 244] }},
                        6: {{ cellWidth: 30, halign: 'center', fontSize: 7 }},
                        7: {{ cellWidth: 20, halign: 'center' }},
                        8: {{ cellWidth: 18, halign: 'center', fontStyle: 'bold' }}
                    }},
                    tableWidth: 'auto',
                    margin: {{ left: 14, right: 14 }},
                    didParseCell: function(data) {{
                        // Highlight top 3 ranks
                        if (data.section === 'body' && data.column.index === 0) {{
                            const rank = parseInt(data.cell.raw.replace('#', ''));
                            if (rank === 1) data.cell.styles.textColor = [220, 38, 38];
                            if (rank === 2) data.cell.styles.textColor = [234, 88, 12];
                            if (rank === 3) data.cell.styles.textColor = [245, 158, 11];
                        }}
                        // Prevent wrapping in number columns
                        if (data.section === 'body' && [2, 3, 4, 5, 8].includes(data.column.index)) {{
                            data.cell.styles.overflow = 'visible';
                            data.cell.styles.cellPadding = {{ left: 2, right: 2, top: 3, bottom: 3 }};
                        }}
                    }}
                }});

                // Helper function to get compressed chart image with white background
                function getChartImage(canvasId) {{
                    const canvas = document.getElementById(canvasId);
                    if (!canvas) return null;

                    // Create a new canvas with white background
                    const tempCanvas = document.createElement('canvas');
                    tempCanvas.width = canvas.width;
                    tempCanvas.height = canvas.height;
                    const ctx = tempCanvas.getContext('2d');

                    // Fill with white background
                    ctx.fillStyle = '#ffffff';
                    ctx.fillRect(0, 0, tempCanvas.width, tempCanvas.height);

                    // Draw the original chart on top
                    ctx.drawImage(canvas, 0, 0);

                    // Export as JPEG with compression
                    return tempCanvas.toDataURL('image/jpeg', 0.85);
                }}

                // Page 2: Charts
                doc.addPage();

                // Row 1 - Two charts side by side (reduced height to prevent squish)
                doc.setFontSize(11);
                doc.setFont(undefined, 'bold');
                doc.text('Scan Verdicts Distribution', 14, 12);

                const verdictImg = getChartImage('verdictChart');
                if (verdictImg) {{
                    doc.addImage(verdictImg, 'JPEG', 14, 17, 90, 40);
                }}

                doc.text('Findings by Type', 110, 12);

                const findingTypeImg = getChartImage('findingTypeChart');
                if (findingTypeImg) {{
                    doc.addImage(findingTypeImg, 'JPEG', 110, 17, 90, 40);
                }}

                // Row 2 - Two more charts side by side
                doc.text('Findings by Severity', 14, 65);

                const severityImg = getChartImage('severityChart');
                if (severityImg) {{
                    doc.addImage(severityImg, 'JPEG', 14, 70, 90, 40);
                }}

                doc.text('Finding Type Breakdown', 110, 65);

                const breakdownImg = getChartImage('findingBreakdownChart');
                if (breakdownImg) {{
                    doc.addImage(breakdownImg, 'JPEG', 110, 70, 90, 40);
                }}

                // Row 3 - Daily Scan Verdicts (full width)
                doc.text('Daily Scan Verdicts Trend', 14, 118);

                const verdictTrendImg = getChartImage('verdictTrendChart');
                if (verdictTrendImg) {{
                    doc.addImage(verdictTrendImg, 'JPEG', 14, 123, 180, 50);
                }}

                // Row 4 - Secret Types Trend (full width)
                doc.text('Secret Types Detected Over Time', 14, 181);

                const secretTypesTrendImg = getChartImage('secretTypesTrendChart');
                if (secretTypesTrendImg) {{
                    doc.addImage(secretTypesTrendImg, 'JPEG', 14, 186, 180, 50);
                }}

                // Add page numbers
                const totalPages = doc.internal.getNumberOfPages();
                for (let i = 1; i <= totalPages; i++) {{
                    doc.setPage(i);
                    doc.setFontSize(9);
                    doc.setFont(undefined, 'normal');
                    doc.text(`Page ${{i}} of ${{totalPages}}`, 190, 285, {{ align: 'right' }});
                }}

                // Save
                const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
                doc.save(`executive-summary-${{timestamp}}.pdf`);
            }} catch (error) {{
                console.error('PDF generation error:', error);
                alert('Error generating PDF: ' + error.message);
            }}
        }}

        // Detailed Reporting PDF Export
        function exportDetailedPDF() {{
            if (!window.jspdf) {{
                alert('PDF library not loaded. Please refresh the page and try again.');
                return;
            }}

            if (!selectedResourceId) {{
                alert('Please select a resource first.');
                return;
            }}

            try {{
                const {{ jsPDF }} = window.jspdf;
                const doc = new jsPDF();

                // Get resource scans
                const resourceScans = allScans.filter(s =>
                    (s.resource_id || s.resource_name) === selectedResourceId
                ).sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));

                const latestScan = resourceScans[0];
                const resourceName = latestScan.resource_name || 'Unknown Resource';

                // Page 1: Title & Latest Scan
                doc.setFontSize(20);
                doc.setFont(undefined, 'bold');
                doc.text('Wiz CI/CD Detailed Resource Report', 14, 20);

                // Resource name with wrapping for long names
                doc.setFontSize(13);
                const maxWidth = 180;  // Max width for text wrapping
                const wrappedResourceName = doc.splitTextToSize(resourceName, maxWidth);
                doc.text(wrappedResourceName, 14, 30);

                // Calculate Y position after wrapped text
                const nameHeight = wrappedResourceName.length * 6;
                let currentY = 30 + nameHeight + 4;

                doc.setFontSize(10);
                doc.setFont(undefined, 'normal');
                doc.text(`Generated: ${{new Date().toLocaleString()}}`, 14, currentY);
                doc.setFont(undefined, 'bold');
                doc.text(`Report Period: ${{reportTimeRange}}`, 14, currentY + 6);
                doc.setFont(undefined, 'normal');
                doc.text(`Total Scans: ${{resourceScans.length}}`, 14, currentY + 12);
                doc.text(`Latest Scan: ${{latestScan.date || 'N/A'}}`, 14, currentY + 18);

                // Latest Scan Breakdown
                currentY = currentY + 30;
                doc.setFontSize(13);
                doc.setFont(undefined, 'bold');
                doc.text('Latest Scan Breakdown', 14, currentY);

                const matrixData = [
                    ['Vulnerabilities', latestScan.vuln_critical || 0, latestScan.vuln_high || 0, latestScan.vuln_medium || 0, latestScan.vuln_low || 0, latestScan.vuln_info || 0, latestScan.vuln_total || 0],
                    ['Secrets', latestScan.secret_critical || 0, latestScan.secret_high || 0, latestScan.secret_medium || 0, latestScan.secret_low || 0, latestScan.secret_info || 0, latestScan.secret_total || 0],
                    ['IaC Issues', latestScan.iac_critical || 0, latestScan.iac_high || 0, latestScan.iac_medium || 0, latestScan.iac_low || 0, latestScan.iac_info || 0, latestScan.iac_total || 0],
                    ['SAST', latestScan.sast_critical || 0, latestScan.sast_high || 0, latestScan.sast_medium || 0, latestScan.sast_low || 0, latestScan.sast_info || 0, latestScan.sast_total || 0],
                    ['Data', latestScan.data_critical || 0, latestScan.data_high || 0, latestScan.data_medium || 0, latestScan.data_low || 0, latestScan.data_info || 0, latestScan.data_total || 0],
                    ['Malware', latestScan.malware_critical || 0, latestScan.malware_high || 0, latestScan.malware_medium || 0, latestScan.malware_low || 0, latestScan.malware_info || 0, latestScan.malware_total || 0]
                ];

                doc.autoTable({{
                    head: [['Finding Type', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Total']],
                    body: matrixData,
                    startY: currentY + 6,
                    theme: 'striped',
                    styles: {{ fontSize: 9 }},
                    headStyles: {{ fillColor: [0, 67, 143] }},
                    columnStyles: {{
                        0: {{ fontStyle: 'bold' }}
                    }}
                }});

                // Recent Scan History
                currentY = doc.lastAutoTable.finalY + 12;
                doc.setFontSize(13);
                doc.setFont(undefined, 'bold');
                doc.text(`Recent Scan History (Last ${{Math.min(resourceScans.length, 10)}} Scans)`, 14, currentY);

                const historyData = resourceScans.slice(0, 10).map(s => {{
                    const timestamp = s.timestamp || '';
                    const dateTime = timestamp ? timestamp.replace('T', ' ').substring(0, 16) : 'N/A';
                    const verdict = s.verdict ? s.verdict.replace('_BY_POLICY', '') : 'N/A';
                    const totalInfo = (s.vuln_info || 0) + (s.secret_info || 0) + (s.iac_info || 0) +
                                     (s.sast_info || 0) + (s.data_info || 0) + (s.malware_info || 0);
                    const total = (s.total_critical || 0) + (s.total_high || 0) + (s.total_medium || 0) +
                                 (s.total_low || 0) + totalInfo;
                    return [
                        dateTime,
                        verdict,
                        s.total_critical || 0,
                        s.total_high || 0,
                        s.total_medium || 0,
                        s.total_low || 0,
                        totalInfo,
                        total
                    ];
                }});

                doc.autoTable({{
                    head: [['Date & Time', 'Verdict', 'C', 'H', 'M', 'L', 'Info', 'Total']],
                    body: historyData,
                    startY: currentY + 8,
                    theme: 'grid',
                    styles: {{ fontSize: 8 }},
                    headStyles: {{ fillColor: [0, 67, 143] }}
                }});

                // Helper function for compressed images with white background
                function getDetailChartImage(canvasId) {{
                    const canvas = document.getElementById(canvasId);
                    if (!canvas) return null;

                    // Create a new canvas with white background
                    const tempCanvas = document.createElement('canvas');
                    tempCanvas.width = canvas.width;
                    tempCanvas.height = canvas.height;
                    const ctx = tempCanvas.getContext('2d');

                    // Fill with white background
                    ctx.fillStyle = '#ffffff';
                    ctx.fillRect(0, 0, tempCanvas.width, tempCanvas.height);

                    // Draw the original chart on top
                    ctx.drawImage(canvas, 0, 0);

                    // Export as JPEG with compression
                    return tempCanvas.toDataURL('image/jpeg', 0.85);
                }}

                // Page 2: Charts (each full-width on own row)
                doc.addPage();

                // Row 1 - Finding Severity Trends (full width)
                doc.setFontSize(12);
                doc.setFont(undefined, 'bold');
                doc.text('Finding Severity Trends', 14, 15);

                const severityTrendImg = getDetailChartImage('resourceSeverityTrendChart');
                if (severityTrendImg) {{
                    doc.addImage(severityTrendImg, 'JPEG', 14, 20, 180, 55);
                }}

                // Row 2 - Verdict History (full width)
                doc.text('Verdict History', 14, 83);

                const verdictHistImg = getDetailChartImage('resourceVerdictHistoryChart');
                if (verdictHistImg) {{
                    doc.addImage(verdictHistImg, 'JPEG', 14, 88, 180, 55);
                }}

                // Row 3 - Finding Type Breakdown (full width)
                doc.text('Finding Type Breakdown', 14, 151);

                const findingTypeImg = getDetailChartImage('resourceFindingTypeChart');
                if (findingTypeImg) {{
                    doc.addImage(findingTypeImg, 'JPEG', 14, 156, 180, 55);
                }}

                // Row 4 - Critical & High Focus (full width)
                doc.text('Critical & High Focus', 14, 219);

                const criticalHighImg = getDetailChartImage('resourceCriticalHighChart');
                if (criticalHighImg) {{
                    doc.addImage(criticalHighImg, 'JPEG', 14, 224, 180, 55);
                }}

                // Add page numbers
                const totalPages = doc.internal.getNumberOfPages();
                for (let i = 1; i <= totalPages; i++) {{
                    doc.setPage(i);
                    doc.setFontSize(9);
                    doc.setFont(undefined, 'normal');
                    doc.text(`Page ${{i}} of ${{totalPages}}`, 190, 285, {{ align: 'right' }});
                }}

                // Save
                const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
                const safeName = resourceName.replace(/[^a-zA-Z0-9-]/g, '_');
                doc.save(`detailed-report-${{safeName}}-${{timestamp}}.pdf`);
            }} catch (error) {{
                console.error('PDF generation error:', error);
                alert('Error generating PDF: ' + error.message);
            }}
        }}

        // Detailed Reporting Tab Functions
        let detailedCharts = {{}};
        let selectedResourceId = null;
        let currentAppFilter = '';
        let currentScanTypes = ['CONTAINER_IMAGE', 'DIRECTORY', 'IAC', 'VIRTUAL_MACHINE_IMAGE', 'VIRTUAL_MACHINE'];
        let allApps = [];

        // Get icon for scan type
        function getScanTypeIcon(scanType) {{
            const icons = {{
                'CONTAINER_IMAGE': '[C]',
                'DIRECTORY': '[D]',
                'IAC': '[I]',
                'VIRTUAL_MACHINE_IMAGE': '[V]',
                'VIRTUAL_MACHINE': '[M]'
            }};
            return icons[scanType] || '[?]';
        }}

        function toggleSidebar() {{
            const sidebar = document.getElementById('resourceSidebar');
            const toggle = sidebar.querySelector('.sidebar-toggle');
            sidebar.classList.toggle('collapsed');
            toggle.textContent = sidebar.classList.contains('collapsed') ? '>' : '<';
        }}

        function initializeDetailedReporting() {{
            // Populate app filter datalist
            const datalist = document.getElementById('appList');
            allApps = Object.keys(applicationGroups).sort();

            // Clear and populate datalist
            datalist.innerHTML = '<option value="">All Applications</option>';
            allApps.forEach(app => {{
                const option = document.createElement('option');
                option.value = app;
                datalist.appendChild(option);
            }});

            // Set initial value
            document.getElementById('appFilterSearch').value = '';

            // Initial load of resources
            filterDrilldownResources();
        }}

        function handleAppInput() {{
            // This fires as user types - browser handles filtering automatically
            // We just need to check if they've cleared the field
            const input = document.getElementById('appFilterSearch');
            if (input.value === '') {{
                currentAppFilter = '';
                filterDrilldownResources();
            }}
        }}

        function handleAppSelection() {{
            // This fires when user selects from dropdown or presses Enter
            const input = document.getElementById('appFilterSearch');
            const value = input.value.trim();

            // Check if it's a valid app or "All Applications"
            if (value === '' || value === 'All Applications') {{
                currentAppFilter = '';
            }} else if (allApps.includes(value)) {{
                currentAppFilter = value;
            }} else {{
                // Invalid entry, reset to current filter
                input.value = currentAppFilter || '';
                return;
            }}

            filterDrilldownResources();
        }}

        function resetAppFilter() {{
            // Reset the filter to show all applications
            const input = document.getElementById('appFilterSearch');
            input.value = '';
            currentAppFilter = '';
            applyFilters();
        }}

        function applyFilters() {{
            // currentScanTypes is already updated by updateScanTypeFilter()
            // Just trigger the filter refresh
            filterDrilldownResources();
        }}

        function toggleScanTypeDropdown() {{
            const panel = document.getElementById('scanTypePanel');
            const button = panel.previousElementSibling;

            panel.classList.toggle('show');
            button.classList.toggle('open');
        }}

        // Close dropdown when clicking outside
        document.addEventListener('click', function(event) {{
            // Close detailed tab dropdown
            const dropdown = document.querySelector('#detailed-tab .checkbox-dropdown');
            if (dropdown && !dropdown.contains(event.target)) {{
                const panel = document.getElementById('scanTypePanel');
                const button = dropdown.querySelector('.dropdown-button');
                if (panel) panel.classList.remove('show');
                if (button) button.classList.remove('open');
            }}
        }});

        function updateScanTypeFilter() {{
            // Get all checked scan types
            const checkboxes = document.querySelectorAll('#scanTypePanel input[type="checkbox"]');
            currentScanTypes = Array.from(checkboxes)
                .filter(cb => cb.checked)
                .map(cb => cb.value);

            // Update button label
            const count = currentScanTypes.length;
            const label = document.getElementById('scanTypeLabel');
            if (count === 0) {{
                label.textContent = 'No types selected';
            }} else if (count === 5) {{
                label.textContent = 'All Types (5)';
            }} else {{
                label.textContent = `${{count}} Type${{count > 1 ? 's' : ''}} Selected`;
            }}

            // Apply filters
            applyFilters();
        }}

        function resetAllFilters() {{
            // Reset tag filter
            const input = document.getElementById('appFilterSearch');
            input.value = '';
            currentAppFilter = '';

            // Reset scan type filter (check all)
            const checkboxes = document.querySelectorAll('#scanTypePanel input[type="checkbox"]');
            checkboxes.forEach(cb => cb.checked = true);
            currentScanTypes = ['CONTAINER_IMAGE', 'DIRECTORY', 'IAC', 'VIRTUAL_MACHINE_IMAGE', 'VIRTUAL_MACHINE'];

            // Update label
            document.getElementById('scanTypeLabel').textContent = 'All Types (5)';

            applyFilters();
        }}

        function filterDrilldownResources() {{
            // currentAppFilter is already set by handleAppSelection()
            const sidebar = document.getElementById('resourceSidebarList');
            sidebar.innerHTML = '';

            // Filter scans by selected tag key:value pair
            let filteredScans = allScans;
            if (currentAppFilter && currentAppFilter !== '') {{
                if (currentAppFilter === 'Untagged') {{
                    // Show scans with no tags
                    filteredScans = allScans.filter(scan => {{
                        const scanTags = scan.tags || [];
                        return !scanTags || scanTags.length === 0;
                    }});
                }} else {{
                    // Parse the tag filter (format: "key: value")
                    const parts = currentAppFilter.split(': ');
                    if (parts.length === 2) {{
                        const filterKey = parts[0];
                        const filterValue = parts[1];

                        // Filter scans that have this exact tag key:value
                        filteredScans = allScans.filter(scan => {{
                            const scanTags = scan.tags || [];
                            return scanTags.some(tag =>
                                tag.key === filterKey && tag.value === filterValue
                            );
                        }});
                    }}
                }}
            }}

            // Apply scan type filter
            if (currentScanTypes && currentScanTypes.length > 0) {{
                filteredScans = filteredScans.filter(scan => {{
                    const scanType = scan.scan_origin_type || 'DIRECTORY';
                    return currentScanTypes.includes(scanType);
                }});
            }}

            // Group by resource and get latest scan per resource
            const resourceMap = new Map();
            filteredScans.forEach(scan => {{
                const resId = scan.resource_id || scan.resource_name;
                const existing = resourceMap.get(resId);

                if (!existing || scan.timestamp > existing.timestamp) {{
                    resourceMap.set(resId, scan);
                }}
            }});

            // Sort by resource name
            const resources = Array.from(resourceMap.values())
                .sort((a, b) => (a.resource_name || '').localeCompare(b.resource_name || ''));

            // Populate sidebar with icons
            resources.forEach(resource => {{
                const li = document.createElement('li');
                li.className = 'resource-item';
                li.dataset.resourceId = resource.resource_id || resource.resource_name;
                li.title = resource.resource_name || 'Unknown';  // Native browser tooltip

                const verdictClass = resource.verdict === 'PASSED_BY_POLICY' ? 'passed'
                    : resource.verdict === 'FAILED_BY_POLICY' ? 'failed' : 'warned';
                const verdictText = resource.verdict ? resource.verdict.replace('_BY_POLICY', '') : 'N/A';

                // Get icon based on scan origin type
                const scanType = resource.scan_origin_type || 'DIRECTORY';
                const icon = getScanTypeIcon(scanType);

                li.innerHTML = `
                    <span class="resource-icon">${{icon}}</span>
                    <div class="resource-info">
                        <span class="resource-name">${{resource.resource_name || 'Unknown'}}</span>
                        <span class="resource-meta">
                            <span class="badge ${{verdictClass}}" style="font-size: 10px; padding: 2px 6px;">
                                ${{verdictText}}
                            </span>
                        </span>
                    </div>
                `;

                li.onclick = () => selectResource(resource.resource_id || resource.resource_name);
                sidebar.appendChild(li);
            }});

            // Select first resource if none selected
            if (resources.length > 0 && !selectedResourceId) {{
                selectResource(resources[0].resource_id || resources[0].resource_name);
            }}
        }}

        function searchSidebarResources() {{
            const search = document.getElementById('resourceSidebarSearch').value.toLowerCase();
            const items = document.querySelectorAll('#resourceSidebarList .resource-item');

            items.forEach(item => {{
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(search) ? '' : 'none';
            }});
        }}

        function selectResource(resourceId) {{
            selectedResourceId = resourceId;

            // Update export button state
            updateExportButton('detailed');

            // Update sidebar selection
            document.querySelectorAll('#resourceSidebarList .resource-item').forEach(item => {{
                item.classList.remove('active');
                if (item.dataset.resourceId === resourceId) {{
                    item.classList.add('active');
                }}
            }});

            // Get all scans for this resource
            const resourceScans = allScans.filter(s =>
                (s.resource_id || s.resource_name) === resourceId
            ).sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));

            if (resourceScans.length === 0) return;

            const latestScan = resourceScans[0];
            renderResourceDetail(latestScan, resourceScans);
        }}

        function renderResourceDetail(latestScan, allResourceScans) {{
            const pane = document.getElementById('resourceDetailPane');

            const verdictClass = latestScan.verdict === 'PASSED_BY_POLICY' ? 'passed'
                : latestScan.verdict === 'FAILED_BY_POLICY' ? 'failed' : 'warned';

            pane.innerHTML = `
                <div class="detail-header">
                    <h2>${{latestScan.resource_name || 'Unknown Resource'}}</h2>
                    <div class="meta">
                        Last Scanned: ${{latestScan.date || 'N/A'}} |
                        Total Scans: ${{allResourceScans.length}} |
                        <span class="badge ${{verdictClass}}">${{latestScan.verdict ? latestScan.verdict.replace('_BY_POLICY', '') : 'N/A'}}</span>
                    </div>
                </div>

                <div class="detail-section">
                    <h3>Scan History (Last ${{Math.min(allResourceScans.length, 10)}} Scans) - Click to Expand</h3>
                    <div class="table-card" style="padding: 0; box-shadow: none; border: 1px solid #e5e7eb;">
                        <table class="data-table expandable-table" id="scanHistoryTable">
                            <thead>
                                <tr>
                                    <th style="width: 30px;"></th>
                                    <th>Date & Time</th>
                                    <th>Verdict</th>
                                    <th>Critical</th>
                                    <th>High</th>
                                    <th>Medium</th>
                                    <th>Low</th>
                                    <th>Info</th>
                                    <th>Total</th>
                                </tr>
                            </thead>
                            <tbody id="scanHistoryBody">
                                <!-- Populated dynamically with expandable rows -->
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="detail-section">
                    <h3>Historical Trends (${{allResourceScans.length}} scans)</h3>

                    <div class="charts-grid">
                        <div class="chart-card">
                            <h2>Finding Severity Trends</h2>
                            <div class="chart-container">
                                <canvas id="resourceSeverityTrendChart"></canvas>
                            </div>
                        </div>

                        <div class="chart-card">
                            <h2>Verdict History</h2>
                            <div class="chart-container">
                                <canvas id="resourceVerdictHistoryChart"></canvas>
                            </div>
                        </div>

                        <div class="chart-card">
                            <h2>Finding Type Breakdown</h2>
                            <div class="chart-container">
                                <canvas id="resourceFindingTypeChart"></canvas>
                            </div>
                        </div>

                        <div class="chart-card">
                            <h2>Critical & High Findings Trend</h2>
                            <div class="chart-container">
                                <canvas id="resourceCriticalHighChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            // Populate expandable scan history table
            populateScanHistoryTable(allResourceScans);

            // Render all historical charts
            renderResourceHistoryCharts(allResourceScans);
        }}

        function populateScanHistoryTable(scans) {{
            const tbody = document.getElementById('scanHistoryBody');
            if (!tbody) return;

            tbody.innerHTML = '';

            scans.slice(0, 10).forEach((scan, index) => {{
                const verdictClass = scan.verdict === 'PASSED_BY_POLICY' ? 'passed'
                    : scan.verdict === 'FAILED_BY_POLICY' ? 'failed' : 'warned';
                const verdictText = scan.verdict ? scan.verdict.replace('_BY_POLICY', '') : 'N/A';

                // Format timestamp to show date and time
                const timestamp = scan.timestamp || '';
                const dateTime = timestamp ? timestamp.replace('T', ' ').substring(0, 16) : 'N/A';

                // Calculate info total
                const totalInfo = (scan.vuln_info || 0) + (scan.secret_info || 0) + (scan.iac_info || 0) +
                                 (scan.sast_info || 0) + (scan.data_info || 0) + (scan.malware_info || 0);

                // Summary row (clickable)
                const summaryRow = document.createElement('tr');
                summaryRow.className = 'scan-row';
                if (index === 0) summaryRow.classList.add('expanded');  // First row expanded by default
                summaryRow.dataset.scanIndex = index;

                summaryRow.innerHTML = `
                    <td><span class="expand-icon">&gt;</span></td>
                    <td>${{dateTime}}</td>
                    <td><span class="badge ${{verdictClass}}">${{verdictText}}</span></td>
                    <td><span class="badge critical">${{scan.total_critical || 0}}</span></td>
                    <td><span class="badge high">${{scan.total_high || 0}}</span></td>
                    <td><span class="badge medium">${{scan.total_medium || 0}}</span></td>
                    <td><span class="badge low">${{scan.total_low || 0}}</span></td>
                    <td style="color: #64748b;">${{totalInfo}}</td>
                    <td style="font-weight: 700;">${{
                        (scan.total_critical || 0) +
                        (scan.total_high || 0) +
                        (scan.total_medium || 0) +
                        (scan.total_low || 0) +
                        totalInfo
                    }}</td>
                `;

                summaryRow.onclick = function() {{
                    toggleScanDetail(index);
                }};

                // Detail row (expandable content)
                const detailRow = document.createElement('tr');
                detailRow.className = 'detail-row';
                if (index === 0) detailRow.classList.add('show');  // First row expanded by default
                detailRow.dataset.scanIndex = index;

                detailRow.innerHTML = `
                    <td colspan="9">
                        <div class="detail-content">
                            <table class="detail-matrix">
                                <thead>
                                    <tr>
                                        <th style="text-align: left;">Finding Type</th>
                                        <th>Critical</th>
                                        <th>High</th>
                                        <th>Medium</th>
                                        <th>Low</th>
                                        <th>Info</th>
                                        <th>Total</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>Vulnerabilities</td>
                                        <td><span class="badge critical">${{scan.vuln_critical || 0}}</span></td>
                                        <td><span class="badge high">${{scan.vuln_high || 0}}</span></td>
                                        <td><span class="badge medium">${{scan.vuln_medium || 0}}</span></td>
                                        <td><span class="badge low">${{scan.vuln_low || 0}}</span></td>
                                        <td style="color: #64748b;">${{scan.vuln_info || 0}}</td>
                                        <td style="font-weight: 700;">${{scan.vuln_total || 0}}</td>
                                    </tr>
                                    <tr>
                                        <td>Secrets</td>
                                        <td><span class="badge critical">${{scan.secret_critical || 0}}</span></td>
                                        <td><span class="badge high">${{scan.secret_high || 0}}</span></td>
                                        <td><span class="badge medium">${{scan.secret_medium || 0}}</span></td>
                                        <td><span class="badge low">${{scan.secret_low || 0}}</span></td>
                                        <td style="color: #64748b;">${{scan.secret_info || 0}}</td>
                                        <td style="font-weight: 700;">${{scan.secret_total || 0}}</td>
                                    </tr>
                                    <tr>
                                        <td>IaC Issues</td>
                                        <td><span class="badge critical">${{scan.iac_critical || 0}}</span></td>
                                        <td><span class="badge high">${{scan.iac_high || 0}}</span></td>
                                        <td><span class="badge medium">${{scan.iac_medium || 0}}</span></td>
                                        <td><span class="badge low">${{scan.iac_low || 0}}</span></td>
                                        <td style="color: #64748b;">${{scan.iac_info || 0}}</td>
                                        <td style="font-weight: 700;">${{scan.iac_total || 0}}</td>
                                    </tr>
                                    <tr>
                                        <td>SAST Findings</td>
                                        <td><span class="badge critical">${{scan.sast_critical || 0}}</span></td>
                                        <td><span class="badge high">${{scan.sast_high || 0}}</span></td>
                                        <td><span class="badge medium">${{scan.sast_medium || 0}}</span></td>
                                        <td><span class="badge low">${{scan.sast_low || 0}}</span></td>
                                        <td style="color: #64748b;">${{scan.sast_info || 0}}</td>
                                        <td style="font-weight: 700;">${{scan.sast_total || 0}}</td>
                                    </tr>
                                    <tr>
                                        <td>Data Findings</td>
                                        <td><span class="badge critical">${{scan.data_critical || 0}}</span></td>
                                        <td><span class="badge high">${{scan.data_high || 0}}</span></td>
                                        <td><span class="badge medium">${{scan.data_medium || 0}}</span></td>
                                        <td><span class="badge low">${{scan.data_low || 0}}</span></td>
                                        <td style="color: #64748b;">${{scan.data_info || 0}}</td>
                                        <td style="font-weight: 700;">${{scan.data_total || 0}}</td>
                                    </tr>
                                    <tr>
                                        <td>Malware</td>
                                        <td><span class="badge critical">${{scan.malware_critical || 0}}</span></td>
                                        <td><span class="badge high">${{scan.malware_high || 0}}</span></td>
                                        <td><span class="badge medium">${{scan.malware_medium || 0}}</span></td>
                                        <td><span class="badge low">${{scan.malware_low || 0}}</span></td>
                                        <td style="color: #64748b;">${{scan.malware_info || 0}}</td>
                                        <td style="font-weight: 700;">${{scan.malware_total || 0}}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                `;

                tbody.appendChild(summaryRow);
                tbody.appendChild(detailRow);
            }});
        }}

        function toggleScanDetail(index) {{
            const summaryRow = document.querySelector(`.scan-row[data-scan-index="${{index}}"]`);
            const detailRow = document.querySelector(`.detail-row[data-scan-index="${{index}}"]`);

            if (!summaryRow || !detailRow) return;

            // Toggle expanded state
            summaryRow.classList.toggle('expanded');
            detailRow.classList.toggle('show');
        }}

        function renderResourceHistoryCharts(scans) {{
            // Destroy existing charts
            Object.values(detailedCharts).forEach(chart => chart?.destroy());
            detailedCharts = {{}};

            // Sort by date ascending for charts
            const sortedScans = [...scans].sort((a, b) =>
                (a.timestamp || '').localeCompare(b.timestamp || '')
            );

            const dates = sortedScans.map(s => s.date || 'N/A');

            // Chart 1: Severity Trends (line chart)
            const severityCtx = document.getElementById('resourceSeverityTrendChart');
            if (severityCtx) {{
                detailedCharts.severity = new Chart(severityCtx.getContext('2d'), {{
                    type: 'line',
                    data: {{
                        labels: dates,
                        datasets: [
                            {{
                                label: 'Critical',
                                data: sortedScans.map(s => s.total_critical || 0),
                                borderColor: '#ef4444',
                                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                                tension: 0.4,
                                fill: true
                            }},
                            {{
                                label: 'High',
                                data: sortedScans.map(s => s.total_high || 0),
                                borderColor: '#f59e0b',
                                backgroundColor: 'rgba(245, 158, 11, 0.1)',
                                tension: 0.4,
                                fill: true
                            }},
                            {{
                                label: 'Medium',
                                data: sortedScans.map(s => s.total_medium || 0),
                                borderColor: '#3b82f6',
                                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                tension: 0.4,
                                fill: true
                            }},
                            {{
                                label: 'Low',
                                data: sortedScans.map(s => s.total_low || 0),
                                borderColor: '#10b981',
                                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                                tension: 0.4,
                                fill: true
                            }}
                        ]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{ legend: {{ position: 'bottom' }} }},
                        scales: {{ y: {{ beginAtZero: true }} }}
                    }}
                }});
            }}

            // Chart 2: Verdict History (bar chart)
            const verdictCtx = document.getElementById('resourceVerdictHistoryChart');
            if (verdictCtx) {{
                const verdictData = sortedScans.map(s => {{
                    if (s.verdict === 'PASSED_BY_POLICY') return 1;
                    if (s.verdict === 'FAILED_BY_POLICY') return -1;
                    if (s.verdict === 'WARN_BY_POLICY') return 0;
                    return 0;
                }});

                detailedCharts.verdict = new Chart(verdictCtx.getContext('2d'), {{
                    type: 'bar',
                    data: {{
                        labels: dates,
                        datasets: [{{
                            label: 'Verdict',
                            data: verdictData,
                            backgroundColor: verdictData.map(v =>
                                v === 1 ? '#10b981' : v === -1 ? '#ef4444' : '#f59e0b'
                            ),
                            borderRadius: 4
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ display: false }},
                            tooltip: {{
                                callbacks: {{
                                    label: function(context) {{
                                        const val = context.parsed.y;
                                        return val === 1 ? 'PASSED' : val === -1 ? 'FAILED' : 'WARNED';
                                    }}
                                }}
                            }}
                        }},
                        scales: {{
                            y: {{
                                display: false,
                                min: -1.5,
                                max: 1.5
                            }}
                        }}
                    }}
                }});
            }}

            // Chart 3: Finding Type Breakdown (stacked area chart)
            const findingTypeCtx = document.getElementById('resourceFindingTypeChart');
            if (findingTypeCtx) {{
                detailedCharts.findingType = new Chart(findingTypeCtx.getContext('2d'), {{
                    type: 'line',
                    data: {{
                        labels: dates,
                        datasets: [
                            {{
                                label: 'Vulnerabilities',
                                data: sortedScans.map(s => s.vuln_total || 0),
                                borderColor: '#8b5cf6',
                                backgroundColor: 'rgba(139, 92, 246, 0.2)',
                                tension: 0.4,
                                fill: true
                            }},
                            {{
                                label: 'Secrets',
                                data: sortedScans.map(s => s.secret_total || 0),
                                borderColor: '#ec4899',
                                backgroundColor: 'rgba(236, 72, 153, 0.2)',
                                tension: 0.4,
                                fill: true
                            }},
                            {{
                                label: 'IaC',
                                data: sortedScans.map(s => s.iac_total || 0),
                                borderColor: '#06b6d4',
                                backgroundColor: 'rgba(6, 182, 212, 0.2)',
                                tension: 0.4,
                                fill: true
                            }},
                            {{
                                label: 'SAST',
                                data: sortedScans.map(s => s.sast_total || 0),
                                borderColor: '#84cc16',
                                backgroundColor: 'rgba(132, 204, 22, 0.2)',
                                tension: 0.4,
                                fill: true
                            }}
                        ]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{ legend: {{ position: 'bottom' }} }},
                        scales: {{
                            y: {{ beginAtZero: true, stacked: true }}
                        }}
                    }}
                }});
            }}

            // Chart 4: Critical & High Focus (area chart)
            const criticalHighCtx = document.getElementById('resourceCriticalHighChart');
            if (criticalHighCtx) {{
                detailedCharts.criticalHigh = new Chart(criticalHighCtx.getContext('2d'), {{
                    type: 'line',
                    data: {{
                        labels: dates,
                        datasets: [
                            {{
                                label: 'Critical',
                                data: sortedScans.map(s => s.total_critical || 0),
                                borderColor: '#ef4444',
                                backgroundColor: 'rgba(239, 68, 68, 0.3)',
                                tension: 0.4,
                                fill: true,
                                borderWidth: 2
                            }},
                            {{
                                label: 'High',
                                data: sortedScans.map(s => s.total_high || 0),
                                borderColor: '#f59e0b',
                                backgroundColor: 'rgba(245, 158, 11, 0.3)',
                                tension: 0.4,
                                fill: true,
                                borderWidth: 2
                            }}
                        ]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{ legend: {{ position: 'bottom' }} }},
                        scales: {{ y: {{ beginAtZero: true }} }}
                    }}
                }});
            }}
        }}

        // Initialize on load
        window.addEventListener('DOMContentLoaded', function() {{
            initializeExecutiveCharts();
        }});
    </script>
</body>
</html>
"""

    with open(filename, 'w') as f:
        f.write(html_content)

    print(f"Multi-tab HTML dashboard saved: {filename}")
    return filename


def parse_time_range(time_str):
    """
    Parse time range string like '1d', '7d', '24h', '30d'.

    Returns:
        tuple: (days, hours, description)
    """
    time_str = time_str.lower().strip()

    if time_str.endswith('h'):
        # Hours
        hours = int(time_str[:-1])
        return (None, hours, f"Last {hours} hour{'s' if hours != 1 else ''}")
    elif time_str.endswith('d'):
        # Days
        days = int(time_str[:-1])
        return (days, None, f"Last {days} day{'s' if days != 1 else ''}")
    else:
        # Assume days if no unit
        days = int(time_str)
        return (days, None, f"Last {days} day{'s' if days != 1 else ''}")


def main():
    """Main function"""

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Generate Wiz CI/CD multi-tab dashboard with time filtering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python generate_dashboard_multitab.py                    # Last 30 days (default)
  python generate_dashboard_multitab.py --time-range 1d    # Last 1 day
  python generate_dashboard_multitab.py --time-range 7d    # Last 7 days
  python generate_dashboard_multitab.py --time-range 24h   # Last 24 hours
  python generate_dashboard_multitab.py --time-range 6h    # Last 6 hours
        '''
    )
    parser.add_argument(
        '--time-range',
        '-t',
        type=str,
        default='30d',
        help='Time range for scan data (e.g., 1d, 7d, 24h, 6h). Default: 30d'
    )
    parser.add_argument(
        '--output-dir',
        '-o',
        type=str,
        default='output',
        help='Output directory for generated dashboard. Default: output/'
    )

    args = parser.parse_args()

    if not CLIENT_ID or not CLIENT_SECRET:
        print("\nERROR: Missing credentials.")
        print(f"Please ensure WIZ_CLIENT_ID and WIZ_CLIENT_SECRET are set in: {env_path}")
        return 1

    # Parse time range
    try:
        days, hours, time_desc = parse_time_range(args.time_range)
    except ValueError as e:
        print(f"\nERROR: Invalid time range format: {args.time_range}")
        print("Use format like: 1d, 7d, 24h, 6h")
        return 1

    print("="*80)
    print("WIZ CI/CD MULTI-TAB DASHBOARD GENERATOR")
    print("="*80)
    print(f"Time Range: {time_desc}")
    print(f"Output Dir: {args.output_dir}")
    print()

    # Initialize reporter
    reporter = WizCICDReporter(CLIENT_ID, CLIENT_SECRET)

    # Authenticate
    print("Authenticating with Wiz API...")
    token, dc = reporter.authenticate()
    print(f"  [OK] Authenticated (Data Center: {dc})")
    print()

    # Create custom query variables with time filter
    variables = create_time_filter_variables(days=days, hours=hours)

    # Fetch data
    print(f"Fetching CI/CD scan data ({time_desc})...")
    scans = reporter.fetch_all_scans(variables=variables)

    # Generate dashboard
    print("Generating multi-tab HTML dashboard...")
    print("  Tab 1: Executive Summary (high-level charts and KPIs)")
    print("  Tab 2: Detailed Reporting (app filter + resource drill-down + trends)")
    filename = generate_html_dashboard(reporter, output_dir=args.output_dir, time_range_desc=time_desc)
    print()

    print("="*80)
    print(f"[OK] Multi-tab dashboard generated successfully!")
    print(f"  Time Range: {time_desc}")
    print(f"  Total Scans: {len(scans)}")
    print(f"  Open in browser: {filename}")
    print("="*80)

    return 0


if __name__ == '__main__':
    exit(main())
