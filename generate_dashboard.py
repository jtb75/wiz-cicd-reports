#!/usr/bin/env python3
"""
Generate HTML dashboard with charts from Wiz CI/CD scan data.

This script generates an interactive HTML dashboard with charts, graphs,
and tag filtering capabilities.

Usage:
    python generate_dashboard.py              # Default: last 30 days
    python generate_dashboard.py -t 7d        # Last 7 days
    python generate_dashboard.py -t 24h       # Last 24 hours
    python generate_dashboard.py --debug      # Enable debug logging
"""

import json
import html
import os
import argparse
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

from wiz_cicd import WizCICDReporter, create_time_filter_variables, configure_logging

# Load environment variables
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

CLIENT_ID = os.environ.get("WIZ_CLIENT_ID")
CLIENT_SECRET = os.environ.get("WIZ_CLIENT_SECRET")


def generate_html_dashboard(reporter: WizCICDReporter, output_dir="output"):
    """Generate HTML dashboard with charts and tag filtering."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"{output_dir}/dashboard_{timestamp}.html"

    # Get statistics
    verdict_stats = reporter.get_verdict_stats()
    finding_stats = reporter.get_finding_stats()
    daily_trends = reporter.get_daily_trends()

    # Get tag index for filtering
    tag_index = reporter.extract_tags()

    # Get raw scans with tags for client-side filtering
    raw_scans = reporter._raw_scans
    parsed_scans = reporter.get_parsed_scans()

    # Create a mapping of scan_id to tags for easy lookup
    scan_tags = {}
    for scan in raw_scans:
        scan_id = scan.get('id')
        extra = scan.get('extraDetails') or {}
        tags = extra.get('tags') or []
        scan_tags[scan_id] = tags

    # Embed the parsed scans with tags in the HTML for client-side filtering
    scans_with_tags = []
    for scan in parsed_scans:
        scan_copy = scan.copy()
        scan_copy['tags'] = scan_tags.get(scan['scan_id'], [])
        scans_with_tags.append(scan_copy)

    # Pre-compute JSON strings outside f-string for Python <3.12 compatibility
    # (backslashes not allowed in f-string expressions before 3.12)
    escape_script_close = '<\\/'
    all_scans_json = json.dumps(json.dumps(scans_with_tags).replace('</', escape_script_close))
    tag_index_json = json.dumps(json.dumps(tag_index).replace('</', escape_script_close))

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wiz CI/CD Pipeline Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
            integrity="sha384-e6nUZLBkQ86NJ6TVVKAeSaK8jWa3NhkYWZFomE39AvDbQWeie9PlQqM3pmYW5d1g"
            crossorigin="anonymous"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        .header {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        .header h1 {{
            color: #1f2937;
            font-size: 32px;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            color: #6b7280;
            font-size: 14px;
        }}

        .filter-section {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        .filter-section h3 {{
            color: #1f2937;
            font-size: 16px;
            margin-bottom: 15px;
        }}

        .filter-controls {{
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 5px;
        }}

        .filter-group label {{
            color: #6b7280;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .filter-group select {{
            padding: 8px 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            background: white;
            font-size: 14px;
            min-width: 200px;
        }}

        .filter-group button {{
            padding: 8px 16px;
            background: #3b82f6;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 600;
        }}

        .filter-group button:hover {{
            background: #2563eb;
        }}

        .filter-group button.reset {{
            background: #6b7280;
        }}

        .filter-group button.reset:hover {{
            background: #4b5563;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .stat-card {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        .stat-card h3 {{
            color: #6b7280;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}

        .stat-card .value {{
            font-size: 36px;
            font-weight: bold;
            color: #1f2937;
            margin-bottom: 5px;
        }}

        .stat-card .percentage {{
            font-size: 14px;
            color: #6b7280;
        }}

        .stat-card.passed .value {{ color: #10b981; }}
        .stat-card.failed .value {{ color: #ef4444; }}
        .stat-card.warned .value {{ color: #f59e0b; }}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .chart-card {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        .chart-card h2 {{
            color: #1f2937;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
        }}

        .chart-container {{
            position: relative;
            height: 300px;
        }}

        .full-width {{
            grid-column: 1 / -1;
        }}

        .full-width .chart-container {{
            height: 400px;
        }}

        .footer {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            color: #6b7280;
            font-size: 14px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Wiz CI/CD Pipeline Security Dashboard</h1>
            <p class="subtitle">Executive Report - Generated on {report_date}</p>
        </div>

        <div class="filter-section">
            <h3>Filter by Tag</h3>
            <div class="filter-controls">
                <div class="filter-group">
                    <label>Tag Key</label>
                    <select id="tagKeySelect">
                        <option value="">All Tags</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Tag Value</label>
                    <select id="tagValueSelect">
                        <option value="">All Values</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>&nbsp;</label>
                    <button onclick="applyFilter()">Apply Filter</button>
                </div>
                <div class="filter-group">
                    <label>&nbsp;</label>
                    <button class="reset" onclick="resetFilter()">Reset</button>
                </div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Scans</h3>
                <div class="value" id="statTotalScans">0</div>
                <div class="percentage">Filtered results</div>
            </div>

            <div class="stat-card passed">
                <h3>Passed</h3>
                <div class="value" id="statPassed">0</div>
                <div class="percentage" id="statPassedPct">0% of total</div>
            </div>

            <div class="stat-card failed">
                <h3>Failed</h3>
                <div class="value" id="statFailed">0</div>
                <div class="percentage" id="statFailedPct">0% of total</div>
            </div>

            <div class="stat-card warned">
                <h3>Warned</h3>
                <div class="value" id="statWarned">0</div>
                <div class="percentage" id="statWarnedPct">0% of total</div>
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
                <h2>Daily Critical & High Findings Trend</h2>
                <div class="chart-container">
                    <canvas id="findingTrendChart"></canvas>
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
        const tagIndex = JSON.parse({tag_index_json});

        let currentScans = allScans;
        let charts = {{}};

        // Initialize tag dropdowns
        function initializeTagDropdowns() {{
            const tagKeySelect = document.getElementById('tagKeySelect');
            const tagKeys = Object.keys(tagIndex).sort();

            tagKeys.forEach(key => {{
                const option = document.createElement('option');
                option.value = key;
                option.textContent = key;
                tagKeySelect.appendChild(option);
            }});

            // Update values when key changes
            tagKeySelect.addEventListener('change', function() {{
                const tagValueSelect = document.getElementById('tagValueSelect');
                tagValueSelect.innerHTML = '<option value="">All Values</option>';

                if (this.value) {{
                    const values = tagIndex[this.value];
                    values.forEach(value => {{
                        const option = document.createElement('option');
                        option.value = value;
                        option.textContent = value;
                        tagValueSelect.appendChild(option);
                    }});
                }}
            }});
        }}

        // Filter scans by tag
        function filterScansByTag(scans, tagKey, tagValue) {{
            if (!tagKey && !tagValue) {{
                return scans;
            }}

            return scans.filter(scan => {{
                const tags = scan.tags || [];
                return tags.some(tag => {{
                    const keyMatch = !tagKey || tag.key === tagKey;
                    const valueMatch = !tagValue || tag.value === tagValue;
                    return keyMatch && valueMatch;
                }});
            }});
        }}

        // Apply filter
        function applyFilter() {{
            const tagKey = document.getElementById('tagKeySelect').value;
            const tagValue = document.getElementById('tagValueSelect').value;

            currentScans = filterScansByTag(allScans, tagKey, tagValue);
            updateDashboard();
        }}

        // Reset filter
        function resetFilter() {{
            document.getElementById('tagKeySelect').value = '';
            document.getElementById('tagValueSelect').innerHTML = '<option value="">All Values</option>';
            currentScans = allScans;
            updateDashboard();
        }}

        // Calculate statistics
        function calculateStats(scans) {{
            const total = scans.length;
            const passed = scans.filter(s => s.verdict === 'PASSED_BY_POLICY').length;
            const failed = scans.filter(s => s.verdict === 'FAILED_BY_POLICY').length;
            const warned = scans.filter(s => s.verdict === 'WARN_BY_POLICY').length;

            const findings = {{
                vulnerabilities: {{ total: 0, critical: 0, high: 0, medium: 0, low: 0 }},
                secrets: {{ total: 0, critical: 0, high: 0, medium: 0, low: 0 }},
                iac: {{ total: 0, critical: 0, high: 0, medium: 0, low: 0 }},
                sast: {{ total: 0, critical: 0, high: 0, medium: 0, low: 0 }},
                data: {{ total: 0, critical: 0, high: 0, medium: 0, low: 0 }},
                malware: {{ total: 0, critical: 0, high: 0, medium: 0, low: 0 }}
            }};

            scans.forEach(scan => {{
                // Vulnerabilities
                findings.vulnerabilities.total += scan.vuln_total || 0;
                findings.vulnerabilities.critical += scan.vuln_critical || 0;
                findings.vulnerabilities.high += scan.vuln_high || 0;
                findings.vulnerabilities.medium += scan.vuln_medium || 0;
                findings.vulnerabilities.low += scan.vuln_low || 0;

                // Secrets
                findings.secrets.total += scan.secret_total || 0;
                findings.secrets.critical += scan.secret_critical || 0;
                findings.secrets.high += scan.secret_high || 0;
                findings.secrets.medium += scan.secret_medium || 0;
                findings.secrets.low += scan.secret_low || 0;

                // IaC
                findings.iac.total += scan.iac_total || 0;
                findings.iac.critical += scan.iac_critical || 0;
                findings.iac.high += scan.iac_high || 0;
                findings.iac.medium += scan.iac_medium || 0;
                findings.iac.low += scan.iac_low || 0;

                // SAST
                findings.sast.total += scan.sast_total || 0;
                findings.sast.critical += scan.sast_critical || 0;
                findings.sast.high += scan.sast_high || 0;
                findings.sast.medium += scan.sast_medium || 0;
                findings.sast.low += scan.sast_low || 0;

                // Data
                findings.data.total += scan.data_total || 0;
                findings.data.critical += scan.data_critical || 0;
                findings.data.high += scan.data_high || 0;
                findings.data.medium += scan.data_medium || 0;
                findings.data.low += scan.data_low || 0;

                // Malware
                findings.malware.total += scan.malware_total || 0;
                findings.malware.critical += scan.malware_critical || 0;
                findings.malware.high += scan.malware_high || 0;
                findings.malware.medium += scan.malware_medium || 0;
                findings.malware.low += scan.malware_low || 0;
            }});

            return {{ total, passed, failed, warned, findings }};
        }}

        // Update dashboard
        function updateDashboard() {{
            const stats = calculateStats(currentScans);

            // Update stat cards
            document.getElementById('statTotalScans').textContent = stats.total;
            document.getElementById('statPassed').textContent = stats.passed;
            document.getElementById('statFailed').textContent = stats.failed;
            document.getElementById('statWarned').textContent = stats.warned;

            const passRate = stats.total > 0 ? (stats.passed / stats.total * 100).toFixed(1) : 0;
            const failRate = stats.total > 0 ? (stats.failed / stats.total * 100).toFixed(1) : 0;
            const warnRate = stats.total > 0 ? (stats.warned / stats.total * 100).toFixed(1) : 0;

            document.getElementById('statPassedPct').textContent = `${{passRate}}% of total`;
            document.getElementById('statFailedPct').textContent = `${{failRate}}% of total`;
            document.getElementById('statWarnedPct').textContent = `${{warnRate}}% of total`;

            // Update charts
            updateCharts(stats);
        }}

        // Update all charts
        function updateCharts(stats) {{
            // Destroy existing charts
            Object.values(charts).forEach(chart => chart.destroy());
            charts = {{}};

            // Verdict Chart
            const verdictCtx = document.getElementById('verdictChart').getContext('2d');
            charts.verdict = new Chart(verdictCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Passed', 'Failed', 'Warned'],
                    datasets: [{{
                        data: [stats.passed, stats.failed, stats.warned],
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
            Object.entries(stats.findings).forEach(([type, data]) => {{
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
            const totalCritical = Object.values(stats.findings).reduce((sum, f) => sum + f.critical, 0);
            const totalHigh = Object.values(stats.findings).reduce((sum, f) => sum + f.high, 0);
            const totalMedium = Object.values(stats.findings).reduce((sum, f) => sum + f.medium, 0);
            const totalLow = Object.values(stats.findings).reduce((sum, f) => sum + f.low, 0);

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
                                return stats.findings[key]?.critical || 0;
                            }}),
                            backgroundColor: '#ef4444'
                        }},
                        {{
                            label: 'High',
                            data: findingLabels.map(label => {{
                                const key = label.toLowerCase();
                                return stats.findings[key]?.high || 0;
                            }}),
                            backgroundColor: '#f59e0b'
                        }},
                        {{
                            label: 'Medium',
                            data: findingLabels.map(label => {{
                                const key = label.toLowerCase();
                                return stats.findings[key]?.medium || 0;
                            }}),
                            backgroundColor: '#3b82f6'
                        }},
                        {{
                            label: 'Low',
                            data: findingLabels.map(label => {{
                                const key = label.toLowerCase();
                                return stats.findings[key]?.low || 0;
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

            // Daily trends (simplified - just show overall trends)
            const dailyData = {{}};
            currentScans.forEach(scan => {{
                const date = scan.date;
                if (!date) return;

                if (!dailyData[date]) {{
                    dailyData[date] = {{ passed: 0, failed: 0, warned: 0, critical: 0, high: 0 }};
                }}

                if (scan.verdict === 'PASSED_BY_POLICY') dailyData[date].passed++;
                if (scan.verdict === 'FAILED_BY_POLICY') dailyData[date].failed++;
                if (scan.verdict === 'WARN_BY_POLICY') dailyData[date].warned++;
                dailyData[date].critical += scan.total_critical || 0;
                dailyData[date].high += scan.total_high || 0;
            }});

            const dates = Object.keys(dailyData).sort();
            const verdictTrendCtx = document.getElementById('verdictTrendChart').getContext('2d');
            charts.verdictTrend = new Chart(verdictTrendCtx, {{
                type: 'line',
                data: {{
                    labels: dates,
                    datasets: [
                        {{
                            label: 'Passed',
                            data: dates.map(d => dailyData[d].passed),
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'Failed',
                            data: dates.map(d => dailyData[d].failed),
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'Warned',
                            data: dates.map(d => dailyData[d].warned),
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

            const findingTrendCtx = document.getElementById('findingTrendChart').getContext('2d');
            charts.findingTrend = new Chart(findingTrendCtx, {{
                type: 'line',
                data: {{
                    labels: dates,
                    datasets: [
                        {{
                            label: 'Critical',
                            data: dates.map(d => dailyData[d].critical),
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.4,
                            fill: true
                        }},
                        {{
                            label: 'High',
                            data: dates.map(d => dailyData[d].high),
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
        }}

        // Initialize on load
        window.addEventListener('DOMContentLoaded', function() {{
            initializeTagDropdowns();
            updateDashboard();
        }});
    </script>
</body>
</html>
"""

    with open(filename, 'w') as f:
        f.write(html_content)

    print(f"HTML dashboard saved: {filename}")
    return filename


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
    parser = argparse.ArgumentParser(description='Generate Wiz CI/CD HTML dashboard')
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
    print("WIZ CI/CD HTML DASHBOARD GENERATOR")
    print("="*80)
    print(f"Time Range: {time_desc}")
    print()

    # Initialize reporter
    reporter = WizCICDReporter(CLIENT_ID, CLIENT_SECRET)

    # Authenticate
    print("Authenticating with Wiz API...")
    token, dc = reporter.authenticate()
    print(f"  ✓ Authenticated (Data Center: {dc})")
    print()

    # Fetch data with time filter
    print(f"Fetching CI/CD scan data ({time_desc})...")
    variables = create_time_filter_variables(days=days, hours=hours)
    scans = reporter.fetch_all_scans(variables=variables)

    # Generate dashboard
    print("Generating HTML dashboard...")
    filename = generate_html_dashboard(reporter)
    print()

    print("="*80)
    print(f"✓ Dashboard generated successfully!")
    print(f"  Open in browser: {filename}")
    print("="*80)

    return 0


if __name__ == '__main__':
    exit(main())
