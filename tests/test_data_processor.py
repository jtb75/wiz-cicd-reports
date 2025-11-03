"""
Unit tests for data_processor module.
"""

import pytest
from wiz_cicd.processor import (
    parse_scan_data,
    calculate_verdict_stats,
    calculate_finding_type_stats,
    calculate_daily_trends
)


class TestParseScanData:
    """Tests for parse_scan_data function."""

    @pytest.mark.unit
    def test_parse_single_scan(self, mock_scan_basic):
        """Test parsing a single scan."""
        result = parse_scan_data([mock_scan_basic])

        assert len(result) == 1
        scan = result[0]

        # Check basic fields
        assert scan['scan_id'] == 'scan-123'
        assert scan['timestamp'] == '2025-11-02T10:00:00Z'
        assert scan['date'] == '2025-11-02'
        assert scan['resource_name'] == 'test-app'
        assert scan['resource_type'] == 'CONTAINER_IMAGE'
        assert scan['verdict'] == 'PASSED_BY_POLICY'

        # Check vulnerability counts
        assert scan['vuln_critical'] == 1
        assert scan['vuln_high'] == 5
        assert scan['vuln_medium'] == 10
        assert scan['vuln_low'] == 15
        assert scan['vuln_info'] == 2
        assert scan['vuln_total'] == 33

        # Check secret counts
        assert scan['secret_total'] == 1
        assert scan['secret_high'] == 1

    @pytest.mark.unit
    def test_parse_scan_with_iac(self, mock_scan_with_iac):
        """Test parsing a scan with IaC findings."""
        result = parse_scan_data([mock_scan_with_iac])

        assert len(result) == 1
        scan = result[0]

        assert scan['iac_critical'] == 2
        assert scan['iac_high'] == 8
        assert scan['iac_medium'] == 20
        assert scan['iac_low'] == 5
        assert scan['iac_info'] == 1
        assert scan['iac_total'] == 36

    @pytest.mark.unit
    def test_parse_multiple_scans(self, mock_scans_list):
        """Test parsing multiple scans."""
        result = parse_scan_data(mock_scans_list)

        assert len(result) == 3
        assert result[0]['scan_id'] == 'scan-123'
        assert result[1]['scan_id'] == 'scan-789'
        assert result[2]['scan_id'] == 'scan-failed'

    @pytest.mark.unit
    def test_parse_handles_null_fields(self):
        """Test that parser handles null/missing fields gracefully."""
        minimal_scan = {
            'id': 'minimal',
            'timestamp': '2025-11-02T00:00:00Z',
            'subjectResource': None,
            'actor': None,
            'extraDetails': None
        }

        result = parse_scan_data([minimal_scan])
        assert len(result) == 1
        assert result[0]['scan_id'] == 'minimal'
        assert result[0]['vuln_total'] == 0
        assert result[0]['verdict'] is None

    @pytest.mark.unit
    def test_parse_calculates_total_severities(self, mock_scan_failed):
        """Test that total severity counts are calculated correctly."""
        result = parse_scan_data([mock_scan_failed])
        scan = result[0]

        # Total critical: vuln(10) + secret(0) + sast(2) + data(1) = 13
        assert scan['total_critical'] == 13

        # Total high: vuln(25) + secret(3) + sast(5) + data(2) = 35
        assert scan['total_high'] == 35


class TestCalculateVerdictStats:
    """Tests for calculate_verdict_stats function."""

    @pytest.mark.unit
    def test_verdict_stats_single_passed(self, mock_scan_basic):
        """Test verdict stats with single passed scan."""
        parsed = parse_scan_data([mock_scan_basic])
        stats = calculate_verdict_stats(parsed)

        assert stats['total_scans'] == 1
        assert stats['passed'] == 1
        assert stats['failed'] == 0
        assert stats['warned'] == 0
        assert stats['pass_rate'] == 100.0
        assert stats['fail_rate'] == 0.0
        assert stats['warn_rate'] == 0.0

    @pytest.mark.unit
    def test_verdict_stats_multiple_scans(self, mock_scans_list):
        """Test verdict stats with multiple scans."""
        parsed = parse_scan_data(mock_scans_list)
        stats = calculate_verdict_stats(parsed)

        assert stats['total_scans'] == 3
        assert stats['passed'] == 1  # mock_scan_basic
        assert stats['failed'] == 1  # mock_scan_failed
        assert stats['warned'] == 1  # mock_scan_with_iac

        # Rates: 1/3 = 33.33%
        assert abs(stats['pass_rate'] - 33.33) < 0.01
        assert abs(stats['fail_rate'] - 33.33) < 0.01
        assert abs(stats['warn_rate'] - 33.33) < 0.01

    @pytest.mark.unit
    def test_verdict_stats_empty_list(self):
        """Test verdict stats with empty scan list."""
        stats = calculate_verdict_stats([])

        assert stats['total_scans'] == 0
        assert stats['passed'] == 0
        assert stats['failed'] == 0
        assert stats['warned'] == 0
        assert stats['pass_rate'] == 0
        assert stats['fail_rate'] == 0
        assert stats['warn_rate'] == 0


class TestCalculateFindingTypeStats:
    """Tests for calculate_finding_type_stats function."""

    @pytest.mark.unit
    def test_finding_stats_single_scan(self, mock_scan_basic):
        """Test finding type stats with single scan."""
        parsed = parse_scan_data([mock_scan_basic])
        stats = calculate_finding_type_stats(parsed)

        # Vulnerabilities
        assert stats['vulnerabilities']['total'] == 33
        assert stats['vulnerabilities']['critical'] == 1
        assert stats['vulnerabilities']['high'] == 5

        # Secrets
        assert stats['secrets']['total'] == 1
        assert stats['secrets']['high'] == 1

        # IaC should be 0 for this scan
        assert stats['iac']['total'] == 0

    @pytest.mark.unit
    def test_finding_stats_multiple_scans(self, mock_scans_list):
        """Test finding type stats with multiple scans."""
        parsed = parse_scan_data(mock_scans_list)
        stats = calculate_finding_type_stats(parsed)

        # Vulnerabilities from all 3 scans
        assert stats['vulnerabilities']['total'] > 0
        assert stats['vulnerabilities']['critical'] > 0

        # IaC only from mock_scan_with_iac
        assert stats['iac']['total'] == 36
        assert stats['iac']['critical'] == 2

    @pytest.mark.unit
    def test_finding_stats_empty_list(self):
        """Test finding type stats with empty list."""
        stats = calculate_finding_type_stats([])

        for finding_type in ['vulnerabilities', 'secrets', 'iac', 'sast', 'data', 'malware']:
            assert stats[finding_type]['total'] == 0
            assert stats[finding_type]['critical'] == 0


class TestCalculateDailyTrends:
    """Tests for calculate_daily_trends function."""

    @pytest.mark.unit
    def test_daily_trends_single_day(self, mock_scans_list):
        """Test daily trends calculation."""
        parsed = parse_scan_data(mock_scans_list)
        trends = calculate_daily_trends(parsed)

        # Should have 2 days (2025-11-01 and 2025-11-02)
        assert len(trends) == 2

        # Check structure
        assert all('date' in day for day in trends)
        assert all('total_scans' in day for day in trends)
        assert all('passed' in day for day in trends)
        assert all('failed' in day for day in trends)
        assert all('warned' in day for day in trends)

        # Check sorting (should be chronological)
        assert trends[0]['date'] < trends[1]['date']

    @pytest.mark.unit
    def test_daily_trends_aggregation(self, mock_scan_basic, mock_scan_failed):
        """Test that scans on the same day are aggregated."""
        # Both scans on same day
        parsed = parse_scan_data([mock_scan_basic, mock_scan_failed])
        trends = calculate_daily_trends(parsed)

        # Should have 1 day with 2 scans
        assert len(trends) == 1
        assert trends[0]['total_scans'] == 2
        assert trends[0]['date'] == '2025-11-02'

    @pytest.mark.unit
    def test_daily_trends_empty_list(self):
        """Test daily trends with empty list."""
        trends = calculate_daily_trends([])
        assert len(trends) == 0

    @pytest.mark.unit
    def test_daily_trends_severity_counts(self, mock_scan_failed):
        """Test that daily trends include severity counts."""
        parsed = parse_scan_data([mock_scan_failed])
        trends = calculate_daily_trends(parsed)

        assert len(trends) == 1
        day = trends[0]

        assert day['critical'] > 0
        assert day['high'] > 0
        assert day['total_findings'] > 0

    @pytest.mark.unit
    def test_daily_trends_includes_secret_types(self):
        """Test that daily trends include secret type breakdown."""
        scan_with_secrets = {
            "id": "test-scan",
            "timestamp": "2024-01-15T10:00:00Z",
            "extraDetails": {
                "analytics": {
                    "secretScanResultAnalytics": {
                        "cloudKeyCount": 5,
                        "dbConnectionStringCount": 3,
                        "gitCredentialCount": 2,
                        "passwordCount": 10,
                        "privateKeyCount": 1,
                        "saasAPIKeyCount": 4,
                        "criticalCount": 0,
                        "highCount": 15,
                        "mediumCount": 10,
                        "lowCount": 0,
                        "infoCount": 0,
                        "totalCount": 25
                    },
                    "vulnerabilityScanResultAnalytics": {},
                    "iacScanResultAnalytics": None,
                    "sastScanResultAnalytics": {},
                    "dataScanResultAnalytics": {}
                },
                "status": {"verdict": "FAILED_BY_POLICY"}
            },
            "subjectResource": {},
            "actor": {}
        }

        parsed = parse_scan_data([scan_with_secrets])
        trends = calculate_daily_trends(parsed)

        assert len(trends) == 1
        day = trends[0]

        # Check secret type counts
        assert day['secret_cloud_keys'] == 5
        assert day['secret_db_connections'] == 3
        assert day['secret_git_credentials'] == 2
        assert day['secret_passwords'] == 10
        assert day['secret_private_keys'] == 1
        assert day['secret_saas_api_keys'] == 4

    @pytest.mark.unit
    def test_parse_scan_includes_secret_types(self):
        """Test that parse_scan_data includes secret type breakdown."""
        scan_with_secrets = {
            "id": "test-scan",
            "timestamp": "2024-01-15T10:00:00Z",
            "extraDetails": {
                "analytics": {
                    "secretScanResultAnalytics": {
                        "cloudKeyCount": 3,
                        "dbConnectionStringCount": 1,
                        "gitCredentialCount": 0,
                        "passwordCount": 5,
                        "privateKeyCount": 2,
                        "saasAPIKeyCount": 1,
                        "criticalCount": 0,
                        "highCount": 8,
                        "mediumCount": 4,
                        "lowCount": 0,
                        "infoCount": 0,
                        "totalCount": 12
                    },
                    "vulnerabilityScanResultAnalytics": {},
                    "iacScanResultAnalytics": None,
                    "sastScanResultAnalytics": {},
                    "dataScanResultAnalytics": {}
                },
                "status": {"verdict": "FAILED_BY_POLICY"}
            },
            "subjectResource": {},
            "actor": {}
        }

        parsed = parse_scan_data([scan_with_secrets])

        assert len(parsed) == 1
        scan = parsed[0]

        # Check secret type fields exist and are correct
        assert scan['secret_cloud_keys'] == 3
        assert scan['secret_db_connections'] == 1
        assert scan['secret_git_credentials'] == 0
        assert scan['secret_passwords'] == 5
        assert scan['secret_private_keys'] == 2
        assert scan['secret_saas_api_keys'] == 1
