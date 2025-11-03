"""
Unit tests for WizCICDReporter class.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from wiz_cicd.reporter import WizCICDReporter


class TestWizCICDReporterInit:
    """Tests for WizCICDReporter initialization."""

    @pytest.mark.unit
    def test_init_sets_credentials(self):
        """Test that initialization sets credentials."""
        reporter = WizCICDReporter("test_id", "test_secret")

        assert reporter.client_id == "test_id"
        assert reporter.client_secret == "test_secret"
        assert reporter.token is None
        assert reporter.dc is None

    @pytest.mark.unit
    def test_init_sets_headers(self):
        """Test that initialization sets proper headers."""
        reporter = WizCICDReporter("test_id", "test_secret")

        assert reporter.headers_auth["Content-Type"] == "application/x-www-form-urlencoded"
        assert reporter.headers["Content-Type"] == "application/json"

    @pytest.mark.unit
    def test_init_caches_are_none(self):
        """Test that caches are initialized to None."""
        reporter = WizCICDReporter("test_id", "test_secret")

        assert reporter._raw_scans is None
        assert reporter._parsed_scans is None
        assert reporter._verdict_stats is None
        assert reporter._finding_stats is None
        assert reporter._daily_trends is None
        assert reporter._tag_index is None


class TestWizCICDReporterAuthentication:
    """Tests for authentication methods."""

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    def test_authenticate_success(self, mock_post, mock_auth_response):
        """Test successful authentication."""
        mock_response = Mock()
        mock_response.json.return_value = mock_auth_response
        mock_post.return_value = mock_response

        reporter = WizCICDReporter("test_id", "test_secret")
        token, dc = reporter.authenticate()

        assert token is not None
        assert dc == "us20"
        assert reporter.token is not None
        assert reporter.dc == "us20"

        # Check that Authorization header was set
        assert "Authorization" in reporter.headers
        assert reporter.headers["Authorization"].startswith("Bearer ")

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    def test_authenticate_missing_token(self, mock_post):
        """Test authentication with missing token in response."""
        mock_response = Mock()
        mock_response.json.return_value = {"error": "invalid_client"}
        mock_post.return_value = mock_response

        reporter = WizCICDReporter("test_id", "test_secret")

        with pytest.raises(ValueError, match="Could not retrieve token"):
            reporter.authenticate()

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    def test_authenticate_network_error(self, mock_post):
        """Test authentication with network error."""
        import requests
        mock_post.side_effect = requests.exceptions.RequestException("Network error")

        reporter = WizCICDReporter("test_id", "test_secret")

        with pytest.raises(ValueError, match="Authentication failed"):
            reporter.authenticate()

    @pytest.mark.unit
    def test_pad_base64_adds_padding(self):
        """Test that _pad_base64 adds correct padding."""
        # No padding needed
        assert WizCICDReporter._pad_base64("ABCD") == "ABCD"

        # 1 char padding
        assert WizCICDReporter._pad_base64("ABC") == "ABC="

        # 2 char padding
        assert WizCICDReporter._pad_base64("AB") == "AB=="


class TestWizCICDReporterQueryAPI:
    """Tests for query_api method."""

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    def test_query_api_success(self, mock_post, mock_wiz_api_response):
        """Test successful API query."""
        mock_response = Mock()
        mock_response.json.return_value = mock_wiz_api_response
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.dc = "us20"
        # Set token expiry to future date to pass validation
        from datetime import datetime, timedelta
        reporter.token_expiry = datetime.now() + timedelta(hours=1)

        result = reporter.query_api("query { test }", {})

        assert result == mock_wiz_api_response
        assert mock_post.called

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    @patch.object(WizCICDReporter, 'authenticate')
    def test_query_api_authenticates_if_needed(self, mock_auth, mock_post, mock_wiz_api_response):
        """Test that query_api authenticates if token is not set."""
        mock_auth.return_value = ("token", "us20")
        mock_response = Mock()
        mock_response.json.return_value = mock_wiz_api_response
        mock_post.return_value = mock_response

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.query_api("query { test }", {})

        assert mock_auth.called

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    def test_query_api_network_error(self, mock_post):
        """Test query_api with network error."""
        import requests
        from datetime import datetime, timedelta
        mock_post.side_effect = requests.exceptions.RequestException("Network error")

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.dc = "us20"
        # Set token expiry to future date to pass validation
        reporter.token_expiry = datetime.now() + timedelta(hours=1)

        with pytest.raises(ValueError, match="API query failed"):
            reporter.query_api("query { test }", {})


class TestWizCICDReporterRetryLogic:
    """Tests for retry logic with exponential backoff."""

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    @patch('wiz_cicd.reporter.time.sleep')
    def test_retry_succeeds_on_second_attempt(self, mock_sleep, mock_post):
        """Test that retry logic succeeds on second attempt."""
        from datetime import datetime, timedelta
        import requests

        # First call fails, second succeeds
        mock_response_fail = Mock()
        mock_response_fail.raise_for_status.side_effect = requests.exceptions.RequestException("Temporary error")

        mock_response_success = Mock()
        mock_response_success.json.return_value = {"data": "success"}
        mock_response_success.raise_for_status = Mock()

        mock_post.side_effect = [mock_response_fail, mock_response_success]

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.dc = "us20"
        reporter.token_expiry = datetime.now() + timedelta(hours=1)

        result = reporter.query_api("query { test }", {})

        assert result == {"data": "success"}
        assert mock_post.call_count == 2
        assert mock_sleep.call_count == 1
        mock_sleep.assert_called_with(1)  # 2^0 = 1 second backoff

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    @patch('wiz_cicd.reporter.time.sleep')
    def test_retry_handles_rate_limiting(self, mock_sleep, mock_post):
        """Test that retry logic handles 429 rate limiting."""
        from datetime import datetime, timedelta
        import requests

        # Create 429 response
        mock_response_429 = Mock()
        mock_response_429.status_code = 429
        mock_response_429.headers = {'Retry-After': '5'}
        error_429 = requests.exceptions.HTTPError(response=mock_response_429)
        mock_response_429.raise_for_status.side_effect = error_429

        # Success response
        mock_response_success = Mock()
        mock_response_success.json.return_value = {"data": "success"}
        mock_response_success.raise_for_status = Mock()

        mock_post.side_effect = [mock_response_429, mock_response_success]

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.dc = "us20"
        reporter.token_expiry = datetime.now() + timedelta(hours=1)

        result = reporter.query_api("query { test }", {})

        assert result == {"data": "success"}
        assert mock_post.call_count == 2
        mock_sleep.assert_called_with(5)  # Should respect Retry-After header

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    def test_retry_fails_on_client_error(self, mock_post):
        """Test that retry logic doesn't retry on 4xx client errors (except 429)."""
        from datetime import datetime, timedelta
        import requests

        # Create 400 response
        mock_response_400 = Mock()
        mock_response_400.status_code = 400
        error_400 = requests.exceptions.HTTPError(response=mock_response_400)
        mock_response_400.raise_for_status.side_effect = error_400

        mock_post.return_value = mock_response_400

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.dc = "us20"
        reporter.token_expiry = datetime.now() + timedelta(hours=1)

        with pytest.raises(ValueError, match="API query failed"):
            reporter.query_api("query { test }", {})

        # Should only try once (no retries on 4xx)
        assert mock_post.call_count == 1

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    @patch('wiz_cicd.reporter.time.sleep')
    def test_retry_exhausts_all_attempts(self, mock_sleep, mock_post):
        """Test that retry logic exhausts all attempts before failing."""
        from datetime import datetime, timedelta
        import requests

        # All attempts fail
        mock_response_fail = Mock()
        mock_response_fail.raise_for_status.side_effect = requests.exceptions.RequestException("Network error")
        mock_post.return_value = mock_response_fail

        reporter = WizCICDReporter("test_id", "test_secret", max_retries=3)
        reporter.token = "fake_token"
        reporter.dc = "us20"
        reporter.token_expiry = datetime.now() + timedelta(hours=1)

        with pytest.raises(ValueError, match="API query failed"):
            reporter.query_api("query { test }", {})

        # Should try 3 times
        assert mock_post.call_count == 3
        # Should sleep twice (after 1st and 2nd attempts)
        assert mock_sleep.call_count == 2
        # Check exponential backoff: 2^0=1, 2^1=2
        assert mock_sleep.call_args_list[0][0][0] == 1
        assert mock_sleep.call_args_list[1][0][0] == 2


class TestWizCICDReporterTokenManagement:
    """Tests for token expiry and refresh."""

    @pytest.mark.unit
    def test_is_token_valid_with_valid_token(self):
        """Test token validation with valid token."""
        from datetime import datetime, timedelta

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.token_expiry = datetime.now() + timedelta(hours=1)

        assert reporter._is_token_valid() is True

    @pytest.mark.unit
    def test_is_token_valid_with_expired_token(self):
        """Test token validation with expired token."""
        from datetime import datetime, timedelta

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.token_expiry = datetime.now() - timedelta(hours=1)

        assert reporter._is_token_valid() is False

    @pytest.mark.unit
    def test_is_token_valid_with_soon_to_expire_token(self):
        """Test token validation with token expiring in < 60 seconds."""
        from datetime import datetime, timedelta

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        # Expires in 30 seconds (less than 60 second buffer)
        reporter.token_expiry = datetime.now() + timedelta(seconds=30)

        assert reporter._is_token_valid() is False

    @pytest.mark.unit
    def test_is_token_valid_with_no_token(self):
        """Test token validation with no token set."""
        reporter = WizCICDReporter("test_id", "test_secret")

        assert reporter._is_token_valid() is False

    @pytest.mark.unit
    @patch('wiz_cicd.reporter.requests.post')
    @patch.object(WizCICDReporter, 'authenticate')
    def test_query_api_refreshes_expired_token(self, mock_auth, mock_post, mock_wiz_api_response):
        """Test that query_api refreshes token when expired."""
        from datetime import datetime, timedelta

        mock_auth.return_value = ("new_token", "us20")
        mock_response = Mock()
        mock_response.json.return_value = mock_wiz_api_response
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "old_token"
        reporter.dc = "us20"
        # Set expired token
        reporter.token_expiry = datetime.now() - timedelta(hours=1)

        result = reporter.query_api("query { test }", {})

        # Should call authenticate to refresh token
        assert mock_auth.called
        assert result == mock_wiz_api_response


class TestWizCICDReporterFetchScans:
    """Tests for fetch_all_scans method."""

    @pytest.mark.unit
    @patch.object(WizCICDReporter, 'query_api')
    def test_fetch_all_scans_single_page(self, mock_query, mock_wiz_api_response, mock_scans_list):
        """Test fetching scans with single page."""
        mock_query.return_value = mock_wiz_api_response

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.dc = "us20"

        scans = reporter.fetch_all_scans(verbose=False)

        assert len(scans) == len(mock_scans_list)
        assert scans == mock_scans_list
        assert reporter._raw_scans == mock_scans_list

    @pytest.mark.unit
    @patch.object(WizCICDReporter, 'query_api')
    def test_fetch_all_scans_pagination(self, mock_query, mock_wiz_api_response_paginated):
        """Test fetching scans with pagination."""
        # Mock query to return different responses for page 1 and 2
        mock_query.side_effect = [
            mock_wiz_api_response_paginated['page1'],
            mock_wiz_api_response_paginated['page2']
        ]

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.dc = "us20"

        scans = reporter.fetch_all_scans(verbose=False)

        # Should have 30 scans total (20 from page1, 10 from page2)
        assert len(scans) == 30
        assert mock_query.call_count == 2

    @pytest.mark.unit
    @patch.object(WizCICDReporter, 'query_api')
    def test_fetch_all_scans_handles_api_errors(self, mock_query):
        """Test that fetch_all_scans handles API errors gracefully."""
        mock_query.return_value = {
            'errors': [{'message': 'Some error'}],
            'data': {
                'cloudEvents': None
            }
        }

        reporter = WizCICDReporter("test_id", "test_secret")
        reporter.token = "fake_token"
        reporter.dc = "us20"

        scans = reporter.fetch_all_scans(verbose=False)

        assert len(scans) == 0


class TestWizCICDReporterDataAccess:
    """Tests for data access methods with caching."""

    @pytest.mark.unit
    def test_get_parsed_scans_uses_cache(self, mock_scans_list):
        """Test that get_parsed_scans uses cache."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        # First call parses
        parsed1 = reporter.get_parsed_scans()

        # Second call should use cache
        parsed2 = reporter.get_parsed_scans()

        assert parsed1 is parsed2  # Same object

    @pytest.mark.unit
    def test_get_parsed_scans_force_refresh(self, mock_scans_list):
        """Test that force_refresh re-parses data."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        parsed1 = reporter.get_parsed_scans()
        parsed2 = reporter.get_parsed_scans(force_refresh=True)

        # Should be different objects
        assert parsed1 is not parsed2
        # But same content
        assert len(parsed1) == len(parsed2)

    @pytest.mark.unit
    def test_get_verdict_stats_uses_cache(self, mock_scans_list):
        """Test that get_verdict_stats uses cache."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        stats1 = reporter.get_verdict_stats()
        stats2 = reporter.get_verdict_stats()

        assert stats1 is stats2

    @pytest.mark.unit
    def test_get_finding_stats_uses_cache(self, mock_scans_list):
        """Test that get_finding_stats uses cache."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        stats1 = reporter.get_finding_stats()
        stats2 = reporter.get_finding_stats()

        assert stats1 is stats2


class TestWizCICDReporterTagOperations:
    """Tests for tag extraction and filtering."""

    @pytest.mark.unit
    def test_extract_tags(self, mock_scans_list):
        """Test tag extraction from scans."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        tags = reporter.extract_tags()

        assert 'environment' in tags
        assert 'team' in tags
        assert 'github_action_run_id' in tags

        # Check values are sorted lists
        assert isinstance(tags['environment'], list)
        assert 'production' in tags['environment']
        assert 'staging' in tags['environment']
        assert 'development' in tags['environment']

    @pytest.mark.unit
    def test_extract_tags_caches(self, mock_scans_list):
        """Test that extract_tags uses cache."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        tags1 = reporter.extract_tags()
        tags2 = reporter.extract_tags()

        assert tags1 is tags2

    @pytest.mark.unit
    def test_filter_scans_by_tag_key_only(self, mock_scans_list):
        """Test filtering scans by tag key only."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        filtered = reporter.filter_scans_by_tag(tag_key="environment")

        # All 3 scans have environment tag
        assert len(filtered) == 3

    @pytest.mark.unit
    def test_filter_scans_by_tag_key_and_value(self, mock_scans_list):
        """Test filtering scans by tag key and value."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        filtered = reporter.filter_scans_by_tag(
            tag_key="environment",
            tag_value="production"
        )

        # Only mock_scan_basic has environment=production
        assert len(filtered) == 1
        assert filtered[0]['id'] == 'scan-123'

    @pytest.mark.unit
    def test_filter_scans_by_tag_value_only(self, mock_scans_list):
        """Test filtering scans by tag value only."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        filtered = reporter.filter_scans_by_tag(tag_value="backend")

        # Only mock_scan_basic has team=backend
        assert len(filtered) == 1

    @pytest.mark.unit
    def test_filter_scans_no_filter_returns_all(self, mock_scans_list):
        """Test that no filter returns all scans."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        filtered = reporter.filter_scans_by_tag()

        assert len(filtered) == len(mock_scans_list)


class TestWizCICDReporterReportGeneration:
    """Tests for report generation methods."""

    @pytest.mark.unit
    def test_generate_csv_reports_creates_files(self, mock_scans_list, tmp_path):
        """Test that generate_csv_reports creates files."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        output_dir = str(tmp_path / "test_output")
        files = reporter.generate_csv_reports(output_dir=output_dir)

        assert 'executive_summary' in files
        assert 'daily_trends' in files
        assert 'detailed_scans' in files

        # Check files exist
        import os
        for file_path in files.values():
            assert os.path.exists(file_path)

    @pytest.mark.unit
    def test_print_summary_no_errors(self, mock_scans_list, capsys):
        """Test that print_summary executes without errors."""
        reporter = WizCICDReporter("test_id", "test_secret")
        reporter._raw_scans = mock_scans_list

        reporter.print_summary()

        captured = capsys.readouterr()
        assert "EXECUTIVE SUMMARY" in captured.out
        assert "Total Scans" in captured.out
