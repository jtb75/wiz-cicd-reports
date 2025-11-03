# Test Suite

Comprehensive test suite for the Wiz CI/CD reporting system using pytest.

## Test Coverage

**Current Status: 40 tests, 100% passing**

- **data_processor.py**: 98% coverage
- **wiz_reporter.py**: 94% coverage
- **Overall**: 65% coverage (core modules at 94%+)

## Running Tests

### Run All Tests

```bash
pytest tests/
```

### Run with Verbose Output

```bash
pytest tests/ -v
```

### Run with Coverage Report

```bash
pytest tests/ --cov=. --cov-report=html
```

Then open `htmlcov/index.html` in a browser to see detailed coverage.

### Run Specific Test File

```bash
pytest tests/test_data_processor.py -v
```

### Run Specific Test Class or Function

```bash
pytest tests/test_wiz_reporter.py::TestWizCICDReporterAuthentication -v
pytest tests/test_data_processor.py::TestParseScanData::test_parse_single_scan -v
```

### Run Only Unit Tests

```bash
pytest tests/ -m unit
```

## Test Structure

### conftest.py
Shared fixtures and test configuration:
- `mock_scan_basic` - Basic passing scan
- `mock_scan_with_iac` - Scan with IaC findings
- `mock_scan_failed` - Failed scan with many findings
- `mock_scans_list` - List of varied scans
- `mock_wiz_api_response` - Mock API response
- `mock_auth_response` - Mock authentication response

### test_data_processor.py
Tests for data parsing and analysis:
- **TestParseScanData** (5 tests)
  - Single scan parsing
  - IaC scan parsing
  - Multiple scans
  - Null field handling
  - Severity calculations

- **TestCalculateVerdictStats** (3 tests)
  - Single passed scan stats
  - Multiple scans stats
  - Empty list handling

- **TestCalculateFindingTypeStats** (3 tests)
  - Single scan findings
  - Multiple scans aggregation
  - Empty list handling

- **TestCalculateDailyTrends** (4 tests)
  - Single day trends
  - Daily aggregation
  - Empty list
  - Severity counts

### test_wiz_reporter.py
Tests for WizCICDReporter class:
- **TestWizCICDReporterInit** (3 tests)
  - Credential initialization
  - Header configuration
  - Cache initialization

- **TestWizCICDReporterAuthentication** (4 tests)
  - Successful authentication
  - Missing token handling
  - Network error handling
  - Base64 padding

- **TestWizCICDReporterQueryAPI** (3 tests)
  - Successful queries
  - Auto-authentication
  - Network error handling

- **TestWizCICDReporterFetchScans** (3 tests)
  - Single page fetching
  - Pagination handling
  - API error handling

- **TestWizCICDReporterDataAccess** (4 tests)
  - Cache usage
  - Force refresh
  - Stats caching

- **TestWizCICDReporterTagOperations** (6 tests)
  - Tag extraction
  - Tag caching
  - Filter by key only
  - Filter by key and value
  - Filter by value only
  - No filter returns all

- **TestWizCICDReporterReportGeneration** (2 tests)
  - CSV file generation
  - Summary printing

## Test Markers

Tests are marked with the following categories:

- `@pytest.mark.unit` - Fast unit tests (no external dependencies)
- `@pytest.mark.integration` - Integration tests (may require API credentials)
- `@pytest.mark.slow` - Slow-running tests

Run specific categories:
```bash
pytest -m unit          # Only unit tests
pytest -m "not slow"    # Exclude slow tests
```

## Writing New Tests

### Basic Test Template

```python
import pytest
from wiz_reporter import WizCICDReporter

class TestYourFeature:
    """Tests for your feature."""

    @pytest.mark.unit
    def test_basic_functionality(self, mock_scan_basic):
        """Test basic functionality."""
        # Arrange
        reporter = WizCICDReporter("test_id", "test_secret")

        # Act
        result = reporter.some_method()

        # Assert
        assert result is not None
```

### Using Fixtures

```python
@pytest.mark.unit
def test_with_fixture(self, mock_scans_list):
    """Test using a fixture."""
    # mock_scans_list is automatically provided
    assert len(mock_scans_list) == 3
```

### Mocking API Calls

```python
@pytest.mark.unit
@patch.object(WizCICDReporter, 'query_api')
def test_with_mock(self, mock_query, mock_wiz_api_response):
    """Test with mocked API."""
    mock_query.return_value = mock_wiz_api_response

    reporter = WizCICDReporter("test_id", "test_secret")
    result = reporter.fetch_all_scans(verbose=False)

    assert mock_query.called
```

## Continuous Integration

Add to your CI/CD pipeline:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    pip install -r requirements.txt
    pytest tests/ -v --cov=. --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

## Coverage Goals

- **Core modules (wiz_reporter, data_processor)**: 90%+
- **Overall project**: 80%+
- **Critical paths**: 100%

## Known Limitations

- Scripts (generate_*.py, get_*.py) have 0% coverage as they're entry points
- Integration tests with real API are not included (require credentials)
- HTML generation code is tested functionally but not unit tested

## Future Test Enhancements

- [ ] Add integration tests with real Wiz API (optional, credential-gated)
- [ ] Add performance tests for large datasets
- [ ] Add tests for HTML dashboard generation
- [ ] Add property-based tests with hypothesis
- [ ] Add mutation testing with mutpy
