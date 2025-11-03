"""
Pytest configuration and shared fixtures.
"""

import sys
from pathlib import Path

# Add parent directory to path so we can import wiz_cicd
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import json
from datetime import datetime, timedelta


@pytest.fixture
def mock_scan_basic():
    """Basic mock scan data."""
    return {
        'id': 'scan-123',
        'timestamp': '2025-11-02T10:00:00Z',
        'kind': 'CI_CD_SCAN',
        'origin': 'WIZ_CLI',
        'cloudPlatform': 'GitHub Actions',
        'subjectResource': {
            'id': 'resource-456',
            'name': 'test-app',
            'type': 'CONTAINER_IMAGE'
        },
        'actor': {
            'email': 'test@example.com',
            'name': 'Test User',
            'type': 'USER_ACCOUNT'
        },
        'extraDetails': {
            'status': {
                'state': 'SUCCESS',
                'verdict': 'PASSED_BY_POLICY'
            },
            'cliDetails': {
                'scanOriginResourceType': 'CONTAINER_IMAGE',
                'clientVersion': '0.103.0'
            },
            'analytics': {
                'vulnerabilityScanResultAnalytics': {
                    'criticalCount': 1,
                    'highCount': 5,
                    'mediumCount': 10,
                    'lowCount': 15,
                    'infoCount': 2
                },
                'secretScanResultAnalytics': {
                    'criticalCount': 0,
                    'highCount': 1,
                    'mediumCount': 0,
                    'lowCount': 0,
                    'infoCount': 0,
                    'totalCount': 1
                },
                'iacScanResultAnalytics': None,
                'sastScanResultAnalytics': {
                    'criticalCount': 0,
                    'highCount': 0,
                    'mediumCount': 0,
                    'lowCount': 0,
                    'infoCount': 0
                },
                'dataScanResultAnalytics': {
                    'criticalCount': 0,
                    'highCount': 0,
                    'mediumCount': 0,
                    'lowCount': 0,
                    'infoCount': 0
                }
            },
            'tags': [
                {'key': 'environment', 'value': 'production'},
                {'key': 'team', 'value': 'backend'}
            ]
        }
    }


@pytest.fixture
def mock_scan_with_iac():
    """Mock scan with IaC findings."""
    return {
        'id': 'scan-789',
        'timestamp': '2025-11-01T15:30:00Z',
        'kind': 'CI_CD_SCAN',
        'origin': 'WIZ_CLI',
        'cloudPlatform': 'Wiz',
        'subjectResource': {
            'id': 'resource-789',
            'name': 'infrastructure',
            'type': 'IAC_RESOURCE_DECLARATION'
        },
        'actor': {
            'email': 'devops@example.com',
            'name': 'DevOps Team',
            'type': 'SERVICE_ACCOUNT'
        },
        'extraDetails': {
            'status': {
                'state': 'SUCCESS',
                'verdict': 'WARN_BY_POLICY'
            },
            'cliDetails': {
                'scanOriginResourceType': 'IAC',
                'clientVersion': '0.103.0'
            },
            'analytics': {
                'vulnerabilityScanResultAnalytics': {
                    'criticalCount': 0,
                    'highCount': 0,
                    'mediumCount': 0,
                    'lowCount': 0,
                    'infoCount': 0
                },
                'secretScanResultAnalytics': {
                    'criticalCount': 0,
                    'highCount': 0,
                    'mediumCount': 0,
                    'lowCount': 0,
                    'infoCount': 0,
                    'totalCount': 0
                },
                'iacScanResultAnalytics': {
                    'criticalCount': 2,
                    'highCount': 8,
                    'mediumCount': 20,
                    'lowCount': 5,
                    'infoCount': 1
                },
                'sastScanResultAnalytics': {
                    'criticalCount': 0,
                    'highCount': 0,
                    'mediumCount': 0,
                    'lowCount': 0,
                    'infoCount': 0
                },
                'dataScanResultAnalytics': {
                    'criticalCount': 0,
                    'highCount': 0,
                    'mediumCount': 0,
                    'lowCount': 0,
                    'infoCount': 0
                }
            },
            'tags': [
                {'key': 'environment', 'value': 'staging'},
                {'key': 'team', 'value': 'infrastructure'}
            ]
        }
    }


@pytest.fixture
def mock_scan_failed():
    """Mock scan with FAILED verdict."""
    return {
        'id': 'scan-failed',
        'timestamp': '2025-11-02T08:00:00Z',
        'kind': 'CI_CD_SCAN',
        'origin': 'WIZ_CLI',
        'cloudPlatform': 'GitHub Actions',
        'subjectResource': {
            'id': 'resource-fail',
            'name': 'vulnerable-app',
            'type': 'CONTAINER_IMAGE'
        },
        'actor': {
            'email': 'dev@example.com',
            'name': 'Developer',
            'type': 'USER_ACCOUNT'
        },
        'extraDetails': {
            'status': {
                'state': 'SUCCESS',
                'verdict': 'FAILED_BY_POLICY'
            },
            'cliDetails': {
                'scanOriginResourceType': 'CONTAINER_IMAGE',
                'clientVersion': '0.103.0'
            },
            'analytics': {
                'vulnerabilityScanResultAnalytics': {
                    'criticalCount': 10,
                    'highCount': 25,
                    'mediumCount': 30,
                    'lowCount': 20,
                    'infoCount': 5
                },
                'secretScanResultAnalytics': {
                    'criticalCount': 0,
                    'highCount': 3,
                    'mediumCount': 1,
                    'lowCount': 0,
                    'infoCount': 0,
                    'totalCount': 4
                },
                'iacScanResultAnalytics': None,
                'sastScanResultAnalytics': {
                    'criticalCount': 2,
                    'highCount': 5,
                    'mediumCount': 3,
                    'lowCount': 1,
                    'infoCount': 0
                },
                'dataScanResultAnalytics': {
                    'criticalCount': 1,
                    'highCount': 2,
                    'mediumCount': 0,
                    'lowCount': 0,
                    'infoCount': 0
                }
            },
            'tags': [
                {'key': 'environment', 'value': 'development'},
                {'key': 'github_action_run_id', 'value': '12345'}
            ]
        }
    }


@pytest.fixture
def mock_scans_list(mock_scan_basic, mock_scan_with_iac, mock_scan_failed):
    """List of mock scans for testing."""
    return [mock_scan_basic, mock_scan_with_iac, mock_scan_failed]


@pytest.fixture
def mock_wiz_api_response(mock_scans_list):
    """Mock Wiz API response structure."""
    return {
        'data': {
            'cloudEvents': {
                'nodes': mock_scans_list,
                'pageInfo': {
                    'hasNextPage': False,
                    'endCursor': None
                },
                'totalCount': len(mock_scans_list),
                'maxCountReached': False
            }
        }
    }


@pytest.fixture
def mock_wiz_api_response_paginated():
    """Mock Wiz API response with pagination."""
    return {
        'page1': {
            'data': {
                'cloudEvents': {
                    'nodes': [{'id': f'scan-{i}'} for i in range(20)],
                    'pageInfo': {
                        'hasNextPage': True,
                        'endCursor': 'cursor-1'
                    }
                }
            }
        },
        'page2': {
            'data': {
                'cloudEvents': {
                    'nodes': [{'id': f'scan-{i}'} for i in range(20, 30)],
                    'pageInfo': {
                        'hasNextPage': False,
                        'endCursor': None
                    }
                }
            }
        }
    }


@pytest.fixture
def mock_auth_response():
    """Mock authentication response."""
    import base64

    # Create a mock JWT payload
    payload = {
        'dc': 'us20',
        'exp': (datetime.now() + timedelta(hours=1)).timestamp()
    }

    # Create a fake JWT (header.payload.signature)
    header = base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode()
    payload_encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    signature = base64.b64encode(b'fake-signature').decode()

    fake_token = f"{header}.{payload_encoded}.{signature}"

    return {
        'access_token': fake_token,
        'token_type': 'Bearer',
        'expires_in': 3600
    }
