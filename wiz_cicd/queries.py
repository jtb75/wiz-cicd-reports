"""
Wiz API GraphQL queries and variables for CI/CD scanning data.

This module contains the query definitions and variables used to fetch
pipeline scanning data from the Wiz API.
"""


def create_time_filter_variables(days=None, hours=None):
    """
    Create query variables with custom time filter.

    Args:
        days: Number of days to look back (default: 30)
        hours: Number of hours to look back (overrides days if provided)

    Returns:
        Dictionary of query variables with time filter applied

    Examples:
        >>> create_time_filter_variables(days=1)  # Last 24 hours
        >>> create_time_filter_variables(hours=6)  # Last 6 hours
        >>> create_time_filter_variables(days=7)  # Last 7 days
    """
    # Default to 30 days if nothing specified
    if days is None and hours is None:
        days = 30

    # Determine unit and amount
    if hours is not None:
        amount = hours
        unit = "DurationFilterValueUnitHours"
    else:
        amount = days
        unit = "DurationFilterValueUnitDays"

    variables = {
        "first": 20,
        "filterBy": {
            "and": [
                {
                    "timestamp": {
                        "inLast": {
                            "amount": amount,
                            "unit": unit
                        }
                    },
                    "origin": {
                        "equals": [
                            "WIZ_CLI"
                        ]
                    },
                    "kind": {
                        "equals": [
                            "CI_CD_SCAN"
                        ]
                    }
                },
                {
                    "or": [
                        {
                            "resource": {}
                        },
                        {
                            "resource": {}
                        }
                    ]
                },
                {
                    "or": [
                        {
                            "cicdScan": {
                                "vulnerabilityFindingCount": {}
                            }
                        },
                        {
                            "cicdScan": {
                                "iacFindingCount": {}
                            }
                        },
                        {
                            "cicdScan": {
                                "secretFindingCount": {}
                            }
                        },
                        {
                            "cicdScan": {
                                "dataFindingCount": {}
                            }
                        },
                        {
                            "cicdScan": {
                                "hostConfigurationFindingCount": {}
                            }
                        },
                        {
                            "cicdScan": {
                                "malwareFindingCount": {}
                            }
                        },
                        {
                            "cicdScan": {
                                "softwareSupplyChainFindingCount": {}
                            }
                        },
                        {
                            "cicdScan": {
                                "sastFindingCount": {}
                            }
                        }
                    ]
                },
                {
                    "cicdScan": {
                        "resourceType": {},
                        "verdict": {},
                        "type": {},
                        "state": {},
                        "severities": {},
                        "hasTriggerableRemediation": {},
                        "hasFindingsIgnoredByCommentException": {}
                    }
                },
                {}
            ]
        },
        "includeCount": False
    }

    return variables


WIZ_CODE_ANALYZER_QUERY = """
    query CodeCICDScansTable($after: String, $first: Int, $filterBy: CloudEventFilters, $groupBy: CloudEventGroupBy, $orderDirection: OrderDirection, $projectId: [String!], $includeCount: Boolean!) {
      cloudEvents(
        filterBy: $filterBy
        first: $first
        after: $after
        groupBy: $groupBy
        orderDirection: $orderDirection
        projectId: $projectId
      ) {
        nodes {
          ... on CloudEventGroupByResult {
            values
            count: countV2 @include(if: $includeCount)
            cloudEvents {
              id
              timestamp
              cloudPlatform
              category
              hash
              kind
              externalName
              origin
              path
              actor {
                email
                type
                name
                id
                userAgent
                providerUniqueId
              }
              subjectResource {
                id
                type
                externalId
                name
                nativeType
                region
                cloudAccount {
                  id
                  externalId
                }
                kubernetesCluster {
                  id
                  name
                  type
                }
                vcsRepository {
                  id
                  name
                }
                openToAllInternet
              }
              matchedRules {
                rule {
                  builtInId
                  name
                  id
                }
              }
              extraDetails {
                ...CloudEventCICDScanDetailsExtraDetails
              }
            }
          }
          ... on CloudEvent {
            id
            timestamp
            kind
            origin
            cloudPlatform
            subjectResource {
              id
              name
              type
              vcsRepository {
                id
                name
              }
            }
            actor {
              email
              type
              name
              id
              userAgent
              providerUniqueId
            }
            extraDetails {
              ... on CloudEventCICDScanDetails {
                ...CloudEventCICDScanDetailsExtraDetails
              }
            }
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
        totalCount @include(if: $includeCount)
        maxCountReached
      }
    }
    
        fragment CloudEventCICDScanDetailsExtraDetails on CloudEventCICDScanDetails {
      trigger
      tags {
        key
        value
      }
      policies {
        __typename
        id
        name
        params {
          __typename
        }
      }
      createdBy {
        serviceAccount {
          id
          name
        }
      }
      cliDetails {
        scanOriginResourceType
        clientVersion
      }
      malwareDetails {
        analytics {
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
          totalCount
        }
      }
      analytics {
        vulnerabilityScanResultAnalytics {
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
        }
        dataScanResultAnalytics {
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
        }
        iacScanResultAnalytics {
          infoCount: infoMatches
          lowCount: lowMatches
          mediumCount: mediumMatches
          highCount: highMatches
          criticalCount: criticalMatches
        }
        secretScanResultAnalytics {
          cloudKeyCount
          dbConnectionStringCount
          gitCredentialCount
          passwordCount
          privateKeyCount
          saasAPIKeyCount
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
          totalCount
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
        }
        sastScanResultAnalytics {
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
        }
      }
      status {
        details
        state
        verdict
      }
      codeAnalyzerDetails {
        pullRequest {
          infoURL
          title
        }
      }
      infoMatches
      lowMatches
      mediumMatches
      highMatches
      criticalMatches
      hasTriggerableRemediation
    }
"""

WIZ_CODE_ANALYZER_VARIABLES = {
  "first": 20,
  "filterBy": {
    "and": [
      {
        "timestamp": {
          "inLast": {
            "amount": 30,
            "unit": "DurationFilterValueUnitDays"
          }
        },
        "origin": {
          "equals": [
            "WIZ_CLI"
          ]
        },
        "kind": {
          "equals": [
            "CI_CD_SCAN"
          ]
        }
      },
      {
        "or": [
          {
            "resource": {}
          },
          {
            "resource": {}
          }
        ]
      },
      {
        "or": [
          {
            "cicdScan": {
              "vulnerabilityFindingCount": {}
            }
          },
          {
            "cicdScan": {
              "iacFindingCount": {}
            }
          },
          {
            "cicdScan": {
              "secretFindingCount": {}
            }
          },
          {
            "cicdScan": {
              "dataFindingCount": {}
            }
          },
          {
            "cicdScan": {
              "hostConfigurationFindingCount": {}
            }
          },
          {
            "cicdScan": {
              "malwareFindingCount": {}
            }
          },
          {
            "cicdScan": {
              "softwareSupplyChainFindingCount": {}
            }
          },
          {
            "cicdScan": {
              "sastFindingCount": {}
            }
          }
        ]
      },
      {
        "cicdScan": {
          "resourceType": {},
          "verdict": {},
          "type": {},
          "state": {},
          "severities": {},
          "hasTriggerableRemediation": {},
          "hasFindingsIgnoredByCommentException": {}
        }
      },
      {}
    ]
  },
  "includeCount": False
}