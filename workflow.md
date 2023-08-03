# Workflow

- Get Queries
  - For every query ID:
    - Get rule Info
        - "IsEnabled": false, "IsDeleted": false
          - Get Query Text
            - Generate Post Data
              - Check time statement in query
              - Calculate 30 day before timestamp
          - Run Query
          - Check result
            - Results are empty
              - Enable Query
            - Results are not empty
              - Add rule to edit list
        - Else
          - Continue
- Print activated rule count
- Print passed rule count
- Print edit list

## Get Queries

```text
Request URL     : https://security.microsoft.com/apiproxy/mtp/huntingService/queries/?type=scheduled
Request Method  : GET
```

```text
Response        :
[
    {
        "Id": 30002,
        "UserId": null,
        "Path": "",
        "Name": "\"Clear Bash History\" Activity",
        "IsReadOnly": false,
        "IsGuided": false
    },
    {
        "Id": 30003,
        "UserId": null,
        "Path": "",
        "Name": "\"Defense Evasion - Signed Binary Proxy Execution  - rasautou.exe\"",
        "IsReadOnly": false,
        "IsGuided": false
    }, ...
]
```

## Get Query Text

```text
Request URL     : https://security.microsoft.com/apiproxy/mtp/huntingService/queries/{query_id}
Request Method  : GET
```

```text
{
    "FunctionUsages": null,
    "QueryText": "DeviceFileEvents\r\n| where Timestamp > ago(3d)\r\n| where InitiatingProcessFileName contains \"rm\"\r\n| where FileName contains \".bash_history\"",
    "DashboardQueryProperties": null,
    "IsScheduled": true,
    "IsDeleted": false,
    "IsMdatp": true,
    "BitwiseProducts": 1,
    "GuidedQueryObjectJson": null,
    "GuidedQuery": null,
    "Id": 30002,
    "UserId": null,
    "Path": "",
    "Name": "\"Clear Bash History\" Activity",
    "IsReadOnly": false,
    "IsGuided": false
}
```

## Run Query

```text
Request URL     : https://security.microsoft.com/apiproxy/mtp/huntingService/queryExecutor
Request Method  : POST
```

```text
Post Data       :
{
  "QueryText": "DeviceProcessEvents\r\n| where Timestamp > ago(3d)\r\n| where FileName == \"rasautou.exe\"\r\n| where ProcessCommandLine contains \"-p\"\r\n| where ProcessCommandLine contains \"-d\"",
  "StartTime": null,
  "EndTime": "2023-07-26T15:31:18.773Z",
  "MaxRecordCount": null,
  "TenantIds": null
}
```

```text
Response        :
{
    "Quota": {
        "QueryCpuUsage": 0.0,
        "CpuLoad": 0,
        "ExecutionTime": "00:00:00.0312104",
        "TotalCpuTime": "00:00:00.0156250"
    },
    "ChartVisualization": {
        "ChartType": "None"
    },
    "Schema": [],
    "Results": []
}
```

## Get rule Info

```text
Request URL     : https://security.microsoft.com/apiproxy/mtp/huntingService/rules/byquery/{query_id}?tenantIds={tenant_id}
Request Method  : GET
```

```text
Response:

{
    "Id": 23,
    "OrgId": "df803bf6-690e-4442-a529-9fa711b6a2e8",
    "QueryId": 30002,
    "IoaDefinitionId": "72ae707b-a88f-4ba6-8dc6-73658f36aede",
    "Name": "\"Clear Bash History\" Activity",
    "Title": "\"Clear Bash History\" Activity",
    "Severity": 256,
    "Category": "SuspiciousActivity",
    "Description": "\"Clear Bash History\" Activity",
    "RecommendedAction": null,
    "LastRunTime": null,
    "NextRunTime": "2023-07-03T10:25:27.9832476Z",
    "CreatedBy": "tyrel.wellick@e-corp.onmicrosoft.com",
    "CreationTime": "2023-07-03T10:25:27.9832476Z",
    "LastUpdatedTime": "2023-07-07T12:48:38.0685144Z",
    "LastQueryUpdateTime": null,
    "LastUpdatedBy": "tyrel.wellick@e-corp.onmicrosoft.com",
    "IntervalHours": 0,
    "ThreatId": null,
    "HuntingQuery": null,
    "CustomActions": [
        {
            "ActionType": 3,
            "Entities": [
                {
                    "EntityType": "Machine",
                    "EntityIdField": "DeviceId",
                    "EntityNameField": null
                }
            ]
        }
    ],
    "ImpactedEntities": [
        {
            "EntityType": "Machine",
            "EntityIdentifiers": [
                "DeviceId"
            ]
        },
        {
            "EntityType": "User",
            "EntityIdentifiers": [
                "InitiatingProcessAccountObjectId"
            ]
        }
    ],
    "MitreTechniques": [],
    "RbacGroupIds": "",
    "IsEnabled": true,
    "IsDeleted": false,
    "LastRunStatus": null,
    "LastRunFailureReason": null,
    "LastRunErrorCode": null,
    "IsMdatp": true,
    "BitwiseProducts": 1,
    "LastProcessingTime": null,
    "MtpWorkloads": [
        1
    ],
    "ServiceSources": [
        1
    ]
}
```

## Enable Query

```text
Request URL     : https://security.microsoft.com/apiproxy/mtp/huntingService/rules/status
Request Method  : PATCH
```

```text
{"RuleIds":[24],"IsEnabled":true}
```
