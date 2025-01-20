# Security Analysis: Permissive Rules Detection

## Framework Alignments

### MITRE ATT&CK
- Initial Access (TA0001)
- Defense Evasion (TA0005)
- Persistence (TA0003)
- Technique: Access Policy Modification (T1484)

### ISO 27001 Controls
- A.9.1.1 Access Control Policy
- A.9.4.1 Information Access Restriction
- A.12.4 Logging and Monitoring

### NIS 2 Compliance
- Article 21: Risk Management Measures
- Network Access Control and Configuration Management
- Regular Security Assessments

### DORA Requirements
- ICT Risk Management
- Security Configuration Management
- Incident Reporting Requirements

### PCI DSS Requirements
- Requirement 7: Restrict Access
- Requirement 10: Monitor Network Resources
- Requirement 1: Install and Maintain Network Security Controls

### SOC 2 Controls
- CC6.1: Logical Access Security
- CC7.1: Change Management
- CC7.2: Incident Response

## Log Sources & Detection Methods

### Firewall Logs
1. Cisco ASA
   - Syslog facility: LOCAL4
   - Key logs: %ASA-6-302013, %ASA-6-302015, %ASA-4-106023
   
2. Fortinet FortiGate
   - Log Type: traffic, event, security
   - Key logs: action=accept, logid="0316013056"
   
3. F5 BIG-IP
   - Log facility: security, traffic, audit
   - Key events: "Policy Modified", "Rule Added"

### Cloud Platform Logs
- Azure Activity Logs
- AWS CloudTrail
- GCP Audit Logs

## Detection Queries

### Microsoft Sentinel KQL Query
```kql
let timeframe = 24h;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID in ("4670", "4663", "4656")
| where ObjectName contains "firewall"
    or ObjectName contains "security policy"
    or ObjectName contains "network rules"
| project TimeGenerated, Account, ObjectName, 
    Activity, Computer
| join kind=leftouter (
    AuditLogs
    | where TimeGenerated > ago(timeframe)
    | where OperationName contains "Update policy"
    | project InitiatedBy, TargetResources
)
on $left.Account == $right.InitiatedBy
| summarize count() by Account, bin(TimeGenerated, 1h)
| where count_ > 10
```

### Microsoft Defender Advanced Hunting Query
```kql
let lookback = 48h;
DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FirewallRuleModified", 
    "NetworkSecurityGroupModified")
| join kind=inner (
    DeviceNetworkEvents
    | where RemotePort in ("22", "3389", "445", "139")
    | where ActionType == "ConnectionSuccess"
)
on DeviceId
| summarize AllowedConnections=count() 
    by DeviceId, InitiatingProcessAccountName
| where AllowedConnections > threshold
```

## Configuration Monitoring
- Network Security Group (NSG) Flow Logs
- Windows Firewall Logs
- Security Group Change Monitoring
- IAM Policy Changes