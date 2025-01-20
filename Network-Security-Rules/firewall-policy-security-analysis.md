# Firewall Policy Change - Security Analysis and Response Procedure

## Threat Analysis & Framework Mapping

### MITRE ATT&CK
- **Technique ID**: T1562.004 - Disable/Modify Firewall
- **Tactics**: Defense Evasion
- **Sub-techniques**: Modify firewall rules, Add firewall exceptions

### Compliance Framework Relevance
- **ISO 27001**: Controls A.13.1.1 (Network Controls), A.12.1.2 (Change Management)
- **NIS 2**: Article 21 - Security measures for network and information systems
- **DORA**: Article 13 - ICT Risk Management
- **PCI DSS**: Requirement 1 (Install and maintain network security controls)
- **SOC 2**: CC6.1, CC6.7 (Logical Access, System Operations)

## Log Sources & Monitoring

### Vendor-Specific Log Sources

#### Cisco ASA
```
%ASA-5-111008: User 'admin' executed the 'configure' command.
%ASA-5-111010: User 'admin', running 'CLI' from IP 10.0.0.1, executed 'access-list inside_access_in line 1 extended permit ip any any'
```

#### Fortinet FortiGate
```
action=modify cfgpath="firewall policy" cfgobj=1 msg="Edit firewall policy 1" user=admin ui=gui
```

#### F5 BIG-IP
```
tmsh[pid]: 01420002:5: AUDIT - pid(PID):User admin - client IP - modify { fw_rule { name "RULE_1" } }
```

## Detection Queries

### Microsoft Sentinel KQL Query
```kql
let timeframe = 1h;
union 
    (CommonSecurityLog
    | where TimeGenerated > ago(timeframe)
    | where DeviceVendor in ("Cisco", "Fortinet", "F5")
    | where Activity contains "policy" or Activity contains "firewall"
    | where Activity contains "modify" or Activity contains "change" or Activity contains "update"
    ),
    (AuditLogs
    | where TimeGenerated > ago(timeframe)
    | where Category == "Firewall"
    | where OperationName contains "Update" or OperationName contains "Modify"
    )
| project TimeGenerated, DeviceVendor, Activity, SourceUserID, SourceIP

```

### Microsoft Defender Advanced Hunting Query
```kql
let timeframe = 1h;
DeviceEvents
| where Timestamp > ago(timeframe)
| where ActionType in ("FirewallRuleModified", "FirewallPolicyChanged")
| extend RuleDetails = parse_json(AdditionalFields)
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, 
    RuleName = RuleDetails.RuleName,
    RuleDirection = RuleDetails.Direction,
    RuleAction = RuleDetails.Action
```

## Incident Response Flowchart

1. **Initial Detection & Triage** (0-15 minutes)
   - Validate alert authenticity
   - Identify affected firewall(s)
   - Document policy changes

2. **Impact Assessment** (15-30 minutes)
   - Compare changes against approved change requests
   - Assess potential security impact
   - Identify affected systems/services

3. **Containment & Investigation** (30-60 minutes)
   - If unauthorized:
     - Document current state
     - Revert unauthorized changes
     - Preserve evidence
   - If authorized:
     - Validate implementation
     - Update documentation

4. **Resolution & Recovery**
   - Implement additional monitoring
   - Update baseline configuration
   - Document incident timeline

## IT Team Instructions

### Immediate Actions
1. DO NOT immediately revert changes without analysis
2. Take screenshots/export of current firewall configuration
3. Compare against last known good configuration
4. Document all changes in detail

### Analysis Steps
1. Review change management tickets
2. Verify source IP of changes
3. Validate admin credentials used
4. Check for concurrent suspicious activities

### If Unauthorized Change Detected
1. Notify Security Team immediately
2. Do not delete or modify logs
3. Take network captures if possible
4. Stand by for further instructions

### Documentation Requirements
- Change timestamp
- Admin account used
- Source IP address
- Specific rules modified
- Before/After configuration
- Associated ticket number (if exists)

## Risk Mitigation Recommendations

1. Implement change control procedures
2. Enable multi-factor authentication
3. Use jump boxes for admin access
4. Regular configuration backups
5. Automated compliance checking