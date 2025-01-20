# Security Analysis Report: Audit Logs Disabled
## Document ID: SEC-IR-001-AUDIT_LOGS_DISABLED

### Threat Analysis
#### MITRE ATT&CK Framework Reference
- Technique: T1562.002 - Impair Defenses: Disable Windows Event Logging
- Tactic: Defense Evasion
- Impact: Reduced ability to detect and investigate malicious activities

#### Compliance Impact
- ISO 27001: A.12.4 (Logging and Monitoring)
- NIS 2: Article 20 (Security Monitoring and Logging)
- DORA: Article 13 (ICT Risk Management)
- PCI DSS: Requirement 10 (Track and Monitor Network Access)
- SOC2: CC7.2 (Monitor System Components)

### Log Sources
1. Microsoft Windows Event Logs
   - Security Event ID 1102 (Audit log cleared)
   - System Event ID 104 (Log file cleared)

2. Network Device Logs
   - Cisco ASA: %ASA-4-713256 (Audit logging disabled)
   - Fortigate: event_id=44548 (Audit configuration changed)
   - F5 BIG-IP: Audit logging configuration changes

3. EDR/XDR Solutions
   - Microsoft Defender for Endpoint
   - CrowdStrike Falcon
   - SentinelOne

### Microsoft Sentinel KQL Query
```kql
union SecurityEvent, Event
| where EventID in (1102, 104)
    or (EventID == 4719 and TargetObject contains "Audit")
    or (EventID == 4739 and AuditPolicyChanges contains "Success" or AuditPolicyChanges contains "Failure")
| extend AccountType = iff(isempty(AccountType), "Unknown", AccountType)
| project TimeGenerated, Computer, Account, AccountType, EventID,
    Activity = case(
        EventID == 1102, "Audit log cleared",
        EventID == 104, "Security log cleared",
        EventID == 4719, "Audit policy changed",
        EventID == 4739, "Domain policy changed",
        "Unknown"
    )
| sort by TimeGenerated desc
```

### Microsoft Defender Advanced Hunting Query
```kql
union DeviceEvents, DeviceRegistryEvents
| where (ActionType == "AuditPolicyModification" or ActionType == "AuditLogCleared")
    or (RegistryValueName contains "Audit" and RegistryValueData == "0")
| project Timestamp, DeviceName, ActionType, AccountName, 
    RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessCommandLine, InitiatingProcessFolderPath
| sort by Timestamp desc
```

### Incident Response Steps for Security Analysts
1. Initial Assessment
   - Verify alert authenticity
   - Document timestamp and affected systems
   - Identify the account used to disable logging

2. Containment
   - Isolate affected systems if necessary
   - Re-enable audit logging immediately
   - Document any gaps in logging coverage

3. Investigation
   - Review surrounding events before logging disabled
   - Check for other suspicious activities
   - Analyze authentication logs for unauthorized access
   - Investigate lateral movement attempts

4. Recovery
   - Restore logging configurations
   - Verify logging functionality
   - Document incident timeline
   - Update monitoring rules if needed

### IT Team Instructions
1. Immediate Actions
   ```powershell
   # Re-enable Security Auditing
   auditpol /set /category:* /success:enable /failure:enable
   
   # Verify Windows Event Log service is running
   Get-Service EventLog | Start-Service
   
   # Configure log size and retention
   wevtutil sl Security /ms:1073741824
   ```

2. System Hardening
   - Implement Group Policy to enforce audit policies
   - Enable protected event logging
   - Configure centralized logging
   - Implement SIEM forwarding

3. Access Control
   - Review and restrict audit configuration permissions
   - Implement change control for logging modifications
   - Document authorized changes

4. Monitoring Enhancement
   - Deploy file integrity monitoring
   - Enable PowerShell logging
   - Configure alerts for logging changes