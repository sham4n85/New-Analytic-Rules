# Unauthorized Firewall Access Attempt - L1 Analysis and Response

## 1. Incident Overview

### MITRE ATT&CK Mapping
- Technique: T1078 - Valid Accounts
- Tactic: Initial Access (TA0001)
- Sub-technique: T1078.002 - Domain Accounts

### Regulatory Impact
- ISO 27001: A.9.2.1 (User registration and de-registration)
- NIS 2: Article 21 (Access Control Measures)
- PCI DSS: Requirement 7.1, 7.2 (Access Control)
- SOC2: CC6.1 (Logical Access Security)

## 2. Detection Queries

### Microsoft Sentinel KQL Query
```kql
// Detect unauthorized firewall access attempts
let threshold = 3; // Adjust based on environment
SecurityEvent
| where EventID in (4625, 4771)
| where TargetAccount endswith "-fw" or TargetAccount contains "firewall"
    or Computer contains "fw" or Computer contains "firewall"
| extend SourceIPAddress = case(
    EventID == 4625, extract("Source Network Address:\\s+([^\\s]+)", 1, RenderedDescription),
    EventID == 4771, IpAddress,
    "")
| where isnotempty(SourceIPAddress)
| summarize 
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    FailedAttempts = count(),
    LastFailedLocation = any(WorkstationName),
    LastFailedIP = any(SourceIPAddress)
    by TargetAccount, Computer
| where FailedAttempts >= threshold
| extend TimeDelta = EndTime - StartTime
| extend AttemptsPerMinute = FailedAttempts / (totimespan(TimeDelta) / 1m)
| project
    StartTime,
    EndTime,
    TargetAccount,
    Computer,
    FailedAttempts,
    AttemptsPerMinute,
    LastFailedLocation,
    LastFailedIP
| order by FailedAttempts desc
```

### Microsoft Defender Advanced Hunting Query
```kql
// Monitor suspicious firewall management access
DeviceNetworkEvents
| where RemotePort in (22, 443, 8443) // Common firewall management ports
| where InitiatingProcessFileName !in ("svchost.exe", "System")
| where TimeGenerated > ago(1h)
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    RemoteIP,
    RemotePort,
    Protocol
| join kind=leftouter (
    DeviceInfo
    | project DeviceName, DeviceType
) on DeviceName
| where DeviceType contains "firewall" or DeviceName contains "fw"
```

## 3. Incident Response Procedure

### Initial Assessment (0-15 minutes)
1. Validate alert authenticity
   - Confirm source IP and target system
   - Verify timestamp and access patterns
   - Check for concurrent alerts

2. Quick Response Actions
   - Block source IP at perimeter
   - Enable enhanced logging
   - Notify security team lead

### Investigation Phase (15-60 minutes)
1. Access Analysis
   - Review authentication logs
   - Check for related access attempts
   - Analyze source IP reputation

2. Scope Assessment
   - Identify affected systems
   - Check for successful access
   - Review configuration changes

3. Evidence Collection
   - Export relevant logs
   - Capture network traffic
   - Document timeline

### Remediation Steps (1-4 hours)
1. Immediate Actions
   - Reset affected credentials
   - Update access control lists
   - Implement additional monitoring

2. System Hardening
   - Review firewall rules
   - Update authentication policies
   - Implement geo-blocking if applicable

### Recovery & Prevention
1. System Updates
   - Apply security patches
   - Update access policies
   - Implement MFA if not present

2. Documentation
   - Update incident report
   - Record remediation steps
   - Update security procedures

## 4. Metrics & Reporting

### Key Metrics
- Time to Detection
- Time to Response
- Number of Affected Systems
- Success/Failure Ratio
- Geographic Origin of Attempts

### Required Documentation
1. Initial Incident Report
   - Timestamp of detection
   - Systems affected
   - Initial response actions
   - Preliminary impact assessment

2. Investigation Report
   - Detailed timeline
   - Attack vector analysis
   - Evidence collected
   - Remediation actions

3. Post-Incident Analysis
   - Root cause identification
   - Improvement recommendations
   - Updated security controls

## 5. Prevention Recommendations

### Technical Controls
1. Access Management
   - Implement strong password policies
   - Deploy multi-factor authentication
   - Use jump servers for access

2. Network Security
   - Segment management networks
   - Implement network access control
   - Deploy IPS/IDS solutions

3. Monitoring
   - Enable detailed audit logging
   - Implement SIEM correlation
   - Deploy network behavior analysis

### Administrative Controls
1. Policy Updates
   - Access control procedures
   - Change management process
   - Incident response procedures

2. Training Requirements
   - Security awareness training
   - Incident response drills
   - Administrative access procedures

## 6. Escalation Criteria

### L2 Escalation Triggers
- Multiple devices affected
- Successful unauthorized access
- Evidence of lateral movement
- Critical system compromise

### L3 Escalation Triggers
- Active breach detected
- Multiple sites affected
- Data exfiltration observed
- Advanced persistent threat indicators
