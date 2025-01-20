# Anomalous Log Spike Security Analysis

## Threat Analysis & Framework References

### MITRE ATT&CK Mapping
- **Discovery [TA0007]**: Adversaries attempting to gain knowledge about the system and internal network
- **Defense Evasion [TA0005]**: Possible attempts to avoid detection
- **Command and Control [TA0011]**: Potential C2 communication attempts

### Compliance Framework Relevance
- **ISO 27001**: A.12.4 (Logging and Monitoring), A.16.1 (Information Security Incident Management)
- **NIS 2**: Article 20 (Risk Management Measures), Article 23 (Incident Reporting)
- **DORA**: Article 10 (ICT Risk Management), Article 15 (Incident Reporting)
- **PCI DSS 4.0**: Requirement 10 (Logging and Monitoring)
- **SOC2**: CC7.2 (Monitoring Controls), CC7.3 (Incident Response)

## Log Sources & Monitoring Points

### Network Devices
1. **Cisco ASA**
   ```
   - Syslog facility: LOCAL4
   - Log levels: 0-7
   - Key log types: %ASA-6-302013, %ASA-6-302014, %ASA-4-733100
   ```

2. **Fortinet FortiGate**
   ```
   - Log types: traffic, event, virus, webfilter, IPS, emailfilter
   - Severity levels: emergency, alert, critical, error, warning
   ```

3. **F5 BIG-IP**
   ```
   - Log facilities: local0-local7
   - Key log types: /var/log/ltm, /var/log/audit, /var/log/security
   ```

## Detection Queries

### Microsoft Sentinel KQL Query
```kql
let threshold = 2.0; // Adjust based on baseline
let timeframe = 1h;
let baseline_period = 7d;
SecurityEvent
| where TimeGenerated > ago(baseline_period)
| make-series EventCount=count() on TimeGenerated from ago(baseline_period) to now() step timeframe
| extend baseline = series_decompose_anomalies(EventCount, threshold)
| mv-expand TimeGenerated, EventCount, baseline
| where baseline == 1
| project TimeGenerated, EventCount
```

### Microsoft Defender Advanced Hunting Query
```kql
let anomaly_threshold = 2.0;
DeviceEvents
| where Timestamp > ago(1h)
| summarize EventCount=count() by bin(Timestamp, 5m), DeviceId
| join kind=leftouter (
    DeviceEvents
    | where Timestamp between(ago(7d)..ago(1h))
    | summarize BaselineCount=avg(count()) by DeviceId
) on DeviceId
| where EventCount > BaselineCount * anomaly_threshold
```

## Incident Response Flowchart

1. **Initial Detection (0-15 minutes)**
   - Validate alert authenticity
   - Determine affected systems
   - Assess initial severity

2. **Investigation (15-60 minutes)**
   - Collect relevant logs
   - Analyze traffic patterns
   - Identify source of anomaly
   - Look for correlation with other security events

3. **Containment Decision (60-90 minutes)**
   - If malicious:
     - Isolate affected systems
     - Block suspicious IPs/domains
   - If benign:
     - Document findings
     - Update baseline

4. **Resolution & Recovery**
   - Implement fixes
   - Restore normal operations
   - Update detection rules

## IT Team Instructions

### Immediate Actions
1. DO NOT immediately restart affected systems
2. Enable verbose logging on affected systems
3. Take network captures if possible
4. Preserve all logs

### Analysis Steps
1. Compare current log patterns with historical baseline
2. Check for:
   - New applications or services
   - Recent system changes
   - Scheduled tasks/jobs
   - Unusual user activity

### Containment Procedures
1. If malicious activity confirmed:
   - Isolate affected systems using network segmentation
   - Block suspicious external communications
   - Disable compromised accounts
2. If false positive:
   - Document root cause
   - Update monitoring thresholds
   - Adjust alert rules

### Documentation Requirements
- Timeline of events
- Systems affected
- Actions taken
- Root cause identification
- Recommendations for prevention