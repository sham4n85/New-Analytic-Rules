# Abnormal Protocol Use - Security Analysis

## Framework References

### MITRE ATT&CK
- **Technique ID**: T1071 - Command and Control over Standard Application Layer Protocol
- **Technique ID**: T1571 - Non-Standard Port
- **Tactic**: Command and Control

### ISO 27001
- A.13.1.1 Network controls
- A.13.1.2 Security of network services
- A.12.4 Logging and monitoring

### NIS 2
- Article 21: Security measures for network and information systems
- Article 23: Reporting obligations

### DORA
- Article 11: ICT Risk Management
- Chapter IV: Digital Operational Resilience Testing

### PCI DSS v4.0
- Requirement 10: Log and Monitor
- Requirement 1: Network Security

### SOC2
- CC7.2: Monitoring Security Events
- CC7.3: Security Incident Response

## Log Sources and Monitoring

### Network Devices
1. Cisco ASA
   ```
   %ASA-4-*: Protocol violation, source [IP]
   %ASA-6-302013: Built outbound TCP connection
   ```

2. Fortinet FortiGate
   ```
   type=traffic subtype=anomaly action=detected
   type=utm subtype=ips action=blocked
   ```

3. F5 BIG-IP
   ```
   "protocol_violation"
   "ASM:Protocol Violation"
   ```

### EDR/XDR
- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- SentinelOne

### SIEM Integration
- Network Traffic Analysis (NTA)
- Protocol Analysis Tools
- IDS/IPS Alerts

## KQL Queries

### Microsoft Sentinel
```kql
let timeframe = 1d;
let threshold = 3;
NetworkProtocol
| where TimeGenerated >= ago(timeframe)
| where isnotempty(DestinationPort)
| summarize 
    NonStandardCount = count(),
    DistinctPorts = make_set(DestinationPort),
    DistinctProtocols = make_set(Protocol)
    by SourceIP, DestinationIP
| where NonStandardCount > threshold
| extend Timestamp = now()
| extend HostCustomEntity = SourceIP
| extend IPCustomEntity = DestinationIP
```

### Microsoft Defender Advanced Hunting
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort !in (80, 443, 53, 22, 3389)
| summarize 
    UnusualPortCount = count(),
    Ports = make_set(RemotePort),
    LastSeen = max(Timestamp)
    by DeviceName, RemoteIP
| where UnusualPortCount > 10
| project-reorder DeviceName, RemoteIP, UnusualPortCount, Ports, LastSeen
```

## Instructions for IT Team

### Immediate Actions
1. Isolate affected systems using network segmentation
2. Enable enhanced logging on network devices
3. Review firewall rules and ACLs
4. Document all changes made

### Investigation Steps
1. Collect network captures (pcap) from relevant segments
2. Review protocol analyzers and IDS/IPS logs
3. Cross-reference with EDR telemetry
4. Document findings in incident tracking system

### Containment Procedures
1. Implement temporary blocking rules
2. Update IPS signatures
3. Enable protocol validation on firewalls
4. Monitor for protocol anomalies

### Recovery Actions
1. Validate legitimate business needs
2. Update network documentation
3. Implement permanent controls
4. Conduct post-incident review

## Risk Assessment Matrix

| Impact | Likelihood | Risk Level | Controls |
|--------|------------|------------|-----------|
| High | Medium | High | Network Segmentation |
| High | Low | Medium | Protocol Validation |
| Medium | High | High | Traffic Monitoring |
| Low | High | Medium | Logging Enhancement |