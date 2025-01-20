# Unauthorized Firewall Access Attempt - L1 Analysis and Response

[Previous sections remain the same...]

## 2. Detection Queries

### Microsoft Sentinel KQL Queries

#### 2.1 General Security Events
```kql
// [Previous general security events query remains the same...]
```

#### 2.2 Cisco ASA Logs
```kql
// Monitor Cisco ASA Authentication Failures
CommonSecurityLog
| where DeviceVendor == "Cisco"
| where DeviceProduct == "ASA"
| where Activity in ("Authentication Failed", "AAA user locked out", "Login Failed")
| extend SourceIP = extract("([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})", 1, SourceIP)
| where isnotempty(SourceIP)
| summarize 
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    FailedCount = count(),
    LastFailedUser = any(SourceUserID),
    Messages = make_set(Activity)
    by SourceIP, DestinationHostName
| where FailedCount >= 3
| project 
    StartTime,
    EndTime,
    SourceIP,
    DestinationHostName,
    FailedCount,
    LastFailedUser,
    Messages

// Monitor Cisco ASA Configuration Changes
CommonSecurityLog
| where DeviceVendor == "Cisco"
| where DeviceProduct == "ASA"
| where Activity contains "config" 
    or Activity contains "command"
| extend Command = extract("command: (.+)", 1, AdditionalExtensions)
| project
    TimeGenerated,
    SourceIP,
    SourceUserID,
    Activity,
    Command,
    DeviceAction
```

#### 2.3 FortiGate Logs
```kql
// Monitor FortiGate Authentication Failures
CommonSecurityLog
| where DeviceVendor == "Fortinet"
| where DeviceProduct contains "Fortigate"
| where Activity == "admin-login-failed" 
    or Activity contains "authentication" and DeviceAction == "denied"
| summarize 
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    FailedCount = count(),
    Users = make_set(SourceUserID),
    Messages = make_set(Activity)
    by SourceIP, DestinationHostName
| where FailedCount >= 3

// Monitor FortiGate Configuration Changes
CommonSecurityLog
| where DeviceVendor == "Fortinet"
| where DeviceProduct contains "Fortigate"
| where Activity in ("configuration-changes", "setting-change", "admin-login")
| extend ConfigChange = extract("msg=\\"(.+?)\\"", 1, AdditionalExtensions)
| project
    TimeGenerated,
    SourceIP,
    SourceUserID,
    Activity,
    ConfigChange,
    DeviceAction

// Monitor FortiGate Suspicious Admin Access
CommonSecurityLog
| where DeviceVendor == "Fortinet"
| where DeviceProduct contains "Fortigate"
| where Activity == "admin-login"
| extend Status = case(
    DeviceAction == "denied", "Failed",
    DeviceAction == "success", "Success",
    "Unknown")
| summarize 
    AccessCount = count(),
    SuccessfulLogins = countif(Status == "Success"),
    FailedLogins = countif(Status == "Failed")
    by bin(TimeGenerated, 1h), SourceIP, SourceUserID
```

#### 2.4 F5 BIG-IP Logs
```kql
// Monitor F5 Authentication Failures
CommonSecurityLog
| where DeviceVendor == "F5"
| where DeviceProduct contains "ASM"
    or DeviceProduct contains "BIG-IP"
| where Activity contains "Authentication"
    and DeviceAction == "Failure"
| summarize 
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    FailedCount = count(),
    LastFailedUser = any(SourceUserID)
    by SourceIP, DestinationHostName
| where FailedCount >= 3

// Monitor F5 Configuration Changes
CommonSecurityLog
| where DeviceVendor == "F5"
| where DeviceProduct contains "ASM"
    or DeviceProduct contains "BIG-IP"
| where Activity contains "Configuration"
    or Activity contains "AUDIT"
| extend ConfigDetails = extract("audit.conf.change=(.+?);", 1, AdditionalExtensions)
| project
    TimeGenerated,
    SourceIP,
    SourceUserID,
    Activity,
    ConfigDetails,
    DeviceAction

// Monitor F5 Administrative Access
CommonSecurityLog
| where DeviceVendor == "F5"
| where DeviceProduct contains "ASM"
    or DeviceProduct contains "BIG-IP"
| where Activity contains "Admin"
    or Activity contains "Configuration"
| extend AdminAction = extract("action=(.+?);", 1, AdditionalExtensions)
| summarize 
    ActionCount = count(),
    Actions = make_set(AdminAction)
    by bin(TimeGenerated, 1h), SourceIP, SourceUserID
```

#### 2.5 Correlation Query Across Vendors
```kql
// Detect distributed authentication attempts across multiple firewall vendors
let threshold = 3;
CommonSecurityLog
| where DeviceVendor in ("Cisco", "Fortinet", "F5")
| where Activity contains "Authentication"
    or Activity contains "login"
    or Activity contains "Failed"
| extend NormalizedStatus = case(
    DeviceAction == "denied", "Failed",
    DeviceAction contains "fail", "Failed",
    DeviceAction == "success", "Success",
    Activity contains "Failed", "Failed",
    "Unknown")
| where NormalizedStatus == "Failed"
| summarize 
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    FailedCount = count(),
    VendorsTargeted = make_set(DeviceVendor),
    DevicesTargeted = make_set(DeviceProduct),
    LastFailedUser = any(SourceUserID)
    by SourceIP
| where FailedCount >= threshold
| where array_length(VendorsTargeted) > 1
| project
    StartTime,
    EndTime,
    SourceIP,
    FailedCount,
    VendorsTargeted,
    DevicesTargeted,
    LastFailedUser
| order by FailedCount desc
```

[Rest of the document remains the same...]
