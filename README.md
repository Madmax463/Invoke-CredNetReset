# Invoke-CredNetReset

Enterprise-grade PowerShell script for safe credential and network resolver reset operations on Windows systems.

## Overview

`Invoke-CredNetReset` is a production-ready tool designed for IT administrators and security teams to safely reset Kerberos tickets, DNS cache, and network configurations. It provides comprehensive logging, event mirroring, and graceful handling of edge cases like offline domain controllers and missing system tools.

## Use Cases

### Primary Scenarios
- **Authentication Issues**: Resolve Kerberos ticket corruption or stale authentication tokens
- **Network Connectivity Problems**: Clear DNS cache and refresh network stack after configuration changes
- **Security Incidents**: Force credential refresh as part of incident response procedures
- **System Maintenance**: Preventive credential hygiene during maintenance windows
- **VPN/Network Changes**: Refresh network state after VPN reconnections or network profile switches

### Operational Context
- **Help Desk**: First-line troubleshooting for authentication and connectivity issues
- **SOC/Security Teams**: Credential reset during security investigations or policy changes
- **System Administrators**: Routine maintenance and troubleshooting automation
- **IT Service Management**: Integration with ITSM tools for automated remediation

## Features

### Core Capabilities
- **Safe Kerberos Ticket Purging**: Uses only supported `klist` commands, never touches LSASS
- **Dynamic Service Account Discovery**: Automatically discovers and purges SYSTEM, LocalService, NetworkService tickets
- **DNS Cache Management**: Comprehensive IPv4/IPv6 cache clearing with verification
- **NetBIOS Operations**: Optional NetBIOS name cache reset and re-registration
- **Network Stack Refresh**: DNS registration and ARP cache clearing

### Enterprise Features
- **Structured Logging**: JSONL/CSV output with complete audit trail
- **Windows Event Log Integration**: SOC-friendly event mirroring with custom EventIDs
- **WhatIf Support**: Complete dry-run capability showing exact commands
- **Session Safety**: Detects active RDP/console sessions and prompts for confirmation
- **Domain Context Awareness**: Handles domain-joined, offline DC, and workgroup scenarios
- **Capability Probing**: Validates system tools and degrades gracefully

## Requirements

### System Requirements
- **Operating System**: Windows 10/11, Server 2016-2022
- **PowerShell**: 5.1 or later (PowerShell 7 supported)
- **Privileges**: Administrator rights required
- **Tools**: klist.exe (required), nltest.exe, nbtstat.exe, ipconfig.exe, netsh.exe (optional)

### Network Context
- **Domain-joined systems**: Full functionality including Kerberos operations
- **Workgroup systems**: DNS and network operations only
- **Offline scenarios**: Graceful handling with appropriate warnings

## Installation

1. Download `Invoke-CredNetReset.ps1` to your target system
2. Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. Run as Administrator

## Usage

### Basic Examples

```powershell
# Complete credential and network reset
.\Invoke-CredNetReset.ps1

# Reset only current user credentials
.\Invoke-CredNetReset.ps1 -Scope CurrentUser

# Reset service accounts only
.\Invoke-CredNetReset.ps1 -Scope Services

# Full reset with NetBIOS and network refresh
.\Invoke-CredNetReset.ps1 -IncludeNBNS -RefreshNetwork

# Dry run to see what would happen
.\Invoke-CredNetReset.ps1 -WhatIf

# Silent operation with structured logging
.\Invoke-CredNetReset.ps1 -Quiet -LogPath "C:\Logs\credreset.jsonl"

# Full operation with event log integration
.\Invoke-CredNetReset.ps1 -WriteEventLog -LogPath "C:\Logs\credreset.csv"
```

### Advanced Examples

```powershell
# Force operation bypassing prompts (automation scenarios)
.\Invoke-CredNetReset.ps1 -Force -RefreshNetwork -WriteEventLog

# Complete reset with comprehensive logging
.\Invoke-CredNetReset.ps1 -Scope All -IncludeNBNS -RefreshNetwork -LogPath "C:\Logs\credreset.jsonl" -WriteEventLog

# Help desk troubleshooting with verbose output
.\Invoke-CredNetReset.ps1 -Scope CurrentUser -LogPath "C:\Support\user-$env:USERNAME.csv"
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Scope` | String | 'All' | Target scope: 'All', 'CurrentUser', or 'Services' |
| `Force` | Switch | - | Bypass confirmations and interactive prompts |
| `Quiet` | Switch | - | Suppress non-error output to console |
| `IncludeNBNS` | Switch | - | Also reset NetBIOS name service cache |
| `RefreshNetwork` | Switch | - | Perform DNS registration and ARP cache operations |
| `LogPath` | String | - | Path to log file (.jsonl, .csv, or .txt) |
| `WriteEventLog` | Switch | - | Write events to Windows Event Log |
| `WhatIf` | Switch | - | Show what would be done without executing |

## Logging and Monitoring

### Structured Logging Schema

When using `-LogPath`, the script writes structured logs with the following fields:

```json
{
  "Timestamp": "2024-01-15T14:30:45.123Z",
  "Action": "PurgeKerberos",
  "Target": "CurrentUser",
  "Method": "klist",
  "Command": "klist purge",
  "ReturnCode": 0,
  "Outcome": "Success",
  "Error": "",
  "ExitCode": 0
}
```

### Windows Event Log Integration

When using `-WriteEventLog`, events are written to the Application log with source "CredNetReset":

| Event ID | Type | Description |
|----------|------|-------------|
| 9100 | Information | Operation started |
| 9101 | Information | All operations successful |
| 9102 | Warning | Partial success |
| 9103 | Error | Operation failed |
| 9104 | Error | Verification failed |

### Log File Formats

- **`.jsonl`**: JSON Lines format for programmatic parsing
- **`.csv`**: Comma-separated values for spreadsheet analysis  
- **`.txt`**: Human-readable transcript format

## Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 0 | Success | All operations completed successfully |
| 1 | Partial Success | Some operations failed, but core functionality worked |
| 2 | Access Denied | Not running as administrator or user cancelled |
| 3 | Fatal Error | Critical failure (missing tools, system error) |

## Operational Considerations

### Safety Features
- **LSASS Protection**: Never directly manipulates LSASS process
- **Session Awareness**: Warns about potential impact on active sessions
- **Graceful Degradation**: Continues operation when optional tools are missing
- **Domain Context**: Adapts behavior based on domain membership and connectivity

### Performance Impact
- **Low Resource Usage**: Minimal CPU and memory footprint
- **Fast Execution**: Typically completes in 5-15 seconds
- **Network Aware**: Minimal network traffic, respects offline scenarios

### Security Considerations
- **Audit Trail**: Complete logging of all operations
- **Privilege Validation**: Requires and validates administrator rights  
- **No Credential Exposure**: Never logs or displays sensitive information
- **Event Integration**: SOC-friendly monitoring capabilities

## Troubleshooting

### Common Issues

**"klist.exe not found"**
- Ensure system is domain-joined or klist.exe is available in PATH
- Check if running 32-bit PowerShell on 64-bit Windows (use 64-bit PowerShell)

**"Access Denied" error**
- Run PowerShell as Administrator
- Verify user account has local administrator privileges

**DNS operations fail**
- Check if DNS Client service is running: `Get-Service Dnscache`
- Verify ipconfig.exe is accessible in System32

**NetBIOS operations skipped**
- Install NetBIOS feature if required: `Enable-WindowsOptionalFeature -Online -FeatureName "NetBIOS"`

### Diagnostic Commands

```powershell
# Check tool availability
Get-Command klist.exe, nltest.exe, ipconfig.exe, netsh.exe, nbtstat.exe

# Verify domain context
Test-ComputerSecureChannel -Verbose

# Check current Kerberos tickets
klist

# Test DNS resolution
Resolve-DnsName -Name $env:LOGONSERVER.TrimStart('\')
```

## Integration Examples

### SCOM/SCCM Integration
```powershell
# Detection script
if ((Get-WinEvent -FilterHashtable @{LogName='System'; ID=1074; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue).Count -gt 0) {
    # System restart detected, credential reset recommended
    exit 1
}

# Remediation script
.\Invoke-CredNetReset.ps1 -Force -LogPath "C:\Windows\Temp\credreset.log"
exit $LASTEXITCODE
```

### Service Desk Automation
```powershell
# User-specific troubleshooting
$LogFile = "C:\Support\Logs\credreset-$env:USERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').jsonl"
.\Invoke-CredNetReset.ps1 -Scope CurrentUser -LogPath $LogFile -WriteEventLog

# Email log to support team
Send-MailMessage -To "helpdesk@company.com" -Subject "Credential Reset - $env:USERNAME" -Attachments $LogFile
```

### Scheduled Maintenance
```powershell
# Weekly credential hygiene
$Task = @{
    TaskName = "WeeklyCredentialReset"
    Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\Invoke-CredNetReset.ps1 -Force -WriteEventLog"
    Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2AM
    Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
}
Register-ScheduledTask @Task
```

## Support

### Documentation
- Built-in help: `Get-Help .\Invoke-CredNetReset.ps1 -Full`
- Examples: `Get-Help .\Invoke-CredNetReset.ps1 -Examples`
- Parameter details: `Get-Help .\Invoke-CredNetReset.ps1 -Parameter *`

### Logging for Support
Always include log files when reporting issues:
```powershell
.\Invoke-CredNetReset.ps1 -WhatIf -LogPath "C:\Temp\debug.jsonl" -Verbose
```

## Version History

### v1.0 - Enterprise Release
- Dynamic service LUID discovery
- Comprehensive DNS cache operations with verification
- Windows Event Log integration
- WOW64 compatibility and system binary path resolution  
- Complete structured logging with audit trail
- Session safety and domain context awareness
- Graceful degradation and capability probing

---

**Author**: PowerShell Automation Expert  
**Compatible**: Windows 10/11, Server 2016-2022  
**License**: Enterprise Use  
**Last Updated**: January 2024