#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Performs safe credential and network resolver reset operations for Windows systems.

.DESCRIPTION
    Invoke-CredNetReset is a production-ready PowerShell script that safely resets Kerberos tickets,
    DNS cache, and network configurations. It supports multiple scopes (All, CurrentUser, Services),
    includes comprehensive logging, and handles edge cases like offline domain controllers.

.PARAMETER Force
    Bypasses confirmations and interactive prompts. Use with caution in production.

.PARAMETER WhatIf
    Performs a dry-run showing what actions would be taken without executing them.

.PARAMETER Quiet
    Suppresses non-error output to console. Errors and warnings will still be displayed.

.PARAMETER Scope
    Specifies the scope of credential reset operations:
    - All: Reset credentials for current user and services (default)
    - CurrentUser: Reset only current user credentials
    - Services: Reset only service account credentials (SYSTEM, LocalService, NetworkService)

.PARAMETER IncludeNBNS
    Also resets NetBIOS name service cache and registrations using nbtstat commands.

.PARAMETER RefreshNetwork
    Performs additional network refresh operations including DNS registration and ARP cache clearing.

.PARAMETER LogPath
    Path to structured log file. Supports .jsonl, .csv (structured), or .txt (PowerShell transcript).

.PARAMETER WriteEventLog
    Writes custom events to Microsoft-Windows-PowerShell/Operational event log with EventIDs 9100-9104.

.EXAMPLE
    Invoke-CredNetReset -Scope All -LogPath C:\Logs\credreset.jsonl -WriteEventLog
    
    Resets all credentials with structured JSON logging and event log integration.

.EXAMPLE
    Invoke-CredNetReset -Scope Services -Force -RefreshNetwork
    
    Resets service account credentials with network refresh, bypassing confirmations.

.EXAMPLE
    Invoke-CredNetReset -WhatIf
    
    Shows what actions would be performed without executing them.

.EXAMPLE
    Invoke-CredNetReset -IncludeNBNS -Quiet -LogPath C:\Logs\credreset.csv
    
    Resets credentials and NetBIOS cache with CSV logging and minimal console output.

.NOTES
    Version: 1.0
    Author: PowerShell Automation Expert
    Requires: PowerShell 5.1+, Administrator privileges
    Compatible: Windows 10/11, Server 2016-2022

.LINK
    https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/klist
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    # Bypass confirmations and interactive prompts
    [switch]$Force,
    
    # Suppress non-error output to console
    [switch]$Quiet,
    
    # Scope of credential reset operations
    [ValidateSet('All', 'CurrentUser', 'Services')]
    [string]$Scope = 'All',
    
    # Also reset NetBIOS name service cache and registrations
    [switch]$IncludeNBNS,
    
    # Perform additional network refresh operations (DNS registration, ARP cache)
    [switch]$RefreshNetwork,
    
    # Path to structured log file (.jsonl, .csv, or .txt for transcript)
    [ValidateScript({
        if ($_ -and (Test-Path (Split-Path $_ -Parent) -PathType Container)) {
            $extension = [System.IO.Path]::GetExtension($_).ToLower()
            if ($extension -notin @('.jsonl', '.csv', '.txt')) {
                throw "LogPath must have .jsonl, .csv, or .txt extension. Got: $extension"
            }
            $true
        } elseif ($_ -and -not (Test-Path (Split-Path $_ -Parent) -PathType Container)) {
            throw "Directory does not exist: $(Split-Path $_ -Parent)"
        } else {
            $true
        }
    })]
    [string]$LogPath,
    
    # Write custom events to Windows Event Log (Application) with EventIDs 9100-9104
    [switch]$WriteEventLog
)

# Global variables for script operation
$script:OperationStartTime = Get-Date
$script:LogEntries = @()
$script:ExitCode = 0
$script:SuccessCount = 0
$script:FailureCount = 0
$script:PartialCount = 0

# Event Log constants
$script:EventSource = "Invoke-CredNetReset"
$script:EventLogName = "Microsoft-Windows-PowerShell/Operational"
$script:EventIds = @{
    OperationStart = 9100
    Success = 9101
    PartialSuccess = 9102
    Failure = 9103
    VerificationFailure = 9104
}

#region Helper Functions

function Test-Admin {
    <#
    .SYNOPSIS
        Checks if the current session is running with administrator privileges.
    .DESCRIPTION
        Verifies elevation status and exits with code 2 if not running as administrator.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            Write-Error "This script requires administrator privileges."
            Write-Host "To elevate: Right-click PowerShell → 'Run as administrator', then re-run this script." -ForegroundColor Yellow
            Write-Record -Action "PrivilegeCheck" -Target "CurrentSession" -Method "WindowsPrincipal" -ReturnCode 2 -Outcome "Failed" -Error "Not running as administrator" -Command "Test-Admin" -ExitCode 2
            exit 2
        }
        
        Write-Record -Action "PrivilegeCheck" -Target "CurrentSession" -Method "WindowsPrincipal" -ReturnCode 0 -Outcome "Success" -Command "Test-Admin" -ExitCode 0
        return $true
    }
    catch {
        Write-Error "Failed to check administrator privileges: $($_.Exception.Message)"
        Write-Record -Action "PrivilegeCheck" -Target "CurrentSession" -Method "WindowsPrincipal" -ReturnCode 3 -Outcome "Failed" -Error $_.Exception.Message -Command "Test-Admin" -ExitCode 3
        exit 3
    }
}

function Write-Record {
    <#
    .SYNOPSIS
        Writes structured log entries with enhanced analytics-ready schema.
    .DESCRIPTION
        Supports JSONL, CSV, and transcript formats with Action/Target/Command/ExitCode fields.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Action,
        
        [Parameter(Mandatory)]
        [string]$Target,
        
        [Parameter(Mandatory)]
        [string]$Method,
        
        [Parameter(Mandatory)]
        [int]$ReturnCode,
        
        [Parameter(Mandatory)]
        [string]$Outcome,
        
        [string]$Error = "",
        
        [string]$Command = "",
        
        [int]$ExitCode = 0
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    
    $logEntry = [PSCustomObject]@{
        Timestamp = $timestamp
        Action = $Action
        Target = $Target
        Method = $Method
        ReturnCode = $ReturnCode
        Outcome = $Outcome
        Error = $Error
        Command = $Command
        ExitCode = $ExitCode
    }
    
    $script:LogEntries += $logEntry
    
    if ($LogPath) {
        try {
            $extension = [System.IO.Path]::GetExtension($LogPath).ToLower()
            
            switch ($extension) {
                '.jsonl' {
                    $jsonLine = $logEntry | ConvertTo-Json -Compress
                    Add-Content -Path $LogPath -Value $jsonLine -Encoding UTF8
                }
                '.csv' {
                    if (-not (Test-Path $LogPath)) {
                        $logEntry | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
                    } else {
                        $logEntry | Export-Csv -Path $LogPath -NoTypeInformation -Append -Encoding UTF8
                    }
                }
                '.txt' {
                    # For .txt files, use transcript-style format with command details
                    $logLine = "[$timestamp] $Action on $Target via $Method - $Outcome (Code: $ReturnCode)"
                    if ($Command) { $logLine += " - Command: $Command" }
                    if ($ExitCode -ne 0) { $logLine += " - ExitCode: $ExitCode" }
                    if ($Error) { $logLine += " - Error: $Error" }
                    Add-Content -Path $LogPath -Value $logLine -Encoding UTF8
                }
                default {
                    Write-Warning "Unsupported log file extension: $extension. Using transcript format."
                    $logLine = "[$timestamp] $Action on $Target via $Method - $Outcome (Code: $ReturnCode)"
                    if ($Command) { $logLine += " - Command: $Command" }
                    if ($ExitCode -ne 0) { $logLine += " - ExitCode: $ExitCode" }
                    if ($Error) { $logLine += " - Error: $Error" }
                    Add-Content -Path $LogPath -Value $logLine -Encoding UTF8
                }
            }
        }
        catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

function Get-ServiceLogonLUIDs {
    <#
    .SYNOPSIS
        Dynamically discovers service account Logon Session LUIDs using klist sessions.
    .DESCRIPTION
        Parses klist sessions output to identify SYSTEM, LocalService, and NetworkService LUIDs.
        No hardcoded values - discovers actual running sessions.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Verify klist capability
        $klistPath = Get-Command klist.exe -ErrorAction SilentlyContinue
        if (-not $klistPath) {
            throw "klist.exe not found in PATH"
        }
        
        $map = @{}
        $sessions = (klist sessions) 2>$null
        
        if ($LASTEXITCODE -ne 0) {
            throw "klist sessions command failed with exit code $LASTEXITCODE"
        }
        
        foreach ($line in $sessions) {
            # Match hex LUID format and service account names
            if ($line -match '^(0x[0-9a-fA-F]+).+NT AUTHORITY\\(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)') {
                $luid = $matches[1]
                switch ($matches[2]) {
                    'SYSTEM'          { $map['System'] = $luid }
                    'LOCAL SERVICE'   { $map['LocalService'] = $luid }
                    'NETWORK SERVICE' { $map['NetworkService'] = $luid }
                }
            }
        }
        
        Write-Record -Action "DiscoverLUIDs" -Target "ServiceAccounts" -Method "KlistSessions" -ReturnCode 0 -Outcome "Success" -Command "klist sessions" -ExitCode $LASTEXITCODE
        return $map
    }
    catch {
        Write-Record -Action "DiscoverLUIDs" -Target "ServiceAccounts" -Method "KlistSessions" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "klist sessions" -ExitCode $LASTEXITCODE
        return @{}
    }
}

function Purge-KerberosTickets {
    <#
    .SYNOPSIS
        Safely purges Kerberos tickets using klist commands with LUID enumeration.
    .DESCRIPTION
        Never touches LSASS directly, uses only klist purge commands with specific LUIDs.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('All', 'CurrentUser', 'Services')]
        [string]$TargetScope
    )
    
    $purgeResults = @{
        Success = 0
        Failed = 0
        Skipped = 0
    }
    
    try {
        # Check domain context
        $ctx = Get-DomainContext
        if (-not $ctx.PartOfDomain) {
            if (-not $Quiet) {
                Write-Host "System is not domain-joined. Skipping Kerberos ticket purge." -ForegroundColor Yellow
            }
            Write-Record -Action "PurgeKerberos" -Target "All" -Method "Klist" -ReturnCode 0 -Outcome "Skipped" -Error "Not domain-joined"
            $purgeResults.Skipped++
            return $purgeResults
        }
        
        # Verify klist capability before any operations
        $klistPath = Get-Command klist.exe -ErrorAction SilentlyContinue
        if (-not $klistPath) {
            Write-Error "FATAL: klist.exe not available. Cannot perform Kerberos operations."
            Write-Record -Action "PurgeKerberos" -Target "All" -Method "Klist" -ReturnCode 3 -Outcome "Failed" -Error "klist.exe not available" -Command "klist" -ExitCode 3
            $purgeResults.Failed++
            return $purgeResults
        }
        
        # Purge current user tickets
        if ($TargetScope -in @('All', 'CurrentUser')) {
            if ($PSCmdlet.ShouldProcess("Current User Kerberos Tickets", "Purge")) {
                try {
                    & klist purge 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        if (-not $Quiet) {
                            Write-Host "Successfully purged current user Kerberos tickets." -ForegroundColor Green
                        }
                        Write-Record -Action "PurgeKerberos" -Target "CurrentUser" -Method "Klist" -ReturnCode 0 -Outcome "Success" -Command "klist purge" -ExitCode $LASTEXITCODE
                        $purgeResults.Success++
                    } else {
                        throw "klist purge failed with exit code $LASTEXITCODE"
                    }
                }
                catch {
                    Write-Warning "Failed to purge current user Kerberos tickets: $($_.Exception.Message)"
                    Write-Record -Action "PurgeKerberos" -Target "CurrentUser" -Method "Klist" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "klist purge" -ExitCode $LASTEXITCODE
                    $purgeResults.Failed++
                }
            }
        }
        
        # Purge service account tickets with dynamic LUID discovery
        if ($TargetScope -in @('All', 'Services')) {
            $svc = Get-ServiceLogonLUIDs
            
            foreach ($ctx in 'System','LocalService','NetworkService') {
                if ($svc.ContainsKey($ctx)) {
                    $luid = $svc[$ctx]
                    
                    if ($PSCmdlet.ShouldProcess("$ctx Kerberos (LUID: $luid)", "Purge")) {
                        try {
                            & klist -li $luid purge 2>$null
                            $exit = $LASTEXITCODE
                            if ($exit -eq 0) {
                                if (-not $Quiet) {
                                    Write-Host "Successfully purged $ctx Kerberos tickets (LUID: $luid)." -ForegroundColor Green
                                }
                                Write-Record -Action "PurgeKerberos" -Target $ctx -Method "klist -li purge" -ReturnCode $exit -Outcome "Success" -Command "klist -li $luid purge" -ExitCode $exit
                                $purgeResults.Success++
                            } else {
                                throw "klist -li $luid purge failed with exit code $exit"
                            }
                        }
                        catch {
                            Write-Warning "Failed to purge $ctx Kerberos tickets: $($_.Exception.Message)"
                            Write-Record -Action "PurgeKerberos" -Target $ctx -Method "klist -li purge" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "klist -li $luid purge" -ExitCode $LASTEXITCODE
                            $purgeResults.Failed++
                        }
                    } else {
                        Write-Record -Action "PurgeKerberos" -Target $ctx -Method "klist -li purge" -ReturnCode 0 -Outcome "WhatIf" -Command "klist -li $luid purge" -ExitCode 0
                    }
                } else {
                    if (-not $Quiet) {
                        Write-Host "No LUID found for $ctx (skipping)" -ForegroundColor Yellow
                    }
                    Write-Record -Action "PurgeKerberos" -Target $ctx -Method "Klist" -ReturnCode 0 -Outcome "Skipped" -Error "LUID not found" -Command "klist sessions" -ExitCode 0
                    $purgeResults.Skipped++
                }
            }
        }
        
        return $purgeResults
    }
    catch {
        Write-Error "Critical error in Kerberos ticket purge: $($_.Exception.Message)"
        Write-Record -Action "PurgeKerberos" -Target "All" -Method "Klist" -ReturnCode 3 -Outcome "Failed" -Error $_.Exception.Message
        $purgeResults.Failed++
        return $purgeResults
    }
}

function Clear-DnsCache {
    <#
    .SYNOPSIS
        Clears DNS resolver cache with IPv4/IPv6 support and verification.
    .DESCRIPTION
        Uses ipconfig /flushdns and Clear-DnsClientCache (if available) for comprehensive cache clearing.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    try {
        # Verify ipconfig capability
        $ipconfigPath = Get-Command ipconfig.exe -ErrorAction SilentlyContinue
        if (-not $ipconfigPath) {
            Write-Warning "ipconfig.exe not available. DNS cache clearing will be skipped."
            Write-Record -Action "ClearDnsCache" -Target "ResolverCache" -Method "Ipconfig" -ReturnCode 0 -Outcome "Skipped" -Error "ipconfig.exe not available" -Command "ipconfig /flushdns" -ExitCode 0
            return $false
        }
        
        if ($PSCmdlet.ShouldProcess("DNS Resolver Cache (IPv4/IPv6)", "Clear")) {
            $cleared = $false
            
            # Primary method: Clear-DnsClientCache (Windows 8+, more comprehensive)
            if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
                try {
                    Clear-DnsClientCache -ErrorAction Stop
                    $cleared = $true
                    if (-not $Quiet) {
                        Write-Host "Successfully cleared DNS client cache." -ForegroundColor Green
                    }
                    Write-Record -Action "ClearDnsClientCache" -Target "ClientCache" -Method "PowerShell" -ReturnCode 0 -Outcome "Success" -Command "Clear-DnsClientCache" -ExitCode 0
                } catch {
                    Write-Warning "Clear-DnsClientCache failed: $($_.Exception.Message). Falling back to ipconfig."
                    Write-Record -Action "ClearDnsClientCache" -Target "ClientCache" -Method "PowerShell" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "Clear-DnsClientCache" -ExitCode 1
                }
            }
            
            # Fallback method: ipconfig /flushdns (works on all Windows versions)
            if (-not $cleared) {
                & ipconfig /flushdns 2>$null
                $cleared = ($LASTEXITCODE -eq 0)
                if ($cleared) {
                    if (-not $Quiet) {
                        Write-Host "Successfully cleared DNS resolver cache (ipconfig)." -ForegroundColor Green
                    }
                    Write-Record -Action "ClearDnsCache" -Target "ResolverCache" -Method "Ipconfig" -ReturnCode 0 -Outcome "Success" -Command "ipconfig /flushdns" -ExitCode $LASTEXITCODE
                } else {
                    throw "ipconfig /flushdns failed with exit code $LASTEXITCODE"
                }
            }
            
            # Optional verification of cache state
            if ($cleared -and (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue)) {
                try {
                    $cacheCount = (Get-DnsClientCache).Count
                    $verifyOutcome = if ($cacheCount -le 1) { "Success" } else { "Warning" }
                    Write-Record -Action "VerifyDnsCache" -Target "ResolverCache" -Method "Get-DnsClientCache" -ReturnCode 0 -Outcome $verifyOutcome -Command "Get-DnsClientCache" -ExitCode 0
                    if ($verifyOutcome -eq "Warning" -and -not $Quiet) {
                        Write-Warning "DNS cache still contains $cacheCount entries after clearing."
                    }
                } catch {
                    Write-Record -Action "VerifyDnsCache" -Target "ResolverCache" -Method "Get-DnsClientCache" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "Get-DnsClientCache" -ExitCode 1
                }
            }
            
            return $cleared
        } else {
            Write-Record -Action "ClearDnsCache" -Target "ResolverCache" -Method "Mixed" -ReturnCode 0 -Outcome "WhatIf" -Command "Clear-DnsClientCache; ipconfig /flushdns" -ExitCode 0
            return $true
        }
    }
    catch {
        Write-Warning "Failed to clear DNS cache: $($_.Exception.Message)"
        Write-Record -Action "ClearDnsCache" -Target "ResolverCache" -Method "Ipconfig" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "ipconfig /flushdns" -ExitCode $LASTEXITCODE
        return $false
    }
}

function Reset-NbnsCache {
    <#
    .SYNOPSIS
        Resets NetBIOS name service cache and registrations.
    .DESCRIPTION
        Uses nbtstat -R and -RR commands to reset NetBIOS cache and re-register names.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    $nbnsResults = @{
        CacheReset = $false
        NamesReregistered = $false
    }
    
    try {
        # Check if nbtstat is available
        $nbtstatPath = Get-Command nbtstat.exe -ErrorAction SilentlyContinue
        if (-not $nbtstatPath) {
            Write-Warning "nbtstat command not found. NetBIOS operations will be skipped."
            Write-Record -Action "ResetNbnsCache" -Target "NetBiosCache" -Method "Nbtstat" -ReturnCode 0 -Outcome "Skipped" -Error "nbtstat not available" -Command "nbtstat" -ExitCode 0
            return $nbnsResults
        }
        
        # Reset NetBIOS name cache
        if ($PSCmdlet.ShouldProcess("NetBIOS Name Cache", "Reset")) {
            & nbtstat -R 2>$null
            if ($LASTEXITCODE -eq 0) {
                if (-not $Quiet) {
                    Write-Host "Successfully reset NetBIOS name cache." -ForegroundColor Green
                }
                Write-Record -Action "ResetNbnsCache" -Target "NameCache" -Method "Nbtstat" -ReturnCode 0 -Outcome "Success" -Command "nbtstat -R" -ExitCode $LASTEXITCODE
                $nbnsResults.CacheReset = $true
            } else {
                Write-Warning "Failed to reset NetBIOS name cache (nbtstat -R failed)"
                Write-Record -Action "ResetNbnsCache" -Target "NameCache" -Method "Nbtstat" -ReturnCode 1 -Outcome "Failed" -Error "nbtstat -R failed with code $LASTEXITCODE" -Command "nbtstat -R" -ExitCode $LASTEXITCODE
            }
        } else {
            Write-Record -Action "ResetNbnsCache" -Target "NameCache" -Method "Nbtstat" -ReturnCode 0 -Outcome "WhatIf" -Command "nbtstat -R" -ExitCode 0
        }
        
        # Re-register NetBIOS names
        if ($PSCmdlet.ShouldProcess("NetBIOS Name Registrations", "Refresh")) {
            & nbtstat -RR 2>$null
            if ($LASTEXITCODE -eq 0) {
                if (-not $Quiet) {
                    Write-Host "Successfully re-registered NetBIOS names." -ForegroundColor Green
                }
                Write-Record -Action "ReregisterNbnsNames" -Target "NameRegistrations" -Method "Nbtstat" -ReturnCode 0 -Outcome "Success" -Command "nbtstat -RR" -ExitCode $LASTEXITCODE
                $nbnsResults.NamesReregistered = $true
            } else {
                Write-Warning "Failed to re-register NetBIOS names (nbtstat -RR failed)"
                Write-Record -Action "ReregisterNbnsNames" -Target "NameRegistrations" -Method "Nbtstat" -ReturnCode 1 -Outcome "Failed" -Error "nbtstat -RR failed with code $LASTEXITCODE" -Command "nbtstat -RR" -ExitCode $LASTEXITCODE
            }
        } else {
            Write-Record -Action "ReregisterNbnsNames" -Target "NameRegistrations" -Method "Nbtstat" -ReturnCode 0 -Outcome "WhatIf" -Command "nbtstat -RR" -ExitCode 0
        }
        
        return $nbnsResults
    }
    catch {
        Write-Warning "Critical error in NetBIOS operations: $($_.Exception.Message)"
        Write-Record -Action "ResetNbnsCache" -Target "NetBiosCache" -Method "Nbtstat" -ReturnCode 3 -Outcome "Failed" -Error $_.Exception.Message -Command "nbtstat operations" -ExitCode 3
        return $nbnsResults
    }
}

function Refresh-NetworkStack {
    <#
    .SYNOPSIS
        Refreshes network stack with DNS registration and ARP cache clearing.
    .DESCRIPTION
        Performs ipconfig /registerdns and netsh ARP cache operations with graceful degradation.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    $op = 'NetworkRefresh'
    $networkResults = @{
        DnsRegistered = $false
        ArpCleared = $false
    }
    
    try {
        # DNS Registration
        if ($PSCmdlet.ShouldProcess("Network stack", "Register DNS and clear ARP cache")) {
            try { 
                ipconfig /registerdns | Out-Null
                $networkResults.DnsRegistered = $true
                if (-not $Quiet) {
                    Write-Host "DNS registration initiated." -ForegroundColor Green
                }
                Write-Record -Action "RefreshDnsRegistration" -Target "DnsRecords" -Method "Ipconfig" -ReturnCode 0 -Outcome "Success" -Command "ipconfig /registerdns" -ExitCode $LASTEXITCODE
            } catch {
                Write-Warning "Failed to register DNS: $($_.Exception.Message)"
                Write-Record -Action "RefreshDnsRegistration" -Target "DnsRecords" -Method "Ipconfig" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "ipconfig /registerdns" -ExitCode $LASTEXITCODE
            }
            
            # ARP Cache Clear
            try { 
                netsh interface ip delete arpcache | Out-Null
                $networkResults.ArpCleared = $true
                if (-not $Quiet) {
                    Write-Host "ARP cache cleared." -ForegroundColor Green
                }
                Write-Record -Action "ClearArpCache" -Target "ArpTable" -Method "Netsh" -ReturnCode 0 -Outcome "Success" -Command "netsh interface ip delete arpcache" -ExitCode $LASTEXITCODE
            } catch {
                Write-Warning "Failed to clear ARP cache: $($_.Exception.Message)"
                Write-Record -Action "ClearArpCache" -Target "ArpTable" -Method "Netsh" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "netsh interface ip delete arpcache" -ExitCode $LASTEXITCODE
            }
        } else {
            Write-Record -Action "RefreshNetworkStack" -Target "NetworkStack" -Method "Mixed" -ReturnCode 0 -Outcome "Skipped" -Error "WhatIf mode" -Command "ipconfig /registerdns; netsh interface ip delete arpcache" -ExitCode 0
        }
        
        return $networkResults
    }
    catch {
        Write-Warning "Critical error in network stack refresh: $($_.Exception.Message)"
        Write-Record -Action "RefreshNetworkStack" -Target "NetworkStack" -Method "Mixed" -ReturnCode 3 -Outcome "Failed" -Error $_.Exception.Message -Command "ipconfig /registerdns; netsh interface ip delete arpcache" -ExitCode 3
        return $networkResults
    }
}

function Verify-KerberosState {
    <#
    .SYNOPSIS
        Verifies post-operation Kerberos state by reacquiring krbtgt ticket.
    .DESCRIPTION
        Actually reacquires krbtgt ticket using klist get krbtgt to verify functionality.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Check domain context first
        $ctx = Get-DomainContext
        if (-not $ctx.PartOfDomain) {
            if (-not $Quiet) {
                Write-Host "Workgroup machine: skipping Kerberos-specific steps" -ForegroundColor Yellow
            }
            Write-Record -Action "VerifyKerberos" -Target "KerberosState" -Method "Klist" -ReturnCode 0 -Outcome "Skipped" -Error "Not domain-joined" -Command "klist get krbtgt" -ExitCode 0
            return $true
        }
        
        if (-not $ctx.DCReachable) {
            Write-Warning "Domain joined but DC unreachable; krbtgt verification will likely fail"
            Write-Record -Action "VerifyKerberos" -Target "KerberosState" -Method "Klist" -ReturnCode 1 -Outcome "Failed" -Error "Domain controller unreachable" -Command "klist get krbtgt" -ExitCode 1
            return $false
        }
        
        # Actually reacquire krbtgt ticket
        $res = (klist get krbtgt) 2>&1
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            if (-not $Quiet) {
                Write-Host "krbtgt successfully reacquired" -ForegroundColor Green
            }
            Write-Record -Action "VerifyKerberos" -Target "KerberosState" -Method "Klist" -ReturnCode 0 -Outcome "Success" -Command "klist get krbtgt" -ExitCode $code
            return $true
        } else {
            Write-Warning "Failed to reacquire krbtgt"
            Write-Record -Action "VerifyKerberos" -Target "KerberosState" -Method "Klist" -ReturnCode 1 -Outcome "Failed" -Error "klist get krbtgt failed" -Command "klist get krbtgt" -ExitCode $code
            return $false
        }
    }
    catch {
        Write-Warning "Error during krbtgt verification: $($_.Exception.Message)"
        Write-Record -Action "VerifyKerberos" -Target "KerberosState" -Method "Klist" -ReturnCode 3 -Outcome "Failed" -Error $_.Exception.Message -Command "klist get krbtgt" -ExitCode 3
        return $false
    }
}

function Get-DomainContext {
    <#
    .SYNOPSIS
        Detects domain vs workgroup and DC reachability for secure context decisions.
    .DESCRIPTION
        Returns domain membership status and DC reachability without false-flagging offline scenarios.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $partOfDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
        $dcReachable = $false
        
        if ($partOfDomain) {
            try {
                # Check if nltest is available
                $nltestPath = Get-Command nltest.exe -ErrorAction SilentlyContinue
                if ($nltestPath) {
                    nltest /dsgetdc: > $null 2>&1
                    $dcReachable = ($LASTEXITCODE -eq 0)
                } else {
                    # Fallback: try Test-ComputerSecureChannel if available
                    try {
                        $dcReachable = Test-ComputerSecureChannel -ErrorAction Stop
                    } catch {
                        $dcReachable = $false
                    }
                }
            } catch { 
                $dcReachable = $false
            }
        }
        
        $result = [pscustomobject]@{ 
            PartOfDomain = $partOfDomain
            DCReachable = $dcReachable 
        }
        
        Write-Record -Action "GetDomainContext" -Target "DomainStatus" -Method "CIM" -ReturnCode 0 -Outcome "Success" -Command "Get-CimInstance Win32_ComputerSystem" -ExitCode 0
        return $result
    }
    catch {
        Write-Warning "Failed to determine domain context: $($_.Exception.Message)"
        Write-Record -Action "GetDomainContext" -Target "DomainStatus" -Method "CIM" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "Get-CimInstance Win32_ComputerSystem" -ExitCode 1
        return [pscustomobject]@{ PartOfDomain = $false; DCReachable = $false }
    }
}

function Write-EventMirror {
    <#
    .SYNOPSIS
        Mirrors key events to Windows Event Log for SOC visibility.
    .DESCRIPTION
        Writes custom events to Application log with EventIDs 9100-9104 when -WriteEventLog is specified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [int]$EventId = 9100,
        
        [System.Diagnostics.EventLogEntryType]$Type = [System.Diagnostics.EventLogEntryType]::Information
    )
    
    if (-not $WriteEventLog) { return }
    
    $source = 'CredNetReset'
    $log = 'Application'
    
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            New-EventLog -LogName $log -Source $source -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName $log -Source $source -EventId $EventId -EntryType $Type -Message $Message -ErrorAction Stop
        Write-Record -Action "WriteEventMirror" -Target "EventLog" -Method "WriteEventLog" -ReturnCode 0 -Outcome "Success" -Command "Write-EventLog" -ExitCode 0
    } catch {
        Write-Warning "Failed to write event log: $($_.Exception.Message)"
        Write-Record -Action "WriteEventMirror" -Target "EventLog" -Method "WriteEventLog" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "Write-EventLog" -ExitCode 1
    }
}

function Test-InteractiveSessions {
    <#
    .SYNOPSIS
        Detects active console/RDP sessions and warns about potential disruption.
    .DESCRIPTION
        Uses quser to detect active sessions and prompts for confirmation unless -Force is specified.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Use quser for better session detection
        $out = (quser 2>$null) -join "`n"
        $hasActiveSessions = $LASTEXITCODE -eq 0 -and $out -match 'Active'
        
        if ($hasActiveSessions) {
            Write-Warning "Active console/RDP session detected; credentials may be interrupted."
            Write-Host "Continuing may invalidate your current admin token; reconnect might be required." -ForegroundColor Yellow
            Write-Record -Action "InteractiveCheck" -Target "UserSessions" -Method "QUser" -ReturnCode 0 -Outcome "DetectedActive" -Command "quser" -ExitCode 0
            
            if (-not $Force -and -not $WhatIfPreference) {
                $resp = Read-Host "Continue? (Y/N)"
                if ($resp -notin @('Y','y')) {
                    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
                    Write-Record -Action "InteractiveCheck" -Target "UserSessions" -Method "QUser" -ReturnCode 0 -Outcome "Cancelled" -Error "User chose to cancel" -Command "quser" -ExitCode 0
                    $script:ExitCode = 2
                    return $false
                }
            }
        } else {
            Write-Record -Action "InteractiveCheck" -Target "UserSessions" -Method "QUser" -ReturnCode 0 -Outcome "NoActiveSessions"
        }
        
        return $hasActiveSessions
    }
    catch {
        Write-Record -Action "InteractiveCheck" -Target "UserSessions" -Method "QUser" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message
        return $false
    }
}

#endregion

#region Capability Probes

function Test-SystemCapabilities {
    <#
    .SYNOPSIS
        Probes for required system binaries and capabilities with WOW64 awareness.
    .DESCRIPTION
        Checks presence of klist, nltest, nbtstat, ipconfig, netsh and degrades gracefully.
        Resolves system binaries explicitly to avoid WOW64 redirection edge cases.
    #>
    [CmdletBinding()]
    param()
    
    $capabilities = @{
        Klist = $false
        Nltest = $false
        Nbtstat = $false
        Ipconfig = $false
        Netsh = $false
        Missing = @()
        Paths = @{}
    }
    
    # Resolve system directory path to avoid WOW64 redirection
    $sys32 = Join-Path ${env:windir} 'System32'
    
    try {
        # Core Kerberos capability - check both PATH and System32
        $klistPath = Get-Command klist.exe -ErrorAction SilentlyContinue
        if (-not $klistPath) {
            $klistPath = Get-Command (Join-Path $sys32 'klist.exe') -ErrorAction SilentlyContinue
        }
        if ($klistPath) {
            $capabilities.Klist = $true
            $capabilities.Paths.Klist = $klistPath.Source
        } else {
            $capabilities.Missing += "klist.exe (required for Kerberos operations)"
        }
        
        # Domain connectivity testing
        $nltestPath = Get-Command nltest.exe -ErrorAction SilentlyContinue
        if (-not $nltestPath) {
            $nltestPath = Get-Command (Join-Path $sys32 'nltest.exe') -ErrorAction SilentlyContinue
        }
        if ($nltestPath) {
            $capabilities.Nltest = $true
            $capabilities.Paths.Nltest = $nltestPath.Source
        } else {
            $capabilities.Missing += "nltest.exe (required for domain connectivity testing)"
        }
        
        # Network tools (optional)
        $ipconfigPath = Get-Command ipconfig.exe -ErrorAction SilentlyContinue
        if (-not $ipconfigPath) {
            $ipconfigPath = Get-Command (Join-Path $sys32 'ipconfig.exe') -ErrorAction SilentlyContinue
        }
        if ($ipconfigPath) {
            $capabilities.Ipconfig = $true
            $capabilities.Paths.Ipconfig = $ipconfigPath.Source
        } else {
            $capabilities.Missing += "ipconfig.exe (required for DNS operations)"
        }
        
        $netshPath = Get-Command netsh.exe -ErrorAction SilentlyContinue
        if (-not $netshPath) {
            $netshPath = Get-Command (Join-Path $sys32 'netsh.exe') -ErrorAction SilentlyContinue
        }
        if ($netshPath) {
            $capabilities.Netsh = $true
            $capabilities.Paths.Netsh = $netshPath.Source
        } else {
            $capabilities.Missing += "netsh.exe (required for ARP cache operations)"
        }
        
        # NetBIOS tools (optional)
        $nbtstatPath = Get-Command nbtstat.exe -ErrorAction SilentlyContinue
        if (-not $nbtstatPath) {
            $nbtstatPath = Get-Command (Join-Path $sys32 'nbtstat.exe') -ErrorAction SilentlyContinue
        }
        if ($nbtstatPath) {
            $capabilities.Nbtstat = $true
            $capabilities.Paths.Nbtstat = $nbtstatPath.Source
        } else {
            $capabilities.Missing += "nbtstat.exe (required for NetBIOS operations)"
        }
        
        Write-Record -Action "TestCapabilities" -Target "SystemBinaries" -Method "GetCommand" -ReturnCode 0 -Outcome "Success" -Command "Get-Command" -ExitCode 0
        return $capabilities
    }
    catch {
        Write-Record -Action "TestCapabilities" -Target "SystemBinaries" -Method "GetCommand" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "Get-Command" -ExitCode 1
        return $capabilities
    }
}

function Assert-CoreCapabilities {
    <#
    .SYNOPSIS
        Validates core requirements and fails fast if critical tools are missing.
    .DESCRIPTION
        Hard fails if klist is missing since Kerberos operations are core functionality.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Capabilities
    )
    
    # Hard requirement: klist for Kerberos operations
    if (-not $Capabilities.Klist) {
        Write-Error "FATAL: klist.exe not found. Kerberos ticket operations require klist.exe to be available in PATH."
        Write-Record -Action "AssertCapabilities" -Target "CoreRequirements" -Method "CapabilityCheck" -ReturnCode 3 -Outcome "Failed" -Error "klist.exe not available" -Command "klist" -ExitCode 3
        $script:ExitCode = 3
        exit 3
    }
    
    # Warn about missing optional tools
    if ($Capabilities.Missing.Count -gt 0) {
        Write-Warning "Some optional tools are missing: $($Capabilities.Missing -join ', ')"
        Write-Record -Action "AssertCapabilities" -Target "OptionalTools" -Method "CapabilityCheck" -ReturnCode 1 -Outcome "Warning" -Error "Optional tools missing: $($Capabilities.Missing -join ', ')" -Command "system probe" -ExitCode 1
    }
    
    Write-Record -Action "AssertCapabilities" -Target "CoreRequirements" -Method "CapabilityCheck" -ReturnCode 0 -Outcome "Success" -Command "capability probe" -ExitCode 0
}

#endregion

#region Parameter Validation

function Test-ParameterHygiene {
    <#
    .SYNOPSIS
        Validates parameter combinations, PowerShell version, and WOW64 context.
    .DESCRIPTION
        Checks for conflicting parameters, PS version compatibility, and provides helpful messages.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # PowerShell version check
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Write-Warning "PowerShell 5.1+ recommended. Current version: $($PSVersionTable.PSVersion). Some features may not work correctly."
        }
        
        # WOW64 context check (32-bit PowerShell on 64-bit Windows)
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            Write-Warning "Running 32-bit PowerShell on 64-bit Windows. Consider using 64-bit PowerShell for better system tool access."
        }
        
        # WhatIf + Force messaging
        if ($WhatIfPreference -and $Force) {
            Write-Host "INFO: -WhatIf overrides -Force; no confirmations will be bypassed in dry-run mode." -ForegroundColor Cyan
        }
        
        # IncludeNBNS without capability warning
        if ($IncludeNBNS) {
            $nbtstatAvailable = Get-Command nbtstat.exe -ErrorAction SilentlyContinue
            if (-not $nbtstatAvailable) {
                Write-Warning "NetBIOS operations requested but nbtstat.exe not available. NetBIOS steps will be skipped."
            }
        }
        
        # RefreshNetwork without capability warning  
        if ($RefreshNetwork) {
            $netshAvailable = Get-Command netsh.exe -ErrorAction SilentlyContinue
            if (-not $netshAvailable) {
                Write-Warning "Network refresh requested but netsh.exe not available. ARP cache clearing will be skipped."
            }
        }
        
        Write-Record -Action "TestParameterHygiene" -Target "ParameterValidation" -Method "ParameterCheck" -ReturnCode 0 -Outcome "Success" -Command "parameter validation" -ExitCode 0
        return $true
    }
    catch {
        Write-Record -Action "TestParameterHygiene" -Target "ParameterValidation" -Method "ParameterCheck" -ReturnCode 1 -Outcome "Failed" -Error $_.Exception.Message -Command "parameter validation" -ExitCode 1
        return $false
    }
}

#endregion

#region Main Script Logic

function Invoke-CredNetResetMain {
    <#
    .SYNOPSIS
        Main function that orchestrates the credential and network reset operations.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Initialize operation with event mirroring
        Write-EventMirror "CredNetReset started" 9100
        
        if (-not $Quiet) {
            Write-Host "`n=== Invoke-CredNetReset v1.0 ===" -ForegroundColor Cyan
            Write-Host "Operation started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
            Write-Host "Scope: $Scope" -ForegroundColor Gray
            if ($WhatIf) {
                Write-Host "Mode: DRY RUN (WhatIf)" -ForegroundColor Yellow
            }
            Write-Host ""
        }
        
        # Check administrator privileges
        Test-Admin
        
        # Probe system capabilities and fail fast if missing core tools
        $capabilities = Test-SystemCapabilities
        Assert-CoreCapabilities -Capabilities $capabilities
        
        # Validate parameter combinations
        Test-ParameterHygiene
        
        # Check for interactive sessions with safety prompt
        Test-InteractiveSessions
        
        # Phase 1: Kerberos Ticket Operations
        if (-not $Quiet) {
            Write-Host "Phase 1: Kerberos Ticket Operations" -ForegroundColor Cyan
        }
        
        $kerberosResults = Purge-KerberosTickets -TargetScope $Scope
        $script:SuccessCount += $kerberosResults.Success
        $script:FailureCount += $kerberosResults.Failed
        
        # Phase 2: DNS Cache Operations
        if (-not $Quiet) {
            Write-Host "`nPhase 2: DNS Cache Operations" -ForegroundColor Cyan
        }
        
        $dnsSuccess = Clear-DnsCache
        if ($dnsSuccess) {
            $script:SuccessCount++
        } else {
            $script:FailureCount++
        }
        
        # Phase 3: NetBIOS Operations (if requested)
        if ($IncludeNBNS) {
            if (-not $Quiet) {
                Write-Host "`nPhase 3: NetBIOS Operations" -ForegroundColor Cyan
            }
            
            $nbnsResults = Reset-NbnsCache
            if ($nbnsResults.CacheReset) { $script:SuccessCount++ } else { $script:FailureCount++ }
            if ($nbnsResults.NamesReregistered) { $script:SuccessCount++ } else { $script:FailureCount++ }
        }
        
        # Phase 4: Network Stack Refresh (if requested)
        if ($RefreshNetwork) {
            if (-not $Quiet) {
                Write-Host "`nPhase 4: Network Stack Refresh" -ForegroundColor Cyan
            }
            
            $networkResults = Refresh-NetworkStack
            if ($networkResults.DnsRegistered) { $script:SuccessCount++ } else { $script:FailureCount++ }
            if ($networkResults.ArpCleared) { $script:SuccessCount++ } else { $script:FailureCount++ }
        }
        
        # Phase 5: Verification
        if (-not $WhatIf) {
            if (-not $Quiet) {
                Write-Host "`nPhase 5: Post-Operation Verification" -ForegroundColor Cyan
            }
            
            $verificationSuccess = Verify-KerberosState
            if (-not $verificationSuccess) {
                Write-EventMirror "Verification failure" 9104 ([System.Diagnostics.EventLogEntryType]::Error)
                $script:PartialCount++
            }
        }
        
        # Determine final exit code and emit event mirrors
        if ($script:FailureCount -eq 0 -and $script:PartialCount -eq 0) {
            $script:ExitCode = 0
            Write-EventMirror "All operations successful" 9101 ([System.Diagnostics.EventLogEntryType]::Information)
        } elseif ($script:SuccessCount -gt 0 -and $script:FailureCount -gt 0) {
            $script:ExitCode = 1
            Write-EventMirror "Partial success" 9102 ([System.Diagnostics.EventLogEntryType]::Warning)
        } else {
            $script:ExitCode = 3
            Write-EventMirror "Failure" 9103 ([System.Diagnostics.EventLogEntryType]::Error)
        }
        
        # Display summary
        if (-not $Quiet) {
            Write-Host "`n=== Operation Summary ===" -ForegroundColor Cyan
            Write-Host "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
            Write-Host "Duration: $((Get-Date) - $script:OperationStartTime | ForEach-Object { '{0:mm\:ss}' -f $_ })" -ForegroundColor Gray
            Write-Host "Successful operations: $($script:SuccessCount)" -ForegroundColor Green
            if ($script:FailureCount -gt 0) {
                Write-Host "Failed operations: $($script:FailureCount)" -ForegroundColor Red
            }
            if ($script:PartialCount -gt 0) {
                Write-Host "Partial operations: $($script:PartialCount)" -ForegroundColor Yellow
            }
            
            # Display rollback/next steps guidance on partial failure
            if ($script:ExitCode -eq 1 -and -not $Quiet) {
                Write-Host "`nNext steps:" -ForegroundColor Yellow
                if (-not $verificationSuccess) { 
                    Write-Host " - Run 'klist get krbtgt' after reconnecting to the domain." -ForegroundColor Gray
                }
                if (-not $dnsSuccess) { 
                    Write-Host " - Retry 'ipconfig /flushdns' or verify Dnscache service." -ForegroundColor Gray
                }
                if ($RefreshNetwork) { 
                    Write-Host " - Validate DNS registration completed: 'ipconfig /displaydns' and check A/AAAA records." -ForegroundColor Gray
                }
                if ($LogPath) {
                    Write-Host " - Review structured log at: $LogPath" -ForegroundColor Gray
                }
            }
            
            Write-Host "`nExit Code: $($script:ExitCode)" -ForegroundColor Gray
        }
        
    }
    catch {
        Write-Error "Critical error in main operation: $($_.Exception.Message)"
        Write-EventLogEntry -EventType "Failure" -Message "Critical error in main operation" -Details $_.Exception.Message
        Write-Record -Action "MainOperation" -Target "CredNetReset" -Method "PowerShell" -ReturnCode 3 -Outcome "Failed" -Error $_.Exception.Message
        $script:ExitCode = 3
    }
    finally {
        exit $script:ExitCode
    }
}

#endregion

# Script entry point
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-CredNetResetMain
}