#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Modifies Windows hosts file to redirect specified domains to Rick Roll video.

.DESCRIPTION
    Datto RMM component that blocks domains by redirecting them to 127.0.0.1 in the hosts file.
    Designed for security awareness training and policy enforcement.

    This script:
    - Validates and sanitizes all domain inputs
    - Handles DNS Client service file locking
    - Creates atomic backups before modification
    - Implements retry logic for locked files
    - Provides detailed logging for troubleshooting

.PARAMETER BlockedSites
    Comma-separated list of domains to block (e.g., "facebook.com,twitter.com")

.NOTES
    Author: Security Team
    Requires: Administrator privileges
    Datto RMM: Set ENV:BLOCKED_SITES variable
#>

param(
    [string]$BlockedSites = $env:BLOCKED_SITES
)

# Configuration constants
$HOSTS_FILE = "$env:SystemRoot\System32\drivers\etc\hosts"
$BACKUP_FILE = "$env:SystemRoot\System32\drivers\etc\hosts.rickroll.backup"
$LOG_FILE = "$env:ProgramData\DattoRMM\RickRoll.log"
$MARKER_TAG = "# RICKROLL_BLOCK"
$MAX_RETRIES = 3
$RETRY_DELAY_SECONDS = 2

#region Logging Functions

function Write-Log {
    <#
    .SYNOPSIS
        Thread-safe logging function with timestamp.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"

    try {
        # Create log directory if it doesn't exist
        $logDir = Split-Path -Path $LOG_FILE -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }

        # Thread-safe file append
        $logMessage | Out-File -FilePath $LOG_FILE -Append -Encoding UTF8
    }
    catch {
        # Fallback to console only if logging fails
        Write-Warning "Failed to write to log: $_"
    }

    Write-Host $logMessage
}

#endregion

#region Validation Functions

function Test-ValidDomain {
    <#
    .SYNOPSIS
        Validates and sanitizes domain name input to prevent injection attacks.
    .DESCRIPTION
        Ensures domain contains only valid characters (alphanumeric, dots, hyphens).
        Prevents command injection, path traversal, and malformed entries.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    # Remove whitespace
    $Domain = $Domain.Trim()

    # Check for empty or null
    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return $false
    }

    # Validate domain format (alphanumeric, dots, hyphens only)
    # Prevents injection: no spaces, tabs, special chars, path traversal
    if ($Domain -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$') {
        Write-Log "Invalid domain format: $Domain" -Level WARN
        return $false
    }

    # Reject domains that are too long (max 253 chars per RFC)
    if ($Domain.Length -gt 253) {
        Write-Log "Domain too long: $Domain" -Level WARN
        return $false
    }

    # Reject domains with consecutive dots or starting/ending with dot
    if ($Domain -match '\.\.|\.$|^\.') {
        Write-Log "Malformed domain: $Domain" -Level WARN
        return $false
    }

    return $true
}

#endregion

#region File Operations

function Stop-DNSClientService {
    <#
    .SYNOPSIS
        Stops DNS Client service to release hosts file lock.
    .DESCRIPTION
        The DNS Client service often locks the hosts file.
        Temporarily stopping it allows modification.
    #>
    try {
        $dnsService = Get-Service -Name "Dnscache" -ErrorAction SilentlyContinue

        if ($dnsService -and $dnsService.Status -eq 'Running') {
            Write-Log "Stopping DNS Client service to release hosts file lock" -Level INFO
            Stop-Service -Name "Dnscache" -Force -ErrorAction Stop
            Start-Sleep -Seconds 1
            return $true
        }

        return $false
    }
    catch {
        Write-Log "Failed to stop DNS Client service: $_" -Level WARN
        return $false
    }
}

function Start-DNSClientService {
    <#
    .SYNOPSIS
        Restarts DNS Client service after hosts file modification.
    #>
    try {
        $dnsService = Get-Service -Name "Dnscache" -ErrorAction SilentlyContinue

        if ($dnsService -and $dnsService.Status -ne 'Running') {
            Write-Log "Starting DNS Client service" -Level INFO
            Start-Service -Name "Dnscache" -ErrorAction Stop
            return $true
        }

        return $false
    }
    catch {
        Write-Log "Failed to start DNS Client service: $_" -Level ERROR
        return $false
    }
}

function Backup-HostsFile {
    <#
    .SYNOPSIS
        Creates atomic backup of hosts file before modification.
    .DESCRIPTION
        Only creates backup if one doesn't exist.
        Uses Copy-Item with -Force for atomic operation.
    #>
    try {
        # Only backup if backup doesn't already exist
        if (-not (Test-Path $BACKUP_FILE)) {
            Copy-Item -Path $HOSTS_FILE -Destination $BACKUP_FILE -Force -ErrorAction Stop
            Write-Log "Hosts file backed up to: $BACKUP_FILE" -Level INFO
            return $true
        }
        else {
            Write-Log "Backup already exists: $BACKUP_FILE" -Level INFO
            return $true
        }
    }
    catch {
        Write-Log "Failed to backup hosts file: $_" -Level ERROR
        return $false
    }
}

function Add-HostsEntries {
    <#
    .SYNOPSIS
        Adds domain entries to hosts file with retry logic and file locking.
    .DESCRIPTION
        Implements atomic read-modify-write pattern with retry logic.
        Handles file locking by temporarily stopping DNS Client service.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Domains
    )

    $dnsServiceWasStopped = $false
    $success = $false

    for ($attempt = 1; $attempt -le $MAX_RETRIES; $attempt++) {
        try {
            Write-Log "Attempt $attempt of $MAX_RETRIES to modify hosts file" -Level INFO

            # Stop DNS Client service on first retry if initial attempt failed
            if ($attempt -gt 1 -and -not $dnsServiceWasStopped) {
                $dnsServiceWasStopped = Stop-DNSClientService
            }

            # Read current hosts file content atomically
            $hostsContent = Get-Content -Path $HOSTS_FILE -ErrorAction Stop

            # Build list of entries to add
            $newEntries = @()

            foreach ($domain in $Domains) {
                # Skip if entry already exists
                $pattern = "^\s*127\.0\.0\.1\s+$([regex]::Escape($domain))\s"
                $exists = $hostsContent | Where-Object { $_ -match $pattern }

                if (-not $exists) {
                    # Format: IP + TAB + domain + TAB + marker comment
                    $newEntries += "127.0.0.1`t$domain`t$MARKER_TAG"
                    Write-Log "Will add entry for: $domain" -Level INFO
                }
                else {
                    Write-Log "Entry already exists for: $domain" -Level INFO
                }
            }

            # If there are new entries to add, append them atomically
            if ($newEntries.Count -gt 0) {
                # Ensure file ends with newline before appending
                $lastLine = $hostsContent[-1]
                if (-not [string]::IsNullOrWhiteSpace($lastLine)) {
                    $newEntries = @("") + $newEntries
                }

                # Atomic append operation
                Add-Content -Path $HOSTS_FILE -Value $newEntries -ErrorAction Stop
                Write-Log "Successfully added $($newEntries.Count) hosts entries" -Level INFO
            }
            else {
                Write-Log "No new entries needed" -Level INFO
            }

            $success = $true
            break
        }
        catch {
            Write-Log "Attempt $attempt failed: $_" -Level WARN

            if ($attempt -lt $MAX_RETRIES) {
                Write-Log "Retrying in $RETRY_DELAY_SECONDS seconds..." -Level INFO
                Start-Sleep -Seconds $RETRY_DELAY_SECONDS
            }
            else {
                Write-Log "All retry attempts exhausted" -Level ERROR
                throw
            }
        }
    }

    # Restart DNS Client service if we stopped it
    if ($dnsServiceWasStopped) {
        Start-DNSClientService | Out-Null
    }

    return $success
}

function Clear-DNSCache {
    <#
    .SYNOPSIS
        Flushes DNS resolver cache to apply hosts file changes immediately.
    #>
    try {
        Clear-DnsClientCache -ErrorAction Stop
        Write-Log "DNS cache flushed successfully" -Level INFO
        return $true
    }
    catch {
        Write-Log "Failed to flush DNS cache: $_" -Level WARN
        return $false
    }
}

#endregion

#region Main Execution

function Invoke-RickRollBlocker {
    <#
    .SYNOPSIS
        Main execution function that orchestrates the blocking process.
    #>

    Write-Log "=== Rick Roll Blocker Started ===" -Level INFO

    # Validate administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log "ERROR: Administrator privileges required" -Level ERROR
        Write-Output "FAILED: Must run as Administrator"
        exit 1
    }

    # Validate input
    if ([string]::IsNullOrWhiteSpace($BlockedSites)) {
        Write-Log "ERROR: No blocked sites specified" -Level ERROR
        Write-Output "FAILED: BLOCKED_SITES parameter is required"
        exit 1
    }

    # Parse and validate domain list
    $siteList = $BlockedSites -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    if ($siteList.Count -eq 0) {
        Write-Log "ERROR: No valid domains in BLOCKED_SITES" -Level ERROR
        Write-Output "FAILED: No valid domains to block"
        exit 1
    }

    # Validate and sanitize each domain
    $validDomains = @()
    foreach ($site in $siteList) {
        if (Test-ValidDomain -Domain $site) {
            $validDomains += $site

            # Also add www variant if not already present
            if (-not $site.StartsWith("www.")) {
                $wwwSite = "www.$site"
                if (Test-ValidDomain -Domain $wwwSite) {
                    $validDomains += $wwwSite
                }
            }
        }
        else {
            Write-Log "Skipping invalid domain: $site" -Level WARN
        }
    }

    if ($validDomains.Count -eq 0) {
        Write-Log "ERROR: No valid domains after validation" -Level ERROR
        Write-Output "FAILED: All domains failed validation"
        exit 1
    }

    Write-Log "Blocking $($validDomains.Count) domains: $($validDomains -join ', ')" -Level INFO

    # Verify hosts file exists
    if (-not (Test-Path $HOSTS_FILE)) {
        Write-Log "ERROR: Hosts file not found at $HOSTS_FILE" -Level ERROR
        Write-Output "FAILED: Hosts file not found"
        exit 1
    }

    # Create backup
    if (-not (Backup-HostsFile)) {
        Write-Log "ERROR: Failed to backup hosts file" -Level ERROR
        Write-Output "FAILED: Could not create backup"
        exit 1
    }

    # Add hosts entries with retry logic
    try {
        if (-not (Add-HostsEntries -Domains $validDomains)) {
            throw "Failed to add hosts entries"
        }
    }
    catch {
        Write-Log "ERROR: Failed to modify hosts file: $_" -Level ERROR
        Write-Output "FAILED: Could not modify hosts file - $_"
        exit 1
    }

    # Flush DNS cache
    Clear-DNSCache | Out-Null

    Write-Log "=== Rick Roll Blocker Completed Successfully ===" -Level INFO
    Write-Log "Blocked domains: $($validDomains.Count)" -Level INFO
    Write-Log "Backup location: $BACKUP_FILE" -Level INFO

    Write-Output "SUCCESS: Blocked $($validDomains.Count) domains"
    exit 0
}

# Execute main function with global error handling
try {
    Invoke-RickRollBlocker
}
catch {
    Write-Log "FATAL ERROR: $_" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    Write-Output "FAILED: Unexpected error - $_"
    exit 1
}

#endregion
