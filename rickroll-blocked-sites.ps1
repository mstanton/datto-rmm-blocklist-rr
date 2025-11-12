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
    [string]$BlockedSites = $env:BLOCKED_SITES,
    [string]$RickRollURL = $env:RICKROLL_URL
)

# Default Rick Roll URL if not specified
if ([string]::IsNullOrWhiteSpace($RickRollURL)) {
    $RickRollURL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
}

# Configuration constants
$HOSTS_FILE = "$env:SystemRoot\System32\drivers\etc\hosts"
$BACKUP_FILE = "$env:SystemRoot\System32\drivers\etc\hosts.rickroll.backup"
$LOG_FILE = "$env:ProgramData\DattoRMM\RickRoll.log"
$LISTENER_SCRIPT = "$env:ProgramData\DattoRMM\rickroll-http-listener.ps1"
$TASK_NAME = "RickRollHTTPListener"
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

function Deploy-HTTPListener {
    <#
    .SYNOPSIS
        Deploys HTTP listener script to handle localhost redirects.
    .DESCRIPTION
        Creates the PowerShell script that listens on port 80 and redirects
        blocked domain requests to the Rick Roll URL.
    #>
    try {
        Write-Log "Deploying HTTP listener script" -Level INFO

        # HTTP listener script content (embedded for single-file deployment)
        $listenerScript = @'
#Requires -RunAsAdministrator
param([string]$RickRollURL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
$LOG_FILE = "$env:ProgramData\DattoRMM\RickRoll.log"
$PID_FILE = "$env:ProgramData\DattoRMM\RickRoll.pid"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        "$timestamp [$Level] $Message" | Out-File -FilePath $LOG_FILE -Append -Encoding UTF8
    } catch {}
}

$redirectHTML = @"
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Access Denied</title>
<meta http-equiv="refresh" content="2; url=$RickRollURL">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', Tahoma, sans-serif;
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh; text-align: center; padding: 20px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}
.container {
    max-width: 600px; padding: 40px;
    background: rgba(0,0,0,0.3); border-radius: 15px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
}
h1 { font-size: 3em; margin-bottom: 20px; animation: pulse 2s infinite; }
p { font-size: 1.3em; margin: 15px 0; line-height: 1.6; }
.spinner {
    margin: 30px auto; width: 50px; height: 50px;
    border: 5px solid rgba(255,255,255,0.3);
    border-top: 5px solid white; border-radius: 50%;
    animation: spin 1s linear infinite;
}
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
@keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.05); } }
</style></head><body>
<div class="container">
    <h1>🚫 Site Blocked</h1>
    <p><strong>This website violates company policy.</strong></p>
    <p>Access has been denied by your IT department.</p>
    <div class="spinner"></div>
    <p><em>Redirecting to approved content...</em></p>
    <p style="font-size: 0.9em; margin-top: 30px; opacity: 0.8;">
        Never gonna give you up! 🎵
    </p>
</div></body></html>
"@

try {
    $PID | Out-File -FilePath $PID_FILE -Force
    Write-Log "Starting HTTP listener on port 80 (PID: $PID)"

    $portInUse = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
    if ($portInUse) {
        Write-Log "Port 80 already in use" -Level WARN
        exit 0
    }

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:80/")
    $listener.Prefixes.Add("http://localhost:80/")
    $listener.Start()
    Write-Log "HTTP listener started successfully"

    $redirectBytes = [System.Text.Encoding]::UTF8.GetBytes($redirectHTML)

    while ($listener.IsListening) {
        try {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response

            Write-Log "Blocked: $($request.Url) from $($request.RemoteEndPoint.Address)"

            $response.StatusCode = 200
            $response.ContentType = "text/html; charset=utf-8"
            $response.ContentLength64 = $redirectBytes.Length
            $response.OutputStream.Write($redirectBytes, 0, $redirectBytes.Length)
            $response.OutputStream.Close()
        } catch {
            Write-Log "Request error: $_" -Level WARN
        }
    }
} catch {
    Write-Log "Listener failed: $_" -Level ERROR
} finally {
    if ($listener -and $listener.IsListening) {
        $listener.Stop()
        $listener.Close()
    }
    if (Test-Path $PID_FILE) {
        Remove-Item -Path $PID_FILE -Force -ErrorAction SilentlyContinue
    }
}
'@

        # Create directory if needed
        $scriptDir = Split-Path -Path $LISTENER_SCRIPT -Parent
        if (-not (Test-Path $scriptDir)) {
            New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
        }

        # Deploy listener script
        $listenerScript | Out-File -FilePath $LISTENER_SCRIPT -Encoding UTF8 -Force
        Write-Log "HTTP listener script deployed to: $LISTENER_SCRIPT" -Level INFO

        return $true
    }
    catch {
        Write-Log "Failed to deploy HTTP listener: $_" -Level ERROR
        return $false
    }
}

function Start-HTTPListenerService {
    <#
    .SYNOPSIS
        Creates scheduled task and starts HTTP listener with fallback mechanisms.
    .DESCRIPTION
        Attempts multiple methods to start the HTTP listener:
        1. Scheduled task (for persistence across reboots)
        2. Direct background process (fallback if scheduled task fails)
        3. Verifies listener is responding with actual HTTP test
    #>
    try {
        Write-Log "Configuring HTTP listener service" -Level INFO

        # Check if port 80 is already in use
        $existingListener = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
        if ($existingListener) {
            $owningProcess = Get-Process -Id $existingListener.OwningProcess -ErrorAction SilentlyContinue
            if ($owningProcess.ProcessName -like "*powershell*" -or $owningProcess.ProcessName -like "*pwsh*") {
                Write-Log "HTTP listener already running on port 80 (PID: $($owningProcess.Id))" -Level INFO
                return $true
            }
            else {
                Write-Log "ERROR: Port 80 is in use by $($owningProcess.ProcessName) (PID: $($owningProcess.Id))" -Level ERROR
                Write-Log "Stop the conflicting service and retry deployment" -Level ERROR
                return $false
            }
        }

        # Method 1: Create and start scheduled task
        Write-Log "Attempting scheduled task deployment" -Level INFO

        $existingTask = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-Log "Removing existing scheduled task" -Level INFO
            Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
        }

        # Create scheduled task
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
            -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$LISTENER_SCRIPT`" -RickRollURL `"$RickRollURL`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask -TaskName $TASK_NAME -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Rick Roll HTTP redirect listener for blocked domains" | Out-Null
        Write-Log "Scheduled task '$TASK_NAME' created successfully" -Level INFO

        # Start scheduled task
        Write-Log "Starting scheduled task" -Level INFO
        Start-ScheduledTask -TaskName $TASK_NAME -ErrorAction Stop
        Start-Sleep -Seconds 3

        # Verify scheduled task method worked
        $listenerPort = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
        if ($listenerPort) {
            Write-Log "HTTP listener started successfully via scheduled task" -Level INFO

            # Test with actual HTTP request
            if (Test-HTTPListener) {
                Write-Log "HTTP listener verified and responding correctly" -Level INFO
                return $true
            }
        }

        # Method 2: Fallback to direct background process
        Write-Log "Scheduled task method failed, trying direct background process" -Level WARN

        $listenerArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$LISTENER_SCRIPT`" -RickRollURL `"$RickRollURL`""

        Start-Process -FilePath "PowerShell.exe" `
            -ArgumentList $listenerArgs `
            -WindowStyle Hidden `
            -PassThru | Out-Null

        Write-Log "Started HTTP listener as background process" -Level INFO
        Start-Sleep -Seconds 4

        # Verify direct process method worked
        $listenerPort = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
        if ($listenerPort) {
            Write-Log "HTTP listener started successfully via background process" -Level INFO

            # Test with actual HTTP request
            if (Test-HTTPListener) {
                Write-Log "HTTP listener verified and responding correctly" -Level INFO
                Write-Log "NOTE: Listener running as process, not scheduled task. May not survive reboot." -Level WARN
                return $true
            }
        }

        # Both methods failed
        Write-Log "ERROR: Failed to start HTTP listener using all methods" -Level ERROR
        Write-Log "Check for port conflicts, firewall rules, or permissions issues" -Level ERROR
        return $false
    }
    catch {
        Write-Log "Failed to start HTTP listener service: $_" -Level ERROR
        return $false
    }
}

function Test-HTTPListener {
    <#
    .SYNOPSIS
        Tests if HTTP listener is actually responding to requests.
    .DESCRIPTION
        Makes a test HTTP request to localhost:80 to verify the listener
        is not just bound to the port but actually serving content.
    #>
    try {
        Write-Log "Testing HTTP listener response" -Level INFO

        $testResponse = Invoke-WebRequest -Uri "http://127.0.0.1:80" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop

        if ($testResponse.StatusCode -eq 200 -and $testResponse.Content -like "*Site Blocked*") {
            Write-Log "HTTP listener test successful: Serving redirect page" -Level INFO
            return $true
        }
        else {
            Write-Log "HTTP listener responding but with unexpected content" -Level WARN
            return $false
        }
    }
    catch {
        Write-Log "HTTP listener test failed: $_" -Level ERROR
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

    # Deploy and start HTTP listener for localhost redirects
    Write-Log "Setting up HTTP redirect listener" -Level INFO

    if (-not (Deploy-HTTPListener)) {
        Write-Log "ERROR: HTTP listener deployment failed" -Level ERROR
        Write-Output "FAILED: Could not deploy HTTP listener script - Rick Roll redirects will not work"
        Write-Output "Hosts file has been updated but users will see 'connection refused' instead of redirect"
        exit 1
    }

    if (-not (Start-HTTPListenerService)) {
        Write-Log "ERROR: HTTP listener service failed to start" -Level ERROR
        Write-Output "FAILED: Could not start HTTP listener - Rick Roll redirects will not work"
        Write-Output "Common causes: Port 80 in use (IIS/Apache), firewall blocking, or permission issues"
        Write-Output "Check log file: C:\ProgramData\DattoRMM\RickRoll.log"
        exit 1
    }

    Write-Log "=== Rick Roll Blocker Completed Successfully ===" -Level INFO
    Write-Log "Blocked domains: $($validDomains.Count)" -Level INFO
    Write-Log "Rick Roll URL: $RickRollURL" -Level INFO
    Write-Log "Backup location: $BACKUP_FILE" -Level INFO
    Write-Log "HTTP listener: Active on port 80" -Level INFO

    Write-Output "SUCCESS: Blocked $($validDomains.Count) domains with HTTP redirect active"
    Write-Output "Rick Roll listener verified and responding on localhost:80"
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
