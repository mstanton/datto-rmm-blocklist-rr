#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Removes Rick Roll domain blocks from Windows hosts file.

.DESCRIPTION
    Datto RMM component that removes all Rick Roll domain redirects from the hosts file.
    Restores the original hosts file from backup if available, or removes entries by marker tag.

    This script:
    - Handles DNS Client service file locking
    - Restores from atomic backup if available
    - Safely removes entries by marker tag
    - Implements retry logic for locked files
    - Provides detailed logging for troubleshooting

.NOTES
    Author: Security Team
    Requires: Administrator privileges
#>

param()

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

function Restore-HostsFromBackup {
    <#
    .SYNOPSIS
        Restores hosts file from backup with retry logic.
    .DESCRIPTION
        Attempts to restore the original hosts file from backup.
        Handles file locking by temporarily stopping DNS Client service.
    #>

    if (-not (Test-Path $BACKUP_FILE)) {
        Write-Log "No backup file found at: $BACKUP_FILE" -Level WARN
        return $false
    }

    $dnsServiceWasStopped = $false
    $success = $false

    for ($attempt = 1; $attempt -le $MAX_RETRIES; $attempt++) {
        try {
            Write-Log "Attempt $attempt of $MAX_RETRIES to restore hosts file from backup" -Level INFO

            # Stop DNS Client service on first retry if initial attempt failed
            if ($attempt -gt 1 -and -not $dnsServiceWasStopped) {
                $dnsServiceWasStopped = Stop-DNSClientService
            }

            # Atomic copy operation to restore
            Copy-Item -Path $BACKUP_FILE -Destination $HOSTS_FILE -Force -ErrorAction Stop
            Write-Log "Hosts file restored from backup" -Level INFO

            # Remove backup file after successful restore
            Remove-Item -Path $BACKUP_FILE -Force -ErrorAction Stop
            Write-Log "Backup file removed" -Level INFO

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

function Remove-RickRollEntries {
    <#
    .SYNOPSIS
        Removes Rick Roll entries from hosts file by marker tag.
    .DESCRIPTION
        Reads hosts file, filters out lines with Rick Roll marker, and rewrites.
        Uses atomic read-modify-write pattern with retry logic.
    #>

    $dnsServiceWasStopped = $false
    $success = $false

    for ($attempt = 1; $attempt -le $MAX_RETRIES; $attempt++) {
        try {
            Write-Log "Attempt $attempt of $MAX_RETRIES to remove Rick Roll entries" -Level INFO

            # Stop DNS Client service on first retry if initial attempt failed
            if ($attempt -gt 1 -and -not $dnsServiceWasStopped) {
                $dnsServiceWasStopped = Stop-DNSClientService
            }

            # Read current hosts file content atomically
            $hostsContent = Get-Content -Path $HOSTS_FILE -ErrorAction Stop

            # Filter out Rick Roll entries by marker tag
            $cleanedContent = $hostsContent | Where-Object { $_ -notmatch [regex]::Escape($MARKER_TAG) }

            # Count removed entries
            $removedCount = $hostsContent.Count - $cleanedContent.Count

            if ($removedCount -gt 0) {
                # Write cleaned content atomically
                Set-Content -Path $HOSTS_FILE -Value $cleanedContent -Force -ErrorAction Stop
                Write-Log "Removed $removedCount Rick Roll entries from hosts file" -Level INFO
            }
            else {
                Write-Log "No Rick Roll entries found in hosts file" -Level INFO
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

function Remove-RickRollArtifacts {
    <#
    .SYNOPSIS
        Removes Rick Roll HTML files and other artifacts.
    #>
    try {
        $htmlPath = "$env:ProgramData\DattoRMM\rickroll.html"

        if (Test-Path $htmlPath) {
            Remove-Item -Path $htmlPath -Force -ErrorAction Stop
            Write-Log "Removed Rick Roll HTML file" -Level INFO
        }
        else {
            Write-Log "No Rick Roll HTML file found" -Level INFO
        }

        return $true
    }
    catch {
        Write-Log "Failed to remove Rick Roll artifacts: $_" -Level WARN
        return $false
    }
}

#endregion

#region Main Execution

function Invoke-RickRollRemoval {
    <#
    .SYNOPSIS
        Main execution function that orchestrates the removal process.
    #>

    Write-Log "=== Rick Roll Removal Started ===" -Level INFO

    # Validate administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log "ERROR: Administrator privileges required" -Level ERROR
        Write-Output "FAILED: Must run as Administrator"
        exit 1
    }

    # Verify hosts file exists
    if (-not (Test-Path $HOSTS_FILE)) {
        Write-Log "ERROR: Hosts file not found at $HOSTS_FILE" -Level ERROR
        Write-Output "FAILED: Hosts file not found"
        exit 1
    }

    # Attempt to restore from backup first (preferred method)
    $restoredFromBackup = $false
    try {
        if (Test-Path $BACKUP_FILE) {
            Write-Log "Backup file found, attempting restoration" -Level INFO
            if (Restore-HostsFromBackup) {
                $restoredFromBackup = $true
                Write-Log "Successfully restored hosts file from backup" -Level INFO
            }
        }
        else {
            Write-Log "No backup file found, will remove entries by marker tag" -Level INFO
        }
    }
    catch {
        Write-Log "Failed to restore from backup: $_" -Level WARN
        Write-Log "Will attempt to remove entries by marker tag" -Level INFO
    }

    # If backup restoration failed or no backup exists, remove entries manually
    if (-not $restoredFromBackup) {
        try {
            if (-not (Remove-RickRollEntries)) {
                throw "Failed to remove Rick Roll entries"
            }
        }
        catch {
            Write-Log "ERROR: Failed to remove Rick Roll entries: $_" -Level ERROR
            Write-Output "FAILED: Could not remove Rick Roll entries - $_"
            exit 1
        }
    }

    # Flush DNS cache
    Clear-DNSCache | Out-Null

    # Remove Rick Roll artifacts
    Remove-RickRollArtifacts | Out-Null

    Write-Log "=== Rick Roll Removal Completed Successfully ===" -Level INFO

    Write-Output "SUCCESS: Rick Roll configuration removed"
    exit 0
}

# Execute main function with global error handling
try {
    Invoke-RickRollRemoval
}
catch {
    Write-Log "FATAL ERROR: $_" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    Write-Output "FAILED: Unexpected error - $_"
    exit 1
}

#endregion
