# Datto RMM Component: Remove Rick Roll Configuration
# Description: Restores original hosts file and removes Rick Roll redirects

param()

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsBackupPath = "$env:SystemRoot\System32\drivers\etc\hosts.rickroll.backup"
$logPath = "$env:ProgramData\DattoRMM\RickRoll.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logPath -Append
    Write-Host $Message
}

try {
    Write-Log "=== Rick Roll Removal Started ==="
    
    # Check for admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Log "ERROR: This script requires administrator privileges"
        exit 1
    }
    
    # Restore from backup if available
    if (Test-Path $hostsBackupPath) {
        Copy-Item -Path $hostsBackupPath -Destination $hostsPath -Force
        Write-Log "Hosts file restored from backup"
        Remove-Item -Path $hostsBackupPath -Force
        Write-Log "Backup file removed"
    } else {
        # Remove Rick Roll entries manually
        $hostsContent = Get-Content -Path $hostsPath
        $cleanedContent = $hostsContent | Where-Object { $_ -notmatch "# RickRoll Redirect" }
        $cleanedContent | Set-Content -Path $hostsPath -Force
        Write-Log "Rick Roll entries removed from hosts file"
    }
    
    # Flush DNS cache
    Clear-DnsClientCache
    Write-Log "DNS cache flushed"
    
    # Remove HTML file
    $htmlPath = "$env:ProgramData\DattoRMM\rickroll.html"
    if (Test-Path $htmlPath) {
        Remove-Item -Path $htmlPath -Force
        Write-Log "Rick Roll HTML file removed"
    }
    
    Write-Log "=== Rick Roll Removal Completed Successfully ==="
    Write-Output "SUCCESS: Rick Roll configuration removed"
    exit 0
    
} catch {
    Write-Log "ERROR: $_"
    Write-Output "FAILED: $_"
    exit 1
}
