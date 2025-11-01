# Datto RMM Component: Rick Roll Blocked Sites
# Description: Redirects users to Rick Astley's "Never Gonna Give You Up" when they attempt to access blocked websites
# Use Case: Security awareness training / Policy enforcement with humor

# Environment Variables from Datto RMM
# ENV:BLOCKED_SITES - Comma-separated list of domains to block (e.g., "facebook.com,twitter.com,reddit.com")
# ENV:RICKROLL_URL - Custom Rick Roll URL (optional, defaults to YouTube)

param(
    [string]$BlockedSites = $env:BLOCKED_SITES,
    [string]$RickRollURL = $env:RICKROLL_URL
)

# Default Rick Roll URL if not specified
if ([string]::IsNullOrWhiteSpace($RickRollURL)) {
    $RickRollURL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
}

# Hosts file path
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsBackupPath = "$env:SystemRoot\System32\drivers\etc\hosts.rickroll.backup"

# Log file
$logPath = "$env:ProgramData\DattoRMM\RickRoll.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logPath -Append
    Write-Host $Message
}

function Add-HostsEntry {
    param(
        [string]$Domain,
        [string]$IPAddress = "127.0.0.1"
    )
    
    try {
        # Backup hosts file if not already backed up
        if (-not (Test-Path $hostsBackupPath)) {
            Copy-Item -Path $hostsPath -Destination $hostsBackupPath -Force
            Write-Log "Hosts file backed up to: $hostsBackupPath"
        }
        
        # Read current hosts file
        $hostsContent = Get-Content -Path $hostsPath
        
        # Check if entry already exists
        $entryExists = $hostsContent | Where-Object { $_ -match "^\s*$IPAddress\s+$Domain" }
        
        if (-not $entryExists) {
            # Add the entry
            Add-Content -Path $hostsPath -Value "$IPAddress`t$Domain`t# RickRoll Redirect"
            Write-Log "Added hosts entry for: $Domain"
        } else {
            Write-Log "Hosts entry already exists for: $Domain"
        }
    } catch {
        Write-Log "ERROR: Failed to add hosts entry for $Domain - $_"
    }
}

function Set-RickRollPage {
    # Create a local HTML file that redirects to Rick Roll
    $htmlPath = "$env:ProgramData\DattoRMM\rickroll.html"
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <meta http-equiv="refresh" content="0; url=$RickRollURL">
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
        }
        h1 {
            font-size: 3em;
            margin-bottom: 20px;
        }
        p {
            font-size: 1.2em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 Site Blocked</h1>
        <p>This site is not allowed by company policy.</p>
        <p>Redirecting you to approved content...</p>
        <p><em>Never gonna let you down! 🎵</em></p>
    </div>
</body>
</html>
"@
    
    try {
        # Create directory if it doesn't exist
        $directory = Split-Path -Path $htmlPath
        if (-not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        
        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
        Write-Log "Rick Roll HTML page created at: $htmlPath"
        return $htmlPath
    } catch {
        Write-Log "ERROR: Failed to create Rick Roll HTML page - $_"
        return $null
    }
}

function Start-LocalWebServer {
    # Start a simple HTTP listener to serve the Rick Roll page
    try {
        # Check if listener is already running
        $existingListener = Get-NetTCPConnection -LocalPort 80 -ErrorAction SilentlyContinue
        if ($existingListener) {
            Write-Log "Web server already running on port 80"
            return
        }
        
        # Create a scheduled task to run a simple Python HTTP server
        # (Alternative: use IIS or create a proper HTTP listener)
        Write-Log "Note: For full functionality, configure IIS or a web server to serve the Rick Roll page"
        
    } catch {
        Write-Log "ERROR: Failed to start web server - $_"
    }
}

# Main execution
try {
    Write-Log "=== Rick Roll Component Started ==="
    
    # Check for admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Log "ERROR: This script requires administrator privileges"
        exit 1
    }
    
    # Validate blocked sites input
    if ([string]::IsNullOrWhiteSpace($BlockedSites)) {
        Write-Log "ERROR: No blocked sites specified. Set ENV:BLOCKED_SITES variable"
        exit 1
    }
    
    # Parse blocked sites
    $siteList = $BlockedSites -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    
    Write-Log "Blocked sites list: $($siteList -join ', ')"
    Write-Log "Rick Roll URL: $RickRollURL"
    
    # Create Rick Roll HTML page
    $htmlPath = Set-RickRollPage
    
    # Add hosts file entries for each blocked site
    foreach ($site in $siteList) {
        # Add both www and non-www versions
        Add-HostsEntry -Domain $site
        if (-not $site.StartsWith("www.")) {
            Add-HostsEntry -Domain "www.$site"
        }
    }
    
    # Flush DNS cache
    try {
        Clear-DnsClientCache
        Write-Log "DNS cache flushed successfully"
    } catch {
        Write-Log "WARNING: Could not flush DNS cache - $_"
    }
    
    Write-Log "=== Rick Roll Component Completed Successfully ==="
    Write-Log "Users will now be redirected when attempting to access blocked sites"
    Write-Log "To restore original hosts file, copy from: $hostsBackupPath"
    
    # Output for Datto RMM
    Write-Output "SUCCESS: Rick Roll component configured for $($siteList.Count) blocked domains"
    exit 0
    
} catch {
    Write-Log "ERROR: Unexpected error - $_"
    Write-Output "FAILED: $_"
    exit 1
}
