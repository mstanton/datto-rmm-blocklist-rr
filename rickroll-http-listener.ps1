#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Lightweight HTTP listener that redirects blocked site requests to Rick Roll video.

.DESCRIPTION
    Background service that listens on localhost:80 and redirects all HTTP requests
    to the Rick Roll YouTube video. Works in conjunction with hosts file blocking.

    This script:
    - Listens on http://127.0.0.1:80 for incoming requests
    - Serves redirect HTML for any blocked domain
    - Runs as a persistent background process
    - Logs all redirect attempts
    - Handles graceful shutdown

.NOTES
    Author: Security Team
    Requires: Administrator privileges
    Deployment: Runs as scheduled task on system startup
#>

param(
    [string]$RickRollURL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
)

# Configuration constants
$LISTENER_PORT = 80
$LOG_FILE = "$env:ProgramData\DattoRMM\RickRoll.log"
$PID_FILE = "$env:ProgramData\DattoRMM\RickRoll.pid"

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
        $logDir = Split-Path -Path $LOG_FILE -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $logMessage | Out-File -FilePath $LOG_FILE -Append -Encoding UTF8
    }
    catch {
        # Silently fail if logging doesn't work
    }
}

#endregion

#region HTTP Server Functions

function New-RedirectHTML {
    <#
    .SYNOPSIS
        Generates HTML redirect page with Rick Roll branding.
    #>
    param([string]$TargetURL)

    return @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Access Denied - Site Blocked</title>
    <meta http-equiv="refresh" content="2; url=$TargetURL">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            padding: 40px;
            background: rgba(0,0,0,0.3);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
        }
        h1 {
            font-size: 3em;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        p {
            font-size: 1.3em;
            margin: 15px 0;
            line-height: 1.6;
        }
        .spinner {
            margin: 30px auto;
            width: 50px;
            height: 50px;
            border: 5px solid rgba(255,255,255,0.3);
            border-top: 5px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 Site Blocked</h1>
        <p><strong>This website violates company policy.</strong></p>
        <p>Access has been denied by your IT department.</p>
        <div class="spinner"></div>
        <p><em>Redirecting to approved content...</em></p>
        <p style="font-size: 0.9em; margin-top: 30px; opacity: 0.8;">
            Never gonna give you up, never gonna let you down! 🎵
        </p>
    </div>
</body>
</html>
"@
}

function Start-HTTPListener {
    <#
    .SYNOPSIS
        Starts HTTP listener on localhost port 80.
    .DESCRIPTION
        Creates HttpListener that responds to all blocked domain requests.
        Runs in infinite loop until process is terminated.
    #>

    try {
        # Write PID file for tracking
        $PID | Out-File -FilePath $PID_FILE -Force

        Write-Log "Starting HTTP listener on port $LISTENER_PORT" -Level INFO
        Write-Log "Rick Roll URL: $RickRollURL" -Level INFO
        Write-Log "Process ID: $PID" -Level INFO

        # Create and configure HTTP listener
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:$LISTENER_PORT/")
        $listener.Prefixes.Add("http://localhost:$LISTENER_PORT/")

        # Start listening
        $listener.Start()
        Write-Log "HTTP listener started successfully" -Level INFO

        # Generate redirect HTML once
        $redirectHTML = New-RedirectHTML -TargetURL $RickRollURL
        $redirectBytes = [System.Text.Encoding]::UTF8.GetBytes($redirectHTML)

        # Infinite loop to handle requests
        while ($listener.IsListening) {
            try {
                # Wait for incoming request (blocking call)
                $context = $listener.GetContext()
                $request = $context.Request
                $response = $context.Response

                # Log the blocked attempt
                $clientIP = $request.RemoteEndPoint.Address
                $requestedURL = $request.Url.ToString()
                Write-Log "Blocked access from $clientIP to $requestedURL" -Level INFO

                # Send redirect response
                $response.StatusCode = 200
                $response.ContentType = "text/html; charset=utf-8"
                $response.ContentLength64 = $redirectBytes.Length
                $response.OutputStream.Write($redirectBytes, 0, $redirectBytes.Length)
                $response.OutputStream.Close()
            }
            catch {
                # Log but continue serving
                Write-Log "Error handling request: $_" -Level WARN
            }
        }
    }
    catch {
        Write-Log "FATAL: HTTP listener failed - $_" -Level ERROR
        throw
    }
    finally {
        if ($listener -and $listener.IsListening) {
            $listener.Stop()
            $listener.Close()
            Write-Log "HTTP listener stopped" -Level INFO
        }

        # Remove PID file
        if (Test-Path $PID_FILE) {
            Remove-Item -Path $PID_FILE -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion

#region Main Execution

try {
    Write-Log "=== Rick Roll HTTP Listener Starting ===" -Level INFO

    # Validate admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log "ERROR: Administrator privileges required" -Level ERROR
        exit 1
    }

    # Check if port is already in use
    $portInUse = Get-NetTCPConnection -LocalPort $LISTENER_PORT -State Listen -ErrorAction SilentlyContinue

    if ($portInUse) {
        Write-Log "WARNING: Port $LISTENER_PORT already in use" -Level WARN
        Write-Log "Existing listener may already be running" -Level INFO
        exit 0
    }

    # Start the HTTP listener (runs indefinitely)
    Start-HTTPListener
}
catch {
    Write-Log "FATAL ERROR: $_" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}

#endregion
