# Rick Roll Blocked Sites - Datto RMM Component

## Overview
This custom Datto RMM component redirects users to Rick Astley's "Never Gonna Give You Up" when they attempt to access blocked websites. Perfect for security awareness training, policy enforcement, or adding some humor to your IT management.

## Features
- ✅ Blocks specified domains via hosts file modification
- ✅ **HTTP redirect listener on localhost port 80**
- ✅ Beautiful animated redirect page before Rick Roll
- ✅ Automatic deployment as persistent Windows service
- ✅ Redirects to classic Rick Roll video
- ✅ Automatic backup of original hosts file
- ✅ DNS Client service locking handled automatically
- ✅ Retry logic for transient failures
- ✅ Comprehensive logging with severity levels
- ✅ Easy removal/restoration with full cleanup
- ✅ Custom Rick Roll URL support
- ✅ Runs on system startup automatically

## Setup in Datto RMM

### Step 1: Create the Blocker Component

1. Log into your Datto RMM dashboard
2. Navigate to **Setup → Components**
3. Click **New Component**
4. Configure the component:
   - **Name**: Rick Roll Blocked Sites
   - **Description**: Redirects blocked site attempts to Rick Roll video with HTTP listener
   - **Category**: Custom Scripts
   - **Component Type**: PowerShell
   - **Execution Policy**: Bypass
   - **Run As**: System (Administrator)

### Step 2: Add the Blocker Script

Copy the contents of `rickroll-blocked-sites.ps1` into the component script field.

### Step 3: Configure Environment Variables

Add the following environment variables to the component:

| Variable Name | Type | Required | Description | Example |
|--------------|------|----------|-------------|---------|
| `BLOCKED_SITES` | String | **Yes** | Comma-separated list of domains to block | `facebook.com,twitter.com,reddit.com,tiktok.com` |
| `RICKROLL_URL` | String | No | Custom Rick Roll URL (defaults to YouTube classic) | `https://www.youtube.com/watch?v=dQw4w9WgXcQ` |

**Important**: In Datto RMM, set these as **Environment Variables** at the component level or when running the component.

### Step 4: Create the Removal Component

1. Create another component named **"Remove Rick Roll Configuration"**
2. Configure the same execution settings as above
3. Copy the contents of `rickroll-remove.ps1` into the script field
4. No environment variables needed for removal

## Implementation in Datto RMM

### Quick Start Guide

**1. Deploy the Blocker Component**

Navigate to your device or site:
```
Devices → [Select Device] → Components → Run Component
```

Select "Rick Roll Blocked Sites" and configure:
```
Environment Variables:
├── BLOCKED_SITES: facebook.com,twitter.com,instagram.com
└── RICKROLL_URL: https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

Click **Run Now**

**2. Verify Deployment**

The script will:
- ✅ Backup the hosts file
- ✅ Add domain redirects to hosts file
- ✅ Deploy HTTP listener script
- ✅ Create scheduled task "RickRollHTTPListener"
- ✅ Start HTTP listener on port 80
- ✅ Flush DNS cache

Check the **Component Result** in Datto RMM:
```
SUCCESS: Blocked X domains with HTTP redirect active
```

**3. Test the Implementation**

On the target device:
- Open browser
- Navigate to blocked domain (e.g., facebook.com)
- Should see animated "Site Blocked" page
- Auto-redirect to Rick Roll after 2 seconds

**4. Monitor via Datto RMM**

Create a monitor to check HTTP listener status:
```powershell
# Custom monitor script
$listener = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    Write-Output "HEALTHY: Rick Roll listener active"
    exit 0
} else {
    Write-Output "ALERT: Rick Roll listener not running"
    exit 1
}
```

### Deployment Options

**Option 1: Manual Deployment (Immediate)**
1. Go to **Devices** → Select target device(s)
2. Click **Run Component**
3. Select "Rick Roll Blocked Sites"
4. Set environment variables:
   ```
   BLOCKED_SITES: facebook.com,twitter.com,instagram.com
   RICKROLL_URL: https://www.youtube.com/watch?v=dQw4w9WgXcQ
   ```
5. Click **Run**
6. Monitor execution in **Activity Log**

**Option 2: Automated via Policy**
1. Navigate to **Setup → Policies**
2. Create new policy or modify existing one
3. Add component under **Monitoring → Components**
4. Set variables at the policy level
5. Schedule: One-time or recurring
6. Apply policy to device group

**Option 3: Monitor-Triggered Remediation**
1. Create a monitor for policy violations
2. Set the blocker component as remediation action
3. Automatically deploys when violation detected
4. Useful for responding to security events

**Option 4: Site-Wide Deployment**
1. Navigate to **Sites** → [Your Site]
2. Select multiple devices
3. Run component across all selected devices
4. Monitor deployment via **Jobs** view

### Removal/Restoration

To remove the Rick Roll configuration:
1. Go to **Devices** → Select device(s)
2. Click **Run Component**
3. Select "Remove Rick Roll Configuration"
4. Click **Run**

The removal script will:
- ✅ Stop HTTP listener process
- ✅ Remove scheduled task
- ✅ Restore original hosts file from backup
- ✅ Remove all Rick Roll artifacts
- ✅ Flush DNS cache

## How It Works

### Complete Technical Implementation

**Phase 1: Hosts File Modification**
1. Script validates administrator privileges
2. Creates atomic backup of hosts file
3. Handles DNS Client service file locking:
   - Attempts write operation
   - If locked, temporarily stops Dnscache service
   - Retries up to 3 times with 2-second delays
4. Adds domain entries: `127.0.0.1 [domain] # RICKROLL_BLOCK`
5. Automatically adds www variants
6. Flushes DNS resolver cache

**Phase 2: HTTP Listener Deployment**
1. Creates HTTP listener PowerShell script at:
   ```
   C:\ProgramData\DattoRMM\rickroll-http-listener.ps1
   ```
2. Script contains:
   - Embedded HTML redirect page
   - System.Net.HttpListener implementation
   - Logging and error handling
   - PID tracking for process management

**Phase 3: Scheduled Task Creation**
1. Registers Windows scheduled task:
   - **Name**: RickRollHTTPListener
   - **Trigger**: At system startup
   - **User**: SYSTEM account
   - **Privileges**: Highest
   - **Settings**: Restart on failure (3 attempts, 1-min intervals)
2. Task runs listener script with custom Rick Roll URL parameter
3. Listener persists across reboots

**Phase 4: HTTP Listener Activation**
1. Starts scheduled task immediately
2. PowerShell HTTP listener binds to port 80
3. Listens for requests on:
   - http://127.0.0.1:80
   - http://localhost:80
4. Serves redirect HTML for all requests
5. Logs every blocked access attempt

### User Experience

When a user attempts to access `facebook.com` (if blocked):

1. **Browser DNS lookup**
   - Windows checks hosts file first
   - Finds entry: `127.0.0.1 facebook.com`
   - Redirects connection to localhost

2. **HTTP request to localhost**
   - Browser connects to 127.0.0.1:80
   - HTTP listener receives request
   - Logs attempt with timestamp, URL, and client IP

3. **Beautiful redirect page displayed**
   - Animated purple gradient background
   - "🚫 Site Blocked" header (pulsing animation)
   - "This website violates company policy"
   - "Access has been denied by your IT department"
   - Spinning loading animation
   - "Redirecting to approved content..."
   - "Never gonna give you up! 🎵"

4. **Auto-redirect after 2 seconds**
   - HTML meta refresh tag triggers redirect
   - Navigates to Rick Roll YouTube video
   - User experiences the full Rick Roll

5. **IT audit trail**
   - All access logged to: `C:\ProgramData\DattoRMM\RickRoll.log`
   - Includes timestamp, blocked URL, client IP
   - Viewable via Datto RMM or local access

### Architecture Diagram

```
User Browser
     ↓
Tries to access blocked domain
     ↓
Windows Hosts File (127.0.0.1 redirect)
     ↓
HTTP Listener (localhost:80)
     ↓
Beautiful HTML Redirect Page
     ↓
Rick Roll YouTube Video 🎵
```

## Logging

### Log File Location
All actions are logged to: `C:\ProgramData\DattoRMM\RickRoll.log`

### Log Format
```
YYYY-MM-DD HH:MM:SS [LEVEL] Message
```

### Example Log Entries

**Successful Deployment:**
```
2025-11-12 10:30:15 [INFO] === Rick Roll Blocker Started ===
2025-11-12 10:30:15 [INFO] Blocking 6 domains: facebook.com, www.facebook.com, twitter.com, www.twitter.com, instagram.com, www.instagram.com
2025-11-12 10:30:15 [INFO] Rick Roll URL: https://www.youtube.com/watch?v=dQw4w9WgXcQ
2025-11-12 10:30:15 [INFO] Hosts file backed up to: C:\Windows\System32\drivers\etc\hosts.rickroll.backup
2025-11-12 10:30:15 [INFO] Attempt 1 of 3 to modify hosts file
2025-11-12 10:30:15 [INFO] Will add entry for: facebook.com
2025-11-12 10:30:15 [INFO] Will add entry for: www.facebook.com
2025-11-12 10:30:15 [INFO] Successfully added 6 hosts entries
2025-11-12 10:30:16 [INFO] DNS cache flushed successfully
2025-11-12 10:30:16 [INFO] Setting up HTTP redirect listener
2025-11-12 10:30:16 [INFO] Deploying HTTP listener script
2025-11-12 10:30:16 [INFO] HTTP listener script deployed to: C:\ProgramData\DattoRMM\rickroll-http-listener.ps1
2025-11-12 10:30:16 [INFO] Configuring HTTP listener service
2025-11-12 10:30:16 [INFO] Scheduled task 'RickRollHTTPListener' created successfully
2025-11-12 10:30:16 [INFO] Starting HTTP listener process
2025-11-12 10:30:18 [INFO] HTTP listener is running on port 80
2025-11-12 10:30:18 [INFO] === Rick Roll Blocker Completed Successfully ===
2025-11-12 10:30:18 [INFO] Blocked domains: 6
2025-11-12 10:30:18 [INFO] Rick Roll URL: https://www.youtube.com/watch?v=dQw4w9WgXcQ
2025-11-12 10:30:18 [INFO] Backup location: C:\Windows\System32\drivers\etc\hosts.rickroll.backup
2025-11-12 10:30:18 [INFO] HTTP listener: Active on port 80
```

**Active Blocking (HTTP Listener):**
```
2025-11-12 14:23:45 [INFO] Starting HTTP listener on port 80 (PID: 5432)
2025-11-12 14:23:45 [INFO] HTTP listener started successfully
2025-11-12 14:25:12 [INFO] Blocked: http://facebook.com/ from 127.0.0.1
2025-11-12 14:26:03 [INFO] Blocked: http://twitter.com/ from 127.0.0.1
2025-11-12 14:27:34 [INFO] Blocked: http://www.instagram.com/ from 127.0.0.1
```

**Successful Removal:**
```
2025-11-12 16:00:00 [INFO] === Rick Roll Removal Started ===
2025-11-12 16:00:00 [INFO] Stopping HTTP redirect listener
2025-11-12 16:00:00 [INFO] Stopping HTTP listener service
2025-11-12 16:00:00 [INFO] Found scheduled task 'RickRollHTTPListener'
2025-11-12 16:00:00 [INFO] Stopped scheduled task
2025-11-12 16:00:01 [INFO] Removed scheduled task 'RickRollHTTPListener'
2025-11-12 16:00:01 [INFO] Terminating HTTP listener process (PID: 5432)
2025-11-12 16:00:02 [INFO] Port 80 is now free
2025-11-12 16:00:02 [INFO] Backup file found, attempting restoration
2025-11-12 16:00:02 [INFO] Attempt 1 of 3 to restore hosts file from backup
2025-11-12 16:00:02 [INFO] Hosts file restored from backup
2025-11-12 16:00:02 [INFO] Backup file removed
2025-11-12 16:00:02 [INFO] Successfully restored hosts file from backup
2025-11-12 16:00:03 [INFO] DNS cache flushed successfully
2025-11-12 16:00:03 [INFO] Removed HTTP listener script
2025-11-12 16:00:03 [INFO] Removed PID file
2025-11-12 16:00:03 [INFO] === Rick Roll Removal Completed Successfully ===
```

### Viewing Logs in Datto RMM

**Method 1: Component Output**
- View in component execution results
- Shows real-time output during deployment

**Method 2: Remote PowerShell via Datto**
```powershell
Get-Content C:\ProgramData\DattoRMM\RickRoll.log -Tail 50
```

**Method 3: Create Monitoring Component**
```powershell
# Monitor component to fetch logs
$logPath = "C:\ProgramData\DattoRMM\RickRoll.log"
if (Test-Path $logPath) {
    Get-Content $logPath -Tail 20
} else {
    Write-Output "No log file found"
}
```

## Example Use Cases

### 1. Security Awareness Training
**Scenario**: Deploy during security awareness month
**Blocked Sites**: Common phishing domains or risky sites
**Duration**: 1-2 weeks
**Benefits**: Makes training memorable and engaging
**Example**:
```
BLOCKED_SITES: examplebadsite.com,phishingtest.com,suspiciousdomain.com
```

### 2. Productivity Policy Enforcement
**Scenario**: Block social media during work hours
**Blocked Sites**: Major social platforms
**Duration**: Ongoing
**Benefits**: Humorous reminder about acceptable use policies
**Example**:
```
BLOCKED_SITES: facebook.com,twitter.com,instagram.com,tiktok.com,snapchat.com
```

### 3. April Fools' Day Prank
**Scenario**: Temporary deployment for office fun
**Blocked Sites**: Popular sites employees use
**Duration**: 1 day
**Benefits**: Harmless prank that reinforces policy awareness
**Example**:
```
BLOCKED_SITES: amazon.com,ebay.com,reddit.com,youtube.com
```

### 4. Policy Violation Remediation
**Scenario**: Automatic response to security events
**Trigger**: Datto RMM monitor detects policy violation
**Action**: Deploy blocker as remediation
**Benefits**: Immediate response, educational impact
**Example**:
```
Monitor: Detects suspicious domain access
Action: Runs Rick Roll blocker component
Result: User redirected and educated
```

### 5. New Employee Onboarding
**Scenario**: Part of acceptable use policy training
**Blocked Sites**: Examples of prohibited sites
**Duration**: First week of employment
**Benefits**: Interactive policy demonstration
**Example**:
```
BLOCKED_SITES: gambling.com,torrentsite.com,proxyvpn.com
RICKROLL_URL: https://yourcompany.com/it-policy-training
```

## Blocked Sites Examples

### Social Media
```
facebook.com,twitter.com,instagram.com,tiktok.com,snapchat.com,linkedin.com
```

### Gaming
```
steam.com,twitch.tv,discord.com,roblox.com,epicgames.com
```

### Streaming
```
netflix.com,hulu.com,youtube.com,disney.com,twitch.tv
```

### Shopping
```
amazon.com,ebay.com,etsy.com,aliexpress.com
```

### News & Entertainment
```
reddit.com,buzzfeed.com,9gag.com,espn.com
```

### Custom Mix (Recommended for Testing)
```
facebook.com,reddit.com,netflix.com,amazon.com,twitter.com
```

## Troubleshooting

### Script Fails with "Access Denied"
**Cause**: Insufficient permissions or execution policy restrictions

**Solution**:
1. Verify Datto RMM component set to run as **System**
2. Check execution policy in component settings: **Bypass**
3. Ensure device has administrator access enabled
4. Review Datto RMM security policies

**Verification**:
```powershell
# Check if script can run with admin rights
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# Should return: True
```

### Sites Not Being Blocked
**Cause**: DNS cache not flushed, hosts file not updated, or DNS over HTTPS enabled

**Solution**:
1. Check the log file for errors:
   ```powershell
   Get-Content C:\ProgramData\DattoRMM\RickRoll.log -Tail 50
   ```

2. Manually verify hosts file entries:
   ```powershell
   notepad C:\Windows\System32\drivers\etc\hosts
   # Look for lines ending with: # RICKROLL_BLOCK
   ```

3. Flush DNS cache manually:
   ```powershell
   Clear-DnsClientCache
   ipconfig /flushdns
   ```

4. Check for DNS over HTTPS (DoH):
   - Windows 11: Settings → Network → Ethernet/WiFi → DNS settings
   - Disable DoH if enabled (bypasses hosts file)

5. Verify browser not using custom DNS:
   - Chrome: chrome://settings/security → Secure DNS
   - Firefox: about:preferences#privacy → DNS over HTTPS
   - Edge: edge://settings/privacy → Security → Secure DNS

**Verification**:
```powershell
# Check if domain resolves to localhost
nslookup facebook.com
# Should return: 127.0.0.1
```

### Rick Roll Redirect Not Working
**Cause**: HTTP listener not running on port 80

**Solution**:
1. Check if HTTP listener is running:
   ```powershell
   Get-NetTCPConnection -LocalPort 80 -State Listen
   ```
   Should show connection on port 80

2. Check scheduled task status:
   ```powershell
   Get-ScheduledTask -TaskName "RickRollHTTPListener"
   ```
   Should show: Ready or Running

3. Check for port 80 conflicts:
   ```powershell
   Get-NetTCPConnection -LocalPort 80 -State Listen | Select-Object -ExpandProperty OwningProcess | ForEach-Object {Get-Process -Id $_}
   ```
   - If IIS is running: Stop IIS or use different port
   - If other service: Stop conflicting service

4. Manually start the listener:
   ```powershell
   Start-ScheduledTask -TaskName "RickRollHTTPListener"
   ```

5. Check listener logs:
   ```powershell
   Get-Content C:\ProgramData\DattoRMM\RickRoll.log | Select-String "listener"
   ```

6. Verify PID file exists:
   ```powershell
   Test-Path C:\ProgramData\DattoRMM\RickRoll.pid
   ```

**Verification**:
```powershell
# Test HTTP listener response
(Invoke-WebRequest -Uri "http://localhost" -UseBasicParsing).Content
# Should return HTML redirect page
```

### Port 80 Already in Use
**Cause**: IIS, Apache, or another web server running

**Solution**:
1. Identify process using port 80:
   ```powershell
   Get-Process -Id (Get-NetTCPConnection -LocalPort 80).OwningProcess
   ```

2. If IIS (w3svc):
   ```powershell
   Stop-Service -Name W3SVC
   Set-Service -Name W3SVC -StartupType Disabled
   ```

3. If Apache or other:
   - Stop the service via Services.msc
   - Or change Rick Roll listener to different port (requires script modification)

4. Restart Rick Roll listener:
   ```powershell
   Start-ScheduledTask -TaskName "RickRollHTTPListener"
   ```

### Hosts File Write Failures
**Cause**: DNS Client service locking, antivirus interference, or file corruption

**Solution**:
1. Check log for retry attempts:
   ```powershell
   Get-Content C:\ProgramData\DattoRMM\RickRoll.log | Select-String "retry"
   ```

2. Temporarily disable antivirus real-time protection:
   - May block hosts file modification
   - Re-run component
   - Re-enable antivirus

3. Stop DNS Client service manually:
   ```powershell
   Stop-Service -Name Dnscache -Force
   # Re-run component
   Start-Service -Name Dnscache
   ```

4. Check hosts file permissions:
   ```powershell
   icacls C:\Windows\System32\drivers\etc\hosts
   # Should show: NT AUTHORITY\SYSTEM:(F)
   ```

5. Verify hosts file not corrupted:
   ```powershell
   Get-Content C:\Windows\System32\drivers\etc\hosts
   ```

### Need to Restore Original Configuration
**Cause**: Want to remove Rick Roll functionality

**Solution**:
1. Run removal component via Datto RMM:
   - Select device → Run Component → "Remove Rick Roll Configuration"

2. Manual removal if component unavailable:
   ```powershell
   # Stop and remove scheduled task
   Stop-ScheduledTask -TaskName "RickRollHTTPListener"
   Unregister-ScheduledTask -TaskName "RickRollHTTPListener" -Confirm:$false

   # Restore hosts file
   Copy-Item "C:\Windows\System32\drivers\etc\hosts.rickroll.backup" "C:\Windows\System32\drivers\etc\hosts" -Force

   # Flush DNS
   Clear-DnsClientCache

   # Remove artifacts
   Remove-Item "C:\ProgramData\DattoRMM\rickroll-http-listener.ps1" -Force
   Remove-Item "C:\ProgramData\DattoRMM\RickRoll.pid" -Force
   ```

3. Verify removal:
   ```powershell
   # Check scheduled task removed
   Get-ScheduledTask -TaskName "RickRollHTTPListener" -ErrorAction SilentlyContinue
   # Should return: nothing

   # Check port 80 released
   Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
   # Should return: nothing (or other service)

   # Check hosts file restored
   Get-Content C:\Windows\System32\drivers\etc\hosts | Select-String "RICKROLL"
   # Should return: nothing
   ```

### HTTP Listener Crashes or Stops
**Cause**: Unhandled exception, port conflict, or resource exhaustion

**Solution**:
1. Check Windows Event Log:
   ```powershell
   Get-EventLog -LogName Application -Source "PowerShell" -Newest 20
   ```

2. Review listener logs:
   ```powershell
   Get-Content C:\ProgramData\DattoRMM\RickRoll.log | Select-String "ERROR"
   ```

3. Verify scheduled task restart settings:
   ```powershell
   Get-ScheduledTaskInfo -TaskName "RickRollHTTPListener"
   ```
   - Should have 3 restart attempts configured

4. Manually restart:
   ```powershell
   Start-ScheduledTask -TaskName "RickRollHTTPListener"
   ```

5. If persistent crashes, redeploy:
   - Run removal component
   - Run blocker component again

### Datto RMM Component Shows Warning
**Cause**: HTTP listener deployment succeeded but listener may not be running immediately

**Message**: `WARNING: Hosts file updated but HTTP listener failed to start`

**Solution**:
1. This is often a timing issue - listener may start shortly
2. Wait 30 seconds and verify:
   ```powershell
   Get-NetTCPConnection -LocalPort 80 -State Listen
   ```
3. Check scheduled task will start on reboot:
   ```powershell
   Get-ScheduledTask -TaskName "RickRollHTTPListener"
   ```
4. If truly failed, check firewall rules:
   ```powershell
   Get-NetFirewallRule | Where-Object {$_.LocalPorts -eq 80}
   ```

### Multiple Devices Deployment Issues
**Cause**: Timing issues, network variance, or device-specific conflicts

**Solution**:
1. Deploy to test device first
2. Verify success before site-wide deployment
3. Use Datto RMM job scheduling for staggered deployment
4. Monitor deployment via **Jobs** view
5. Address failures individually via device logs

## Monitoring & Verification

### Create Status Monitor in Datto RMM

**Monitor Name**: Rick Roll HTTP Listener Status

**Script**:
```powershell
# Check if HTTP listener is active
$listener = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
$task = Get-ScheduledTask -TaskName "RickRollHTTPListener" -ErrorAction SilentlyContinue
$hostsFile = Get-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue

$rickrollEntries = $hostsFile | Select-String "RICKROLL_BLOCK"

if ($listener -and $task -and $rickrollEntries) {
    Write-Output "HEALTHY: Rick Roll system fully operational ($($rickrollEntries.Count) domains blocked)"
    exit 0
} elseif ($task -and $rickrollEntries) {
    Write-Output "WARNING: Rick Roll hosts active but HTTP listener not running"
    exit 1
} else {
    Write-Output "OK: Rick Roll system not deployed"
    exit 0
}
```

**Alert Settings**:
- Threshold: Status = WARNING or CRITICAL
- Action: Restart scheduled task or redeploy component

### Verify Deployment Checklist

After deploying via Datto RMM, verify:

- [ ] Component execution shows: **SUCCESS**
- [ ] Hosts file contains entries with `# RICKROLL_BLOCK`
- [ ] Scheduled task "RickRollHTTPListener" exists and is Running
- [ ] Port 80 shows listener: `Get-NetTCPConnection -LocalPort 80`
- [ ] Log file exists: `C:\ProgramData\DattoRMM\RickRoll.log`
- [ ] Test blocked domain shows redirect page
- [ ] Browser successfully redirects to Rick Roll after 2 seconds

## Best Practices

### Deployment Best Practices

1. **Test First**: Always deploy to a test device before rolling out widely
   - Single workstation in controlled environment
   - Verify all functionality works
   - Test removal process

2. **Communicate Appropriately**: Let users know about the policy
   - Inform about blocked sites (educational context)
   - Maybe keep the Rick Roll part as a surprise 😉
   - Document in acceptable use policy

3. **Schedule Wisely**: Consider timing of deployment
   - During training sessions for educational impact
   - Avoid critical business periods
   - Plan for high-traffic times if demonstrating

4. **Monitor Logs**: Review logs regularly
   - Identify which sites users attempt to access
   - Assess policy compliance
   - Detect potential security issues

5. **Be Reasonable**: Don't block essential services
   - Avoid business-critical sites
   - Don't block IT management tools
   - Consider VPN or remote access needs

6. **Start Small**: Gradual rollout approach
   - Single site or department first
   - Monitor for issues
   - Expand based on success

7. **Have Fun**: This is educational AND entertaining
   - Maintains morale during security training
   - Creates memorable learning experience
   - Reinforces policies with humor

### Security Best Practices

1. **Document Deployment**: Keep records
   - Which devices have Rick Roll deployed
   - What domains are blocked
   - Business justification

2. **Review Periodically**: Regular audits
   - Ensure still appropriate
   - Update blocked domain lists
   - Review access logs

3. **Backup Verification**: Before large deployments
   - Confirm backup file created
   - Test restoration process
   - Have rollback plan

4. **Access Control**: Limit who can deploy
   - Datto RMM role-based access
   - Require approval for site-wide deployment
   - Audit component usage

5. **Combine with Other Controls**: Defense in depth
   - This is awareness training, not primary security
   - Use with DNS filtering, firewalls, EDR
   - Part of broader security program

### Maintenance Best Practices

1. **Regular Log Review**: Weekly or monthly
   ```powershell
   # Check for errors
   Get-Content C:\ProgramData\DattoRMM\RickRoll.log | Select-String "ERROR"
   ```

2. **Listener Health Checks**: Via Datto RMM monitor
   - Alert if listener stops
   - Auto-remediate by restarting scheduled task

3. **Update Blocked Lists**: As needed
   - Redeploy component with updated BLOCKED_SITES
   - Previous entries automatically maintained or replaced

4. **Windows Updates**: Test after major updates
   - Verify listener still works
   - Check scheduled task persists

5. **Cleanup Old Deployments**: Remove when no longer needed
   - Run removal component
   - Verify complete cleanup
   - Archive logs if needed for audit

## Security Considerations

### System Security
- Script modifies system hosts file - requires proper authorization
- Runs with SYSTEM privileges - understand security implications
- Automatic backup created - verify before large deployments
- HTTP listener runs on localhost only - no external network exposure

### User Bypasses
- Users with admin rights can modify their own hosts file
- Users can use VPN or DNS over HTTPS to bypass
- Power users can disable scheduled task or kill listener
- Mobile devices unaffected (hosts file only impacts local machine)

### Enterprise Security
- This is a training/awareness tool, not primary security control
- For production security, use enterprise solutions:
  - DNS-level filtering (e.g., Cisco Umbrella, Cloudflare Gateway)
  - Web proxy with content filtering
  - Next-gen firewall with application control
  - Endpoint detection and response (EDR)
- Rick Roll component best for:
  - Security awareness demonstrations
  - Policy enforcement with humor
  - Training scenarios
  - Educational purposes

### Data Privacy
- HTTP listener logs include:
  - Timestamp of access attempts
  - Blocked URL
  - Local IP address (127.0.0.1)
- Logs stored locally on device
- No external data transmission
- Consider data retention policies

### Compliance
- Ensure deployment complies with:
  - Company IT policies
  - User acceptable use agreements
  - Privacy regulations (GDPR, etc.)
  - Employment laws regarding monitoring
- Document business justification
- Obtain necessary approvals

## Customization Options

### Custom Rick Roll URL

Use alternatives to the classic YouTube video:

**Different Rick Roll Version:**
```
RICKROLL_URL: https://www.youtube.com/watch?v=oHg5SJYRHA0
```

**Custom Internal Training Video:**
```
RICKROLL_URL: https://yourcompany.com/security-training.html
```

**IT Policy Page:**
```
RICKROLL_URL: https://yourcompany.com/it-policy/acceptable-use.html
```

**Security Awareness Video:**
```
RICKROLL_URL: https://yourcompany.com/training/phishing-awareness.mp4
```

### Modify Redirect Page HTML

Edit the embedded HTML in `rickroll-blocked-sites.ps1` (lines 329-368) to customize:
- Company branding
- Custom messages
- Different colors/styling
- Redirect delay (change `content="2"` to desired seconds)

Example customization:
```html
<h1>⚠️ Security Alert</h1>
<p><strong>This website is blocked by YourCompany IT.</strong></p>
<p>Please review our acceptable use policy.</p>
```

### Add to Existing Scripts

Integrate the blocking logic into your existing policy enforcement:

```powershell
# In your main Datto RMM script
# Set environment variable
$env:BLOCKED_SITES = "facebook.com,twitter.com"

# Run Rick Roll blocker
& "C:\Path\To\rickroll-blocked-sites.ps1"
```

## Files Included

### Primary Scripts
- **rickroll-blocked-sites.ps1** (632 lines)
  - Main blocker deployment script
  - Hosts file modification with locking handlers
  - HTTP listener deployment
  - Scheduled task creation
  - Comprehensive error handling and logging

- **rickroll-remove.ps1** (467 lines)
  - Complete removal and restoration
  - HTTP listener termination
  - Scheduled task cleanup
  - Hosts file restoration
  - Artifact cleanup

- **rickroll-http-listener.ps1** (254 lines)
  - Standalone HTTP redirect server
  - Embedded HTML redirect page
  - Request logging
  - Process management

### Documentation
- **README.md** (this file)
  - Complete implementation guide
  - Troubleshooting reference
  - Best practices
  - Security considerations

## Support & Resources

### Getting Help

**Check Logs First:**
```powershell
Get-Content C:\ProgramData\DattoRMM\RickRoll.log -Tail 100
```

**Review Component Execution:**
- Datto RMM → Devices → [Device] → Activity → Component Results

**Test Manually:**
```powershell
# Run blocker script locally
PowerShell.exe -ExecutionPolicy Bypass -File "C:\Path\To\rickroll-blocked-sites.ps1"
```

### Common Resources

**Datto RMM Documentation:**
- [Components Overview](https://help.datto.com/s/article/components)
- [PowerShell Components](https://help.datto.com/s/article/powershell-components)
- [Scheduling Components](https://help.datto.com/s/article/scheduling-components)

**PowerShell Documentation:**
- [System.Net.HttpListener](https://docs.microsoft.com/en-us/dotnet/api/system.net.httplistener)
- [Scheduled Tasks](https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/)
- [Hosts File Management](https://docs.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/hosts-file)

### Testing Environment

**Recommended Test Setup:**
1. Virtual machine or test workstation
2. Non-production Datto RMM account
3. Isolated network segment
4. Admin access
5. Ability to revert/restore

**Test Sequence:**
1. Deploy blocker component
2. Verify hosts file modified
3. Verify HTTP listener running
4. Test blocked domain in browser
5. Verify redirect page displays
6. Confirm Rick Roll redirect works
7. Deploy removal component
8. Verify complete cleanup
9. Confirm original hosts file restored

## Version History

**Version 2.0** (Current)
- Added HTTP listener for localhost redirects
- Implemented scheduled task for persistent operation
- Added DNS Client service lock handling
- Implemented retry logic for transient failures
- Enhanced logging with severity levels
- Added comprehensive cleanup on removal
- Embedded HTTP listener script for single-file deployment
- Added beautiful animated redirect page
- Improved security with input validation
- Added process tracking and monitoring

**Version 1.0** (Deprecated)
- Basic hosts file modification
- Simple redirect without HTTP listener
- Limited error handling
- No persistence across reboots

## License

Use freely for legitimate IT management and training purposes.

**Terms:**
- Educational and training use
- Security awareness demonstrations
- Policy enforcement with humor
- No malicious use
- No warranty provided
- Use at your own risk

Keep it fun, keep it legal! 🎵

---

## Quick Reference Card

### Deployment
```
Datto RMM → Devices → Run Component → "Rick Roll Blocked Sites"
Environment: BLOCKED_SITES=facebook.com,twitter.com
Result: SUCCESS with HTTP redirect active
```

### Verification
```powershell
Get-NetTCPConnection -LocalPort 80
Get-ScheduledTask -TaskName "RickRollHTTPListener"
Get-Content C:\Windows\System32\drivers\etc\hosts | Select-String "RICKROLL"
```

### Removal
```
Datto RMM → Devices → Run Component → "Remove Rick Roll Configuration"
Result: SUCCESS with complete cleanup
```

### Troubleshooting
```powershell
Get-Content C:\ProgramData\DattoRMM\RickRoll.log -Tail 50
```

---

**Remember**: With great power comes great responsibility... to Rick Roll responsibly! 🎵

**Never gonna give you up, never gonna let you down!** 🎸

---

*Created with ❤️ for IT professionals who believe security training should be memorable*
