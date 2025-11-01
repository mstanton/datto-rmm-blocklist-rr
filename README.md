# Rick Roll Blocked Sites - Datto RMM Component

## Overview
This custom Datto RMM component redirects users to Rick Astley's "Never Gonna Give You Up" when they attempt to access blocked websites. Perfect for security awareness training, policy enforcement, or adding some humor to your IT management.

## Features
- ✅ Blocks specified domains via hosts file modification
- ✅ Redirects to classic Rick Roll video
- ✅ Automatic backup of original hosts file
- ✅ Detailed logging
- ✅ Easy removal/restoration
- ✅ Custom Rick Roll URL support

## Setup in Datto RMM

### Step 1: Create the Component

1. Log into your Datto RMM dashboard
2. Navigate to **Setup → Components**
3. Click **New Component**
4. Configure the component:
   - **Name**: Rick Roll Blocked Sites
   - **Description**: Redirects blocked site attempts to Rick Roll video
   - **Category**: Custom Scripts
   - **Component Type**: PowerShell

### Step 2: Add the Script

Copy the contents of `rickroll-blocked-sites.ps1` into the component script field.

### Step 3: Configure Environment Variables

Add the following environment variables:

| Variable Name | Type | Required | Description | Example |
|--------------|------|----------|-------------|---------|
| `BLOCKED_SITES` | String | Yes | Comma-separated list of domains to block | `facebook.com,twitter.com,reddit.com,tiktok.com` |
| `RICKROLL_URL` | String | No | Custom Rick Roll URL (defaults to YouTube) | `https://www.youtube.com/watch?v=dQw4w9WgXcQ` |

### Step 4: Create the Removal Component

1. Create another component named "Remove Rick Roll Configuration"
2. Copy the contents of `rickroll-remove.ps1`

## Usage

### Deploy to Devices

**Option 1: Manual Deployment**
1. Go to **Devices** → Select target device(s)
2. Click **Run Component**
3. Select "Rick Roll Blocked Sites"
4. Set environment variables:
   ```
   BLOCKED_SITES: facebook.com,twitter.com,instagram.com
   RICKROLL_URL: https://www.youtube.com/watch?v=dQw4w9WgXcQ
   ```
5. Click **Run**

**Option 2: Automated via Policy**
1. Create a policy or modify existing one
2. Add the component to run on a schedule
3. Set variables at the policy level

**Option 3: Monitor-Triggered**
1. Create a monitor for policy violations
2. Set the component as a remediation action

### To Remove/Restore
Simply run the "Remove Rick Roll Configuration" component on affected devices.

## How It Works

### Technical Implementation
1. **Hosts File Modification**: The script modifies the Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`) to redirect blocked domains to `127.0.0.1`
2. **Backup Creation**: Original hosts file is backed up before modification
3. **DNS Cache Flush**: Ensures changes take effect immediately
4. **Local HTML Page**: Creates a redirect page with a fun message before sending users to Rick Roll

### User Experience
When a user attempts to access `facebook.com` (if blocked):
1. Browser attempts to resolve the domain
2. Hosts file redirects to `127.0.0.1`
3. User sees "Site Blocked" message with a fun note
4. Automatically redirects to Rick Roll video after 0 seconds
5. IT gets notified via logs

## Logging

All actions are logged to: `C:\ProgramData\DattoRMM\RickRoll.log`

Example log entries:
```
2025-11-01 10:30:15 - === Rick Roll Component Started ===
2025-11-01 10:30:15 - Blocked sites list: facebook.com, twitter.com
2025-11-01 10:30:15 - Rick Roll URL: https://www.youtube.com/watch?v=dQw4w9WgXcQ
2025-11-01 10:30:15 - Hosts file backed up to: C:\Windows\System32\drivers\etc\hosts.rickroll.backup
2025-11-01 10:30:15 - Added hosts entry for: facebook.com
2025-11-01 10:30:15 - Added hosts entry for: www.facebook.com
2025-11-01 10:30:16 - DNS cache flushed successfully
2025-11-01 10:30:16 - === Rick Roll Component Completed Successfully ===
```

## Example Use Cases

### 1. Security Awareness Training
Deploy during security awareness month with a list of common phishing domains or risky sites. Makes training memorable!

### 2. Productivity Policy Enforcement
Block social media sites with a humorous reminder about acceptable use policies.

### 3. April Fools' Day
Deploy temporarily to create a harmless prank that reinforces policy awareness.

### 4. Policy Violation Remediation
Trigger automatically when monitoring detects attempts to access blocked content.

## Blocked Sites Examples

### Social Media
```
facebook.com,twitter.com,instagram.com,tiktok.com,snapchat.com
```

### Gaming
```
steam.com,twitch.tv,discord.com,roblox.com
```

### Streaming
```
netflix.com,hulu.com,youtube.com,disney.com
```

### Shopping
```
amazon.com,ebay.com,etsy.com
```

### Custom Mix
```
facebook.com,reddit.com,netflix.com,amazon.com,twitter.com
```

## Troubleshooting

### Script Fails with "Access Denied"
- **Cause**: Insufficient permissions
- **Solution**: Ensure the script runs with administrator privileges in Datto RMM

### Sites Not Being Blocked
- **Cause**: DNS cache not flushed or hosts file not updated
- **Solution**: 
  1. Check the log file for errors
  2. Manually verify hosts file: `notepad C:\Windows\System32\drivers\etc\hosts`
  3. Run `ipconfig /flushdns` manually

### Rick Roll Not Loading
- **Cause**: No local web server or firewall blocking
- **Solution**: The script redirects directly to YouTube by default (no local server needed)

### Need to Restore Original Configuration
- **Solution**: Run the removal component or manually restore from: `C:\Windows\System32\drivers\etc\hosts.rickroll.backup`

## Best Practices

1. **Test First**: Deploy to a test device before rolling out widely
2. **Communicate**: Let users know about the policy (but maybe not the Rick Roll part 😉)
3. **Schedule Wisely**: Consider deploying during training sessions
4. **Monitor Logs**: Review logs to see which sites users attempt to access
5. **Be Reasonable**: Don't block too many sites or critical business tools
6. **Have Fun**: This is meant to be educational AND entertaining!

## Security Considerations

- This script modifies system files (hosts file) - ensure proper authorization
- Backup is automatically created but verify before large deployments
- Users with admin rights can bypass this by modifying their own hosts file
- For enterprise-grade blocking, consider using DNS-level filtering or proxy solutions
- This is best used for awareness and training, not as primary security control

## Customization Options

### Custom Rick Roll URL
You can use alternatives to the classic YouTube video:
```
# Different Rick Roll version
https://www.youtube.com/watch?v=oHg5SJYRHA0

# Custom internal video
https://yourcompany.com/security-training.html

# Funny IT policy page
https://yourcompany.com/nice-try.html
```

### Add to Existing Scripts
Integrate the blocking logic into your existing policy enforcement scripts:
```powershell
# In your main script
. .\rickroll-blocked-sites.ps1
```

## Support

For questions or issues:
- Check logs: `C:\ProgramData\DattoRMM\RickRoll.log`
- Review Datto RMM component execution logs
- Test manually via PowerShell ISE with administrator rights

## License
Use freely for legitimate IT management and training purposes. Keep it fun, keep it legal! 

---

**Remember**: With great power comes great responsibility... to Rick Roll responsibly! 🎵

**Never gonna give you up, never gonna let you down!** 🎸
