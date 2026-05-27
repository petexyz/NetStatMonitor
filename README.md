# Netstat-Claude Network Monitor

A PowerShell-based network monitoring tool that collects `netstat` snapshots on a schedule, performs local pre-analysis, and sends batched results to the Anthropic Claude API for AI-powered security assessment.

---

## Features

- **Scheduled snapshot collection** — captures netstat output every 15 minutes
- **Batched AI analysis** — sends collected snapshots to Claude every 2 hours for comparative trend analysis
- **Prompt caching** — static machine context cached with Anthropic for cost efficiency (1-hour TTL)
- **Cache keepalive** — automatically refreshes the prompt cache every 55 minutes
- **Local pre-analysis** — identifies persistent IPs, fleeting IPs, new processes, and torrent residuals before sending to Claude
- **Torrent noise filtering** — torrent client TIME_WAIT and SYN_SENT residuals summarised and stripped from batch payloads to reduce token usage
- **New device detection** — immediately alerts and analyses when an unknown device appears on the local network
- **Dynamic VPN detection** — detects VPN and virtual network interface IPs at startup and on hourly refresh — no hardcoding needed
- **Elevated batch mode** — shortens batch interval to 30 minutes on HIGH/CRITICAL findings (snapshot interval never changes)
- **New device alerts do not trigger elevated mode** — avoids snapshot flood from transient VPN IP changes
- **Rate limit retry** — automatically waits 60 seconds and retries on rate limit errors
- **Dual console and log output** — all status messages and analysis written to both console and log file
- **Properties file architecture** — secrets, machine config, and prompts live in a git-ignored `.properties` file
- **Auto-generated example** — `netstat-claude.properties.example` regenerated on every run with current settings and dummy values (also generates `.txt` version for download convenience)

---

## File Structure

```
NetStatMonitor/
├── netstat-claude.ps1                   # Main monitoring script (git tracked)
├── netstat-claude.config.ps1            # Properties loader and config builder (git tracked)
├── netstat-claude.properties.example    # Documented template - auto-generated (git tracked)
├── netstat-claude.properties            # Your secrets and machine config (GIT IGNORED)
├── .gitignore                           # Ignores .properties and log/
├── README.md                            # This file (git tracked)
├── TODO.md                              # Pending and completed items (git tracked)
└── log/                                 # Log files - auto-created (GIT IGNORED)
    └── netstat-YYYYMMDD-HHmmss.txt
```

---

## Requirements

- Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges (required for `netstat -b` process name resolution)
- Anthropic API account and key — https://console.anthropic.com

---

## Installation

### 1. Clone or download the repository

```powershell
git clone https://github.com/youruser/NetStatMonitor.git
cd NetStatMonitor
```

### 2. Create your properties file

```powershell
Copy-Item netstat-claude.properties.example netstat-claude.properties
notepad netstat-claude.properties
```

Fill in at minimum:
- `ApiKey` — your Anthropic API key (no quotes around the value)
- `KnownLocalIPs` — comma-separated IPs of known devices on your network
- `PromptStatic` — description of your machine's software for Claude's context

### 3. Set execution policy

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
Unblock-File -Path .\netstat-claude.ps1
Unblock-File -Path .\netstat-claude.config.ps1
```

### 4. Run as Administrator

Right-click PowerShell → **Run as Administrator**, then:

```powershell
cd C:\path\to\NetStatMonitor
.\netstat-claude.ps1
```

---

## Configuration

All settings live in `netstat-claude.properties` (git-ignored). See `netstat-claude.properties.example` for full documentation of every setting.

### Key Settings

| Property | Default | Description |
|----------|---------|-------------|
| `ApiKey` | — | Your Anthropic API key — no quotes |
| `Model` | `claude-haiku-4-5-20251001` | Claude model for analysis |
| `SnapshotIntervalSeconds` | `900` | How often to collect netstat (15 min) |
| `BatchIntervalMinutes` | `120` | How often to send to Claude (2 hrs) |
| `MaxSnapshotsPerBatch` | `10` | Safety cap — prevents rate limit errors |
| `KeepaliveIntervalMinutes` | `55` | Cache keepalive interval |
| `ElevatedBatchMinutes` | `30` | Batch interval when HIGH/CRITICAL found |
| `KnownLocalIPs` | — | Comma-separated known device IPs |
| `KnownLocalSubnets` | — | Optional regex patterns for static subnets — VPN is auto-detected |
| `KnownHostnames` | — | Pipe-separated hostname=description pairs |

### Multi-line Prompts

The three prompts (`PromptStatic`, `PromptImmediate`, `PromptBatch`) use a block syntax in the properties file:

```properties
PromptStatic=<<END_PROMPT_STATIC
Your prompt text here
spanning multiple lines
END_PROMPT_STATIC
```

### VPN and Virtual Interfaces

VPN tunnel IPs are detected **automatically** at startup and on every hourly refresh. You do not need to add VPN IPs or subnets to your properties file — they change on every connection and the script handles this dynamically.

`KnownLocalSubnets` is optional and only needed for truly static non-VPN subnets.

---

## How It Works

### Startup
1. Loads properties file and validates required settings
2. Creates log file immediately
3. Detects all VPN and virtual network interface IPs dynamically
4. Resolves known hostnames to IPs
5. Warms the Anthropic prompt cache

### Normal Operation (every 15 minutes)
1. Runs `netstat -b -n` (named) and `netstat -a -o -n` (PID enriched)
2. Cross-references PIDs to process names for unknown connections
3. Checks for new local network devices — fires immediate Claude analysis if found (does not change polling interval)
4. Adds snapshot to batch buffer

### Batch Analysis (every 2 hours)
1. Pre-analyses batch locally — identifies persistent IPs, fleeting IPs, new processes
2. Counts and strips torrent peer TIME_WAIT/SYN_SENT noise (summarised as count)
3. Trims to `MaxSnapshotsPerBatch` if batch grew too large
4. Sends formatted batch to Claude with full machine context
5. Logs analysis to file and displays on console with colour highlighting
6. Switches to 30-minute batch interval if HIGH/CRITICAL detected
7. Returns to normal interval when analysis clears to LOW

### Hourly Refresh
- Re-resolves known hostnames (IPs can change)
- Re-detects VPN interface IPs (catches reconnects with new tunnel IP)

### Prompt Caching
- Static machine context sent with `cache_control: ephemeral, ttl: 1h`
- Keepalive fires every 55 minutes to keep cache warm across 2-hour batch intervals
- Cache write/read token stats logged after every API call
- Reduces cost significantly on static context tokens

---

## Estimated Cost

Running 24/7 with default settings (Haiku model, 15-min snapshots, 2-hour batches):

| Item | Value |
|------|-------|
| Snapshots per batch | ~8 |
| Batch calls per day | 12 |
| Est. daily cost | ~$0.36 |
| Est. monthly cost | ~$10.80 |

Cost is dominated by dynamic netstat token volume. Prompt caching reduces static context cost by ~90%.

To reduce cost — increase `SnapshotIntervalSeconds` or `BatchIntervalMinutes`.

---

## Log Files

Log files are written to the `log/` folder (git-ignored) named `netstat-YYYYMMDD-HHmmss.txt`.

Each log entry contains:
- Timestamp, machine IP, and mode (BATCH or IMMEDIATE-NEW-DEVICE)
- Raw netstat output (named and PID-enriched)
- Known IPs at time of analysis
- Full Claude analysis text

All console status messages including startup banner, host resolution, VPN detection, cache stats, and batch trigger reasons are also written to the log file.

---

## Security Notes

- **Never commit `netstat-claude.properties`** — it contains your API key, network topology, and machine details
- The `.gitignore` excludes `*.properties` and `log/` automatically
- `netstat-claude.properties.example` is safe to commit — it contains only generic dummy values
- API key must be entered without quotes in the properties file
- Consider restricting permissions on your properties file:

```powershell
$acl = Get-Acl "netstat-claude.properties"
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $env:USERNAME, "FullControl", "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "netstat-claude.properties" $acl
```

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `cannot be loaded... not digitally signed` | Execution policy | `Unblock-File .\netstat-claude.ps1` |
| `requested operation requires elevation` | Not running as admin | Right-click PowerShell → Run as Administrator |
| `401 Unauthorized` | Invalid or quoted API key | Remove quotes from key in properties file |
| `404 Not Found` | Wrong model string | Check `Model` in properties file |
| `rate_limit_error` | Batch too large | Reduce `MaxSnapshotsPerBatch` or increase `SnapshotIntervalSeconds` |
| `Config file not found` | Wrong working directory | `cd` to script folder first |
| `Missing required properties` | Incomplete properties file | Compare against `.example` file |
| `Stream was not readable` | Log file not created yet | Fixed — log file now created immediately at startup |
| `Cannot bind argument... Path is null` | Log file path null | Fixed — log folder created before first Write-Log call |
| Cache stats show `wrote=0 read=0` | Beta header issue | Check `anthropic-beta` header in `Build-CachedHeaders` |
| VPN IP flagged as new device | VPN not yet detected | Check startup output for VPN detection — re-run as admin |

---

## Known Legitimate Patterns

These are commonly flagged but are normal — ensure your `PromptStatic` covers them:

| Pattern | Explanation |
|---------|-------------|
| Torrent client `TIME_WAIT` to random high ports | Normal peer residuals — never flag |
| Torrent client `SYN_SENT` | Normal peer connection attempts — never flag |
| Individual BitTorrent peer IPs | Transient, meaningless for security analysis — ignored by pre-analysis |
| Antivirus `Cannot obtain ownership` | Protected process — cross-reference with `netstat -aon` + `tasklist` |
| VPN tunnel IP detected as new device | Re-run script — dynamic detection resolves on startup |
| System service polling a localhost port repeatedly | Normal background service behaviour |
| Temp folder XML files generated regularly | Normal background application polling |
| Multiple connections from antivirus service host | Normal antivirus cloud scanning behaviour |

---

## Contributing

1. Fork the repository
2. Create your properties file from the example
3. Make changes to tracked files only (`*.ps1`, `README.md`, `TODO.md`, `.gitignore`, `*.example`)
4. Never commit `netstat-claude.properties` or `log/` files
5. Submit a pull request

---

## Licence

MIT