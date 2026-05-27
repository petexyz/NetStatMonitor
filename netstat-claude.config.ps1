# netstat-claude.config.ps1
# This file is git-tracked. It contains loading logic only - no secrets,
# no system-specific details, no prompts.
# All machine-specific settings and prompts live in netstat-claude.properties
# which is git-ignored.
#
# On first run:
#   Copy-Item netstat-claude.properties.example netstat-claude.properties
#   notepad netstat-claude.properties

# ── Load and parse properties file ───────────────────────────────────────────

$propertiesPath = Join-Path $PSScriptRoot "netstat-claude.properties"
if (-not (Test-Path $propertiesPath)) {
    Write-Host "ERROR: netstat-claude.properties not found." -ForegroundColor Red
    Write-Host "Copy netstat-claude.properties.example to netstat-claude.properties and fill in your values." -ForegroundColor Yellow
    exit 1
}

# Parse key=value, ignore # comments, handle <<END_BLOCK multi-line values
$props       = @{}
$inBlock     = $false
$blockKey    = ""
$blockLines  = @()

foreach ($line in (Get-Content $propertiesPath)) {
    if ($inBlock) {
        if ($line.Trim() -eq $blockKey) {
            $props[$blockKey -replace "^END_", ""] = $blockLines -join "`n"
            $inBlock    = $false
            $blockKey   = ""
            $blockLines = @()
        } else {
            $blockLines += $line
        }
        continue
    }

    $line = $line.Trim()
    if (-not $line -or $line -match "^#") { continue }

    $parts = $line -split "=", 2
    if ($parts.Count -ne 2) { continue }

    $key = $parts[0].Trim()
    $val = $parts[1].Trim()

    # Multi-line block: Value=<<END_BLOCKNAME
    if ($val -match "^<<(.+)$") {
        $inBlock    = $true
        $blockKey   = $matches[1].Trim()
        $blockLines = @()
        # Store under the property key for later retrieval
        $props["__BLOCKKEY__$key"] = $blockKey
        continue
    }

    $props[$key] = $val
}

# Retrieve multi-line blocks by original key
function Get-BlockProp {
    param([string]$key)
    $blockKey = $props["__BLOCKKEY__$key"]
    if ($blockKey) { return $props[$blockKey -replace "^END_", ""] }
    return $props[$key]
}

function Parse-StringList {
    param([string]$val)
    return ($val -split ",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

function Parse-Hashtable {
    param([string]$val, [string]$pairSep = "|", [string]$kvSep = "=")
    $ht = @{}
    ($val -split [regex]::Escape($pairSep)) | ForEach-Object {
        $kv = $_ -split [regex]::Escape($kvSep), 2
        if ($kv.Count -eq 2) { $ht[$kv[0].Trim()] = $kv[1].Trim() }
    }
    return $ht
}

# ── Auto-generate properties.example on every run ────────────────────────────

function Update-PropertiesExample {
    $examplePath = Join-Path $PSScriptRoot "netstat-claude.properties.example"

    $header = @"
# =============================================================================
# netstat-claude.properties.example
# =============================================================================
# Copy this file to netstat-claude.properties and fill in your values.
# netstat-claude.properties is git-ignored and will never be committed.
# This example file is auto-generated each run and always reflects current settings.
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# =============================================================================

# -----------------------------------------------------------------------------
# ANTHROPIC API SETTINGS
# -----------------------------------------------------------------------------

# Your Anthropic API key from https://console.anthropic.com/settings/keys
# Format: sk-ant-api03-xxxx...
# WARNING: Never commit your actual API key to git
ApiKey=sk-ant-api03-YOUR-KEY-HERE

# Model to use for analysis
# Available: claude-haiku-4-5-20251001 (cheapest), claude-sonnet-4-5-20251022 (smarter)
Model=claude-haiku-4-5-20251001

# Anthropic API version header - do not change unless instructed
ApiVersion=2023-06-01

# Anthropic API endpoint - do not change
Uri=https://api.anthropic.com/v1/messages

# Maximum tokens in Claude response per analysis call
MaxTokens=2000

# -----------------------------------------------------------------------------
# TIMING SETTINGS
# -----------------------------------------------------------------------------

# How often to collect a netstat snapshot (seconds)
# 900 = 15 minutes recommended. Do not go below 300.
SnapshotIntervalSeconds=900

# How often to send collected snapshots to Claude for analysis (minutes)
# 120 = 2 hours recommended
BatchIntervalMinutes=120

# Maximum snapshots per batch - safety cap to prevent rate limit errors
MaxSnapshotsPerBatch=10

# How often to send a cache keepalive to Anthropic (minutes)
# Must be less than 60 to keep the 1-hour prompt cache warm
KeepaliveIntervalMinutes=55

# When elevated threat mode is active batch interval drops to this (minutes)
# NOTE: Snapshot interval is NEVER changed - only batch frequency
ElevatedBatchMinutes=30

# How often to re-resolve known hostnames to IPs (seconds)
ResolveInterval=3600

# -----------------------------------------------------------------------------
# FILE PATHS
# -----------------------------------------------------------------------------

# Folder where log files are written (relative to script location)
LogFolder=.\log

# -----------------------------------------------------------------------------
# KNOWN LOCAL NETWORK DEVICES
# -----------------------------------------------------------------------------
# Comma-separated list of IP addresses of known devices on your network.
# These will never be flagged as new/unknown devices.
#
# Common entries:
#   Your router:       usually 192.168.1.1 or 192.168.0.1
#   This machine:      the IP of the Windows PC running this script
#   Your workstation:  the machine you VNC/connect from
#   Media devices:     smart TVs, streaming boxes etc
#   VPN tunnel IP:     specific IP currently assigned by your VPN client

KnownLocalIPs=192.168.1.1,192.168.1.100,192.168.1.101,192.168.1.102

# -----------------------------------------------------------------------------
# KNOWN LOCAL SUBNETS
# -----------------------------------------------------------------------------
# Comma-separated regex patterns for entire subnets to NEVER flag as new devices.
# Use for VPN tunnel subnets where the IP may vary within the range.
#
# Format: regex1,regex2
# Example for VPN using 10.20.224.x: 10\.20\.224\.
# Example for corporate VPN 172.16.x: 172\.16\.
#
# IMPORTANT: These are regex patterns - escape dots with backslash

KnownLocalSubnets=10\.0\.0\.

# -----------------------------------------------------------------------------
# KNOWN EXTERNAL HOSTNAMES
# -----------------------------------------------------------------------------
# Pipe-separated list of hostname=description pairs.
# Resolved to IPs at startup and refreshed hourly.
# Connections to these IPs are identified as legitimate in analysis.
#
# Format: hostname=description|hostname=description

KnownHostnames=api.anthropic.com=Anthropic API|example-service.com=My Service

# -----------------------------------------------------------------------------
# PROMPT - STATIC MACHINE CONTEXT (cached with Anthropic 1hr TTL)
# -----------------------------------------------------------------------------
# Describe your specific machine so Claude can identify legitimate traffic.
# Be specific - list all software that makes network connections.
# This block is sent with every API call and cached for efficiency.
#
# Format: multi-line block ending with END_PROMPT_STATIC on its own line.

PromptStatic=<<END_PROMPT_STATIC
Describe your machine context here. List all software that makes network
connections so Claude can identify legitimate vs suspicious traffic.

Examples to customise:
- [YourVPN] VPN software is intentionally installed and running
- [YourVPN] routes all [YourTorrentClient] traffic through tunnel subnet [x.x.x.x/24]
- [YourAntivirus] is running - its processes are legitimate
- [YourAntivirus] may show 'Cannot obtain ownership' in netstat - this is expected
- [YourMediaServer] is running on port [port]
- Remote desktop/VNC connections from [your workstation IP] are expected
- [ProcessName].exe is [description] (legitimate)
- Port [port] is used by [application] for [purpose]

Known local network devices:
- [IP] = Router/DNS gateway
- [IP] = Your workstation (remote access machine)
- [IP] = [Device description e.g. Smart TV, NAS, Printer]
- [IP] = This Windows machine
- [subnet e.g. 10.x.x.x] = This machine via VPN tunnel
END_PROMPT_STATIC

# -----------------------------------------------------------------------------
# PROMPT - IMMEDIATE ALERT (triggered when new unknown device detected)
# -----------------------------------------------------------------------------
# {0} = netstat output  {1} = known IPs context  {2} = new device alert

PromptImmediate=<<END_PROMPT_IMMEDIATE
This is an IMMEDIATE ALERT triggered by a new local network device.

Known legitimate IPs resolved at startup:
{1}

NEW LOCAL DEVICE ALERT:
{2}

Please:
1. Identify the new device and assess whether it is expected
2. Flag anything suspicious about its connections
3. Provide risk rating (LOW/MODERATE/HIGH/CRITICAL)
4. Suggest PowerShell investigation commands

Netstat output:
{0}
END_PROMPT_IMMEDIATE

# -----------------------------------------------------------------------------
# PROMPT - BATCH ANALYSIS (sent on schedule every 2 hours)
# -----------------------------------------------------------------------------
# {0} = formatted snapshots  {1} = known IPs  {2} = new devices
# {3} = snapshot count       {4} = persistent IPs  {5} = fleeting IPs
# {6} = timestamps

PromptBatch=<<END_PROMPT_BATCH
Analyze this master connection log from a Windows machine.
This is a deduplicated rolling log of all unique connections observed this session.
Each row: FirstSeen, LastSeen, Count, State, LocalAddress, RemoteAddress, Process.
High Count = persistent. Low Count = transient. Large time gap = long-running.
Torrent peer rows have been excluded - confirmed normal activity.

Known legitimate IPs resolved at startup:
{1}

New local devices detected this session: {2}

Focus your analysis on:
1. Persistent connections (high Count) to unknown or suspicious external IPs
2. Any process making connections it should not be making
3. Connections to non-standard ports on external IPs
4. Long-running connections to unknown hosts
5. Any pattern suggesting data exfiltration, C2 or lateral movement
6. Provide overall risk rating (LOW/MODERATE/HIGH/CRITICAL)
7. Suggest PowerShell investigation commands for anything flagged

Master connection log (CSV):
{0}
END_PROMPT_BATCH

# =============================================================================
# END OF PROPERTIES
# =============================================================================
"@
    Set-Content -Path $examplePath -Value $header -Encoding UTF8
}

Update-PropertiesExample

# ── Validate required properties ─────────────────────────────────────────────

$required = @("ApiKey","Model","ApiVersion","MaxTokens","Uri",
              "SnapshotIntervalSeconds","BatchIntervalMinutes","MaxSnapshotsPerBatch",
              "KeepaliveIntervalMinutes","ElevatedBatchMinutes","ResolveInterval",
              "LogFolder","KnownLocalIPs","KnownHostnames")
# Note: KnownLocalSubnets is optional - VPN interfaces are detected dynamically

$missing = $required | Where-Object {
    -not $props.ContainsKey($_) -and
    -not $props.ContainsKey("__BLOCKKEY__$_")
}
if ($missing.Count -gt 0) {
    Write-Host "ERROR: Missing required properties: $($missing -join ', ')" -ForegroundColor Red
    Write-Host "Check netstat-claude.properties against netstat-claude.properties.example" -ForegroundColor Yellow
    exit 1
}

# ── Build config hashtable ────────────────────────────────────────────────────

$config = @{
    ApiKey                   = $props["ApiKey"]
    Model                    = $props["Model"]
    ApiVersion               = $props["ApiVersion"]
    MaxTokens                = [int]$props["MaxTokens"]
    Uri                      = $props["Uri"]
    SnapshotIntervalSeconds  = [int]$props["SnapshotIntervalSeconds"]
    BatchIntervalMinutes     = [int]$props["BatchIntervalMinutes"]
    MaxSnapshotsPerBatch     = [int]$props["MaxSnapshotsPerBatch"]
    KeepaliveIntervalMinutes = [int]$props["KeepaliveIntervalMinutes"]
    ElevatedBatchMinutes     = [int]$props["ElevatedBatchMinutes"]
    ResolveInterval          = [int]$props["ResolveInterval"]
    LogFolder                = $props["LogFolder"]
    KnownLocalIPs            = Parse-StringList $props["KnownLocalIPs"]
    KnownLocalSubnets        = Parse-StringList $props["KnownLocalSubnets"]
    KnownHostnames           = Parse-Hashtable  $props["KnownHostnames"]
    PromptStatic             = Get-BlockProp "PromptStatic"
    ImmediatePromptDynamic   = Get-BlockProp "PromptImmediate"
    BatchPromptDynamic       = Get-BlockProp "PromptBatch"

    # Keywords to highlight red in console output
    # SYN_SENT intentionally excluded - normal for qBittorrent/torrent clients
    SuspiciousKeywords       = @(
        "suspicious", "malicious", "flag",
        "WARNING", "ALERT",
        "unknown", "unexpected", "NEW LOCAL DEVICE",
        "HIGH", "CRITICAL"
    )
}