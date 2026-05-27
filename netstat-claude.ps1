# netstat-claude.ps1
# Run as Administrator for full process visibility
# Usage: .\netstat-claude.ps1

# Prevent console truncation and fix UTF-8 encoding
$host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(8192, 9999)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Load config
$configPath = Join-Path $PSScriptRoot "netstat-claude.config.ps1"
if (-not (Test-Path $configPath)) {
    Write-Host "Config file not found: $configPath" -ForegroundColor Red
    exit 1
}
. $configPath

# Create log folder and files IMMEDIATELY - before any Write-Log calls
if (-not (Test-Path $config.LogFolder)) {
    New-Item -ItemType Directory -Path $config.LogFolder -Force | Out-Null
}
$logFile       = Join-Path $config.LogFolder "netstat-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$masterCsvFile = Join-Path $config.LogFolder "master-connections-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
New-Item -ItemType File -Path $logFile -Force | Out-Null

# Get local machine IP
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notmatch "^127\." -and
    $_.IPAddress -notmatch "^169\."
} | Select-Object -First 1).IPAddress

# Initialise known local IPs as a growable list seeded from config
$script:knownLocalIPs = [System.Collections.ArrayList]$config.KnownLocalIPs

# Dynamically detect VPN and virtual network interface IPs
function Get-VirtualInterfaceIPs {
    $virtualIPs      = @()
    $vpnAdapterNames = @(
        "pia", "vpn", "tun", "tap", "wg", "wireguard",
        "openvpn", "nordvpn", "expressvpn", "proton",
        "virtualbox", "vmware", "hyper-v", "vethernet"
    )

    Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object {
        $ip      = $_.IPAddress
        $ifAlias = (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceDescription
        $ifName  = (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Name

        if ($ip -match "^127\." -or $ip -match "^169\.254\.") { return }
        if ($ip -eq $localIP) { return }

        $isVirtual = $false
        foreach ($name in $vpnAdapterNames) {
            if ($ifAlias -imatch $name -or $ifName -imatch $name) {
                $isVirtual = $true; break
            }
        }
        if (-not $isVirtual -and $ip -notmatch "^192\.168\.") { $isVirtual = $true }

        if ($isVirtual) {
            $virtualIPs += $ip
            $parts         = $ip -split "\."
            $subnetPattern = "$($parts[0])\.$($parts[1])\."
            if ($script:knownLocalIPs -notcontains $ip) {
                $script:knownLocalIPs.Add($ip) | Out-Null
            }
            if ($config.KnownLocalSubnets -notcontains $subnetPattern) {
                $config.KnownLocalSubnets += $subnetPattern
            }
        }
    }
    return $virtualIPs
}

# Global state
$knownIPs          = @{}
$lastResolve       = [DateTime]::MinValue
$lastBatchTime     = Get-Date
$lastSnapshotTime  = [DateTime]::MinValue
$lastKeepalive     = [DateTime]::MinValue
$elevatedBatchMode = $false
$elevatedBatchMins = 30

# Master connection log - ESTABLISHED connections only, no torrent
$masterConnections = @{}
$masterAddCount    = 0
$masterUpdateCount = 0

# ── Logging ───────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$message, [string]$color = "White")
    Write-Host $message -ForegroundColor $color
    Add-Content -Path $logFile -Value $message -Encoding UTF8
}

# ── Functions ─────────────────────────────────────────────────────────────────

function Resolve-KnownHosts {
    $resolved = @{}
    foreach ($hostname in $config.KnownHostnames.Keys) {
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($hostname) |
                   ForEach-Object { $_.IPAddressToString }
            foreach ($ip in $ips) { $resolved[$ip] = $config.KnownHostnames[$hostname] }
            Write-Log "  Resolved: $hostname -> $($ips -join ', ')" "DarkGray"
        }
        catch { Write-Log "  Could not resolve: $hostname" "Yellow" }
    }
    return $resolved
}

function Get-KnownIPContext {
    return ($knownIPs.GetEnumerator() | ForEach-Object {
        "- $($_.Key) is $($_.Value) (legitimate)"
    }) -join "`n"
}

function Test-IsKnownSubnet {
    param([string]$ip)
    foreach ($subnet in $config.KnownLocalSubnets) {
        if ($ip -match $subnet) { return $true }
    }
    return $false
}

function Find-NewLocalDevices {
    param([string]$snapshot)
    $newDevices  = @()
    $localRanges = @("192\.168\.", "10\.", "172\.(1[6-9]|2[0-9]|3[01])\.")

    foreach ($line in ($snapshot -split "`n")) {
        if ($line -match "ESTABLISHED") {
            foreach ($range in $localRanges) {
                if ($line -match "($range\d+\.\d+)") {
                    $ip = $matches[1]
                    if (Test-IsKnownSubnet -ip $ip) { continue }
                    if ($ip -ne $localIP -and $script:knownLocalIPs -notcontains $ip) {
                        $newDevices += $ip
                        $script:knownLocalIPs.Add($ip) | Out-Null
                        Write-Log "NEW LOCAL DEVICE DETECTED: $ip" "Red"
                    }
                }
            }
        }
    }
    return $newDevices
}

function Resolve-UnknownProcesses {
    param([string]$pidOutput)
    $results = @()
    foreach ($line in ($pidOutput -split "`n")) {
        if ($line -match "ESTABLISHED") {
            $parts = ($line -split "\s+") | Where-Object { $_ }
            if ($parts.Count -ge 5) {
                $procID = $parts[-1]
                if ($procID -match "^\d+$" -and $procID -ne "0") {
                    $proc = Get-Process -Id $procID -ErrorAction SilentlyContinue
                    if ($proc) {
                        $results += "$line [$($proc.Name)]"
                    } else {
                        $results += "$line [PID:$procID Protected/System]"
                    }
                } else { $results += $line }
            } else { $results += $line }
        }
    }
    return $results -join "`n"
}

function Get-NetstatSnapshot {
    $withNames = netstat -b -n 2>&1
    $withPIDs  = netstat -a -o -n 2>&1
    $joined    = $withNames -join "`n"

    if ($joined -match "requires elevation") {
        Write-Log "$(Get-Date -Format 'HH:mm:ss') - WARNING: Not running as Administrator" "Red"
        return $null
    }

    # Only enrich ESTABLISHED connections - skip TIME_WAIT entirely
    $enriched = Resolve-UnknownProcesses -pidOutput ($withPIDs -join "`n")

    return @{
        WithNames = $joined
        Enriched  = $enriched
        Timestamp = (Get-Date -Format 'HH:mm:ss')
    }
}

# ── Master Connection Log ─────────────────────────────────────────────────────
# ESTABLISHED connections only - TIME_WAIT and torrent excluded entirely

function Update-MasterLog {
    param([hashtable]$snapshot)

    $timestamp = $snapshot.Timestamp
    $addCount  = 0
    $updCount  = 0

    foreach ($line in ($snapshot.Enriched -split "`n")) {

        # ESTABLISHED only - skip TIME_WAIT, SYN_SENT, CLOSE_WAIT etc
        if ($line -notmatch "ESTABLISHED") { continue }

        # Skip localhost internal connections
        if ($line -match "127\.0\.0\.1.*127\.0\.0\.1") { continue }

        if ($line -match "^\s*TCP\s+(\S+)\s+(\S+)\s+ESTABLISHED") {
            $local  = $matches[1]
            $remote = $matches[2]
            $proc   = "unknown"

            if ($line -match "\[(.+?)\]") { $proc = $matches[1] }

            # Skip torrent process entirely - not stored at all
            if ($proc -imatch "qbittorrent|bittorrent|utorrent|transmission|deluge") { continue }

            $key = "$local|$remote|$proc"

            if ($masterConnections.ContainsKey($key)) {
                $masterConnections[$key].LastSeen = $timestamp
                $masterConnections[$key].Count++
                $script:masterUpdateCount++
                $updCount++
            } else {
                $masterConnections[$key] = [PSCustomObject]@{
                    FirstSeen = $timestamp
                    LastSeen  = $timestamp
                    Count     = 1
                    Local     = $local
                    Remote    = $remote
                    Process   = $proc
                }
                $script:masterAddCount++
                $addCount++
            }
        }
    }

    $total = $masterConnections.Count
    Write-Log "$timestamp - Master log: +$addCount new, ~$updCount updated | Total: $total ESTABLISHED | Session: $($script:masterAddCount) added, $($script:masterUpdateCount) updated" "DarkGray"

    if ($addCount -gt 0) { Write-MasterCsv }
}

function Write-MasterCsv {
    $header = "FirstSeen,LastSeen,Count,LocalAddress,RemoteAddress,Process"
    $rows   = $masterConnections.Values |
        Sort-Object FirstSeen |
        ForEach-Object {
            "$($_.FirstSeen),$($_.LastSeen),$($_.Count),$($_.Local),$($_.Remote),$($_.Process)"
        }

    @($header) + $rows | Set-Content -Path $masterCsvFile -Encoding UTF8
    Write-Log "  Master CSV updated -> $masterCsvFile ($($masterConnections.Count) rows)" "DarkGray"
}

function Format-MasterForClaude {
    $rows = $masterConnections.Values | Sort-Object FirstSeen

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("=== MASTER CONNECTION LOG - ESTABLISHED ONLY ===")
    [void]$sb.AppendLine("Session start  : $($masterConnections.Values | Sort-Object FirstSeen | Select-Object -First 1 | ForEach-Object { $_.FirstSeen })")
    [void]$sb.AppendLine("Current time   : $(Get-Date -Format 'HH:mm:ss')")
    [void]$sb.AppendLine("Total unique   : $($masterConnections.Count)")
    [void]$sb.AppendLine("Session adds   : $($script:masterAddCount)")
    [void]$sb.AppendLine("Session updates: $($script:masterUpdateCount)")
    [void]$sb.AppendLine("Note: TIME_WAIT, torrent, and localhost connections excluded entirely")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("FirstSeen,LastSeen,Count,LocalAddress,RemoteAddress,Process")

    foreach ($row in $rows) {
        [void]$sb.AppendLine("$($row.FirstSeen),$($row.LastSeen),$($row.Count),$($row.Local),$($row.Remote),$($row.Process)")
    }

    return $sb.ToString()
}

# ── API Functions ─────────────────────────────────────────────────────────────

function Build-CachedHeaders {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("x-api-key",         $config.ApiKey)
    $headers.Add("anthropic-version",  $config.ApiVersion)
    $headers.Add("content-type",       "application/json")
    $headers.Add("anthropic-beta",     "prompt-caching-2024-07-31")
    return $headers
}

function Build-CachedBody {
    param([string]$dynamicText, [int]$maxTokens)

    # Use [ordered] and Depth 10 to ensure cache_control serialises correctly
    $body = [ordered]@{
        model      = $config.Model
        max_tokens = $maxTokens
        messages   = @(
            [ordered]@{
                role    = "user"
                content = @(
                    [ordered]@{
                        type          = "text"
                        text          = $config.PromptStatic
                        cache_control = [ordered]@{ type = "ephemeral"; ttl = "1h" }
                    },
                    [ordered]@{
                        type = "text"
                        text = $dynamicText
                    }
                )
            }
        )
    }
    return $body | ConvertTo-Json -Depth 10
}

function Invoke-CacheKeepalive {
    Write-Log "$(Get-Date -Format 'HH:mm:ss') - Sending cache keepalive..." "DarkGray"

    $body = Build-CachedBody -dynamicText "Keepalive" -maxTokens 1

    try {
        Invoke-RestMethod -Uri $config.Uri -Method POST -Headers (Build-CachedHeaders) -Body $body | Out-Null
        Write-Log "$(Get-Date -Format 'HH:mm:ss') - Cache keepalive OK" "DarkGray"
    }
    catch {
        Write-Log "$(Get-Date -Format 'HH:mm:ss') - Cache keepalive failed: $($_.Exception.Message)" "Yellow"
    }
}

function Invoke-ClaudeAnalysis {
    param(
        [string]$netstatOutput,
        [string[]]$newLocalDevices,
        [bool]$isBatchMode = $false
    )

    $knownIPContext   = Get-KnownIPContext
    $newDeviceContext = if ($newLocalDevices.Count -gt 0) {
        "ALERT - New unknown local devices detected: $($newLocalDevices -join ', ')"
    } else { "None detected" }

    $dynamicText = if ($isBatchMode) {
        $config.BatchPromptDynamic -f $netstatOutput, $knownIPContext, $newDeviceContext
    } else {
        $config.ImmediatePromptDynamic -f $netstatOutput, $knownIPContext, $newDeviceContext
    }

    $body = Build-CachedBody -dynamicText $dynamicText -maxTokens $config.MaxTokens

    try {
        $response = Invoke-RestMethod -Uri $config.Uri -Method POST -Headers (Build-CachedHeaders) -Body $body

        $usage = $response.usage
        if ($usage) {
            $cacheRead    = if ($usage.cache_read_input_tokens)     { $usage.cache_read_input_tokens }     else { 0 }
            $cacheCreated = if ($usage.cache_creation_input_tokens) { $usage.cache_creation_input_tokens } else { 0 }
            Write-Log "  Cache: wrote=$cacheCreated read=$cacheRead input=$($usage.input_tokens) output=$($usage.output_tokens)" "DarkGray"

            # Warn if cache still not hitting after first call
            if ($cacheRead -eq 0 -and $cacheCreated -eq 0) {
                Write-Log "  WARNING: Cache not activating - check anthropic-beta header and prompt size" "Yellow"
            }
        }
        return $response.content[0].text
    }
    catch {
        try {
            $reader  = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $errBody = $reader.ReadToEnd()
            if ($errBody -match "rate_limit_error") {
                Write-Log "  Rate limit hit - waiting 60 seconds before retry..." "Yellow"
                Start-Sleep -Seconds 60
                $response = Invoke-RestMethod -Uri $config.Uri -Method POST -Headers (Build-CachedHeaders) -Body $body
                return $response.content[0].text
            }
            return "API error: $errBody"
        }
        catch { return "API error: $($_.Exception.Message)" }
    }
}

function Write-ColorOutput {
    param([string]$text)
    foreach ($line in $text -split "`n") {
        $color = "White"
        foreach ($keyword in $config.SuspiciousKeywords) {
            if ($line -imatch $keyword) { $color = "Red"; break }
        }
        Write-Host $line -ForegroundColor $color
        Add-Content -Path $logFile -Value $line -Encoding UTF8
    }
}

function Write-LogEntry {
    param([string]$timestamp, [string]$mode, [string]$payload, [string]$analysis, [string[]]$newDevices)
    $logEntry = @"
=== $timestamp | Machine: $localIP | Mode: $mode ===
NEW LOCAL DEVICES: $($newDevices -join ', ')

PAYLOAD SENT TO CLAUDE:
$payload

KNOWN IPs AT TIME OF ANALYSIS:
$(Get-KnownIPContext)

ANALYSIS:
$analysis

"@
    Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
}

function Get-CurrentBatchInterval {
    if ($elevatedBatchMode) { return $elevatedBatchMins }
    return $config.BatchIntervalMinutes
}

# ── Startup ───────────────────────────────────────────────────────────────────

Write-Log "========================================" "Cyan"
Write-Log "  Netstat-Claude Network Monitor" "Cyan"
Write-Log "  Machine IP      : $localIP" "Cyan"
Write-Log "  Session log     : $logFile" "Cyan"
Write-Log "  Master CSV      : $masterCsvFile" "Cyan"
Write-Log "  Snapshot every  : $($config.SnapshotIntervalSeconds)s (1 min)" "Cyan"
Write-Log "  Batch analysis  : every $($config.BatchIntervalMinutes) min (1 hr)" "Cyan"
Write-Log "  Elevated batch  : every ${elevatedBatchMins} min on HIGH/CRITICAL" "Cyan"
Write-Log "  Cache keepalive : every $($config.KeepaliveIntervalMinutes) min" "Cyan"
Write-Log "  API Uri         : $($config.Uri)" "Cyan"
Write-Log "  Model           : $($config.Model)" "Cyan"
Write-Log "  Est. cost 24/7  : ~$0.19/day (~$5.80/month)" "Cyan"
Write-Log "  ESTABLISHED connections only - TIME_WAIT and torrent excluded" "Cyan"
Write-Log "========================================" "Cyan"
Write-Log "" "White"

Write-Log "Known local devices:" "Cyan"
foreach ($ip in $script:knownLocalIPs) {
    $label = switch -Regex ($ip) {
        "192\.168\.4\.20"  { "Mac workstation (VNC client)" }
        "192\.168\.4\.47"  { "Smart TV (Cast client)" }
        "192\.168\.1\.1"   { "Router/DNS" }
        "192\.168\.5\.251" { "This machine" }
        default            { "Known device" }
    }
    Write-Log "  $ip - $label" "DarkGray"
}
Write-Log "" "White"

Write-Log "Detecting VPN/virtual interfaces..." "Cyan"
$detectedVIPs = Get-VirtualInterfaceIPs
if ($detectedVIPs.Count -gt 0) {
    foreach ($vip in $detectedVIPs) {
        Write-Log "  Detected: $vip" "DarkGray"
    }
} else {
    Write-Log "  No VPN/virtual interfaces detected" "DarkGray"
}
Write-Log "" "White"

Write-Log "Resolving known hosts..." "Cyan"
$knownIPs    = Resolve-KnownHosts
$lastResolve = Get-Date
Write-Log "" "White"

Write-Log "Warming prompt cache..." "Cyan"
Invoke-CacheKeepalive
$lastKeepalive = Get-Date
Write-Log "" "White"

# Initialise master CSV header
"FirstSeen,LastSeen,Count,LocalAddress,RemoteAddress,Process" |
    Set-Content -Path $masterCsvFile -Encoding UTF8
Write-Log "Master CSV initialised: $masterCsvFile" "DarkGray"
Write-Log "" "White"

# ── Main Loop ─────────────────────────────────────────────────────────────────

while ($true) {
    $now       = Get-Date
    $timestamp = $now.ToString('HH:mm:ss')

    # Hourly: refresh host resolutions and re-detect VPN
    if (((Get-Date) - $lastResolve).TotalSeconds -gt $config.ResolveInterval) {
        Write-Log "$timestamp - Refreshing host resolutions..." "Cyan"
        $knownIPs    = Resolve-KnownHosts
        $lastResolve = Get-Date
        $newVIPs     = Get-VirtualInterfaceIPs
        foreach ($vip in $newVIPs) {
            Write-Log "$timestamp - VPN interface refresh: $vip" "DarkGray"
        }
    }

    # Cache keepalive
    if (((Get-Date) - $lastKeepalive).TotalMinutes -ge $config.KeepaliveIntervalMinutes) {
        Invoke-CacheKeepalive
        $lastKeepalive = Get-Date
    }

    # Collect snapshot on interval
    if (($now - $lastSnapshotTime).TotalSeconds -ge $config.SnapshotIntervalSeconds) {

        $snapshot = Get-NetstatSnapshot
        if ($null -eq $snapshot) { Start-Sleep -Seconds 30; continue }

        # Update master log - ESTABLISHED only, torrent excluded
        Update-MasterLog -snapshot $snapshot

        # Check for new local devices - immediate analysis, no interval change
        $newDevices = Find-NewLocalDevices -snapshot $snapshot.WithNames
        if ($newDevices.Count -gt 0) {
            Write-Log "" "White"
            Write-Log "=== $timestamp - NEW LOCAL DEVICE - IMMEDIATE ANALYSIS ===" "Yellow"

            $analysis = Invoke-ClaudeAnalysis `
                -netstatOutput $snapshot.WithNames `
                -newLocalDevices $newDevices `
                -isBatchMode $false

            Write-Log "" "White"
            Write-Log "--- Immediate Analysis ---" "Yellow"
            Write-ColorOutput $analysis
            Write-Log "--------------------------" "Yellow"
            Write-Log "" "White"

            Write-LogEntry `
                -timestamp $timestamp `
                -mode "IMMEDIATE-NEW-DEVICE" `
                -payload $snapshot.WithNames `
                -analysis $analysis `
                -newDevices $newDevices
        }

        $lastSnapshotTime = $now
    }

    # Send master log to Claude on batch schedule
    $currentBatchInterval = Get-CurrentBatchInterval
    $batchReady           = ($now - $lastBatchTime).TotalMinutes -ge $currentBatchInterval

    if ($batchReady -and $masterConnections.Count -gt 0) {

        $reason = "scheduled ($currentBatchInterval min interval)"
        Write-Log "" "White"
        Write-Log "=== $timestamp - Sending master log to Claude: $reason ===" "Yellow"
        Write-Log "  ESTABLISHED connections: $($masterConnections.Count)" "DarkGray"

        $masterPayload = Format-MasterForClaude

        $analysis = Invoke-ClaudeAnalysis `
            -netstatOutput $masterPayload `
            -newLocalDevices @() `
            -isBatchMode $true

        Write-Log "" "White"
        Write-Log "--- Batch Analysis ---" "Green"
        Write-ColorOutput $analysis
        Write-Log "----------------------" "Green"
        Write-Log "" "White"

        Write-LogEntry `
            -timestamp $timestamp `
            -mode "BATCH-MASTER-LOG ($($masterConnections.Count) connections | $reason)" `
            -payload $masterPayload `
            -analysis $analysis `
            -newDevices @()

        # Elevated mode - batch interval only
        if ($analysis -imatch "HIGH|CRITICAL") {
            if (-not $elevatedBatchMode) {
                $elevatedBatchMode = $true
                Write-Log "$timestamp - ELEVATED BATCH MODE - batches every ${elevatedBatchMins} min" "Red"
            }
        } elseif ($elevatedBatchMode -and $analysis -imatch "LOW|no.*suspicious|nothing.*unusual") {
            $elevatedBatchMode = $false
            Write-Log "$timestamp - Returning to normal batch interval ($($config.BatchIntervalMinutes) min)" "Green"
        }

        $lastBatchTime = $now
        $lastKeepalive = $now
    }

    Start-Sleep -Seconds 30
}