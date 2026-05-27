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

# Create log folder and files IMMEDIATELY - must happen before any Write-Log calls
if (-not (Test-Path $config.LogFolder)) {
    New-Item -ItemType Directory -Path $config.LogFolder -Force | Out-Null
}
$logFile        = Join-Path $config.LogFolder "netstat-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$masterCsvFile  = Join-Path $config.LogFolder "master-connections-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
New-Item -ItemType File -Path $logFile -Force | Out-Null

# Get local machine IP
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notmatch "^127\." -and
    $_.IPAddress -notmatch "^169\."
} | Select-Object -First 1).IPAddress

# Initialise known local IPs as a growable list seeded from config
$script:knownLocalIPs = [System.Collections.ArrayList]$config.KnownLocalIPs

# Dynamically detect VPN and virtual network interface IPs at startup
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

# Global known IPs table populated at startup and refreshed hourly
$knownIPs    = @{}
$lastResolve = [DateTime]::MinValue

# Master connection log - keyed on LocalAddress|RemoteAddress|State|Process
$masterConnections = @{}
$masterAddCount    = 0
$masterUpdateCount = 0

# Batch storage for Claude sends
$lastBatchTime    = Get-Date
$lastSnapshotTime = [DateTime]::MinValue
$lastKeepalive    = [DateTime]::MinValue

# Elevated mode affects batch interval only - NOT snapshot interval
$elevatedBatchMode    = $false
$elevatedBatchMinutes = 30

# ── Logging helper ────────────────────────────────────────────────────────────

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

function Test-IsTorrentLine {
    param([string]$line)
    if ($line -match "qbittorrent" -and $line -match "TIME_WAIT|SYN_SENT") { return $true }
    if ($line -match "TIME_WAIT|SYN_SENT" -and
        $line -notmatch "\["              -and
        $line -notmatch "127\.0\.0\.1") { return $true }
    return $false
}

function Find-NewLocalDevices {
    param([string]$snapshot)
    $newDevices  = @()
    $localRanges = @("192\.168\.", "10\.", "172\.(1[6-9]|2[0-9]|3[01])\.")

    foreach ($line in ($snapshot -split "`n")) {
        if ($line -match "ESTABLISHED|TIME_WAIT") {
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
        if ($line -match "ESTABLISHED|LISTENING|TIME_WAIT|CLOSE_WAIT|FIN_WAIT") {
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

    $enriched = Resolve-UnknownProcesses -pidOutput ($withPIDs -join "`n")
    return @{
        WithNames = $joined
        Enriched  = $enriched
        Timestamp = (Get-Date -Format 'HH:mm:ss')
    }
}

# ── Master Connection Log ─────────────────────────────────────────────────────

function Update-MasterLog {
    param([hashtable]$snapshot)

    $timestamp  = $snapshot.Timestamp
    $addCount   = 0
    $updCount   = 0
    $isTorrent  = $false

    # Parse enriched output which has process names appended
    foreach ($line in ($snapshot.Enriched -split "`n")) {

        # Match TCP connection lines with process name
        if ($line -match "^\s*TCP\s+(\S+)\s+(\S+)\s+(\w+)") {
            $local  = $matches[1]
            $remote = $matches[2]
            $state  = $matches[3]
            $proc   = "unknown"

            # Extract process name from [ProcessName] at end of line
            if ($line -match "\[(.+?)\]") { $proc = $matches[1] }

            # Skip localhost internal connections
            if ($local -match "^127\." -and $remote -match "^127\.") { continue }

            # Identify torrent lines - keep in master but flag
            $isTorrent = Test-IsTorrentLine -line $line

            $key = "$local|$remote|$state|$proc"

            if ($masterConnections.ContainsKey($key)) {
                # Update existing entry
                $masterConnections[$key].LastSeen = $timestamp
                $masterConnections[$key].Count++
                $script:masterUpdateCount++
                $updCount++
            } else {
                # New entry
                $masterConnections[$key] = [PSCustomObject]@{
                    FirstSeen  = $timestamp
                    LastSeen   = $timestamp
                    Count      = 1
                    State      = $state
                    Local      = $local
                    Remote     = $remote
                    Process    = $proc
                    IsTorrent  = $isTorrent
                }
                $script:masterAddCount++
                $addCount++
            }
        }
    }

    # Log running counts on every snapshot
    $total   = $masterConnections.Count
    $torrent = ($masterConnections.Values | Where-Object { $_.IsTorrent }).Count
    $clean   = $total - $torrent

    Write-Log "$timestamp - Master log: +$addCount new, ~$updCount updated | Total: $total ($clean non-torrent, $torrent torrent) | Session totals: $($script:masterAddCount) added, $($script:masterUpdateCount) updated" "DarkGray"

    # Write CSV whenever new entries were added
    if ($addCount -gt 0) {
        Write-MasterCsv
    }
}

function Write-MasterCsv {
    $header = "FirstSeen,LastSeen,Count,State,LocalAddress,RemoteAddress,Process,IsTorrent"
    $rows   = $masterConnections.Values |
        Sort-Object FirstSeen |
        ForEach-Object {
            "$($_.FirstSeen),$($_.LastSeen),$($_.Count),$($_.State),$($_.Local),$($_.Remote),$($_.Process),$($_.IsTorrent)"
        }

    @($header) + $rows | Set-Content -Path $masterCsvFile -Encoding UTF8
    Write-Log "  Master CSV updated -> $masterCsvFile ($($masterConnections.Count) rows)" "DarkGray"
}

function Format-MasterForClaude {
    # Send master log to Claude - exclude torrent rows, include summary of them
    $nonTorrent   = $masterConnections.Values | Where-Object { -not $_.IsTorrent } | Sort-Object FirstSeen
    $torrentRows  = $masterConnections.Values | Where-Object { $_.IsTorrent }
    $torrentCount = $torrentRows.Count
    $torrentIPs   = ($torrentRows | ForEach-Object { $_.Remote -replace ":\d+$","" } | Sort-Object -Unique).Count

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("=== MASTER CONNECTION LOG ===")
    [void]$sb.AppendLine("Session start    : $($masterConnections.Values | Sort-Object FirstSeen | Select-Object -First 1 | ForEach-Object { $_.FirstSeen })")
    [void]$sb.AppendLine("Current time     : $(Get-Date -Format 'HH:mm:ss')")
    [void]$sb.AppendLine("Total unique     : $($masterConnections.Count)")
    [void]$sb.AppendLine("Non-torrent rows : $($nonTorrent.Count)")
    [void]$sb.AppendLine("Torrent rows     : $torrentCount across ~$torrentIPs peer IPs (OMITTED - normal activity)")
    [void]$sb.AppendLine("Session adds     : $($script:masterAddCount)")
    [void]$sb.AppendLine("Session updates  : $($script:masterUpdateCount)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("FirstSeen,LastSeen,Count,State,LocalAddress,RemoteAddress,Process")

    foreach ($row in $nonTorrent) {
        [void]$sb.AppendLine("$($row.FirstSeen),$($row.LastSeen),$($row.Count),$($row.State),$($row.Local),$($row.Remote),$($row.Process)")
    }

    return $sb.ToString()
}

function Build-CachedHeaders {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("x-api-key",        $config.ApiKey)
    $headers.Add("anthropic-version", $config.ApiVersion)
    $headers.Add("content-type",      "application/json")
    $headers.Add("anthropic-beta",    "prompt-caching-2024-07-31")
    return $headers
}

function Invoke-CacheKeepalive {
    Write-Log "$(Get-Date -Format 'HH:mm:ss') - Sending cache keepalive..." "DarkGray"
    $body = @{
        model      = $config.Model
        max_tokens = 1
        messages   = @(@{
            role    = "user"
            content = @(
                @{ type = "text"; text = $config.PromptStatic; cache_control = @{ type = "ephemeral"; ttl = "1h" } },
                @{ type = "text"; text = "Keepalive" }
            )
        })
    } | ConvertTo-Json -Depth 7

    try {
        Invoke-RestMethod -Uri $config.Uri -Method POST -Headers (Build-CachedHeaders) -Body $body | Out-Null
        Write-Log "$(Get-Date -Format 'HH:mm:ss') - Cache keepalive OK" "DarkGray"
    }
    catch { Write-Log "$(Get-Date -Format 'HH:mm:ss') - Cache keepalive failed: $($_.Exception.Message)" "Yellow" }
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

    $body = @{
        model      = $config.Model
        max_tokens = $config.MaxTokens
        messages   = @(@{
            role    = "user"
            content = @(
                @{ type = "text"; text = $config.PromptStatic; cache_control = @{ type = "ephemeral"; ttl = "1h" } },
                @{ type = "text"; text = $dynamicText }
            )
        })
    } | ConvertTo-Json -Depth 7

    try {
        $response = Invoke-RestMethod -Uri $config.Uri -Method POST -Headers (Build-CachedHeaders) -Body $body

        $usage = $response.usage
        if ($usage) {
            $cacheRead    = if ($usage.cache_read_input_tokens)     { $usage.cache_read_input_tokens }     else { 0 }
            $cacheCreated = if ($usage.cache_creation_input_tokens) { $usage.cache_creation_input_tokens } else { 0 }
            Write-Log "  Cache: wrote=$cacheCreated read=$cacheRead input=$($usage.input_tokens) output=$($usage.output_tokens)" "DarkGray"
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
    if ($elevatedBatchMode) { return $elevatedBatchMinutes }
    return $config.BatchIntervalMinutes
}

# ── Startup ───────────────────────────────────────────────────────────────────

Write-Log "========================================" "Cyan"
Write-Log "  Netstat-Claude Network Monitor" "Cyan"
Write-Log "  Machine IP        : $localIP" "Cyan"
Write-Log "  Session log       : $logFile" "Cyan"
Write-Log "  Master CSV        : $masterCsvFile" "Cyan"
Write-Log "  Snapshot every    : $($config.SnapshotIntervalSeconds)s" "Cyan"
Write-Log "  Batch analysis    : every $($config.BatchIntervalMinutes) min" "Cyan"
Write-Log "  Elevated batch    : every ${elevatedBatchMinutes} min on HIGH/CRITICAL" "Cyan"
Write-Log "  Cache keepalive   : every $($config.KeepaliveIntervalMinutes) min" "Cyan"
Write-Log "  API Uri           : $($config.Uri)" "Cyan"
Write-Log "  Model             : $($config.Model)" "Cyan"
Write-Log "  NOTE: Master log deduplicates all connections with first/last seen + count" "Cyan"
Write-Log "  NOTE: Claude receives master log - not raw snapshots" "Cyan"
Write-Log "  NOTE: Torrent rows kept in CSV but excluded from Claude payload" "Cyan"
Write-Log "  NOTE: Elevated mode = shorter batch interval only, snapshot unchanged" "Cyan"
Write-Log "  NOTE: New device alerts do NOT trigger elevated mode" "Cyan"
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

Write-Log "Detecting VPN/virtual network interfaces..." "Cyan"
$detectedVirtualIPs = Get-VirtualInterfaceIPs
if ($detectedVirtualIPs.Count -gt 0) {
    foreach ($vip in $detectedVirtualIPs) {
        Write-Log "  Detected virtual/VPN interface: $vip" "DarkGray"
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

# Write CSV header immediately
"FirstSeen,LastSeen,Count,State,LocalAddress,RemoteAddress,Process,IsTorrent" |
    Set-Content -Path $masterCsvFile -Encoding UTF8
Write-Log "Master CSV initialised: $masterCsvFile" "DarkGray"
Write-Log "" "White"

# ── Main Loop ─────────────────────────────────────────────────────────────────

while ($true) {
    $now       = Get-Date
    $timestamp = $now.ToString('HH:mm:ss')

    # Hourly: refresh host resolutions and re-detect VPN interfaces
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

        # Update master connection log - deduplicates, logs adds/updates, writes CSV
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
        Write-Log "  Non-torrent rows: $(($masterConnections.Values | Where-Object { -not $_.IsTorrent }).Count)" "DarkGray"
        Write-Log "  Torrent rows (excluded from payload): $(($masterConnections.Values | Where-Object { $_.IsTorrent }).Count)" "DarkGray"

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
            -mode "BATCH-MASTER-LOG ($($masterConnections.Count) unique connections | $reason)" `
            -payload $masterPayload `
            -analysis $analysis `
            -newDevices @()

        # Elevated mode - batch interval only
        if ($analysis -imatch "HIGH|CRITICAL") {
            if (-not $elevatedBatchMode) {
                $elevatedBatchMode = $true
                Write-Log "$timestamp - ELEVATED BATCH MODE - batches every ${elevatedBatchMinutes} min" "Red"
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