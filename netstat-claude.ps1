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

# Create log folder and file IMMEDIATELY - must happen before any Write-Log calls
if (-not (Test-Path $config.LogFolder)) {
    New-Item -ItemType Directory -Path $config.LogFolder -Force | Out-Null
}
$logFile = Join-Path $config.LogFolder "netstat-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
New-Item -ItemType File -Path $logFile -Force | Out-Null

# Get local machine IP
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notmatch "^127\." -and
    $_.IPAddress -notmatch "^169\."
} | Select-Object -First 1).IPAddress

# Initialise known local IPs as a growable list seeded from config
$script:knownLocalIPs = [System.Collections.ArrayList]$config.KnownLocalIPs

# Dynamically detect VPN and virtual network interface IPs at startup
# This covers PIA, any other VPN, and virtual adapters - no hardcoding needed
function Get-VirtualInterfaceIPs {
    $virtualIPs = @()
    $vpnAdapterNames = @(
        "pia", "vpn", "tun", "tap", "wg", "wireguard",
        "openvpn", "nordvpn", "expressvpn", "proton",
        "virtualbox", "vmware", "hyper-v", "vethernet"
    )

    Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object {
        $ip        = $_.IPAddress
        $ifAlias   = (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceDescription
        $ifName    = (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Name

        # Skip loopback and link-local
        if ($ip -match "^127\." -or $ip -match "^169\.254\.") { return }

        # Skip the main physical IP we already know
        if ($ip -eq $localIP) { return }

        # Flag if adapter name suggests VPN/virtual
        $isVirtual = $false
        foreach ($name in $vpnAdapterNames) {
            if ($ifAlias -imatch $name -or $ifName -imatch $name) {
                $isVirtual = $true
                break
            }
        }

        # Also flag all non-192.168 and non-10. secondary IPs as potentially VPN
        if (-not $isVirtual -and $ip -notmatch "^192\.168\.") {
            $isVirtual = $true
        }

        if ($isVirtual) {
            $virtualIPs += $ip
            # Derive subnet pattern from IP (first two octets)
            $parts = $ip -split "\."
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

# Batch storage
$snapshots        = [System.Collections.ArrayList]@()
$lastBatchTime    = Get-Date
$lastSnapshotTime = [DateTime]::MinValue
$lastKeepalive    = [DateTime]::MinValue

# Elevated mode affects batch interval only - NOT snapshot interval
$elevatedBatchMode       = $false
$elevatedBatchMinutes    = 30    # Send batches every 30 min when elevated

# ── Logging helper - writes to both console and log file ──────────────────────

function Write-Log {
    param(
        [string]$message,
        [string]$color = "White"
    )
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
            foreach ($ip in $ips) {
                $resolved[$ip] = $config.KnownHostnames[$hostname]
            }
            Write-Log "  Resolved: $hostname -> $($ips -join ', ')" "DarkGray"
        }
        catch {
            Write-Log "  Could not resolve: $hostname" "Yellow"
        }
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
        if ($line -match "ESTABLISHED|TIME_WAIT") {
            foreach ($range in $localRanges) {
                if ($line -match "($range\d+\.\d+)") {
                    $ip = $matches[1]

                    # Skip known subnets (e.g. entire PIA VPN subnet)
                    if (Test-IsKnownSubnet -ip $ip) { continue }

                    if ($ip -ne $localIP -and
                        $script:knownLocalIPs -notcontains $ip) {
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
                } else {
                    $results += $line
                }
            } else {
                $results += $line
            }
        }
    }
    return $results -join "`n"
}

function Get-NetstatSnapshot {
    $withNames = netstat -b -n 2>&1
    $withPIDs  = netstat -a -o -n 2>&1
    $joined    = $withNames -join "`n"

    if ($joined -match "requires elevation") {
        Write-Log "$(Get-Date -Format 'HH:mm:ss') - WARNING: Not running as Administrator - restart elevated" "Red"
        return $null
    }

    $enriched = Resolve-UnknownProcesses -pidOutput ($withPIDs -join "`n")

    return @{
        WithNames = $joined
        Enriched  = $enriched
        Timestamp = (Get-Date -Format 'HH:mm:ss')
    }
}

function Get-ExternalIPs {
    param([string]$snapshot)

    $ips = @{}
    foreach ($line in ($snapshot -split "`n")) {
        if ($line -match "ESTABLISHED" -and $line -notmatch "127\.0\.0\.1") {
            if ($line -match "\s+(\d+\.\d+\.\d+\.\d+):\d+\s+ESTABLISHED") {
                $ip = $matches[1]
                if ($ip -notmatch "^192\.168\." -and
                    $ip -notmatch "^10\."        -and
                    $ip -notmatch "^172\.(1[6-9]|2[0-9]|3[01])\.") {
                    if ($ips.ContainsKey($ip)) {
                        $ips[$ip] = $ips[$ip] + 1
                    } else {
                        $ips[$ip] = 1
                    }
                }
            }
        }
    }
    return $ips
}

function Analyze-SnapshotBatch {
    param([array]$batchSnapshots)

    if ($batchSnapshots.Count -eq 0) { return $null }

    $ipsBySnapshot = @()
    foreach ($snap in $batchSnapshots) {
        $ipsBySnapshot += ,(Get-ExternalIPs -snapshot $snap.WithNames)
    }

    $allIPs = @{}
    foreach ($ipMap in $ipsBySnapshot) {
        foreach ($ip in $ipMap.Keys) {
            if ($allIPs.ContainsKey($ip)) {
                $allIPs[$ip] = $allIPs[$ip] + 1
            } else {
                $allIPs[$ip] = 1
            }
        }
    }

    $persistent = $allIPs.GetEnumerator() |
        Where-Object { $_.Value -eq $batchSnapshots.Count } |
        ForEach-Object { $_.Key }

    $fleeting = $allIPs.GetEnumerator() |
        Where-Object { $_.Value -eq 1 } |
        ForEach-Object { $_.Key }

    $firstProcs = @()
    if ($batchSnapshots.Count -gt 0) {
        $batchSnapshots[0].WithNames -split "`n" | ForEach-Object {
            if ($_ -match "\[(.+\.exe)\]") { $firstProcs += $matches[1] }
        }
    }
    $newProcs = @()
    foreach ($snap in $batchSnapshots[1..($batchSnapshots.Count - 1)]) {
        $snap.WithNames -split "`n" | ForEach-Object {
            if ($_ -match "\[(.+\.exe)\]") {
                $proc = $matches[1]
                if ($firstProcs -notcontains $proc -and $newProcs -notcontains $proc) {
                    $newProcs += $proc
                }
            }
        }
    }

    $torrentResidualCount = 0
    $torrentIPs           = @{}
    foreach ($snap in $batchSnapshots) {
        foreach ($line in ($snap.WithNames -split "`n")) {
            if ($line -match "qbittorrent" -or
                ($line -match "TIME_WAIT|SYN_SENT" -and
                 $line -notmatch "\["              -and
                 $line -notmatch "127\.0\.0\.1")) {
                $torrentResidualCount++
                if ($line -match "(\d+\.\d+\.\d+\.\d+):\d+\s+TIME_WAIT") {
                    $torrentIPs[$matches[1]] = $true
                }
            }
        }
    }

    return @{
        Persistent           = $persistent
        Fleeting             = $fleeting
        NewProcesses         = $newProcs
        TorrentResidualCount = $torrentResidualCount
        TorrentIPCount       = $torrentIPs.Count
        Timestamps           = ($batchSnapshots | ForEach-Object { $_.Timestamp }) -join ", "
    }
}

function Format-BatchForClaude {
    param(
        [array]$batchSnapshots,
        [hashtable]$summary
    )

    # Trim to max batch size to prevent rate limit hits
    if ($batchSnapshots.Count -gt $config.MaxSnapshotsPerBatch) {
        Write-Log "  Trimming batch from $($batchSnapshots.Count) to $($config.MaxSnapshotsPerBatch) snapshots (keeping most recent)" "Yellow"
        $batchSnapshots = $batchSnapshots |
            Select-Object -Last $config.MaxSnapshotsPerBatch
    }

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine("=== BATCH PRE-ANALYSIS SUMMARY ===")
    [void]$sb.AppendLine("Snapshots: $($batchSnapshots.Count)")
    [void]$sb.AppendLine("Timestamps: $($summary.Timestamps)")
    [void]$sb.AppendLine("Persistent external IPs: $($summary.Persistent -join ', ')")
    [void]$sb.AppendLine("Fleeting IPs (once only): $($summary.Fleeting -join ', ')")
    [void]$sb.AppendLine("New processes mid-batch: $($summary.NewProcesses -join ', ')")
    [void]$sb.AppendLine("qBittorrent/torrent residuals: $($summary.TorrentResidualCount) entries across ~$($summary.TorrentIPCount) peer IPs (NORMAL - do not flag)")
    [void]$sb.AppendLine("")

    for ($i = 0; $i -lt $batchSnapshots.Count; $i++) {
        [void]$sb.AppendLine("=== SNAPSHOT [$($batchSnapshots[$i].Timestamp)] ===")

        $torrentSkipped = 0
        foreach ($line in ($batchSnapshots[$i].WithNames -split "`n")) {
            # Strip torrent TIME_WAIT noise - already summarised above
            if (($line -match "TIME_WAIT|SYN_SENT") -and
                $line -notmatch "\["                 -and
                $line -notmatch "127\.0\.0\.1"       -and
                $line -notmatch "192\.168\."         -and
                $line -notmatch "^10\.") {
                $torrentSkipped++
                continue
            }
            [void]$sb.AppendLine($line)
        }

        if ($torrentSkipped -gt 0) {
            [void]$sb.AppendLine("  [[ $torrentSkipped torrent peer TIME_WAIT/SYN_SENT lines omitted - normal qBittorrent activity ]]")
        }
        [void]$sb.AppendLine("")
    }

    return $sb.ToString()
}

function Build-CachedHeaders {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("x-api-key", $config.ApiKey)
    $headers.Add("anthropic-version", $config.ApiVersion)
    $headers.Add("content-type", "application/json")
    $headers.Add("anthropic-beta", "prompt-caching-2024-07-31")
    return $headers
}

function Invoke-CacheKeepalive {
    Write-Log "$(Get-Date -Format 'HH:mm:ss') - Sending cache keepalive..." "DarkGray"

    $body = @{
        model      = $config.Model
        max_tokens = 1
        messages   = @(
            @{
                role    = "user"
                content = @(
                    @{
                        type          = "text"
                        text          = $config.PromptStatic
                        cache_control = @{ type = "ephemeral"; ttl = "1h" }
                    },
                    @{ type = "text"; text = "Keepalive" }
                )
            }
        )
    } | ConvertTo-Json -Depth 7

    try {
        Invoke-RestMethod `
            -Uri $config.Uri `
            -Method POST `
            -Headers (Build-CachedHeaders) `
            -Body $body | Out-Null
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
        [bool]$isBatchMode = $false,
        [int]$snapshotCount = 1,
        [string]$persistentIPs = "",
        [string]$fleetingIPs = "",
        [string]$timestamps = ""
    )

    $knownIPContext   = Get-KnownIPContext
    $newDeviceContext = if ($newLocalDevices.Count -gt 0) {
        "ALERT - New unknown local devices detected: $($newLocalDevices -join ', ')"
    } else {
        "None detected"
    }

    if ($isBatchMode) {
        $dynamicText = $config.BatchPromptDynamic -f `
            $netstatOutput,
            $knownIPContext,
            $newDeviceContext,
            $snapshotCount,
            $persistentIPs,
            $fleetingIPs,
            $timestamps
    } else {
        $dynamicText = $config.ImmediatePromptDynamic -f `
            $netstatOutput,
            $knownIPContext,
            $newDeviceContext
    }

    $body = @{
        model      = $config.Model
        max_tokens = $config.MaxTokens
        messages   = @(
            @{
                role    = "user"
                content = @(
                    @{
                        type          = "text"
                        text          = $config.PromptStatic
                        cache_control = @{ type = "ephemeral"; ttl = "1h" }
                    },
                    @{
                        type = "text"
                        text = $dynamicText
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 7

    try {
        $response = Invoke-RestMethod `
            -Uri $config.Uri `
            -Method POST `
            -Headers (Build-CachedHeaders) `
            -Body $body

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

            # Rate limit - wait 60s and retry once
            if ($errBody -match "rate_limit_error") {
                Write-Log "  Rate limit hit - waiting 60 seconds before retry..." "Yellow"
                Start-Sleep -Seconds 60
                $response = Invoke-RestMethod `
                    -Uri $config.Uri `
                    -Method POST `
                    -Headers (Build-CachedHeaders) `
                    -Body $body
                return $response.content[0].text
            }
            return "API error: $errBody"
        }
        catch {
            return "API error: $($_.Exception.Message)"
        }
    }
}

function Write-ColorOutput {
    param([string]$text)
    foreach ($line in $text -split "`n") {
        $color = "White"
        foreach ($keyword in $config.SuspiciousKeywords) {
            if ($line -imatch $keyword) { $color = "Red"; break }
        }
        # Write to console with color
        Write-Host $line -ForegroundColor $color
        # Also write to log file (no color codes in file)
        Add-Content -Path $logFile -Value $line -Encoding UTF8
    }
}

function Write-LogEntry {
    param(
        [string]$timestamp,
        [string]$mode,
        [string]$netstatRaw,
        [string]$analysis,
        [string[]]$newDevices
    )

    $logEntry = @"
=== $timestamp | Machine: $localIP | Mode: $mode ===
NEW LOCAL DEVICES: $($newDevices -join ', ')

NETSTAT:
$netstatRaw

KNOWN IPs AT TIME OF ANALYSIS:
$(Get-KnownIPContext)

ANALYSIS:
$analysis

"@
    Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
}

function Get-CurrentBatchInterval {
    if ($elevatedBatchMode) {
        return $elevatedBatchMinutes
    }
    return $config.BatchIntervalMinutes
}

# ── Startup ───────────────────────────────────────────────────────────────────

Write-Log "========================================" "Cyan"
Write-Log "  Netstat-Claude Network Monitor" "Cyan"
Write-Log "  Machine IP      : $localIP" "Cyan"
Write-Log "  Logging to      : $logFile" "Cyan"
Write-Log "  Snapshot every  : $($config.SnapshotIntervalSeconds)s (15 min)" "Cyan"
Write-Log "  Batch analysis  : every $($config.BatchIntervalMinutes) min (2 hrs)" "Cyan"
Write-Log "  Elevated batch  : every ${elevatedBatchMinutes} min on HIGH/CRITICAL" "Cyan"
Write-Log "  Max batch size  : $($config.MaxSnapshotsPerBatch) snapshots" "Cyan"
Write-Log "  Cache keepalive : every $($config.KeepaliveIntervalMinutes) min" "Cyan"
Write-Log "  API Uri         : $($config.Uri)" "Cyan"
Write-Log "  Model           : $($config.Model)" "Cyan"
Write-Log "  Est. cost 24/7  : ~$0.36/day (~$10.80/month)" "Cyan"
Write-Log "  NOTE: Elevated mode shortens BATCH interval only - snapshot interval unchanged" "Cyan"
Write-Log "  NOTE: New device alerts do NOT trigger elevated mode" "Cyan"
Write-Log "========================================" "Cyan"
Write-Log "" "White"

Write-Log "Known local devices:" "Cyan"
foreach ($ip in $script:knownLocalIPs) {
    $label = switch -Regex ($ip) {
        "192\.168\.4\.20"  { "Mac workstation (VNC client)" }
        "192\.168\.4\.47"  { "Smart TV (Plex/Cast client)" }
        "192\.168\.1\.1"   { "Router/DNS" }
        "192\.168\.5\.251" { "This machine" }
        "10\."             { "This machine via PIA VPN (dynamic)" }
        default            { "Known device" }
    }
    Write-Log "  $ip - $label" "DarkGray"
}

Write-Log "" "White"
Write-Log "Known subnets (never flagged as new devices):" "Cyan"
foreach ($subnet in $config.KnownLocalSubnets) {
    Write-Log "  $subnet (PIA VPN tunnel)" "DarkGray"
}

Write-Log "" "White"
# Detect VPN and virtual interface IPs dynamically
Write-Log "Detecting VPN/virtual network interfaces..." "Cyan"
$detectedVirtualIPs = Get-VirtualInterfaceIPs
if ($detectedVirtualIPs.Count -gt 0) {
    foreach ($vip in $detectedVirtualIPs) {
        Write-Log "  Detected virtual/VPN interface: $vip (added to known IPs)" "DarkGray"
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

# ── Main Loop ─────────────────────────────────────────────────────────────────

while ($true) {
    $now       = Get-Date
    $timestamp = $now.ToString('HH:mm:ss')

    # Refresh host resolutions and re-detect VPN interfaces hourly
    if (((Get-Date) - $lastResolve).TotalSeconds -gt $config.ResolveInterval) {
        Write-Log "$timestamp - Refreshing host resolutions..." "Cyan"
        $knownIPs    = Resolve-KnownHosts
        $lastResolve = Get-Date

        # Re-detect VPN interfaces in case VPN reconnected with a new IP
        $newVIPs = Get-VirtualInterfaceIPs
        if ($newVIPs.Count -gt 0) {
            foreach ($vip in $newVIPs) {
                Write-Log "$timestamp - VPN interface refresh: $vip" "DarkGray"
            }
        }
    }

    # Cache keepalive every 55 minutes
    if (((Get-Date) - $lastKeepalive).TotalMinutes -ge $config.KeepaliveIntervalMinutes) {
        Invoke-CacheKeepalive
        $lastKeepalive = Get-Date
    }

    # Collect snapshot every 15 minutes - unchanged by elevated mode
    if (($now - $lastSnapshotTime).TotalSeconds -ge $config.SnapshotIntervalSeconds) {

        $snapshot = Get-NetstatSnapshot

        if ($null -eq $snapshot) {
            Start-Sleep -Seconds 30
            continue
        }

        $snapshots.Add($snapshot) | Out-Null
        Write-Log "$timestamp - Snapshot collected ($($snapshots.Count) in batch)" "DarkGray"

        # Check for new local devices - fires immediate analysis but does NOT
        # change snapshot interval or trigger elevated mode
        $newDevices = Find-NewLocalDevices -snapshot $snapshot.WithNames

        if ($newDevices.Count -gt 0) {
            Write-Log "" "White"
            Write-Log "=== $timestamp - NEW LOCAL DEVICE - IMMEDIATE ANALYSIS ===" "Yellow"
            Write-Log "NOTE: This does not change polling interval" "DarkGray"

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
                -mode "IMMEDIATE-NEW-DEVICE (no interval change)" `
                -netstatRaw $snapshot.WithNames `
                -analysis $analysis `
                -newDevices $newDevices
        }

        $lastSnapshotTime = $now
    }

    # Determine current batch interval
    $currentBatchInterval = Get-CurrentBatchInterval

    # Send batch on schedule OR if batch is getting too large
    $batchReady = ($now - $lastBatchTime).TotalMinutes -ge $currentBatchInterval
    $batchFull  = $snapshots.Count -ge $config.MaxSnapshotsPerBatch

    if (($batchReady -or $batchFull) -and $snapshots.Count -gt 0) {

        $reason = if ($batchFull) { "batch cap reached ($($snapshots.Count) snapshots)" } `
                  else            { "scheduled ($currentBatchInterval min interval)" }

        Write-Log "" "White"
        Write-Log "=== $timestamp - Sending batch: $reason ===" "Yellow"

        $summary   = Analyze-SnapshotBatch -batchSnapshots $snapshots
        $formatted = Format-BatchForClaude -batchSnapshots $snapshots -summary $summary

        $analysis = Invoke-ClaudeAnalysis `
            -netstatOutput $formatted `
            -newLocalDevices @() `
            -isBatchMode $true `
            -snapshotCount $snapshots.Count `
            -persistentIPs ($summary.Persistent -join ', ') `
            -fleetingIPs ($summary.Fleeting -join ', ') `
            -timestamps $summary.Timestamps

        Write-Log "" "White"
        Write-Log "--- Batch Analysis ---" "Green"
        Write-ColorOutput $analysis
        Write-Log "----------------------" "Green"
        Write-Log "" "White"

        Write-LogEntry `
            -timestamp $timestamp `
            -mode "BATCH ($($snapshots.Count) snapshots | $reason)" `
            -netstatRaw $formatted `
            -analysis $analysis `
            -newDevices @()

        # Elevated mode shortens BATCH interval only - snapshot interval unchanged
        if ($analysis -imatch "HIGH|CRITICAL") {
            if (-not $elevatedBatchMode) {
                $elevatedBatchMode = $true
                Write-Log "$timestamp - ELEVATED BATCH MODE - sending batches every ${elevatedBatchMinutes} min" "Red"
                Write-Log "$timestamp - Snapshot interval unchanged at $($config.SnapshotIntervalSeconds)s" "DarkGray"
            }
        } elseif ($elevatedBatchMode -and $analysis -imatch "LOW|no.*suspicious|nothing.*unusual") {
            $elevatedBatchMode = $false
            Write-Log "$timestamp - Returning to normal batch interval ($($config.BatchIntervalMinutes) min)" "Green"
        }

        # Reset batch and sync keepalive timer
        $snapshots.Clear()
        $lastBatchTime = $now
        $lastKeepalive = $now
    }

    Start-Sleep -Seconds 30
}