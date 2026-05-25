# netstat-claude.ps1
# Run as Administrator

# Load config
$configPath = Join-Path $PSScriptRoot "netstat-claude.config.ps1"
if (-not (Test-Path $configPath)) {
    Write-Host "Config file not found: $configPath" -ForegroundColor Red
    exit 1
}
. $configPath
# Write-Host "DEBUG - Key prefix: $($config.ApiKey.Substring(0,15))..." -ForegroundColor Magenta
# Write-Host "DEBUG - Model: $($config.Model)" -ForegroundColor Magenta

# Create log folder if needed
if (-not (Test-Path $config.LogFolder)) {
    New-Item -ItemType Directory -Path $config.LogFolder -Force | Out-Null
}
$logFile = Join-Path $config.LogFolder "netstat-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

function Invoke-ClaudeAnalysis {
    param([string]$netstatOutput)

    $prompt = $config.Prompt -f $netstatOutput

    $body = @{
        model      = $config.Model
        max_tokens = $config.MaxTokens
        messages   = @(
            @{ role = "user"; content = $prompt }
        )
    } | ConvertTo-Json -Depth 5

    # Build headers explicitly as a variable
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("x-api-key", $config.ApiKey)
    $headers.Add("anthropic-version", $config.ApiVersion)
    $headers.Add("content-type", "application/json")

    # Write-Host "DEBUG - Header key value: $($headers['x-api-key'].Substring(0,15))..." -ForegroundColor Magenta

    try {
        $response = Invoke-RestMethod `
            -Uri $config.Uri `
            -Method POST `
            -Headers $headers `
            -Body $body

        return $response.content[0].text
    }
    catch {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        return "API error: $($reader.ReadToEnd())"
    }
}

function Get-NetstatSnapshot {
    $output = netstat -b -n 2>&1
    return $output -join "`n"
}

function Write-ColorOutput {
    param([string]$text)
    foreach ($line in $text -split "`n") {
        $color = "White"
        foreach ($keyword in $config.SuspiciousKeywords) {
            if ($line -imatch $keyword) { $color = "Red"; break }
        }
        Write-Host $line -ForegroundColor $color
    }
}

# Main loop
$lastSnapshot = ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Netstat-Claude Network Monitor" -ForegroundColor Cyan
Write-Host "  Logging to: $logFile" -ForegroundColor Cyan
Write-Host "  Interval: $($config.IntervalSeconds)s" -ForegroundColor Cyan
Write-Host "  API Uri: $($config.Uri)" -ForegroundColor Cyan
Write-Host "  Model: $($config.Model)" -ForegroundColor Cyan
Write-Host "  Press Ctrl+C to stop" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

while ($true) {
    $snapshot  = Get-NetstatSnapshot
    $timestamp = Get-Date -Format 'HH:mm:ss'

    if ($snapshot -ne $lastSnapshot) {
        Write-Host "`n=== $timestamp - Changes detected, analysing... ===" -ForegroundColor Yellow

        $analysis = Invoke-ClaudeAnalysis -netstatOutput $snapshot

        Write-Host "`n--- Claude Analysis ---" -ForegroundColor Green
        Write-ColorOutput $analysis
        Write-Host "------------------------`n" -ForegroundColor Green

        $logEntry = @"
=== $timestamp ===
NETSTAT:
$snapshot

ANALYSIS:
$analysis

"@
        Add-Content -Path $logFile -Value $logEntry
        $lastSnapshot = $snapshot
    }
    else {
        Write-Host "$timestamp - No changes detected" -ForegroundColor DarkGray
    }

    Start-Sleep -Seconds $config.IntervalSeconds
}