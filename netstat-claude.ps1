# netstat-claude.ps1
# Run as Administrator

# Load config
$configPath = Join-Path $PSScriptRoot "netstat-claude.config.ps1"
if (-not (Test-Path $configPath)) {
    Write-Host "Config file not found: $configPath" -ForegroundColor Red
    exit 1
}
. $configPath

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

    try {
        $response = Invoke-RestMethod `
            -Uri "https://api.anthropic.com/v1/messages" `
            -Method POST `
            -Headers @{
                "x-api-key"         = $config.ApiKey
                "anthropic-version" = $config.ApiVersion
                "content-type"      = "application/json"
            } `
            -Body $body

        return $response.content[0].text
    }
    catch {
        return "API error: $($_.Exception.Message)"
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