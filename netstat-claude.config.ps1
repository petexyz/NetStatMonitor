# netstat-claude.config.ps1
# Keep this file secure - contains your API key

# API Settings
$config = @{
    ApiKey          = "API-KEY-HERE"
    Model           = "claude-sonnet-4-20250514"
    ApiVersion      = "2023-06-01"
    MaxTokens       = 1500

    # Monitor Settings
    IntervalSeconds = 120
    LogFolder       = ".\log"

    # Alert keywords to highlight red in console
    SuspiciousKeywords = @(
        "suspicious", "malicious", "flag",
        "WARNING", "ALERT", "SYN_SENT",
        "unknown", "unexpected"
    )

    # Whitelist - known good hosts to skip flagging
    KnownGoodHosts = @(
        "googleapis.com",
        "microsoft.com",
        "amazon.com",
        "plex.tv",
        "bitdefender.com"
    )

    # Analysis prompt
    Prompt = @"
Analyze this netstat output from a Windows machine and:
1. Identify each connection and what it likely is
2. Flag anything suspicious, unexpected, or potentially malicious
3. Note any connections to unusual ports or unknown hosts
4. Provide a clean human-readable summary
5. Suggest PowerShell commands to investigate anything flagged

Netstat output:
{0}
"@
}