# netstat-claude.config.ps1
# Keep this file secure - contains your API key

# API Settings
$config = @{
    ApiKey          = "YOUR_API_KEY_HERE"
    Uri             = "https://api.anthropic.com/v1/messages"
    Model           = "claude-haiku-4-5-20251001"
    ApiVersion      = "2023-06-01"
    MaxTokens       = 1500

    # Monitor Settings
    IntervalSeconds = 30
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
Analyze this netstat output from a Windows machine and provide a security assessment.

Context about this machine:

    HERE PLACE CONTEXT ABOUT YOUR SYSTEM - various software you have running in the background, etc.

Please:
1. Identify each connection and what it likely is
2. Flag anything genuinely suspicious or unexpected given the above context
3. Note any connections to unusual ports or unknown hosts that cannot be explained
4. Highlight any processes that should not be making network connections
5. Note any unidentified processes owning connections
6. Provide a clean human-readable summary with a risk rating (LOW/MODERATE/HIGH)
7. Suggest specific PowerShell commands to investigate anything flagged

Netstat output:
{0}
"@
}