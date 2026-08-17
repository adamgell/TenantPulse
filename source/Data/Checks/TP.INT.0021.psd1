@{
    Id         = 'TP.INT.0021'
    Title      = 'Apple Volume Purchase Program tokens valid and syncing'
    Category   = 'Intune.Connectors'
    Severity   = 'High'
    Effort     = 'Low'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('vppTokens')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAppleVppTokensValid'
    }
    Consulting = @{
        WhatItMeans  = 'An Apple Volume Purchase Program (VPP, now integrated into Apple Business/School Manager as "location tokens") token lets Intune synchronize and assign licensed app purchases to iOS/iPadOS and macOS devices. Each token is valid for one year and Intune syncs it with Apple once a day by default. This check Fails a token that is already expired or has not synced within the last day, Warns a token within 30 days of expiry, and treats zero configured tokens as a legitimate skip.'
        WhyItMatters = 'A token showing "invalid" or stuck on a stale sync silently stops new app license assignments and revocations from reaching Apple devices - end users stop receiving app deployments and IT loses the ability to reclaim licenses from devices/users who leave, without any obvious error surfacing until someone notices apps are missing.'
        Remediation  = @(
            'Intune admin center > Tenant administration > Connectors and tokens > Apple VPP tokens - download a fresh location token from Apple Business/School Manager (Preferences > Payments and Billing > Apps and Books > Content Tokens > Download) and upload it to the existing token entry to renew.'
            'If a token shows "invalid" before its expiration date, first check whether the Managed Apple ID account it depends on changed password, was disabled, or had its domain changed - those trigger the same invalid state independent of the expiry date.'
            'Trigger a manual Sync from the same admin center pane if the token is valid but sync is stale, and confirm the Last Sync timestamp updates before assuming renewal is required.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/VPPTokensMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0021--apple-volume-purchase-program-tokens-valid-and-syncing'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/app-management/deployment/manage-vpp-apple'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1094'; License = 'MIT' }
}
