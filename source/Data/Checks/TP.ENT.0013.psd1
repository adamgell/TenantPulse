@{
    Id         = 'TP.ENT.0013'
    Title      = 'Group/team owners cannot grant third-party apps consent to read group data'
    Category   = 'Entra.Consent'
    Severity   = 'High'
    Effort     = 'Low'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('directorySettings')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseConsentPolicyRestricted'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms the Group.Unified/consent directorySetting''s EnableGroupSpecificConsent value is False, so a Microsoft 365 group or Teams team owner cannot independently grant a third-party app permission to read all of that group''s data on members'' behalf (EIDSCA.CP01). This check currently has NO released GraphKit descriptor to collect it - see this check''s own References.Research for the G-batch request.'
        WhyItMatters = 'Group/team owners are not tenant admins, but this one setting gives them admin-adjacent consent power over every member''s data inside their group - and Microsoft''s own default for this setting is True (permissive). User/group consent sprawl is the most common real-world path a malicious OAuth app takes to reach tenant data, and this specific setting is one of the largest, least-visible doors into that path because it is delegated far below the admin console most operators actually watch.'
        Remediation  = @(
            'In Entra ID > Enterprise applications > Consent and permissions > User consent settings, or via the Microsoft Graph settings API, set EnableGroupSpecificConsent to False for the tenant''s Group.Unified directorySetting.'
            'Pair this with an admin-consent-request workflow (TP.ENT.0014) so an owner who legitimately needs an app approved has a path other than self-granting consent.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0013--groupteam-owner-and-risk-based-user-consent-restrictions-eidscacp01-cp03-cp04'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.CP01'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'CP01'; License = 'MIT' }
}
