@{
    Id         = 'TP.ENT.0013'
    Title      = 'Group/team owner and risk-based user consent restrictions'
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
        WhatItMeans  = 'Confirms three consent-policy directorySettings: group/team owners cannot independently grant a third-party app permission to read all of that group''s data on members'' behalf (EnableGroupSpecificConsent = False, EIDSCA.CP01); user consent is blocked for apps Microsoft flags as risky (BlockUserConsentForRiskyApps = true, EIDSCA.CP03); and a user blocked from self-consenting can raise an admin-consent request rather than being dead-ended (EnableAdminConsentRequests = true, EIDSCA.CP04). This check currently has NO released GraphKit descriptor to collect it - see this check''s own References.Research for the G-batch request.'
        WhyItMatters = 'Group/team owners are not tenant admins, but CP01 gives them admin-adjacent consent power over every member''s data inside their group - and Microsoft''s own default for this setting is True (permissive). CP03 is the tenant''s automated backstop against known-risky consent grants slipping through regardless of who requests them. CP04 is the operational complement to restricting consent: without an admin-consent-request path, a legitimately-blocked user has no route forward other than shadow IT. User/group consent sprawl is the most common real-world path a malicious OAuth app takes to reach tenant data, and all three settings sit below the admin console most operators actually watch.'
        Remediation  = @(
            'In Entra ID > Enterprise applications > Consent and permissions > User consent settings, or via the Microsoft Graph settings API, set EnableGroupSpecificConsent to False for the tenant''s Group.Unified directorySetting.'
            'Confirm BlockUserConsentForRiskyApps is set to true so Microsoft''s risk-based consent gate stays active.'
            'Set EnableAdminConsentRequests to true (and pair with TP.ENT.0014''s workflow configuration) so an owner or user who legitimately needs an app approved has a path other than self-granting consent.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0013--groupteam-owner-and-risk-based-user-consent-restrictions-eidscacp01-cp03-cp04'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.CP01'
            'https://maester.dev/docs/tests/EIDSCA.CP03'
            'https://maester.dev/docs/tests/EIDSCA.CP04'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'CP01,CP03,CP04'; License = 'MIT' }
}
