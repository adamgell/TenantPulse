@{
    Id         = 'TP.ENT.0012'
    Title      = 'Default authorization policy settings restrict SSPR-for-admins, guest self-service, and default app-registration rights'
    Category   = 'Entra.AuthorizationPolicy'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('authorizationPolicy')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAuthorizationPolicyDefaults'
    }
    Consulting = @{
        WhatItMeans  = 'Reads the tenant''s single authorizationPolicy object and reports nine separate default-permission settings: admins cannot use SSPR for recovery (EIDSCA.AP01), guest invites are restricted to admins/inviters (AP04), email-based subscription self-signup is off (AP05), join-by-email-verification is off (AP06), the guest role is the most-restricted option (AP07), the default consent policy is not the legacy permissive one (AP08), risk-based user consent is not auto-allowed (AP09), default users cannot register app registrations (AP10), and default users retain their normal profile-read permissions (AP14, informational). This check currently has NO released GraphKit descriptor to collect it - see this check''s own References.Research for the G-batch request.'
        WhyItMatters = 'These nine settings are the tenant''s default permission floor - every user gets them unless a more specific policy overrides them. Left at Microsoft''s out-of-the-box defaults, several of these settings are permissive: any user can register an application (a common privilege-escalation path once that app is granted permissions), guest self-signup is wide open, and admins themselves can bypass normal recovery controls via SSPR. Microsoft''s own guidance (MS.AAD.5.1v1, "only admins register apps") and ScuBA''s guest-access family both anchor directly on this one object.'
        Remediation  = @(
            'In Entra ID > User settings, set "Users can register applications" to No so app registration is not a default right of every user.'
            'In Entra ID > External Identities > External collaboration settings, restrict guest invite rights, disable email-based subscription self-signup and join-by-email-verification, and set the default guest role to the most-restricted option.'
            'In Entra ID > Enterprise applications > Consent and permissions, assign a non-legacy user consent policy and disable auto-allowing consent for apps Microsoft flags as risky.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/UserSettings')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0012--default-authorization-policy-settings-cluster-eidscaap01-ap04ap10-ap14'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.AP01'
            'https://maester.dev/docs/tests/EIDSCA.AP10'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'AP01,AP04,AP05,AP06,AP07,AP08,AP09,AP10,AP14'; License = 'MIT' }
}
