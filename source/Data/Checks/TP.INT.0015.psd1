@{
    Id         = 'TP.INT.0015'
    Title      = 'LAPS configuration policy meets minimum security bar'
    Category   = 'Intune.EndpointSecurity'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('endpointSecurityLapsPolicies')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseLapsConfigurationMeetsBar'
    }
    Consulting = @{
        WhatItMeans  = 'Windows LAPS (Local Administrator Password Solution), configured through Intune''s dedicated Endpoint Security > Account protection blade, randomizes and backs up each device''s local administrator password to Microsoft Entra ID rather than leaving it static or shared across the fleet. This check asserts a minimum security bar on a SINGLE policy: backs up to Entra ID, 4-class-or-higher password complexity, at least 14-character passwords, and a recognized post-authentication action (password rotates after use/unlock/expiry) - all four on the same policy, never mixed across separate policies.'
        WhyItMatters = 'A static or shared local administrator password across a device fleet is one of the most common lateral-movement enablers - one compromised device''s local admin credential works on every other device sharing it, or a credential that never rotates stays valid indefinitely after any single exposure. Backing up to Entra ID (rather than nowhere, or an on-prem-only mechanism unavailable to Entra-joined devices) is what makes the rotated password actually recoverable through Intune''s own RBAC-gated recovery workflow.'
        Remediation  = @(
            'Intune admin center > Endpoint security > Account protection > Create Policy (Windows 10 and later, Local admin password solution (Windows LAPS) profile) - set Backup directory to Microsoft Entra ID (Azure AD only), password complexity to 4-class or higher, password length to 14 or more characters, and a post-authentication action other than "Not configured" (e.g. rotate on unlock).'
            'If an existing LAPS policy is Failing this check, check this check''s own evidence for which of the four criteria falls short on that specific policy - a policy correct on three of four still Fails; there is no partial credit and no OR-ing across multiple policies.'
            'Confirm devices are Microsoft Entra joined or Microsoft Entra hybrid joined - Windows LAPS with Microsoft Entra ID is not supported for Microsoft Entra REGISTERED devices, which will never satisfy this check regardless of policy configuration.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/EndpointSecurityAccountProtection')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0015--laps-configuration-policy-meets-minimum-security-bar'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords'
            'https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1177'; License = 'MIT' }
}
