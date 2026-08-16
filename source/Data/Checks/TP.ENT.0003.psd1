@{
    Id         = 'TP.ENT.0003'
    Title      = 'Break-glass accounts exist and are excluded from Conditional Access'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Critical'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('conditionalAccessPolicies', 'directoryRoleAssignments')
        Gates    = @('EntraP1')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseBreakGlassExcluded'
    }
    Consulting = @{
        WhatItMeans  = 'Break-glass (emergency access) accounts are dedicated, cloud-only, permanently-privileged accounts held back specifically for when normal sign-in is broken - a Conditional Access misconfiguration, an MFA outage, a federation failure. This check confirms the operator has declared which accounts those are AND that every enabled Conditional Access policy explicitly excludes them.'
        WhyItMatters = 'A tenant with no verified break-glass account, or one that Conditional Access itself can lock out, has no way back in during the exact incident that motivated Conditional Access in the first place - a bad policy push, a broken MFA provider, an expired certificate. Microsoft''s own emergency-access guidance treats this as a hard prerequisite before deploying any blocking CA policy, not an optional hardening step.'
        Remediation  = @(
            'Create at least 2 cloud-only (*.onmicrosoft.com) accounts with permanent Global Administrator assignment, strong unique credentials (or phishing-resistant hardware keys) stored offline, and no ties to an individual employee.'
            'Exclude both accounts from EVERY enabled Conditional Access policy''s user/group exclusions - not just the MFA policies, all of them.'
            'Declare the accounts in TenantPulse''s -AssessmentProfile (BreakGlassAccounts) so this check (and TP.ENT.0002/0004/0005) can verify their exclusion automatically on every run.'
            'Monitor sign-ins to these accounts and alert on any use - a break-glass sign-in should always be a rare, deliberate, logged event.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#2-conditional-access-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access'
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies'
        )
    }
    Origin     = $null
}
