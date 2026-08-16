<#
    RESEARCH NOTE (post-review, adjudicated, L3): Severity raised Medium -> High. The only
    condition this check actually Fails on is "no Conditional Access AND Security Defaults
    disabled" - that is not a partial-credit misconfiguration, it is zero baseline identity
    protection: no MFA enforcement anywhere in the tenant, no block on legacy
    authentication. Impact was already scored High; Medium severity understated how bad the
    Fail case genuinely is relative to the rest of the Phase 1 catalog. The CA-in-use case
    is no longer scored as this check's business at all (see the rule function's own
    NotApplicable rework), so severity now describes exactly one thing: the zero-baseline-
    protection Fail.
#>
@{
    Id         = 'TP.ENT.0001'
    Title      = 'Security Defaults state is appropriate'
    Category   = 'Entra.Identity'
    Severity   = 'High'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('securityDefaultsPolicy', 'conditionalAccessPolicies')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseSecurityDefaultsAppropriate'
    }
    Consulting = @{
        WhatItMeans  = 'Security Defaults is Microsoft''s free, all-or-nothing baseline identity policy: it forces MFA registration and enforcement for everyone, blocks legacy authentication protocols, and requires admins to re-authenticate for privileged actions. This check confirms the tenant is not left with NEITHER Security Defaults NOR Conditional Access protecting it - the one configuration state that leaves sign-in fundamentally unprotected.'
        WhyItMatters = 'A tenant with Security Defaults disabled and no Conditional Access policy enabled has no baseline enforcement of MFA and no block on legacy authentication protocols - the two controls almost every credential-compromise incident response finds missing. This is the highest-value, lowest-effort finding a health check can surface: it costs nothing to fix and closes a wide-open door.'
        Remediation  = @(
            'If the tenant does not have Entra ID P1 (no Conditional Access licensing), enable Security Defaults immediately: Entra admin center > Identity > Overview > Properties > Manage Security defaults > Enable Security defaults.'
            'If the tenant DOES have Entra ID P1, build Conditional Access policies covering MFA-for-all-users, MFA-for-admins, and block-legacy-authentication (see TP.ENT.0004/TP.ENT.0005), then turn Security Defaults off once those policies are enabled and validated - running both simultaneously is unsupported and Microsoft recommends against it once CA takes over the same ground.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PropertiesBladeAADSecurityDefaults')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#2-conditional-access-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults'
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common'
        )
    }
    Origin     = $null
}
