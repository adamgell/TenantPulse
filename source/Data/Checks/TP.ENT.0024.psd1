@{
    Id         = 'TP.ENT.0024'
    Title      = 'Conditional Access coverage for workload identities (awareness)'
    Category   = 'Entra.ConditionalAccess'
    Severity   = 'Info'
    Effort     = 'High'
    Impact     = 'Low'
    Data       = @{
        Datasets = @('conditionalAccessPolicies')
        Gates    = @('EntraP1')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseWorkloadIdentityCaCoverage'
    }
    Consulting = @{
        WhatItMeans  = 'Counts enforced Conditional Access policies that scope conditions.clientApplications (workload-identity targeting) rather than only interactive user sign-ins. This is an INFO-severity, non-scored practitioner awareness note - it cannot determine whether the tenant''s specific service principals actually warrant such a policy, only whether one exists at all.'
        WhyItMatters = 'Workload identities (service principals, especially ones holding privileged Graph permissions) are increasingly targeted the same way user accounts are, but most tenants apply Conditional Access to users only. This is a judgment call, not an automatable pass/fail - the finding exists so the gap is not silently absent from the catalog, per the research entry''s own "an idea still needs a paper trail" rule.'
        Remediation  = @(
            'Inventory service principals holding privileged Microsoft Graph application permissions (e.g. Application.ReadWrite.All, RoleManagement.ReadWrite.Directory).'
            'For any that warrant it, create a Conditional Access policy scoping Workload identities > conditions.clientApplications to that service principal, requiring a compliant network location or certificate-based authentication.'
            'Confirm Entra ID Workload ID Premium licensing before relying on this control - Conditional Access for workload identities requires it to actually enforce.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0024--conditional-access-coverage-for-workload-identities-practitioner-note'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity'
            'https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview'
        )
    }
    Origin     = $null
}
