@{
    Id         = 'TP.ENT.0022'
    Title      = 'Zero permanent-active assignments for privileged roles (PIM posture)'
    Category   = 'Entra.PrivilegedRoles'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('roleAssignmentScheduleInstances', 'roleEligibilityScheduleInstances', 'directoryRoleDefinitions')
        Gates    = @('EntraP2')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulsePimPermanentAssignments'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms every privileged-role assignment is either PIM-eligible-with-activation or, if active, time-bound - not a permanent, no-expiration standing assignment. Requires Entra ID P2 (Privileged Identity Management); on a tenant without P2 licensing this renders as NotApplicable with an explicit licensing reason, never a silent pass. A permanent-active assignment held by a declared break-glass or service account (assessment profile BreakGlassAccounts/ServiceAccounts) is treated as a legitimate exception, not a gap - it still appears in evidence, marked exempt.'
        WhyItMatters = 'ScuBA MS.AAD.7.4v1 rates this SHALL NOT. Standing privileged access is the single most common finding in real-world Entra assessments and the specific gap PIM exists to close - licensing and configuring PIM without actually requiring time-bound activation for every non-exempt assignment leaves the tenant with the same blast radius as no PIM at all.'
        Remediation  = @(
            'For each non-exempt permanent-active assignment in evidence, convert it to PIM-eligible so activation requires a deliberate, time-bound request.'
            'If an assignment genuinely needs to stay permanent (break-glass), declare that account in the assessment profile''s BreakGlassAccounts so it is recognized as an intentional exception.'
            'For a legitimate non-interactive service account that cannot use PIM''s activation flow, declare it in ServiceAccounts rather than leaving it as an unexplained permanent assignment.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PrivilegedIdentityManagementMenuBlade/~/AzureADRoles')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0022--zero-permanent-active-assignments-for-privileged-roles-pim-posture'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-deployment-plan'
        )
    }
    Origin     = $null
}
