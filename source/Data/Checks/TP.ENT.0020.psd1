@{
    Id         = 'TP.ENT.0020'
    Title      = 'Global Administrator count is within ScuBA''s 2-8 SHALL range'
    Category   = 'Entra.PrivilegedRoles'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('directoryRoleAssignments', 'directoryRoleDefinitions')
        Gates    = @()
    }
    Rule       = @{
        Type       = 'Expression'
        Expression = @'
$wellKnownGlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
$gaRoleDefinitionIds = @($Datasets.directoryRoleDefinitions | Where-Object { $_.displayName -eq 'Global Administrator' -or $_.templateId -eq $wellKnownGlobalAdminTemplateId } | ForEach-Object { $_.id })
$gaRoleDefinitionIds = @($gaRoleDefinitionIds) + @($wellKnownGlobalAdminTemplateId)
$gaAssignments = @($Datasets.directoryRoleAssignments | Where-Object { $gaRoleDefinitionIds -contains $_.roleDefinitionId })
$uniqueGlobalAdmins = @($gaAssignments | ForEach-Object { $_.principalId } | Sort-Object -Unique)
$uniqueGlobalAdmins.Count -ge 2 -and $uniqueGlobalAdmins.Count -le 8
'@
    }
    Consulting = @{
        WhatItMeans  = 'ScuBA MS.AAD.7.1v1 (SHALL) requires between 2 and 8 (inclusive) users provisioned with the Global Administrator role - enough for break-glass/succession resilience, few enough to bound blast radius. This is a DIFFERENT bar from the already-seeded TP.ENT.0002 (Microsoft''s own <5 guidance, which has no explicit floor): a tenant with exactly 1 Global Administrator passes TP.ENT.0002 but fails this check, since single-admin risk (no succession path if that one account is lost or compromised) is exactly the failure mode ScuBA''s floor targets and Microsoft''s own guidance does not capture at all. Same Global Administrator resolution (role-template-id join, not display name) as TP.ENT.0002.'
        WhyItMatters = 'Too few Global Administrators means no resilient path if the sole admin''s account is lost, locked out, or compromised - a single point of both compromise AND recovery failure. Too many is the more commonly discussed risk (TP.ENT.0002''s own rationale) but the floor half of this range is arguably the more urgent gap for a small tenant to overlook.'
        Remediation  = @(
            'If below 2: designate at least one additional Global Administrator (ideally a dedicated break-glass account per TP.ENT.0003) so a single lost/compromised credential cannot leave the tenant unrecoverable.'
            'If above 8: work through TP.ENT.0002''s own remediation steps - move standing Global Administrator assignments to PIM-eligible, keep only genuine break-glass accounts as permanent.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AllRolesBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0020--global-administrator-count-within-scubas-28-shall-range'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
        )
    }
    Origin     = $null
}
