@{
    Id         = 'TP.ENT.0002'
    Title      = 'Fewer than 5 Global Administrators'
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
$uniqueGlobalAdmins.Count -lt 5
'@
    }
    Consulting = @{
        WhatItMeans  = 'The Microsoft Entra admin center itself flags a tenant when 5 or more principals hold the Global Administrator role - this check mirrors that same threshold. Global Administrator resolution joins active directoryRoleAssignments against directoryRoleDefinitions by display name/template id (falling back to the well-known Global Administrator template id when a role definition cannot be resolved), so a custom or renamed role never masks the count.'
        WhyItMatters = 'Every Global Administrator is a single point of total tenant compromise - if any one of their credentials is phished, the attacker owns every workload, every mailbox, every device policy. Microsoft''s own guidance on Entra role best practices names 5 as the threshold worth alerting on; each admin beyond the minimum needed is pure, uncompensated blast-radius growth.'
        Remediation  = @(
            'Review every Global Administrator assignment in Entra ID > Roles and administrators > Global Administrator; for each one, confirm it is still needed and cannot be replaced by a narrower built-in role (Application Administrator, User Administrator, etc.).'
            'Move any Global Administrator who does not need STANDING access to Privileged Identity Management (PIM) eligible assignment instead of a permanent/active one - eligible-but-not-activated assignments do not count toward this check''s directoryRoleAssignments-based total.'
            'Keep exactly the break-glass accounts (see TP.ENT.0003) as the only PERMANENT Global Administrator assignments; everyone else should be PIM-eligible.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AllRolesBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#5-zero-trust--privileged-access--role-hygiene'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
        )
    }
    Origin     = $null
}
