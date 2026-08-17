@{
    Id         = 'TP.ENT.0021'
    Title      = 'Fewer than 10 total privileged role assignments'
    Category   = 'Entra.PrivilegedRoles'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('directoryRoleAssignments', 'directoryRoleDefinitions')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulsePrivilegedRoleAssignmentCount'
    }
    Consulting = @{
        WhatItMeans  = 'Counts active assignments across every Entra role flagged isPrivileged=true - not just Global Administrator - and confirms the total is below 10, the threshold Microsoft''s own role-hygiene guidance (and the Entra admin center itself) warns above. LIMITATION: this counts direct roleAssignments rows only - a privileged role assigned to a role-assignable GROUP counts as one assignment here, not one per group member, since no group-membership-expansion dataset is wired up yet. A tenant that assigns privileged roles to groups may have a larger true blast radius than this count shows.'
        WhyItMatters = 'Broad privileged-role sprawl - not just Global Administrator - is the realistic picture of blast radius in most tenants. Many high-impact roles (Application Administrator, Privileged Role Administrator, Exchange Administrator) sit outside Global Administrator but carry serious lateral-movement/escalation potential; counting only Global Admin (TP.ENT.0002/TP.ENT.0020) misses this broader exposure.'
        Remediation  = @(
            'Review every assignment surfaced in evidence; for each, confirm it is still needed and cannot be narrowed to a less-privileged built-in or custom role.'
            'Move standing/permanent privileged-role assignments to PIM-eligible where the tenant is licensed for Entra ID P2 (see TP.ENT.0022 for PIM posture specifically).'
            'If a privileged role is assigned to a group, review that group''s membership directly in the Entra admin center - this check''s count does not expand it.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AllRolesBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0021--fewer-than-10-total-privileged-role-assignments'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
        )
    }
    Origin     = $null
}
