@{
    Id         = 'TP.INT.0013'
    Title      = 'Intune RBAC groups protected via RMAU or role-assignable groups'
    Category   = 'Intune.Governance'
    Severity   = 'High'
    Effort     = 'High'
    Impact     = 'High'
    Data       = @{
        Datasets = @('intuneRbacGroupProtection')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseRbacGroupsProtected'
    }
    Consulting = @{
        WhatItMeans  = 'Every Intune RBAC role assignment can target one or more Entra groups as its member scope - anyone who becomes a member of that group inherits the Intune-privileged role. A group is PROTECTED from unauthorized membership changes only if it is either scoped to a Restricted Management Administrative Unit (isManagementRestricted), or was created as a role-assignable group (isAssignableToRole - an IMMUTABLE property that can only be set at group creation, requires Entra ID P1, and forces Assigned rather than dynamic membership). A group backing an Intune RBAC role that has NEITHER property is unprotected: ordinary group-membership permissions (including a dynamic-membership rule, or the Group.ReadWrite.All Graph permission) are enough to add a member and grant them that Intune role, completely outside the RBAC governance the role assignment was meant to enforce.'
        WhyItMatters = 'This is a privilege-escalation path that does not require compromising an admin account at all - it requires only ordinary group-management rights that many more accounts hold than actually hold the Intune role itself. Microsoft''s own guidance uses exactly this scenario (an Exchange administrator who can modify dynamic membership groups adding themselves to a group backing the User Administrator role) to explain why role-assignable groups exist. The same self-nomination pattern applies identically to any unprotected group backing an Intune RBAC role assignment.'
        Remediation  = @(
            'For each offending group in this finding''s evidence, either move it into a Restricted Management Administrative Unit, or replace it with a NEW role-assignable group (isAssignableToRole is immutable and cannot be set on an existing group) with Assigned (never dynamic) membership, then re-point the Intune role assignment at the new group and retire the old one.'
            'Role-assignable groups require Entra ID P1 and at least the Privileged Role Administrator role to create - confirm licensing before planning remediation, and note the 500-role-assignable-group tenant-wide cap.'
            'Once migrated, restrict who can manage the protected group''s membership itself (owners, or Privileged Role Administrator by default) - protecting the group only matters if membership changes are themselves gated by the same governance the Intune role assignment was meant to enforce.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/RolesMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0013--intune-rbac-groups-protected-via-rmau-or-role-assignable-groups'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1103'; License = 'MIT' }
}
