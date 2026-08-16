@{
    Id         = 'TP.ENT.0016'
    Title      = 'Guests cannot become owners of Microsoft 365 groups'
    Category   = 'Entra.GuestAccess'
    Severity   = 'Medium'
    Effort     = 'Low'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('directorySettings')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseGuestGroupOwnershipRestricted'
    }
    Consulting = @{
        WhatItMeans  = 'Confirms the Group.Unified directorySetting''s AllowGuestsToBeGroupOwner value is false (EIDSCA.ST08) - narrower in scope than it sounds: this governs Microsoft 365 group/team ownership specifically, not general external-collaboration invite policy (TP.ENT.0012''s AP04) or tenant-wide B2B cross-tenant defaults (TP.ENT.0023). This check currently has NO released GraphKit descriptor to collect it - see this check''s own References.Research for the G-batch request.'
        WhyItMatters = 'A group owner controls membership, content, and (per TP.ENT.0013''s CP01) potentially third-party app consent for everyone in that group. An external guest holding that role has effectively been handed admin rights over a piece of the tenant''s data and membership without ever passing through the tenant''s own admin-role or PIM controls - a quiet privilege-escalation path that is easy to miss because it never shows up in a Global Administrator or role-assignment review.'
        Remediation  = @(
            'In Entra ID > Groups > General settings (or the equivalent Microsoft 365 admin center guest-access settings), set "Guests can be assigned as group owner" to No.'
            'Audit existing Microsoft 365 groups for any guest account currently in an owner role and either replace it with a member-tenant owner or document the specific business exception.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0016--guest-group-ownership-and-content-access-restrictions-eidscast08st09'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.ST08'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'ST08'; License = 'MIT' }
}
