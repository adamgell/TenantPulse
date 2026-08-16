@{
    Id         = 'TP.ENT.0016'
    Title      = 'Guest group ownership is restricted and guest group-content access is intact'
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
        WhatItMeans  = 'Confirms two Group.Unified directorySettings: guests cannot become owners of Microsoft 365 groups (AllowGuestsToBeGroupOwner = false, EIDSCA.ST08); and, separately, guest access to group content has not been inadvertently disabled (AllowGuestsToAccessGroups = True, EIDSCA.ST09 - this is a functional-continuity check, not a restriction: EIDSCA''s own recommended value matches the platform default, and disabling this tenant-wide toggle breaks guest collaboration in every group). Narrower in scope than it sounds: this governs Microsoft 365 group/team ownership and content access specifically, not general external-collaboration invite policy (TP.ENT.0012''s AP04) or tenant-wide B2B cross-tenant defaults (TP.ENT.0023). This check currently has NO released GraphKit descriptor to collect it - see this check''s own References.Research for the G-batch request.'
        WhyItMatters = 'A group owner controls membership, content, and (per TP.ENT.0013''s CP01) potentially third-party app consent for everyone in that group. An external guest holding that role has effectively been handed admin rights over a piece of the tenant''s data and membership without ever passing through the tenant''s own admin-role or PIM controls - a quiet privilege-escalation path that is easy to miss because it never shows up in a Global Administrator or role-assignment review. ST09 is the opposite kind of finding: it exists to catch a well-intentioned but overly broad guest-restriction effort that also silently switched off the master toggle for guest group-content access, breaking legitimate collaboration rather than closing a real gap.'
        Remediation  = @(
            'In Entra ID > Groups > General settings (or the equivalent Microsoft 365 admin center guest-access settings), set "Guests can be assigned as group owner" to No.'
            'Audit existing Microsoft 365 groups for any guest account currently in an owner role and either replace it with a member-tenant owner or document the specific business exception.'
            'If AllowGuestsToAccessGroups shows as disabled, confirm that was a deliberate, documented decision - an untouched tenant already has this set to True, so an explicit False is very likely an accidental change that will surface as broken guest collaboration complaints.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0016--guest-group-ownership-and-content-access-restrictions-eidscast08st09'
        Authorities = @(
            'https://maester.dev/docs/tests/EIDSCA.ST08'
            'https://maester.dev/docs/tests/EIDSCA.ST09'
        )
    }
    Origin     = @{ Project = 'EIDSCA'; Id = 'ST08,ST09'; License = 'MIT' }
}
