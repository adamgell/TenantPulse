@{
    Id         = 'TP.ENT.0023'
    Title      = 'Cross-tenant access default settings restrict inbound/outbound B2B collaboration'
    Category   = 'Entra.Identity'
    Severity   = 'Medium'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('crossTenantAccessPolicyDefault')
        Gates    = @()
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseCrossTenantAccessDefaultRestricted'
    }
    Consulting = @{
        WhatItMeans  = 'Checks whether the tenant''s DEFAULT cross-tenant access policy (v1.0/policies/crossTenantAccessPolicy/default) still carries Microsoft''s documented wide-open combination in either direction: usersAndGroups allows AllUsers and applications allows AllApplications. A specific user/group or application allowlist, or a block covering all users or all applications in either target configuration, restricts the default even when its sibling configuration is malformed because that valid side is independently decisive. A narrow denylist blocks only the named targets and leaves every other target allowed, so it is reported separately rather than promoted to Pass. An absent or malformed target set is unclassifiable when no sibling configuration already proves restriction. Distinct from the per-group guest controls in TP.ENT.0016 and the invite-approval setting in TP.ENT.0012 (AP04) - this is the tenant''s outer B2B perimeter, not group membership or invite workflow. NO DEDICATED SCUBA CONTROL ANCHORS THIS OBJECT (re-fetched directly against the live ScubaGear aad.md baseline - Section 8 has exactly three numbered controls, 8.1-8.3, none of which test this object); MS.AAD.8.1v1 is cited as directional guest-access authority only.'
        WhyItMatters = 'Default cross-tenant access is permissive by design out of the box, to support ad hoc collaboration - this is a "verify it was a deliberate choice" finding, not a clear violation. An organization with no legitimate broad-collaboration need that has never reviewed this setting may be exposing directory data to any external Entra tenant that attempts B2B collaboration.'
        Remediation  = @(
            'Review Entra ID > External Identities > Cross-tenant access settings > Default settings.'
            'If broad ad hoc collaboration is not a business need, narrow the default inbound and/or outbound user, group, and application target sets instead of leaving both target configurations at allow-all.'
            'Partner-specific overrides live at policies/crossTenantAccessPolicy/partners. Use those for organization-specific exceptions; this check evaluates only the default that applies where no partner override exists.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CrossTenantAccessSettingsMenuBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0023--cross-tenant-access-default-settings-restrict-inboundoutbound-b2b-collaboration'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview'
            'https://learn.microsoft.com/en-us/graph/api/resources/crosstenantaccesspolicy-overview?view=graph-rest-1.0'
        )
    }
    Origin     = $null
}
