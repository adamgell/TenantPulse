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
        WhatItMeans  = 'Checks whether the tenant''s DEFAULT cross-tenant access policy (v1.0/policies/crossTenantAccessPolicy/default) still allows unrestricted inbound and/or outbound B2B collaboration with every external Microsoft Entra tenant - Microsoft''s out-of-the-box default, not necessarily a deliberate choice. Distinct from the per-group guest controls in TP.ENT.0016 and the invite-approval setting in TP.ENT.0012 (AP04) - this is the tenant''s outer B2B perimeter, not group membership or invite workflow. NO DEDICATED SCUBA CONTROL ANCHORS THIS OBJECT (re-fetched directly against the live ScubaGear aad.md baseline - Section 8 has exactly three numbered controls, 8.1-8.3, none of which test this object); MS.AAD.8.1v1 is cited as directional guest-access authority only.'
        WhyItMatters = 'Default cross-tenant access is permissive by design out of the box, to support ad hoc collaboration - this is a "verify it was a deliberate choice" finding, not a clear violation. An organization with no legitimate broad-collaboration need that has never reviewed this setting may be exposing directory data to any external Entra tenant that attempts B2B collaboration.'
        Remediation  = @(
            'Review Entra ID > External Identities > Cross-tenant access settings > Default settings.'
            'If broad ad hoc collaboration is not a business need, restrict inbound and/or outbound B2B collaboration to specific target organizations rather than leaving the default allow-all in place.'
            'Partner-specific overrides live at policies/crossTenantAccessPolicy/partners - this check only evaluates the default, not per-partner exceptions; review those separately.'
        )
        PortalLinks  = @('https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CrossTenantAccessSettingsMenuBlade')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0023--cross-tenant-access-default-settings-restrict-inboundoutbound-b2b-collaboration'
        Authorities = @(
            'https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview'
        )
    }
    Origin     = $null
}
