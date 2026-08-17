@{
    Id         = 'TP.INT.0011'
    Title      = 'Default branding profile customized'
    Category   = 'Intune.Governance'
    Severity   = 'Low'
    Effort     = 'Low'
    Impact     = 'Low'
    Data       = @{
        Datasets = @('intuneBrandingProfiles')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseBrandingProfileCustomized'
    }
    Consulting = @{
        WhatItMeans  = 'Intune Company Portal branding (Tenant Administration > Customization) controls the organization name, theme color, logo, and privacy statement URL end users see across the Company Portal apps, Company Portal website, and the Android Intune app - including during enrollment. Every tenant has a default branding profile; up to 25 additional group-targeted profiles can also be created. This check Passes when the default profile has a non-blank organization name or privacy URL, OR when more than one branding profile exists at all (implying some population already has custom branding).'
        WhyItMatters = 'A completely unbranded enrollment/Company Portal experience - Microsoft''s generic blank defaults - is harder for an end user to distinguish from a convincing phishing/spoofed enrollment prompt asking them to sign in and enroll their device. This is a user-trust and anti-phishing hygiene signal, not a technical security control: it never blocks or permits anything on its own. A fleet that is entirely provisioned via Autopilot/kiosk with little or no interactive end-user Company Portal use may reasonably never need this - treat a Fail here as worth a look, not an incident.'
        Remediation  = @(
            'Intune admin center > Tenant administration > Customization > edit the default policy - set at minimum the Organization name (shown in headers) and the Privacy statement URL, so end users see your organization''s own identity rather than a blank/generic prompt.'
            'Consider adding a logo and theme color matching your organization''s actual brand, and populate the Support information fields (contact name, phone, email, helpdesk website) so end users have a legitimate, recognizable path to verify a request is real.'
            'If your fleet is fully Autopilot/kiosk-provisioned with no interactive Company Portal usage, this check''s Fail carries low urgency - document that reasoning rather than customizing branding purely to satisfy the check.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/TenantAdminMenu/~/customization')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0011--default-branding-profile-customized'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/app-management/configuration/configure-company-portal'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1101'; License = 'MIT' }
}
