@{
    Id         = 'TP.INT.0026'
    Title      = 'Windows Autopilot deployment profile exists and is assigned'
    Category   = 'Intune.Enrollment'
    Severity   = 'Medium'
    Effort     = 'Low'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('windowsAutopilotDeploymentProfiles')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseAutopilotProfileAssigned'
    }
    Consulting = @{
        WhatItMeans  = 'A Windows Autopilot deployment profile is what turns a registered Autopilot hardware hash into an actual out-of-box zero-touch provisioning experience - without an ASSIGNED profile (targeting a group), a registered device still falls through to a standard Azure AD Join/manual setup instead. This check Fails when at least one classic Autopilot deployment profile exists but none of them are assigned to a group; zero profiles configured at all is treated as a legitimate skip, since the tenant may not use Autopilot, or may be fully migrated to Microsoft''s newer "Windows Autopilot device preparation" alternative, which this check does not evaluate.'
        WhyItMatters = 'An unassigned deployment profile is a silent gap that only surfaces at the worst possible moment - when someone unboxes a new device expecting zero-touch provisioning and instead gets a generic OOBE screen with no organizational branding, policies, or apps pre-applied. This is a deployment-quality/logistics issue rather than a direct security control, but it directly undermines whatever corporate-enrollment strategy TP.INT.0025 (personal-device enrollment blocking) is meant to support.'
        Remediation  = @(
            'Intune admin center > Devices > Windows > Windows enrollment > Deployment Profiles - open the profile that should be in use and confirm it has an Assignments group set (not "None").'
            'If the tenant has migrated (or is migrating) to Windows Autopilot device preparation, this classic-profile check is not the right signal for that flow - verify device preparation policy assignment separately rather than treating a Fail/NotApplicable here as evidence of a real gap.'
            'Cross-check against registered Autopilot device identities (TP.INT.0027) after fixing the assignment - a newly-assigned profile does not retroactively fix devices that already failed provisioning and needed manual intervention.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/AutopilotProfilesMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0026--windows-autopilot-deployment-profile-exists-and-is-assigned'
        Authorities = @(
            'https://learn.microsoft.com/en-us/autopilot/'
        )
    }
}
