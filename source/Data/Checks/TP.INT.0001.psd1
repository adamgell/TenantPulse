@{
    Id         = 'TP.INT.0001'
    Title      = 'MDM authority is set to Intune'
    Category   = 'Intune.Enrollment'
    Severity   = 'Critical'
    Effort     = 'Low'
    Impact     = 'High'
    Data       = @{
        Datasets = @('organization', 'organizationMdmAuthority')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type       = 'Expression'
        Expression = @'
$authorityRows = @($Datasets.organizationMdmAuthority)
if ($authorityRows.Count -eq 0) {
    throw 'organizationMdmAuthority dataset returned no rows - the service returned nothing to evaluate.'
}
$authority = $authorityRows[0].mobileDeviceManagementAuthority
if ($null -eq $authority -or $authority -eq '') {
    throw 'organizationMdmAuthority returned no mobileDeviceManagementAuthority value - check the select survived collection; an absent value must never read as pass or fail.'
}
$authority -eq 'intune'
'@
    }
    Consulting = @{
        WhatItMeans  = 'mobileDeviceManagementAuthority is a one-time, tenant-wide switch that determines who is the source of truth for mobile device management policy - Intune, a third-party MDM, or none. This check confirms it is set to Intune, which every other Intune posture check in this tool (compliance, configuration, Autopilot) silently assumes. This property does NOT appear on the plain /organization list response - it only surfaces on the dedicated per-organization read, which is why this check declares two datasets (organization, to resolve the org id; organizationMdmAuthority, the actual read).'
        WhyItMatters = 'If MDM authority is unset or pointed elsewhere, every deviceCompliancePolicies/deviceConfigurations/managedDevices object this tool (and the Intune admin center itself) reads is either empty or not authoritative - policies can be created and assigned in the console with no error, and simply never take effect on any device. This is the single most common "why isn''t anything working" root cause in a fresh or migrated Intune tenant.'
        Remediation  = @(
            'If mobileDeviceManagementAuthority is unset (this is a NEW tenant that has never had a device enroll), it self-resolves to Intune automatically the first time an admin opens the Intune admin center or a device attempts enrollment - open https://intune.microsoft.com once and re-run this check.'
            'If it is set to a third-party MDM or a legacy Configuration Manager co-management state, MDM authority cannot be changed without first removing all enrolled devices from the current authority - this is a disruptive, planned migration, not a toggle; engage Microsoft support guidance before proceeding.'
        )
        PortalLinks  = @('https://intune.microsoft.com/')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#6-intune-operational-guidance'
        Authorities = @(
            'https://learn.microsoft.com/en-us/graph/api/organization-getmdmauthority'
            'https://learn.microsoft.com/en-us/mem/intune/fundamentals/deployment-guide-enrollment'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1105'; License = 'MIT' }
}
