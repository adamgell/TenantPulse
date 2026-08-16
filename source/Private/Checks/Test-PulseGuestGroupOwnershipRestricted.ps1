<#
    Private: TP.ENT.0016 rule function - guest group ownership restriction (EIDSCA.ST08
    port; see docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md). Only ST08
    ships in wave 1 - ST09's exact setting name was not independently re-fetched in the
    research entry (documented as "high confidence" but not verified the same way ST08
    was) and is deliberately NOT implemented here (wave 2, T4.3).

    Reads the `directorySettings` dataset (Pending in DatasetMap.psd1) through the shared
    Get-PulseDirectorySettingValue helper.

    Setting name/expected value verified directly against the EIDSCA config source at
    implementation time (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json):
        EIDSCA.ST08 AllowGuestsToBeGroupOwner -> want 'false' (default 'false')

    NOTABLE ASYMMETRY vs. this cluster's CP01/PR01 siblings: ST08's documented default
    ALREADY equals its recommended value - a tenant that has never customized this setting
    at all passes by construction. Get-PulseDirectorySettingValue's own -DefaultValue
    parameter is what makes that distinction a per-call fact instead of an assumption baked
    into the shared helper.
#>

function Test-PulseGuestGroupOwnershipRestricted {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $result = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'AllowGuestsToBeGroupOwner' -DefaultValue 'false'

    $evidence = @(
        @{ Identity = 'EIDSCA.ST08'; Detail = @{ setting = 'AllowGuestsToBeGroupOwner'; value = $result.Value; expected = 'false'; severity = 'Medium'; explicitlyConfigured = $result.Found } }
    )

    if (-not [string]::Equals($result.Value, 'false', [System.StringComparison]::Ordinal)) {
        return New-PulseFinding -Status Fail -Reason "Guests can become owners of Microsoft 365 groups (AllowGuestsToBeGroupOwner = '$($result.Value)', EIDSCA.ST08)." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "Guests cannot become owners of Microsoft 365 groups (AllowGuestsToBeGroupOwner = 'false', EIDSCA.ST08)." -Evidence $evidence
}
