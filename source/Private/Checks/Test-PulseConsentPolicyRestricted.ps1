<#
    Private: TP.ENT.0013 rule function - group/team owner consent restriction (EIDSCA.CP01
    port; see docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md). Only CP01
    ships in wave 1 - CP03/CP04's exact setting names are flagged UNVERIFIED in the research
    entry and are deliberately NOT implemented here (wave 2, T4.3).

    Reads the `directorySettings` dataset (Pending in DatasetMap.psd1) through the shared
    Get-PulseDirectorySettingValue helper - see that function's own docstring for why an
    absent setting resolves to its EIDSCA-documented DEFAULT ('True', the permissive,
    non-recommended value) rather than an engine Error: a tenant that has never customized
    this setting is the common case, not a shape regression.

    Setting name/expected value verified directly against the EIDSCA config source at
    implementation time (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json):
        EIDSCA.CP01 EnableGroupSpecificConsent -> want 'False' (default 'True')
#>

function Test-PulseConsentPolicyRestricted {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $result = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'EnableGroupSpecificConsent' -DefaultValue 'True'

    $evidence = @(
        @{ Identity = 'EIDSCA.CP01'; Detail = @{ setting = 'EnableGroupSpecificConsent'; value = $result.Value; expected = 'False'; severity = 'High'; explicitlyConfigured = $result.Found } }
    )

    if (-not [string]::Equals($result.Value, 'False', [System.StringComparison]::Ordinal)) {
        $configuredNote = if ($result.Found) { 'is explicitly set to' } else { 'was never customized and defaults to' }
        return New-PulseFinding -Status Fail -Reason "Group/team owner consent for third-party apps to read group data $configuredNote '$($result.Value)', not the recommended 'False' (EIDSCA.CP01)." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "Group/team owner consent for third-party apps to read group data is restricted (EnableGroupSpecificConsent = 'False', EIDSCA.CP01)." -Evidence $evidence
}
