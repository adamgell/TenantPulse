<#
    Private: TP.ENT.0015 rule function - Password Protection mode (EIDSCA.PR01 port; see
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md). Only PR01 ships in wave
    1 - PR02/PR03/PR05/PR06's exact setting names are flagged "UNVERIFIED beyond PR01" in
    the research entry and are deliberately NOT implemented here (wave 2, T4.3).

    Reads the `directorySettings` dataset (Pending in DatasetMap.psd1) through the shared
    Get-PulseDirectorySettingValue helper - see that function's own docstring for the
    absent-setting-defaults-to-EIDSCA-default convention this reuses.

    Setting name/expected value verified directly against the EIDSCA config source at
    implementation time (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json):
        EIDSCA.PR01 BannedPasswordCheckOnPremisesMode -> want 'Enforce' (default 'Audit')

    AUDIT-VS-ENFORCE TRAP (per the research entry's own Notes, same class as TP.INT.0017's
    App Control check): 'Audit' looks like Password Protection is "configured" but blocks
    nothing - the Reason text below names the actual mode explicitly rather than reporting
    a bare "Password Protection: present/absent".
#>

function Test-PulsePasswordProtectionEnforced {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $result = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'BannedPasswordCheckOnPremisesMode' -DefaultValue 'Audit'

    $evidence = @(
        @{ Identity = 'EIDSCA.PR01'; Detail = @{ setting = 'BannedPasswordCheckOnPremisesMode'; value = $result.Value; expected = 'Enforce'; severity = 'High'; explicitlyConfigured = $result.Found } }
    )

    if (-not [string]::Equals($result.Value, 'Enforce', [System.StringComparison]::Ordinal)) {
        return New-PulseFinding -Status Fail -Reason "Password Protection is running in mode '$($result.Value)', not 'Enforce' - banned/weak passwords are logged but not blocked (EIDSCA.PR01)." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "Password Protection is set to 'Enforce' mode (EIDSCA.PR01)." -Evidence $evidence
}
