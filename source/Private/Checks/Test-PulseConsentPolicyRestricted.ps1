<#
    Private: TP.ENT.0013 rule function - group/team owner consent restriction and
    risk-based user consent restrictions (EIDSCA.CP01, CP03, CP04 port; see
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md). Wave 1 (T4.2) shipped
    CP01 only; CP03/CP04 are wave 2 (T4.3) - their setting names were UNVERIFIED at wave-1
    time and have now been independently re-fetched and confirmed (see the research entry's
    updated Notes for the source/date).

    Reads the `directorySettings` dataset (Pending in DatasetMap.psd1) through the shared
    Get-PulseDirectorySettingValue helper - see that function's own docstring for why an
    absent setting resolves to its EIDSCA-documented DEFAULT rather than an engine Error: a
    tenant that has never customized a setting is the common case, not a shape regression.
    Per the TEMPLATE-DEFAULT RESOLUTION RULE, an absent row is evaluated against that
    default with explicit provenance ('explicitlyConfigured' = $false in evidence), never
    treated as NA-for-absence.

    Setting names/expected values re-verified 2026-08-16 directly against the EIDSCA config
    source (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json,
    cross-checked against the individual maester.dev/docs/tests/EIDSCA.CP0x pages, which
    confirm the endpoint/expected-behavior but not the raw Graph property name):
        EIDSCA.CP01 EnableGroupSpecificConsent -> want 'False' (default 'True')
        EIDSCA.CP03 BlockUserConsentForRiskyApps -> want 'true'  (default 'true')
        EIDSCA.CP04 EnableAdminConsentRequests   -> want 'true'  (default 'false')

    CASE NOTED, NOT NORMALIZED: CP01 uses capitalized 'True'/'False' string values while
    CP03/CP04 use lowercase 'true'/'false' - this is the literal casing the EIDSCA config
    source records for each setting's own value space (these are independent
    directorySettingTemplate value definitions, not guaranteed to share a casing
    convention), not a typo to "fix" into consistency. Every comparison stays exact-match
    ordinal per this codebase's standing rule - do not case-fold CP03/CP04 to match CP01.

    GATING: all three (CP01 High, CP03 High, CP04 Medium per EIDSCA's own severity tags)
    independently gate Status - each is reported as its own evidence row, matching the
    nine-property fan-in pattern Test-PulseAuthorizationPolicyDefaults.ps1 established for
    TP.ENT.0012, rather than collapsing three distinct EIDSCA controls into one boolean.
#>

function Test-PulseConsentPolicyRestricted {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $cp01 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'EnableGroupSpecificConsent' -DefaultValue 'True'
    $cp03 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'BlockUserConsentForRiskyApps' -DefaultValue 'true'
    $cp04 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'EnableAdminConsentRequests' -DefaultValue 'false'

    $cp01Ok = [string]::Equals($cp01.Value, 'False', [System.StringComparison]::Ordinal)
    $cp03Ok = [string]::Equals($cp03.Value, 'true', [System.StringComparison]::Ordinal)
    $cp04Ok = [string]::Equals($cp04.Value, 'true', [System.StringComparison]::Ordinal)

    $evidence = @(
        @{ Identity = 'EIDSCA.CP01'; Detail = @{ setting = 'EnableGroupSpecificConsent'; value = $cp01.Value; expected = 'False'; severity = 'High'; explicitlyConfigured = $cp01.Found; ok = $cp01Ok } }
        @{ Identity = 'EIDSCA.CP03'; Detail = @{ setting = 'BlockUserConsentForRiskyApps'; value = $cp03.Value; expected = 'true'; severity = 'High'; explicitlyConfigured = $cp03.Found; ok = $cp03Ok } }
        @{ Identity = 'EIDSCA.CP04'; Detail = @{ setting = 'EnableAdminConsentRequests'; value = $cp04.Value; expected = 'true'; severity = 'Medium'; explicitlyConfigured = $cp04.Found; ok = $cp04Ok } }
    )

    $gapReasons = [System.Collections.Generic.List[string]]::new()
    if (-not $cp01Ok) {
        $configuredNote = if ($cp01.Found) { 'is explicitly set to' } else { 'was never customized and defaults to' }
        $gapReasons.Add("Group/team owner consent for third-party apps to read group data $configuredNote '$($cp01.Value)', not the recommended 'False' (EIDSCA.CP01).")
    }
    if (-not $cp03Ok) {
        $configuredNote = if ($cp03.Found) { 'is explicitly set to' } else { 'was never customized and defaults to' }
        $gapReasons.Add("User consent is not blocked for apps Microsoft flags as risky - BlockUserConsentForRiskyApps $configuredNote '$($cp03.Value)', not 'true' (EIDSCA.CP03).")
    }
    if (-not $cp04Ok) {
        $configuredNote = if ($cp04.Found) { 'is explicitly set to' } else { 'was never customized and defaults to' }
        $gapReasons.Add("Users blocked from self-consenting have no admin-consent-request path - EnableAdminConsentRequests $configuredNote '$($cp04.Value)', not 'true' (EIDSCA.CP04).")
    }

    if ($gapReasons.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason ($gapReasons -join ' ') -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "Group/team owner app consent is restricted, risky-app user consent is blocked, and an admin-consent-request path exists (EIDSCA.CP01/CP03/CP04)." -Evidence $evidence
}
