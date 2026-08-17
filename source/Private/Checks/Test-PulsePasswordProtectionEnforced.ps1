<#
    Private: TP.ENT.0015 rule function - Password Protection mode, on-premises enforcement,
    custom banned-password list, and Smart Lockout thresholds (EIDSCA.PR01-PR03, PR05, PR06
    port; see docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md). Wave 1 (T4.2)
    shipped PR01 only; PR02/PR03/PR05/PR06 are wave 2 (T4.3) - their setting names were
    UNVERIFIED at wave-1 time and have now been independently re-fetched and confirmed (see
    the research entry's updated Notes for the source/date).

    Reads the `directorySettings` dataset (Pending in DatasetMap.psd1) through the shared
    Get-PulseDirectorySettingValue helper - see that function's own docstring for the
    absent-setting-defaults-to-EIDSCA-default convention this reuses. Per the
    TEMPLATE-DEFAULT RESOLUTION RULE, an absent row is evaluated against that default with
    explicit provenance ('explicitlyConfigured' = $false in evidence), never NA-for-absence.

    Setting names/expected values re-verified 2026-08-16 directly against the EIDSCA config
    source (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json),
    cross-checked against the individual maester.dev/docs/tests/EIDSCA.PR0x pages (which
    confirm the endpoint/expected-behavior comparison operator but not the raw Graph
    property name):
        EIDSCA.PR01 BannedPasswordCheckOnPremisesMode  -> want 'Enforce'      (default 'Audit')
        EIDSCA.PR02 EnableBannedPasswordCheckOnPremises -> want 'True'        (default 'False')
        EIDSCA.PR03 EnableBannedPasswordCheck           -> want 'True'        (default 'True')
        EIDSCA.PR05 LockoutDurationInSeconds            -> want >= 60         (default 60)
        EIDSCA.PR06 LockoutThreshold                    -> want <= 10         (default 10)

    PR05/PR06 ARE NUMERIC THRESHOLDS, NOT EXACT-MATCH: unlike every other directorySetting
    control in this codebase (CP01/CP03/CP04/PR01/PR02/PR03/ST08/ST09, all exact-match
    strings), PR05/PR06 are ">="/"<=" comparisons per EIDSCA's own recommended-value
    expression - a tenant that raised lockout duration to 120s or tightened the threshold to
    5 attempts is MORE secure, not a deviation. A value that fails to parse as an integer is
    treated as a gating failure (a malformed/unrecognized shape, not silently ignored).

    AUDIT-VS-ENFORCE TRAP (per the research entry's own Notes, same class as TP.INT.0017's
    App Control check): 'Audit' looks like Password Protection is "configured" but blocks
    nothing - the Reason text below names the actual mode explicitly rather than reporting
    a bare "Password Protection: present/absent".

    GATING: PR01/PR02 (High per EIDSCA tags - mode/on-prem-enforcement are the binary gate)
    and PR03/PR05/PR06 (Medium - tuning parameters once enforcement is on) all independently
    gate Status, each its own evidence row - matching the fan-in pattern
    Test-PulseAuthorizationPolicyDefaults.ps1 established for TP.ENT.0012.
#>

function Test-PulsePasswordProtectionEnforced {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $pr01 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'BannedPasswordCheckOnPremisesMode' -DefaultValue 'Audit'
    $pr02 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'EnableBannedPasswordCheckOnPremises' -DefaultValue 'False'
    $pr03 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'EnableBannedPasswordCheck' -DefaultValue 'True'
    $pr05 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'LockoutDurationInSeconds' -DefaultValue '60'
    $pr06 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'LockoutThreshold' -DefaultValue '10'

    $pr01Ok = [string]::Equals($pr01.Value, 'Enforce', [System.StringComparison]::Ordinal)
    $pr02Ok = [string]::Equals($pr02.Value, 'True', [System.StringComparison]::Ordinal)
    $pr03Ok = [string]::Equals($pr03.Value, 'True', [System.StringComparison]::Ordinal)

    $pr05Parsed = 0
    $pr05Parseable = [int]::TryParse($pr05.Value, [ref] $pr05Parsed)
    $pr05Ok = $pr05Parseable -and $pr05Parsed -ge 60

    $pr06Parsed = 0
    $pr06Parseable = [int]::TryParse($pr06.Value, [ref] $pr06Parsed)
    $pr06Ok = $pr06Parseable -and $pr06Parsed -le 10

    $evidence = @(
        @{ Identity = 'EIDSCA.PR01'; Detail = @{ setting = 'BannedPasswordCheckOnPremisesMode'; value = $pr01.Value; expected = 'Enforce'; severity = 'High'; explicitlyConfigured = $pr01.Found; ok = $pr01Ok } }
        @{ Identity = 'EIDSCA.PR02'; Detail = @{ setting = 'EnableBannedPasswordCheckOnPremises'; value = $pr02.Value; expected = 'True'; severity = 'High'; explicitlyConfigured = $pr02.Found; ok = $pr02Ok } }
        @{ Identity = 'EIDSCA.PR03'; Detail = @{ setting = 'EnableBannedPasswordCheck'; value = $pr03.Value; expected = 'True'; severity = 'Medium'; explicitlyConfigured = $pr03.Found; ok = $pr03Ok } }
        @{ Identity = 'EIDSCA.PR05'; Detail = @{ setting = 'LockoutDurationInSeconds'; value = $pr05.Value; expected = '>=60'; severity = 'Medium'; explicitlyConfigured = $pr05.Found; ok = $pr05Ok } }
        @{ Identity = 'EIDSCA.PR06'; Detail = @{ setting = 'LockoutThreshold'; value = $pr06.Value; expected = '<=10'; severity = 'Medium'; explicitlyConfigured = $pr06.Found; ok = $pr06Ok } }
    )

    $gapReasons = [System.Collections.Generic.List[string]]::new()
    if (-not $pr01Ok) {
        $gapReasons.Add("Password Protection is running in mode '$($pr01.Value)', not 'Enforce' - banned/weak passwords are logged but not blocked (EIDSCA.PR01).")
    }
    if (-not $pr02Ok) {
        $configuredNote = if ($pr02.Found) { 'is explicitly set to' } else { 'was never customized and defaults to' }
        $gapReasons.Add("The on-premises AD password-protection proxy/agent $configuredNote '$($pr02.Value)', not 'True' (EIDSCA.PR02).")
    }
    if (-not $pr03Ok) {
        $configuredNote = if ($pr03.Found) { 'is explicitly set to' } else { 'was never customized and defaults to' }
        $gapReasons.Add("The custom banned-password list $configuredNote '$($pr03.Value)', not enforced ('True') (EIDSCA.PR03).")
    }
    if (-not $pr05Ok) {
        $shownValue = if ($pr05Parseable) { $pr05Parsed } else { "unparseable value '$($pr05.Value)'" }
        $gapReasons.Add("Smart Lockout duration is $shownValue seconds, below the recommended minimum of 60 (EIDSCA.PR05).")
    }
    if (-not $pr06Ok) {
        $shownValue = if ($pr06Parseable) { $pr06Parsed } else { "unparseable value '$($pr06.Value)'" }
        $gapReasons.Add("Smart Lockout threshold is $shownValue failed attempts, above the recommended maximum of 10 (EIDSCA.PR06).")
    }

    if ($gapReasons.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason ($gapReasons -join ' ') -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "Password Protection is set to 'Enforce' mode with on-premises enforcement and a custom banned-password list active, and Smart Lockout thresholds are within the recommended range (EIDSCA.PR01/PR02/PR03/PR05/PR06)." -Evidence $evidence
}
