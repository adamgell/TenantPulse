<#
    Private: TP.ENT.0016 rule function - guest group ownership restriction and guest
    access to M365 group content (EIDSCA.ST08-ST09 port; see
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md). Wave 1 (T4.2) shipped
    ST08 only; ST09 is wave 2 (T4.3) - its setting name was not independently re-fetched at
    wave-1 time and has now been confirmed (see the research entry's updated Notes for the
    source/date).

    Reads the `directorySettings` dataset (Pending in DatasetMap.psd1) through the shared
    Get-PulseDirectorySettingValue helper. Per the TEMPLATE-DEFAULT RESOLUTION RULE, an
    absent row is evaluated against its EIDSCA default with explicit provenance
    ('explicitlyConfigured' = $false in evidence), never NA-for-absence.

    Setting names/expected values re-verified 2026-08-16 directly against the EIDSCA config
    source (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json),
    cross-checked against https://maester.dev/docs/tests/EIDSCA.ST09:
        EIDSCA.ST08 AllowGuestsToBeGroupOwner    -> want 'false' (default 'false')
        EIDSCA.ST09 AllowGuestsToAccessGroups    -> want 'True'  (default 'True')

    ST09'S POLARITY CORRECTS THE ORIGINAL RESEARCH ENTRY'S FRAMING (important - do not
    "fix" the check to invert this): the original T4.2-era research Claim text described
    ST09 as "guest access to group content is limited rather than treated identically to
    member access," implying a restrictive control. The re-verified source data shows the
    opposite - EIDSCA's own RecommendedValue for AllowGuestsToAccessGroups is 'True' (the
    SAME as its default), and maester.dev's own description warns that disabling it "could
    break collaboration." ST09 is a functional-continuity check confirming this tenant-wide
    master toggle for guest access to M365 group content was not inadvertently switched
    off, NOT a guest-restriction control - a tenant that never customizes this setting
    (the common case) already passes. This is a deliberate, source-confirmed correction to
    the research entry's Claim text (see that file's own updated Notes), not an
    implementation choice made independently of the research.

    GATING: ST08 (Medium per EIDSCA tag) and ST09 (Medium per EIDSCA tag) both gate Status,
    each its own evidence row - do not collapse the two into one boolean, they read
    different setting names on the same Group.Unified directorySetting object.
#>

function Test-PulseGuestGroupOwnershipRestricted {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $st08 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'AllowGuestsToBeGroupOwner' -DefaultValue 'false'
    $st09 = Get-PulseDirectorySettingValue -DirectorySettings $Datasets.directorySettings -SettingName 'AllowGuestsToAccessGroups' -DefaultValue 'True'

    $st08Ok = [string]::Equals($st08.Value, 'false', [System.StringComparison]::Ordinal)
    $st09Ok = [string]::Equals($st09.Value, 'True', [System.StringComparison]::Ordinal)

    $evidence = @(
        @{ Identity = 'EIDSCA.ST08'; Detail = @{ setting = 'AllowGuestsToBeGroupOwner'; value = $st08.Value; expected = 'false'; severity = 'Medium'; explicitlyConfigured = $st08.Found; ok = $st08Ok } }
        @{ Identity = 'EIDSCA.ST09'; Detail = @{ setting = 'AllowGuestsToAccessGroups'; value = $st09.Value; expected = 'True'; severity = 'Medium'; explicitlyConfigured = $st09.Found; ok = $st09Ok } }
    )

    $gapReasons = [System.Collections.Generic.List[string]]::new()
    if (-not $st08Ok) {
        $gapReasons.Add("Guests can become owners of Microsoft 365 groups (AllowGuestsToBeGroupOwner = '$($st08.Value)', EIDSCA.ST08).")
    }
    if (-not $st09Ok) {
        $configuredNote = if ($st09.Found) { 'is explicitly set to' } else { 'was never customized and defaults to' }
        $gapReasons.Add("Guest access to Microsoft 365 group content $configuredNote '$($st09.Value)', not the expected 'True' - this master toggle appears to have been disabled, which will break guest collaboration in every group in the tenant (EIDSCA.ST09).")
    }

    if ($gapReasons.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason ($gapReasons -join ' ') -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "Guests cannot become owners of Microsoft 365 groups, and guest access to group content remains enabled as expected (EIDSCA.ST08/ST09)." -Evidence $evidence
}
