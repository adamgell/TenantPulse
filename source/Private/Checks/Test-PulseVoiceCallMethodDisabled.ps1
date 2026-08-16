<#
    Private: TP.ENT.0011 rule function - voice call authentication method disabled
    (EIDSCA.AV01 port; see docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md).
    New check, T4.3 wave 2.

    Consumes the T4.1 auth-method view (ConvertTo-PulseAuthMethodView), matching every other
    method-cluster check in this file - see Test-PulseFido2MethodConfigured's own docstring
    for the shared shape/converter details this check reuses.

    Property mapping - verified directly against the EIDSCA config source at implementation
    time (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json):
        AV01 state -> .state (want 'disabled', default 'disabled', High)

    SIMPLER SHAPE THAN AS04 (per the research entry's own Notes): unlike TP.ENT.0009's SMS
    sibling, this is a single top-level `.state` toggle, not a per-`includeTargets` entry -
    do not apply TP.ENT.0009's per-target evidence shape here.

    NO Voice ENTRY -> FAIL: same "unrecognized/regressed shape for this dataset family"
    convention as TP.ENT.0006/0009/0010's own missing-entry handling - Microsoft's built-in
    method-configuration list always includes an explicit Voice entry on a modern tenant.
#>

function Test-PulseVoiceCallMethodDisabled {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $policyRows = @($Datasets.authenticationMethodsPolicy)
    if ($policyRows.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No authenticationMethodsPolicy row was collected - cannot evaluate the Voice call method configuration.'
    }

    $rawConfigs = Get-PulseSettingsCatalogValueProperty -Node $policyRows[0] -PropertyName 'authenticationMethodConfigurations'
    $views = @(ConvertTo-PulseAuthMethodView -MethodConfigs $rawConfigs)
    $voice = $views | Where-Object { $_.methodId -eq 'Voice' } | Select-Object -First 1

    if (-not $voice) {
        return New-PulseFinding -Status Fail -Reason "No 'Voice' entry exists in authenticationMethodConfigurations - cannot confirm voice call sign-in is disabled (EIDSCA.AV01)."
    }

    $ok = [string]::Equals($voice.state, 'disabled', [System.StringComparison]::Ordinal)

    $evidence = @(
        @{ Identity = 'EIDSCA.AV01'; Detail = @{ setting = 'state'; value = $voice.state; expected = 'disabled'; severity = 'High'; ok = $ok } }
    )

    if (-not $ok) {
        return New-PulseFinding -Status Fail -Reason "Voice call is enabled as an authentication method (state = '$($voice.state)', not 'disabled', EIDSCA.AV01)." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "Voice call is disabled as an authentication method (EIDSCA.AV01)." -Evidence $evidence
}
