<#
    Private: TP.ENT.0009 rule function - SMS sign-in authentication method disabled
    (EIDSCA.AS04 port; see docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md).
    New check, T4.3 wave 2.

    Consumes the T4.1 auth-method view (ConvertTo-PulseAuthMethodView), matching every other
    method-cluster check in this file (TP.ENT.0006/0008/0010/0011). The raw dataset is
    $Datasets.authenticationMethodsPolicy - see Test-PulseFido2MethodConfigured's own
    docstring for the shared shape/converter details this check reuses.

    Property mapping - verified directly against the EIDSCA config source at implementation
    time (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json):
        AS04 includeTargets[].isUsableForSignIn -> want $false for EVERY target (default $true)

    PER-TARGET, NOT A SINGLE TENANT-WIDE BOOLEAN (per the research entry's own Notes): a
    tenant can have SMS disabled for most groups but still usable for a forgotten pilot/
    exception group. Evidence enumerates every target with isUsableForSignIn = $true by id,
    rather than collapsing to one aggregate pass/fail - so a Fail finding names exactly which
    target group(s) still have SMS sign-in open, not just "SMS is not fully disabled."

    NO SMS ENTRY -> FAIL, NOT SILENTLY-DEFAULTED: unlike the directorySettings-backed
    clusters (CP0x/PR0x/ST0x), the authenticationMethodsPolicy dataset always carries a
    built-in entry for every method Microsoft ships (Sms included) - ConvertTo-PulseAuthMethodView
    already throws if a present entry has no recognizable `state`. A genuinely MISSING Sms
    entry (not just disabled) is itself an unrecognized/regressed shape for this dataset
    family, matching TP.ENT.0006's own "no Fido2 entry" Fail precedent - not a legitimate
    "never customized" state the way an absent directorySetting row is.
#>

function Test-PulseSmsSignInMethodDisabled {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $policyRows = @($Datasets.authenticationMethodsPolicy)
    if ($policyRows.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No authenticationMethodsPolicy row was collected - cannot evaluate the SMS sign-in method configuration.'
    }

    $rawConfigs = Get-PulseSettingsCatalogValueProperty -Node $policyRows[0] -PropertyName 'authenticationMethodConfigurations'
    $views = @(ConvertTo-PulseAuthMethodView -MethodConfigs $rawConfigs)
    $sms = $views | Where-Object { $_.methodId -eq 'Sms' } | Select-Object -First 1

    if (-not $sms) {
        return New-PulseFinding -Status Fail -Reason "No 'Sms' entry exists in authenticationMethodConfigurations - cannot confirm SMS sign-in is disabled (EIDSCA.AS04)."
    }

    $usableTargets = @($sms.includeTargets | Where-Object { $_.isUsableForSignIn -eq $true })
    $usableTargetIds = @($usableTargets | ForEach-Object { $_.id })

    $evidence = @(
        @{ Identity = 'EIDSCA.AS04'; Detail = @{ setting = 'includeTargets[].isUsableForSignIn'; usableForSignInTargetIds = $usableTargetIds; targetCount = @($sms.includeTargets).Count; severity = 'High' } }
    )

    if ($usableTargets.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason "SMS is still usable as a sign-in factor for $($usableTargets.Count) target group(s): $($usableTargetIds -join ', ') (EIDSCA.AS04)." -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason 'SMS is not usable as a sign-in factor for any target group (EIDSCA.AS04).' -Evidence $evidence
}
