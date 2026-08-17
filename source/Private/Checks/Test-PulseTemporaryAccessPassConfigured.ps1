<#
    Private: TP.ENT.0010 rule function - Temporary Access Pass method configuration
    (EIDSCA.AT01-AT02 port; see docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md).
    New check, T4.3 wave 2.

    Consumes the T4.1 auth-method view (ConvertTo-PulseAuthMethodView), matching every other
    method-cluster check in this file - see Test-PulseFido2MethodConfigured's own docstring
    for the shared shape/converter details this check reuses.

    Property mapping - verified directly against the EIDSCA config source at implementation
    time (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json):
        AT01 state              -> .state                    (want 'enabled', default 'enabled', High)
        AT02 isUsableOnce        -> .settings.isUsableOnce     (want $true, default $false, Medium)

    POSITIVE-ENABLEMENT POLARITY (per the research entry's own Notes - opposite of
    TP.ENT.0009/0011's "want disabled" polarity): AT01 wants 'enabled', not 'disabled' - a
    tenant that has never touched Temporary Access Pass at all still has it enabled by
    Microsoft's own default (unlike Fido2/AF01, which defaults to disabled), so a genuinely
    MISSING TemporaryAccessPass entry is treated the same as TP.ENT.0006's "no Fido2 entry"
    precedent (Fail, unrecognized/regressed shape for this dataset family) rather than a
    default-resolved Pass - Microsoft's own built-in method-configuration list always
    includes an explicit TemporaryAccessPass entry on a modern tenant.

    GATING: AT01 (High) always gates. AT02 (Medium) is "only meaningful once AT01 is
    enabled" per the research entry's own Notes - it is reported as its own evidence row
    always, but only gates Status when AT01 is already enabled (mirrors
    Test-PulseFido2MethodConfigured's own AF03/AF04-only-gate-when-AF01-enabled pattern).
#>

function Test-PulseTemporaryAccessPassConfigured {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $policyRows = @($Datasets.authenticationMethodsPolicy)
    if ($policyRows.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No authenticationMethodsPolicy row was collected - cannot evaluate the Temporary Access Pass method configuration.'
    }

    $rawConfigs = Get-PulseSettingsCatalogValueProperty -Node $policyRows[0] -PropertyName 'authenticationMethodConfigurations'
    $views = @(ConvertTo-PulseAuthMethodView -MethodConfigs $rawConfigs)
    $tap = $views | Where-Object { $_.methodId -eq 'TemporaryAccessPass' } | Select-Object -First 1

    if (-not $tap) {
        return New-PulseFinding -Status Fail -Reason "No 'TemporaryAccessPass' entry exists in authenticationMethodConfigurations - Temporary Access Pass has never been configured in this tenant (EIDSCA.AT01)."
    }

    $isUsableOnce = [bool] $tap.settings.isUsableOnce
    $at01Ok = [string]::Equals($tap.state, 'enabled', [System.StringComparison]::Ordinal)

    $evidence = @(
        @{ Identity = 'EIDSCA.AT01'; Detail = @{ setting = 'state'; value = $tap.state; expected = 'enabled'; severity = 'High'; ok = $at01Ok } }
        @{ Identity = 'EIDSCA.AT02'; Detail = @{ setting = 'isUsableOnce'; value = $isUsableOnce; expected = $true; severity = 'Medium' } }
    )

    $gapReasons = [System.Collections.Generic.List[string]]::new()
    if (-not $at01Ok) {
        $gapReasons.Add("Temporary Access Pass is not enabled (state = '$($tap.state)', EIDSCA.AT01).")
    }
    if ($at01Ok -and -not $isUsableOnce) {
        $gapReasons.Add('Temporary Access Pass is enabled but configured as reusable rather than one-time use (EIDSCA.AT02).')
    }

    if ($gapReasons.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason ($gapReasons -join ' ') -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason 'Temporary Access Pass is enabled and configured for one-time use (EIDSCA.AT01/AT02).' -Evidence $evidence
}
