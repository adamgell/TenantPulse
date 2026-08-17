<#
    Private: TP.ENT.0006 rule function - FIDO2 security key authentication method
    configuration (EIDSCA.AF01-AF06 port; docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md).

    Consumes the T4.1 auth-method view (ConvertTo-PulseAuthMethodView) - never a raw
    authenticationMethodConfigurations node - matching the standing rule for every method
    cluster in this file. The raw dataset is $Datasets.authenticationMethodsPolicy, itself a
    single-element array (one policy object) whose own `authenticationMethodConfigurations`
    property is the array ConvertTo-PulseAuthMethodView normalizes, one entry per method id.

    Property mapping (verified directly against the EIDSCA config source at implementation
    time - https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json):
        AF01 state                                  -> .state                              (want 'enabled')
        AF02 isSelfServiceRegistrationAllowed        -> .settings.isSelfServiceRegistrationAllowed
        AF03 isAttestationEnforced                   -> .settings.isAttestationEnforced      (want $true)
        AF04 keyRestrictions.isEnforced              -> .settings.keyRestrictions.isEnforced  (want $true)
        AF05 keyRestrictions.enforcementType          -> .settings.keyRestrictions.enforcementType ('allow'|'block')
        AF06 keyRestrictions.aaGuids                  -> .settings.keyRestrictions.aaGuids     (non-empty when restricted)

    GATING (Fail-driving) vs EVIDENCE-ONLY: AF01/AF03/AF04 are each independently High
    severity per EIDSCA's own tags and directly gate this check's Status - a tenant with
    FIDO2 disabled, or enabled without attestation/key-restriction enforcement, fails. AF02
    (self-service registration) and AF05/AF06 (restriction shape once AF04 is on) are
    reported as their own evidence rows but do NOT independently flip Status - AF02 is a
    judgment call, not a fixed pass/fail bar (see this check's own Consulting text), and
    AF05/AF06 only mean anything once AF04 has already gated the finding - collapsing five
    independent EIDSCA controls into one boolean would bury exactly the distinction the
    research entry's own Notes warn against.
#>

function Test-PulseFido2MethodConfigured {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $policyRows = @($Datasets.authenticationMethodsPolicy)
    if ($policyRows.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No authenticationMethodsPolicy row was collected - cannot evaluate the FIDO2 method configuration.'
    }

    $rawConfigs = Get-PulseSettingsCatalogValueProperty -Node $policyRows[0] -PropertyName 'authenticationMethodConfigurations'
    $views = @(ConvertTo-PulseAuthMethodView -MethodConfigs $rawConfigs)
    $fido2 = $views | Where-Object { $_.methodId -eq 'Fido2' } | Select-Object -First 1

    if (-not $fido2) {
        return New-PulseFinding -Status Fail -Reason "No 'Fido2' entry exists in authenticationMethodConfigurations - FIDO2 has never been configured in this tenant (EIDSCA.AF01)."
    }

    $isAttestationEnforced = [bool] $fido2.settings.isAttestationEnforced
    $keyRestrictionsEnforced = [bool] $fido2.settings.keyRestrictions.isEnforced
    $enforcementType = $fido2.settings.keyRestrictions.enforcementType
    $aaGuids = @($fido2.settings.keyRestrictions.aaGuids)
    $selfServiceAllowed = $fido2.settings.isSelfServiceRegistrationAllowed

    $evidence = @(
        @{ Identity = 'EIDSCA.AF01'; Detail = @{ setting = 'state'; value = $fido2.state; expected = 'enabled'; severity = 'High' } }
        @{ Identity = 'EIDSCA.AF02'; Detail = @{ setting = 'isSelfServiceRegistrationAllowed'; value = $selfServiceAllowed } }
        @{ Identity = 'EIDSCA.AF03'; Detail = @{ setting = 'isAttestationEnforced'; value = $isAttestationEnforced; expected = $true; severity = 'High' } }
        @{ Identity = 'EIDSCA.AF04'; Detail = @{ setting = 'keyRestrictions.isEnforced'; value = $keyRestrictionsEnforced; expected = $true; severity = 'High' } }
        @{ Identity = 'EIDSCA.AF05'; Detail = @{ setting = 'keyRestrictions.enforcementType'; value = $enforcementType } }
        @{ Identity = 'EIDSCA.AF06'; Detail = @{ setting = 'keyRestrictions.aaGuids'; value = $aaGuids; count = $aaGuids.Count } }
    )

    $gapReasons = [System.Collections.Generic.List[string]]::new()
    if ($fido2.state -ne 'enabled') { $gapReasons.Add('FIDO2 is not enabled (EIDSCA.AF01).') }
    if ($fido2.state -eq 'enabled' -and -not $isAttestationEnforced) { $gapReasons.Add('FIDO2 attestation is not enforced (EIDSCA.AF03).') }
    if ($fido2.state -eq 'enabled' -and -not $keyRestrictionsEnforced) { $gapReasons.Add('FIDO2 key restrictions are not enforced (EIDSCA.AF04).') }

    if ($gapReasons.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason ($gapReasons -join ' ') -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason 'FIDO2 is enabled with attestation and key restrictions enforced (EIDSCA.AF01/AF03/AF04).' -Evidence $evidence
}
