<#
    Private: TP.ENT.0008 rule function - Microsoft Authenticator method configuration
    (EIDSCA.AM01-AM04, AM06, AM07, AM09, AM10 port; see
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md - AM05/AM08 do not exist
    in the EIDSCA control set and are deliberately not implemented here).

    Consumes the T4.1 auth-method view (ConvertTo-PulseAuthMethodView), same convention as
    TP.ENT.0006's FIDO2 check. Property mapping (verified directly against the EIDSCA config
    source at implementation time - https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json):
        AM01 state                                                    -> .state                                            (want 'enabled')
        AM02 isSoftwareOathEnabled (OTP fallback)                     -> .settings.isSoftwareOathEnabled                    (want 'false' - CISA MS.AAD.3.3v2)
        AM03 numberMatchingRequiredState.state                        -> .settings.featureSettings.numberMatchingRequiredState.state              (want 'enabled')
        AM04 numberMatchingRequiredState.includeTarget.id (scope)     -> .settings.featureSettings.numberMatchingRequiredState.includeTarget.id    (want 'all_users')
        AM06 displayAppInformationRequiredState.state                 -> .settings.featureSettings.displayAppInformationRequiredState.state        (want 'enabled')
        AM07 displayAppInformationRequiredState.includeTarget.id      -> .settings.featureSettings.displayAppInformationRequiredState.includeTarget.id (want 'all_users')
        AM09 displayLocationInformationRequiredState.state            -> .settings.featureSettings.displayLocationInformationRequiredState.state    (want 'enabled')
        AM10 displayLocationInformationRequiredState.includeTarget.id -> .settings.featureSettings.displayLocationInformationRequiredState.includeTarget.id (want 'all_users')

    STATE+SCOPE PAIRS REPORTED TOGETHER (per the research entry's own Notes): each
    state/includeTarget pair (AM03+AM04, AM06+AM07, AM09+AM10) is one evidence row, not two
    independent ones, so a reader cannot misread "number matching enabled" as sufficient
    when its scope is actually empty/narrow.

    GATING vs EVIDENCE-ONLY: AM01 (enabled), AM02 (OTP fallback off) and the AM03/AM04
    number-matching pair are each independently High severity and gate Status - number
    matching absence is the specific control that closes MFA-fatigue/push-bombing. The
    AM06/AM07 app-name pair is also High and gates. The AM09/AM10 geographic-location pair
    is reported as its own evidence row but does NOT gate Status on its own (AM10's own
    EIDSCA severity tag is Medium, the lowest of this cluster's eight controls) - it is
    fraud-detection-assistive, not the primary anti-push-bombing control the other pairs
    are.
#>

function Test-PulseAuthenticatorMethodConfigured {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $policyRows = @($Datasets.authenticationMethodsPolicy)
    if ($policyRows.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No authenticationMethodsPolicy row was collected - cannot evaluate the Microsoft Authenticator method configuration.'
    }

    $rawConfigs = Get-PulseSettingsCatalogValueProperty -Node $policyRows[0] -PropertyName 'authenticationMethodConfigurations'
    $views = @(ConvertTo-PulseAuthMethodView -MethodConfigs $rawConfigs)
    $authenticator = $views | Where-Object { $_.methodId -eq 'MicrosoftAuthenticator' } | Select-Object -First 1

    if (-not $authenticator) {
        return New-PulseFinding -Status Fail -Reason "No 'MicrosoftAuthenticator' entry exists in authenticationMethodConfigurations - Microsoft Authenticator has never been configured in this tenant (EIDSCA.AM01)."
    }

    function Get-PulseFeatureStatePair {
        param($Settings, [string] $FeatureName)
        $feature = $Settings.featureSettings.$FeatureName
        [pscustomobject]@{
            State = $feature.state
            Scope = $feature.includeTarget.id
        }
    }

    $otpFallback = $authenticator.settings.isSoftwareOathEnabled
    $numberMatching = Get-PulseFeatureStatePair -Settings $authenticator.settings -FeatureName 'numberMatchingRequiredState'
    $appInfo = Get-PulseFeatureStatePair -Settings $authenticator.settings -FeatureName 'displayAppInformationRequiredState'
    $geoLocation = Get-PulseFeatureStatePair -Settings $authenticator.settings -FeatureName 'displayLocationInformationRequiredState'

    $otpFallbackOff = ([string] $otpFallback) -eq 'false' -or $otpFallback -eq $false
    $numberMatchingOk = $numberMatching.State -eq 'enabled' -and $numberMatching.Scope -eq 'all_users'
    $appInfoOk = $appInfo.State -eq 'enabled' -and $appInfo.Scope -eq 'all_users'

    $evidence = @(
        @{ Identity = 'EIDSCA.AM01'; Detail = @{ setting = 'state'; value = $authenticator.state; expected = 'enabled'; severity = 'High' } }
        @{ Identity = 'EIDSCA.AM02'; Detail = @{ setting = 'isSoftwareOathEnabled'; value = $otpFallback; expected = 'false'; severity = 'High' } }
        @{ Identity = 'EIDSCA.AM03-AM04'; Detail = @{ feature = 'numberMatchingRequiredState'; state = $numberMatching.State; scope = $numberMatching.Scope; expected = @{ state = 'enabled'; scope = 'all_users' }; severity = 'High' } }
        @{ Identity = 'EIDSCA.AM06-AM07'; Detail = @{ feature = 'displayAppInformationRequiredState'; state = $appInfo.State; scope = $appInfo.Scope; expected = @{ state = 'enabled'; scope = 'all_users' }; severity = 'High' } }
        @{ Identity = 'EIDSCA.AM09-AM10'; Detail = @{ feature = 'displayLocationInformationRequiredState'; state = $geoLocation.State; scope = $geoLocation.Scope; expected = @{ state = 'enabled'; scope = 'all_users' }; severity = 'Medium' } }
    )

    $gapReasons = [System.Collections.Generic.List[string]]::new()
    if ($authenticator.state -ne 'enabled') { $gapReasons.Add('Microsoft Authenticator is not enabled (EIDSCA.AM01).') }
    if ($authenticator.state -eq 'enabled' -and -not $otpFallbackOff) { $gapReasons.Add('Authenticator OTP fallback is still allowed (EIDSCA.AM02).') }
    if ($authenticator.state -eq 'enabled' -and -not $numberMatchingOk) { $gapReasons.Add('Number matching is not enabled tenant-wide for push approvals (EIDSCA.AM03/AM04).') }
    if ($authenticator.state -eq 'enabled' -and -not $appInfoOk) { $gapReasons.Add('Application-name display is not enabled tenant-wide for push/passwordless notifications (EIDSCA.AM06/AM07).') }

    if ($gapReasons.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason ($gapReasons -join ' ') -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason 'Microsoft Authenticator is enabled with OTP fallback disabled and number matching plus app-name display required tenant-wide (EIDSCA.AM01-AM04, AM06-AM07).' -Evidence $evidence
}
