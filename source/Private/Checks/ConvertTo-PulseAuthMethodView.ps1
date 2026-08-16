<#
    Private: normalize one raw authentication method configuration entry (from
    `beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations` - see
    the DatasetMap.psd1 `authenticationMethodsPolicy` entry, whole-object Get whose own
    `authenticationMethodConfigurations` array carries one entry per method, e.g. 'Fido2',
    'MicrosoftAuthenticator', 'Sms', 'Voice', 'TemporaryAccessPass' - see the T4.1 research
    context, docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md, TP.ENT.0006/
    0008/0009/0011) into TenantPulse's shared, stable authentication-method view shape.

    A DIFFERENT OBJECT FAMILY THAN CA POLICIES (omp plan review, CRITICAL clarification -
    see the Task 4.1 plan section): authenticationMethodConfigurations shares NONE of a CA
    policy's conditions/grantControls/state-enum shape - state here is a plain two-value
    enabled/disabled toggle (no report-only tier at all), and per-method settings are
    entirely free-form (FIDO2 carries isAttestationEnforced/keyRestrictions,
    MicrosoftAuthenticator carries numberMatchingRequiredState, etc. - see each EIDSCA
    cluster's own Notes in the research file). This is why it is its own converter, not a
    branch inside ConvertTo-PulseCaPolicyView.

    SHAPE NEUTRALITY: same shared accessor as the CA policy view - see
    Resolve-PulseSettingsCatalogValueClassification.ps1's own Get-PulseSettingsCatalogValueProperty
    docstring for the [PSObject]-vs-[IDictionary] trap this avoids repeating.

    ABSENT STATE THROWS (field-absence lens, matching ConvertTo-PulseCaPolicyView's own
    convention): a method configuration with no `state` property, or a `state` value that
    is neither 'enabled' nor 'disabled', is an unrecognized shape - silently guessing
    'disabled' would bury a real regression as a quiet false-negative for every EIDSCA
    cluster that reads .state (AF01, AM01, AT01, AV01, ...). Throws instead, same as the CA
    policy view's own ABSENT STATE THROWS section.

    -Settings IS EVERY OTHER TOP-LEVEL PROPERTY, DELIBERATELY GENERIC: rather than
    hand-picking which per-method fields matter (a list that would need editing every time
    a new EIDSCA cluster ports a control this file's authors did not anticipate), every
    top-level property on the raw node OTHER than the well-known
    id/state/includeTargets/excludeTargets/@odata.type is copied into -Settings verbatim,
    keyed by its own raw property name (e.g. `.settings.isAttestationEnforced`,
    `.settings.numberMatchingRequiredState`). A consuming check reads
    `.settings.<propertyName>` directly - this function does not interpret per-method
    settings semantics, it only relocates them out of the raw node into one predictable
    bag so every consumer reads settings the same way.
#>

function ConvertTo-PulseAuthMethodView {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $MethodConfigs
    )

    begin {
        # Property names surfaced as their own first-class view fields, not folded into
        # -Settings - kept in one place so the -Settings exclusion list below and the
        # explicit reads above it can never silently drift apart.
        $script:wellKnownAuthMethodProperties = [System.Collections.Generic.HashSet[string]]::new(
            [string[]] @('id', 'state', 'includeTargets', 'excludeTargets', '@odata.type'),
            [System.StringComparer]::OrdinalIgnoreCase
        )

        function ConvertTo-AuthMethodTargetArray {
            param($Value)
            if ($null -eq $Value) { return @() }
            return @($Value | ForEach-Object {
                [pscustomobject]@{
                    id                 = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'id'
                    targetType         = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'targetType'
                    isRegistrationRequired = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'isRegistrationRequired'
                    isUsableForSignIn  = Get-PulseSettingsCatalogValueProperty -Node $_ -PropertyName 'isUsableForSignIn'
                }
            })
        }

        function Get-AuthMethodPropertyNames {
            param($Node)
            if ($Node -is [System.Collections.IDictionary]) { return @($Node.Keys) }
            if ($Node -is [System.Management.Automation.PSObject]) { return @($Node.PSObject.Properties.Name) }
            return @()
        }
    }

    process {
        foreach ($config in @($MethodConfigs)) {
            if ($null -eq $config) { continue }

            $methodId = Get-PulseSettingsCatalogValueProperty -Node $config -PropertyName 'id'

            $rawState = Get-PulseSettingsCatalogValueProperty -Node $config -PropertyName 'state'
            if ($null -eq $rawState -or [string]::IsNullOrEmpty([string] $rawState)) {
                throw "ConvertTo-PulseAuthMethodView: authentication method '$methodId' has no 'state' property - cannot normalize an unrecognized/absent-state method configuration shape."
            }
            $state = [string] $rawState
            if ($state -ne 'enabled' -and $state -ne 'disabled') {
                throw "ConvertTo-PulseAuthMethodView: authentication method '$methodId' has an unrecognized state '$state' - expected 'enabled' or 'disabled'."
            }

            $settings = [ordered]@{}
            foreach ($propertyName in (Get-AuthMethodPropertyNames -Node $config)) {
                if ($script:wellKnownAuthMethodProperties.Contains($propertyName)) { continue }
                $settings[$propertyName] = Get-PulseSettingsCatalogValueProperty -Node $config -PropertyName $propertyName
            }

            [pscustomobject]@{
                methodId       = if ($null -ne $methodId) { [string] $methodId } else { $null }
                state          = $state
                includeTargets = ConvertTo-AuthMethodTargetArray (Get-PulseSettingsCatalogValueProperty -Node $config -PropertyName 'includeTargets')
                excludeTargets = ConvertTo-AuthMethodTargetArray (Get-PulseSettingsCatalogValueProperty -Node $config -PropertyName 'excludeTargets')
                settings       = $settings
            }
        }
    }
}
