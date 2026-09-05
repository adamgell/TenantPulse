<#
    Classifies whether a normalized Conditional Access policy's grant controls actually
    require MFA or phishing-resistant MFA. Graph applies operator across grant controls;
    an OR alternative such as compliantDevice means MFA is optional, while AND still
    requires every listed control. A tenant-defined strength can establish generic MFA
    when its authoritative inline requirementsSatisfied value is `mfa`; phishing-resistant
    coverage remains incomplete until its allowed combinations are evaluated.
#>
function Get-PulseCaGrantRequirement {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $PolicyView,

        [Parameter(Mandatory)]
        [ValidateSet('Mfa', 'PhishingResistant')]
        [string] $Requirement
    )

    $newResult = {
        param(
            [string] $State,
            [AllowNull()][string] $ReasonCode,
            [AllowNull()][string] $Mechanism,
            [int] $ControlCount,
            [AllowNull()][string] $Operator
        )
        [pscustomobject][ordered]@{
            State        = $State
            Complete     = ($State -ne 'Incomplete')
            ReasonCode   = $ReasonCode
            Mechanism    = $Mechanism
            ControlCount = $ControlCount
            Operator     = $Operator
        }
    }

    if ($null -eq $PolicyView) {
        return & $newResult 'Incomplete' 'missing-policy-view' $null 0 $null
    }

    $grants = Get-PulseSettingsCatalogValueProperty -Node $PolicyView -PropertyName 'grants'
    if ($null -eq $grants) {
        return & $newResult 'Incomplete' 'missing-grant-view' $null 0 $null
    }

    [string[]] $builtInControls = @()
    [string[]] $customFactors = @()
    [string[]] $termsOfUse = @()
    $rawBuiltIns = Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'builtInControls'
    $rawCustom = Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'customAuthenticationFactors'
    $rawTerms = Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'termsOfUse'
    if ($null -ne $rawBuiltIns -and @($rawBuiltIns).Count -gt 0) { $builtInControls = [string[]] @($rawBuiltIns) }
    if ($null -ne $rawCustom -and @($rawCustom).Count -gt 0) { $customFactors = [string[]] @($rawCustom) }
    if ($null -ne $rawTerms -and @($rawTerms).Count -gt 0) { $termsOfUse = [string[]] @($rawTerms) }

    $strength = Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'authenticationStrength'
    $operator = [string] (Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'operator')
    if ([string]::IsNullOrWhiteSpace($operator)) { $operator = $null }
    else { $operator = $operator.Trim().ToUpperInvariant() }

    $knownMfaStrengthIds = @(
        '00000000-0000-0000-0000-000000000002'
        '00000000-0000-0000-0000-000000000003'
        '00000000-0000-0000-0000-000000000004'
    )
    $phishingResistantStrengthId = '00000000-0000-0000-0000-000000000004'
    $knownBuiltInControls = @(
        'block', 'mfa', 'compliantdevice', 'domainjoineddevice',
        'approvedapplication', 'compliantapplication', 'passwordchange',
        'riskremediation'
    )
    $normalizedBuiltInControls = @($builtInControls | ForEach-Object {
        if ($null -eq $_) { '' } else { $_.Trim().ToLowerInvariant() }
    })

    $operatorPresent = [bool] (Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'operatorPresent')
    if ($operatorPresent -and $operator -notin @('AND', 'OR')) {
        return & $newResult 'Incomplete' 'missing-or-invalid-operator' $null 0 $operator
    }

    $hasMfa = $normalizedBuiltInControls -contains 'mfa'
    $hasBlock = $normalizedBuiltInControls -contains 'block'
    $hasPasswordChange = $normalizedBuiltInControls -contains 'passwordchange'
    $hasRiskRemediation = $normalizedBuiltInControls -contains 'riskremediation'
    $hasSiblingToBlock = $normalizedBuiltInControls.Count -gt 1 -or $null -ne $strength -or
        $customFactors.Count -gt 0 -or $termsOfUse.Count -gt 0
    $invalidCombination =
        ($null -ne $strength -and $hasMfa) -or
        ($hasBlock -and $hasSiblingToBlock) -or
        ($hasPasswordChange -and (-not $hasMfa -or $operator -ne 'AND' -or $hasRiskRemediation)) -or
        ($hasRiskRemediation -and ($null -eq $strength -or $operator -ne 'AND' -or $hasPasswordChange))
    if ($invalidCombination) {
        $declaredControlCount = $builtInControls.Count + $customFactors.Count + $termsOfUse.Count + $(if ($null -ne $strength) { 1 } else { 0 })
        return & $newResult 'Incomplete' 'invalid-grant-control-combination' $null $declaredControlCount $operator
    }

    # Microsoft only permits passwordChange and riskRemediation in policies that
    # target all applications and configure user risk without any other condition.
    # A syntactically valid grant-control pairing is therefore not sufficient evidence
    # by itself. Graph commonly serializes clientAppTypes = all and empty optional risk
    # arrays on read, so the shared scope classifiers distinguish those defaults from
    # actual narrowing while the explicit node-presence checks below reject otherwise
    # unrestricted-but-configured conditions such as platforms = all.
    if ($hasPasswordChange -or $hasRiskRemediation) {
        $conditions = Get-PulseSettingsCatalogValueProperty -Node $PolicyView -PropertyName 'conditions'
        $userRiskPresent = [bool] (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'userRiskPresent')
        $rawUserRisk = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'userRisk'
        $userRiskLevels = @($rawUserRisk | Where-Object {
            $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string] $_)
        })
        $applicationScope = Get-PulseCaApplicationScope -PolicyView $PolicyView
        $signInScope = Get-PulseCaSignInScope -PolicyView $PolicyView -Mode Mfa
        $unsupportedNarrowReasonCount = @($signInScope.NarrowReasonCodes | Where-Object {
            $_ -ne 'narrow-user-risk-scope'
        }).Count
        $hasUnsupportedConditionNode =
            [bool] (Get-PulseSettingsCatalogValueProperty -Node (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'platforms') -PropertyName 'present') -or
            [bool] (Get-PulseSettingsCatalogValueProperty -Node (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'locations') -PropertyName 'present') -or
            [bool] (Get-PulseSettingsCatalogValueProperty -Node (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'clientApplications') -PropertyName 'present') -or
            [bool] (Get-PulseSettingsCatalogValueProperty -Node (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'devices') -PropertyName 'present') -or
            [bool] (Get-PulseSettingsCatalogValueProperty -Node (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'deviceStates') -PropertyName 'present') -or
            [bool] (Get-PulseSettingsCatalogValueProperty -Node (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'authenticationFlows') -PropertyName 'present') -or
            [bool] (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'timesPresent')
        if (-not $userRiskPresent -or $userRiskLevels.Count -eq 0 -or
            $applicationScope.State -ne 'AllResources' -or -not $signInScope.Complete -or
            $unsupportedNarrowReasonCount -gt 0 -or $hasUnsupportedConditionNode) {
            $declaredControlCount = $builtInControls.Count + $customFactors.Count + $termsOfUse.Count + $(if ($null -ne $strength) { 1 } else { 0 })
            return & $newResult 'Incomplete' 'invalid-remediation-policy-conditions' $null $declaredControlCount $operator
        }
    }

    $targetCount = 0
    $nonTargetCount = 0
    $unknownCount = 0
    $unknownBuiltInCount = 0
    $unknownStrengthCount = 0
    $mechanisms = [System.Collections.Generic.List[string]]::new()

    foreach ($control in $builtInControls) {
        if ([string]::IsNullOrWhiteSpace($control)) {
            $unknownCount++
            $unknownBuiltInCount++
            continue
        }
        $normalizedControl = $control.Trim().ToLowerInvariant()
        if ($normalizedControl -notin $knownBuiltInControls -or $normalizedControl -eq 'unknownfuturevalue') {
            $unknownCount++
            $unknownBuiltInCount++
        } elseif ($Requirement -eq 'Mfa' -and $normalizedControl -eq 'mfa') {
            $targetCount++
            $mechanisms.Add('builtInControls:mfa')
        } else {
            $nonTargetCount++
        }
    }

    if ($null -ne $strength) {
        $strengthId = [string] (Get-PulseSettingsCatalogValueProperty -Node $strength -PropertyName 'id')
        $requirementsSatisfied = [string] (Get-PulseSettingsCatalogValueProperty -Node $strength -PropertyName 'requirementsSatisfied')
        if (-not [string]::IsNullOrWhiteSpace($requirementsSatisfied)) {
            $requirementsSatisfied = $requirementsSatisfied.Trim().ToLowerInvariant()
        }
        if ([string]::IsNullOrWhiteSpace($strengthId)) {
            $unknownCount++
            $unknownStrengthCount++
        } elseif ($Requirement -eq 'Mfa' -and $knownMfaStrengthIds -contains $strengthId) {
            $targetCount++
            $mechanisms.Add('authenticationStrength')
        } elseif ($Requirement -eq 'PhishingResistant' -and [string]::Equals($strengthId, $phishingResistantStrengthId, [System.StringComparison]::OrdinalIgnoreCase)) {
            $targetCount++
            $mechanisms.Add('authenticationStrength')
        } elseif ($knownMfaStrengthIds -contains $strengthId) {
            $nonTargetCount++
        } elseif ($Requirement -eq 'Mfa' -and $requirementsSatisfied -eq 'mfa') {
            $targetCount++
            $mechanisms.Add('authenticationStrength:requirementsSatisfied')
        } elseif ($Requirement -eq 'Mfa' -and $requirementsSatisfied -eq 'none') {
            $nonTargetCount++
        } else {
            $unknownCount++
            $unknownStrengthCount++
        }
    }

    foreach ($factor in $customFactors) {
        if ([string]::IsNullOrWhiteSpace($factor)) { $unknownCount++ }
        else { $unknownCount++ }
    }
    foreach ($term in $termsOfUse) {
        if ([string]::IsNullOrWhiteSpace($term)) { $unknownCount++ }
        else { $nonTargetCount++ }
    }

    $controlCount = $targetCount + $nonTargetCount + $unknownCount
    $mechanism = if ($mechanisms.Count -gt 0) { (@($mechanisms | Select-Object -Unique) -join '+') } else { $null }
    $unresolvedReason = if ($unknownBuiltInCount -gt 0) { 'unresolved-grant-control' }
        elseif ($unknownStrengthCount -gt 0) { 'unresolved-authentication-strength' }
        else { 'unresolved-grant-control' }
    if ($controlCount -eq 0) {
        return & $newResult 'NotRequired' 'no-matching-grant-control' $null 0 $operator
    }

    if ($controlCount -eq 1) {
        if ($targetCount -eq 1) { return & $newResult 'Required' $null $mechanism 1 $operator }
        if ($unknownCount -eq 1) { return & $newResult 'Incomplete' $unresolvedReason $null 1 $operator }
        return & $newResult 'NotRequired' 'sole-control-does-not-satisfy-requirement' $null 1 $operator
    }

    if ($operator -notin @('AND', 'OR')) {
        return & $newResult 'Incomplete' 'missing-or-invalid-operator' $mechanism $controlCount $operator
    }

    if ($operator -eq 'AND') {
        if ($targetCount -gt 0) { return & $newResult 'Required' $null $mechanism $controlCount $operator }
        if ($unknownCount -gt 0) { return & $newResult 'Incomplete' $unresolvedReason $null $controlCount $operator }
        return & $newResult 'NotRequired' 'and-has-no-required-control' $null $controlCount $operator
    }

    if ($nonTargetCount -gt 0) {
        return & $newResult 'NotRequired' 'or-allows-non-required-control' $mechanism $controlCount $operator
    }
    if ($unknownCount -gt 0) {
        return & $newResult 'Incomplete' $unresolvedReason $mechanism $controlCount $operator
    }
    return & $newResult 'Required' $null $mechanism $controlCount $operator
}
