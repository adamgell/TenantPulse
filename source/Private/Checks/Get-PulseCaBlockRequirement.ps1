<#
    Classifies whether a normalized Conditional Access grant is an unambiguous block.
    A block combined with any sibling grant is not authoritative proof that every matching
    sign-in is denied. Unsupported or ambiguous combinations remain incomplete rather than
    being promoted to coverage.
#>
function Get-PulseCaBlockRequirement {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $PolicyView
    )

    $newResult = {
        param([string] $State, [AllowNull()][string] $ReasonCode)
        [pscustomobject][ordered]@{
            State      = $State
            Complete   = ($State -ne 'Incomplete')
            ReasonCode = $ReasonCode
        }
    }

    if ($null -eq $PolicyView) { return & $newResult 'Incomplete' 'missing-policy-view' }
    $grants = Get-PulseSettingsCatalogValueProperty -Node $PolicyView -PropertyName 'grants'
    if ($null -eq $grants) {
        return & $newResult 'Incomplete' 'missing-grant-view'
    }
    $grantsPresent = Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'present'
    if ($grantsPresent -isnot [bool]) { return & $newResult 'Incomplete' 'missing-grant-view' }
    if (-not $grantsPresent) { return & $newResult 'NotRequired' 'no-block-control' }

    $builtIns = @((Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'builtInControls'))
    $customFactors = @((Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'customAuthenticationFactors'))
    $termsOfUse = @((Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'termsOfUse'))
    $strength = Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'authenticationStrength'
    $hasBlankBuiltIn = @($builtIns | Where-Object { [string]::IsNullOrWhiteSpace([string] $_) }).Count -gt 0
    $knownBuiltInControls = @(
        'mfa', 'compliantdevice', 'domainjoineddevice', 'approvedapplication',
        'compliantapplication', 'passwordchange', 'riskremediation'
    )
    $containsBlock = @($builtIns | Where-Object {
        [string]::Equals([string] $_, 'block', [System.StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
    $hasUnknownBuiltIn = @($builtIns | Where-Object {
        if ([string]::IsNullOrWhiteSpace([string] $_)) { return $false }
        $normalized = ([string] $_).Trim().ToLowerInvariant()
        $normalized -eq 'unknownfuturevalue' -or $normalized -notin @($knownBuiltInControls + 'block')
    }).Count -gt 0

    # Only builtInControls can declare block. Invalid operator or authentication-strength
    # metadata on a known non-block grant cannot turn it into a block policy and must not
    # hide a definite legacy-auth coverage gap. Keep uncertainty only when the built-in
    # collection itself is blank or contains an unknown/future member.
    if (-not $containsBlock) {
        if ($hasBlankBuiltIn) { return & $newResult 'Incomplete' 'blank-grant-control' }
        if ($hasUnknownBuiltIn) { return & $newResult 'Incomplete' 'unresolved-grant-control' }
        return & $newResult 'NotRequired' 'no-block-control'
    }

    if ($hasBlankBuiltIn -or
        @($customFactors + $termsOfUse | Where-Object { [string]::IsNullOrWhiteSpace([string] $_) }).Count -gt 0) {
        return & $newResult 'Incomplete' 'blank-grant-control'
    }

    $operatorPresent = [bool] (Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'operatorPresent')
    $operator = [string] (Get-PulseSettingsCatalogValueProperty -Node $grants -PropertyName 'operator')
    if (-not [string]::IsNullOrWhiteSpace($operator)) { $operator = $operator.Trim().ToUpperInvariant() }
    if ($operatorPresent -and $operator -notin @('AND', 'OR')) {
        return & $newResult 'Incomplete' 'missing-or-invalid-operator'
    }

    $isSoleBlock = $builtIns.Count -eq 1 -and
        [string]::Equals([string] $builtIns[0], 'block', [System.StringComparison]::OrdinalIgnoreCase) -and
        $customFactors.Count -eq 0 -and $termsOfUse.Count -eq 0 -and $null -eq $strength
    if ($isSoleBlock) { return & $newResult 'Required' $null }

    return & $newResult 'Incomplete' 'block-combined-with-other-controls'
}
