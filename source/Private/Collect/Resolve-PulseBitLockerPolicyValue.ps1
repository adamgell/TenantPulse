function Resolve-PulseBitLockerPolicyValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Settings
    )

    $definitionId = 'device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name'
    $fullOption = $definitionId + '_1'
    $usedSpaceOption = $definitionId + '_2'
    $settingRows = @(Get-PulseEndpointSecuritySettingTokens -Settings $Settings)
    $childRows = @($settingRows | Where-Object {
            [string]::Equals([string] $_.DefinitionId, $definitionId, [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals([string] $_.DefinitionId, $fullOption, [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals([string] $_.DefinitionId, $usedSpaceOption, [System.StringComparison]::OrdinalIgnoreCase)
        })

    if ($childRows.Count -eq 0) {
        throw "BitLocker child setting '$definitionId' was not returned."
    }

    $sawKnownTrue = $false
    $sawKnownFalse = $false
    $sawUnknown = $false
    $tokenCount = 0
    foreach ($row in $childRows) {
        if ([string]::Equals([string] $row.DefinitionId, $fullOption, [System.StringComparison]::OrdinalIgnoreCase)) {
            $tokenCount++
            $sawKnownTrue = $true
        } elseif ([string]::Equals([string] $row.DefinitionId, $usedSpaceOption, [System.StringComparison]::OrdinalIgnoreCase)) {
            $tokenCount++
            $sawKnownFalse = $true
        }
        foreach ($token in @($row.Tokens)) {
            $tokenCount++
            if ([string]::Equals([string] $token, $fullOption, [System.StringComparison]::OrdinalIgnoreCase)) {
                $sawKnownTrue = $true
                continue
            }
            if ([string]::Equals([string] $token, $usedSpaceOption, [System.StringComparison]::OrdinalIgnoreCase)) {
                $sawKnownFalse = $true
                continue
            }
            $sawUnknown = $true
        }
    }

    # Unknown or contradictory values take precedence over a positive token: mixed
    # evidence cannot become an authoritative policy result.
    if ($tokenCount -eq 0 -or $sawUnknown -or ($sawKnownTrue -and $sawKnownFalse)) {
        throw "BitLocker child setting value is unknown."
    }
    if ($sawKnownTrue) { return [bool] $true }
    if ($sawKnownFalse) { return [bool] $false }
    throw "BitLocker child setting value is unknown."
}
