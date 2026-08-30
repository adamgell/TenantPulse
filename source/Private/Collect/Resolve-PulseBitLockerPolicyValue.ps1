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
    $settingRows = @(Get-PulseEndpointSecuritySettingTokens -Settings $Settings)
    $childRows = @($settingRows | Where-Object {
            [string]::Equals([string] $_.DefinitionId, $definitionId, [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals([string] $_.DefinitionId, $fullOption, [System.StringComparison]::OrdinalIgnoreCase)
        })

    if ($childRows.Count -eq 0) {
        throw "BitLocker child setting '$definitionId' was not returned."
    }

    foreach ($row in $childRows) {
        if ([string]::Equals([string] $row.DefinitionId, $fullOption, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [bool] $true
        }
        foreach ($token in @($row.Tokens)) {
            if ([string]::Equals([string] $token, $fullOption, [System.StringComparison]::OrdinalIgnoreCase)) {
                return [bool] $true
            }
        }
    }

    return [bool] $false
}
