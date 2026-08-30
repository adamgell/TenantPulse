function Get-PulseEndpointSecurityNodeProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)] $Node,
        [Parameter(Mandatory)] [string] $PropertyName
    )

    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains($PropertyName)) { return $Node[$PropertyName] }
        return $null
    }

    $property = $Node.PSObject.Properties[$PropertyName]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-PulseEndpointSecuritySettingTokens {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Settings
    )

    $result = [System.Collections.Generic.List[object]]::new()

    function Add-SettingNode {
        param($Node)
        if ($null -eq $Node) { return }

        $definitionId = Get-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName 'settingDefinitionId'
        if ($null -ne $definitionId) { $definitionId = [string] $definitionId }
        else { $definitionId = '' }

        $valueTokens = [System.Collections.Generic.List[string]]::new()
        foreach ($valuePropertyName in @('choiceSettingValue', 'choiceSettingCollectionValue', 'simpleSettingValue', 'simpleSettingCollectionValue', 'groupSettingCollectionValue')) {
            $valueContainer = Get-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName $valuePropertyName
            foreach ($valueNode in @($valueContainer)) {
                if ($null -eq $valueNode) { continue }
                $value = Get-PulseEndpointSecurityNodeProperty -Node $valueNode -PropertyName 'value'
                if ($null -ne $value) { $valueTokens.Add([string] $value) | Out-Null }

                $children = Get-PulseEndpointSecurityNodeProperty -Node $valueNode -PropertyName 'children'
                foreach ($child in @($children)) { Add-SettingNode -Node $child }
            }
        }

        $directChildren = Get-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName 'children'
        foreach ($child in @($directChildren)) { Add-SettingNode -Node $child }

        $nestedSetting = Get-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName 'settingInstance'
        if ($null -ne $nestedSetting) { Add-SettingNode -Node $nestedSetting }

        if (-not [string]::IsNullOrEmpty($definitionId) -or $valueTokens.Count -gt 0) {
            $result.Add([pscustomobject][ordered]@{
                    DefinitionId = $definitionId
                    Tokens       = [string[]] $valueTokens.ToArray()
                }) | Out-Null
        }
    }

    foreach ($setting in @($Settings)) {
        if ($null -eq $setting) { continue }
        $instance = Get-PulseEndpointSecurityNodeProperty -Node $setting -PropertyName 'settingInstance'
        if ($null -eq $instance) { $instance = $setting }
        Add-SettingNode -Node $instance
    }

    return $result.ToArray()
}
