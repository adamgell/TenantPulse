function Get-PulseEndpointSecurityNodeProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)] $Node,
        [Parameter(Mandatory)] [string] $PropertyName
    )

    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains($PropertyName)) {
            $value = $Node[$PropertyName]
            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { return , $value }
            return $value
        }
        return $null
    }

    $property = $Node.PSObject.Properties[$PropertyName]
    if ($null -ne $property) {
        $value = $property.Value
        if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { return , $value }
        return $value
    }
    return $null
}

function Test-PulseEndpointSecurityNodeProperty {
    param(
        [Parameter(Mandatory = $false)] $Node,
        [Parameter(Mandatory)] [string] $PropertyName
    )

    if ($null -eq $Node) { return $false }
    if ($Node -is [System.Collections.IDictionary]) {
        return $Node.Contains($PropertyName)
    }
    return $null -ne $Node.PSObject.Properties[$PropertyName]
}

function Test-PulseEndpointSecuritySettingValueNode {
    param([Parameter(Mandatory = $false)] $Node)

    return $Node -is [System.Collections.IDictionary] -or
        $Node -is [System.Management.Automation.PSCustomObject]
}

function Get-PulseEndpointSecurityNativeStringField {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)] $Node,
        [Parameter(Mandatory)] [string] $PropertyName
    )

    $isPresent = Test-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName $PropertyName
    if (-not $isPresent) {
        return [pscustomobject][ordered]@{
            IsPresent = $false
            IsValid = $true
            Value   = $null
        }
    }

    $value = Get-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName $PropertyName

    if ($value -isnot [string]) {
        return [pscustomobject][ordered]@{
            IsPresent = $true
            IsValid = $false
            Value   = $null
        }
    }

    return [pscustomobject][ordered]@{
        IsPresent = $true
        IsValid = $true
        Value   = $value
    }
}

function Get-PulseEndpointSecuritySettingValueTokenField {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)] $Node,
        [Parameter(Mandatory)] [string] $PropertyName,
        [Parameter()] [switch] $AllowIntegralNumber
    )

    $isPresent = Test-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName $PropertyName
    if (-not $isPresent) {
        return [pscustomobject][ordered]@{
            IsPresent = $false
            IsValid = $true
            Value   = $null
        }
    }

    $value = Get-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName $PropertyName

    if ($value -is [string]) {
        return [pscustomobject][ordered]@{
            IsPresent = $true
            IsValid = $true
            Value   = $value
        }
    }

    if ($AllowIntegralNumber -and (
            $value -is [sbyte] -or $value -is [byte] -or
            $value -is [int16] -or $value -is [uint16] -or
            $value -is [int32] -or $value -is [uint32] -or
            $value -is [int64] -or $value -is [uint64]
        )) {
        return [pscustomobject][ordered]@{
            IsPresent = $true
            IsValid = $true
            Value   = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $value)
        }
    }

    return [pscustomobject][ordered]@{
        IsPresent = $true
        IsValid = $false
        Value   = $null
    }
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

        $definitionIdField = Get-PulseEndpointSecurityNativeStringField -Node $Node -PropertyName 'settingDefinitionId'
        if ($definitionIdField.IsPresent -and
            (-not $definitionIdField.IsValid -or [string]::IsNullOrWhiteSpace($definitionIdField.Value))) {
            throw 'Endpoint Security setting definition has an invalid native shape.'
        }
        $definitionId = if ($definitionIdField.IsPresent) {
            $definitionIdField.Value
        } else {
            ''
        }

        $valueTokens = [System.Collections.Generic.List[string]]::new()
        $valueContainerCount = 0
        foreach ($valueProperty in @(
                @{ Name = 'choiceSettingValue'; Kind = 'Singular'; AllowIntegralNumber = $false; ValueOptional = $false }
                @{ Name = 'choiceSettingCollectionValue'; Kind = 'Collection'; AllowIntegralNumber = $false; ValueOptional = $false }
                @{ Name = 'simpleSettingValue'; Kind = 'Singular'; AllowIntegralNumber = $true; ValueOptional = $false }
                @{ Name = 'simpleSettingCollectionValue'; Kind = 'Collection'; AllowIntegralNumber = $true; ValueOptional = $false }
                @{ Name = 'groupSettingCollectionValue'; Kind = 'Collection'; AllowIntegralNumber = $false; ValueOptional = $true }
            )) {
            if (-not (Test-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName $valueProperty.Name)) {
                continue
            }
            $valueContainerCount++
            $valueContainer = Get-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName $valueProperty.Name
            if ($valueProperty.Kind -eq 'Singular') {
                if (-not (Test-PulseEndpointSecuritySettingValueNode -Node $valueContainer)) {
                    throw 'Endpoint Security setting value container has an invalid native shape.'
                }
                $valueNodes = @($valueContainer)
            } else {
                if ($null -eq $valueContainer -or
                    $valueContainer -is [string] -or
                    $valueContainer -is [System.Collections.IDictionary] -or
                    $valueContainer -isnot [System.Collections.IEnumerable]) {
                    throw 'Endpoint Security setting value container has an invalid native shape.'
                }
                $valueNodes = @($valueContainer)
                if ($valueNodes.Count -eq 0) {
                    throw 'Endpoint Security setting value container has an invalid native shape.'
                }
            }

            foreach ($valueNode in $valueNodes) {
                if (-not (Test-PulseEndpointSecuritySettingValueNode -Node $valueNode)) {
                    throw 'Endpoint Security setting value container has an invalid native shape.'
                }
                $valueField = Get-PulseEndpointSecuritySettingValueTokenField -Node $valueNode -PropertyName 'value' `
                    -AllowIntegralNumber:$valueProperty.AllowIntegralNumber
                if ((-not $valueProperty.ValueOptional -and -not $valueField.IsPresent) -or
                    ($valueField.IsPresent -and -not $valueField.IsValid)) {
                    throw 'Endpoint Security setting value has an invalid native shape.'
                }
                if ($valueField.IsValid -and $null -ne $valueField.Value) {
                    $valueTokens.Add($valueField.Value) | Out-Null
                }

                $children = Get-PulseEndpointSecurityNodeProperty -Node $valueNode -PropertyName 'children'
                foreach ($child in @($children)) { Add-SettingNode -Node $child }
            }
        }

        if ($valueContainerCount -gt 1 -or
            ($definitionIdField.IsPresent -and $valueContainerCount -eq 0) -or
            (-not $definitionIdField.IsPresent -and $valueContainerCount -gt 0)) {
            throw 'Endpoint Security setting definition has an invalid native shape.'
        }

        if ($definitionIdField.IsPresent -and $valueTokens.Count -eq 0 -and
            -not (Test-PulseEndpointSecurityNodeProperty -Node $Node -PropertyName 'groupSettingCollectionValue')) {
            $valueTokens.Add('__TenantPulse.EndpointSecuritySetting.UnknownShape__') | Out-Null
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
