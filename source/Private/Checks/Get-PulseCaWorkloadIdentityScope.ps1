<#
    Classifies Conditional Access workload- and agent-identity selectors without
    exposing the selected object identifiers. The v1 service-principal fields and
    beta agent-identity fields share one fail-closed contract so awareness reporting
    and sign-in-scope analysis cannot disagree about malformed Graph shapes.
#>
function Get-PulseCaWorkloadIdentityScope {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $ClientApplications
    )

    function ConvertTo-LocalStringArray {
        param([AllowNull()] $Value)
        if ($null -eq $Value) { return , ([string[]] @()) }
        return , ([string[]] @($Value | ForEach-Object { [string] $_ }))
    }

    function Test-GraphObjectId {
        param([AllowNull()] [string] $Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        $parsed = [guid]::Empty
        return [guid]::TryParse($Value, [ref] $parsed)
    }

    function Test-CaFilter {
        param([AllowNull()] $Filter)
        if ($null -eq $Filter) { return $true }
        $mode = [string] (Get-PulseSettingsCatalogValueProperty -Node $Filter -PropertyName 'mode')
        $rule = [string] (Get-PulseSettingsCatalogValueProperty -Node $Filter -PropertyName 'rule')
        return $mode -in @('include', 'exclude') -and -not [string]::IsNullOrWhiteSpace($rule)
    }

    $isPresent = $null -ne $ClientApplications -and
        [bool] (Get-PulseSettingsCatalogValueProperty -Node $ClientApplications -PropertyName 'present')
    if (-not $isPresent) {
        return [pscustomobject][ordered]@{
            State                                  = 'Absent'
            Complete                               = $true
            ReasonCodes                            = [string[]] @()
            HasValidInclude                        = $false
            IncludedServicePrincipalCount          = 0
            ExcludedServicePrincipalCount          = 0
            IncludesAllServicePrincipals           = $false
            HasServicePrincipalFilter              = $false
            IncludedAgentIdServicePrincipalCount   = 0
            ExcludedAgentIdServicePrincipalCount   = 0
            IncludesAllAgentIdServicePrincipals    = $false
            HasAgentIdServicePrincipalFilter       = $false
        }
    }

    [string[]] $includedServicePrincipals = ConvertTo-LocalStringArray (
        Get-PulseSettingsCatalogValueProperty -Node $ClientApplications -PropertyName 'includeServicePrincipals'
    )
    [string[]] $excludedServicePrincipals = ConvertTo-LocalStringArray (
        Get-PulseSettingsCatalogValueProperty -Node $ClientApplications -PropertyName 'excludeServicePrincipals'
    )
    [string[]] $includedAgentIdServicePrincipals = ConvertTo-LocalStringArray (
        Get-PulseSettingsCatalogValueProperty -Node $ClientApplications -PropertyName 'includeAgentIdServicePrincipals'
    )
    [string[]] $excludedAgentIdServicePrincipals = ConvertTo-LocalStringArray (
        Get-PulseSettingsCatalogValueProperty -Node $ClientApplications -PropertyName 'excludeAgentIdServicePrincipals'
    )
    $servicePrincipalFilter = Get-PulseSettingsCatalogValueProperty -Node $ClientApplications -PropertyName 'servicePrincipalFilter'
    $agentIdServicePrincipalFilter = Get-PulseSettingsCatalogValueProperty -Node $ClientApplications -PropertyName 'agentIdServicePrincipalFilter'

    $reasons = [System.Collections.Generic.List[string]]::new()
    $includesAllServicePrincipals = $false
    $includedServicePrincipalCount = 0
    foreach ($value in $includedServicePrincipals) {
        if ([string]::Equals($value, 'ServicePrincipalsInMyTenant', [System.StringComparison]::Ordinal)) {
            $includesAllServicePrincipals = $true
        } elseif (Test-GraphObjectId -Value $value) {
            $includedServicePrincipalCount++
        } else {
            $reasons.Add('invalid-included-service-principal')
        }
    }

    $excludedServicePrincipalCount = 0
    foreach ($value in $excludedServicePrincipals) {
        if (Test-GraphObjectId -Value $value) { $excludedServicePrincipalCount++ }
        else { $reasons.Add('invalid-excluded-service-principal') }
    }

    $includesAllAgentIdServicePrincipals = $false
    $includedAgentIdServicePrincipalCount = 0
    foreach ($value in $includedAgentIdServicePrincipals) {
        if ([string]::Equals($value, 'All', [System.StringComparison]::Ordinal)) {
            $includesAllAgentIdServicePrincipals = $true
        } elseif (Test-GraphObjectId -Value $value) { $includedAgentIdServicePrincipalCount++ }
        else { $reasons.Add('invalid-included-agent-id-service-principal') }
    }

    $excludedAgentIdServicePrincipalCount = 0
    foreach ($value in $excludedAgentIdServicePrincipals) {
        if (Test-GraphObjectId -Value $value) { $excludedAgentIdServicePrincipalCount++ }
        else { $reasons.Add('invalid-excluded-agent-id-service-principal') }
    }

    $hasServicePrincipalFilter = $null -ne $servicePrincipalFilter
    if ($hasServicePrincipalFilter -and -not (Test-CaFilter -Filter $servicePrincipalFilter)) {
        $reasons.Add('invalid-service-principal-filter')
    }
    $hasAgentIdServicePrincipalFilter = $null -ne $agentIdServicePrincipalFilter
    if ($hasAgentIdServicePrincipalFilter -and -not (Test-CaFilter -Filter $agentIdServicePrincipalFilter)) {
        $reasons.Add('invalid-agent-id-service-principal-filter')
    }

    $hasValidInclude = $includesAllServicePrincipals -or $includesAllAgentIdServicePrincipals -or
        $includedServicePrincipalCount -gt 0 -or
        $includedAgentIdServicePrincipalCount -gt 0 -or
        ($hasServicePrincipalFilter -and (Test-CaFilter -Filter $servicePrincipalFilter)) -or
        ($hasAgentIdServicePrincipalFilter -and (Test-CaFilter -Filter $agentIdServicePrincipalFilter))
    if (-not $hasValidInclude) {
        $reasons.Add('missing-workload-identity-selector')
    }

    $state = if ($reasons.Count -gt 0) { 'Malformed' } else { 'Valid' }
    [pscustomobject][ordered]@{
        State                                  = $state
        Complete                               = ($state -eq 'Valid')
        ReasonCodes                            = [string[]] @($reasons | Select-Object -Unique)
        HasValidInclude                        = $hasValidInclude
        IncludedServicePrincipalCount          = $includedServicePrincipalCount
        ExcludedServicePrincipalCount          = $excludedServicePrincipalCount
        IncludesAllServicePrincipals           = $includesAllServicePrincipals
        HasServicePrincipalFilter              = $hasServicePrincipalFilter
        IncludedAgentIdServicePrincipalCount   = $includedAgentIdServicePrincipalCount
        ExcludedAgentIdServicePrincipalCount   = $excludedAgentIdServicePrincipalCount
        IncludesAllAgentIdServicePrincipals    = $includesAllAgentIdServicePrincipals
        HasAgentIdServicePrincipalFilter       = $hasAgentIdServicePrincipalFilter
    }
}
