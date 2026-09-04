<#
    Private: compose TenantPulse's built-in provider plans with validated caller overrides.

    The synthetic Pending entries in DatasetMap.psd1 are static manifest placeholders for
    composite datasets, not an operator wiring requirement. Every shipped plan is active in
    the normal public collection path. A caller-supplied entry replaces only the matching
    built-in plan. Every network-backed registration declares the exact GraphKit operation
    set it may call so the catalog-wide permission preflight can authorize the selected
    plan before the command dispatches. Caller overrides cannot claim the built-in
    no-network exemption and cannot use the legacy raw-scriptblock shape.
#>

function ConvertTo-PulseProviderPlanOperations {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Dataset,

        [AllowNull()]
        [AllowEmptyCollection()]
        $Operations,

        [switch] $AllowEmpty
    )

    $items = @($Operations)
    if (-not $AllowEmpty -and $items.Count -eq 0) {
        throw "ProviderPlanRegistry override for '$Dataset' must declare at least one Graph operation."
    }

    $normalized = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $items) {
        $type = $null
        $operation = $null
        $apiVersion = $null
        if ($null -ne $item -and $item -is [System.Collections.IDictionary]) {
            if ($item.Contains('Type')) { $type = [string] $item['Type'] }
            if ($item.Contains('Operation')) { $operation = [string] $item['Operation'] }
            if ($item.Contains('ApiVersion')) { $apiVersion = [string] $item['ApiVersion'] }
        }
        elseif ($null -ne $item) {
            if ($item.PSObject.Properties['Type']) { $type = [string] $item.Type }
            if ($item.PSObject.Properties['Operation']) { $operation = [string] $item.Operation }
            if ($item.PSObject.Properties['ApiVersion']) { $apiVersion = [string] $item.ApiVersion }
        }

        if ([string]::IsNullOrWhiteSpace($type) -or
            [string]::IsNullOrWhiteSpace($operation) -or
            $apiVersion -notin @('v1.0', 'beta')) {
            throw "ProviderPlanRegistry override for '$Dataset' has a malformed Graph operation declaration."
        }

        $key = '{0}/{1}' -f $type, $operation
        if (-not $seen.Add($key)) {
            throw "ProviderPlanRegistry override for '$Dataset' has a duplicate Graph operation declaration '$key'."
        }

        $normalized.Add([pscustomobject][ordered]@{
                Type       = $type
                Operation  = $operation
                ApiVersion = $apiVersion
            }) | Out-Null
    }

    return @($normalized)
}

function Resolve-PulseProviderPlanRegistry {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [AllowNull()]
        [hashtable] $Overrides
    )

    # Resolve the named plan at invocation time. Besides keeping the registry independent of
    # module build order, this lets tests and embedding hosts replace a plan through the
    # normal command-resolution seam instead of retaining a stale CommandInfo reference.
    $windowsDataProcessorPlan = {
        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym, $NetworkAbortState)
        Invoke-PulseWindowsDataProcessorPlan @PSBoundParameters
    }
    $intuneRbacPlan = {
        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym, $NetworkAbortState)
        Invoke-PulseIntuneRbacGroupProtectionPlan @PSBoundParameters
    }
    $endpointSecurityPlan = {
        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym, $NetworkAbortState)
        Invoke-PulseEndpointSecurityPolicyPlan @PSBoundParameters
    }
    $securityBaselinePlan = {
        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym, $NetworkAbortState)
        Invoke-PulseSecurityBaselinePlan @PSBoundParameters
    }
    $subscribedSkuLicensePlan = {
        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym, $NetworkAbortState)
        Invoke-PulseSubscribedSkuLicensePlan @PSBoundParameters
    }

    $registry = @{
        subscribedSkus                                    = @{
            Command = $subscribedSkuLicensePlan
            RequiresNetwork = $true
            SupportsNetworkAbortState = $true
            Operations = @(ConvertTo-PulseProviderPlanOperations -Dataset 'subscribedSkus' -Operations @(
                    @{ Type = 'SubscribedSku'; Operation = 'List'; ApiVersion = 'beta' }
                ))
        }
        # This disposition is the one built-in plan that is safe to run after an
        # authentication abort: it records a fixed platform outcome and performs no Graph
        # call. Unmarked plans, including caller overrides below, remain network-backed.
        dataProcessorServiceForWindowsFeaturesOnboarding = @{
            Command         = $windowsDataProcessorPlan
            RequiresNetwork = $false
            SupportsNetworkAbortState = $true
            Operations      = @(ConvertTo-PulseProviderPlanOperations `
                    -Dataset 'dataProcessorServiceForWindowsFeaturesOnboarding' -Operations @() -AllowEmpty)
        }
        intuneRbacGroupProtection                         = @{
            Command = $intuneRbacPlan
            RequiresNetwork = $true
            SupportsNetworkAbortState = $true
            Operations = @(ConvertTo-PulseProviderPlanOperations -Dataset 'intuneRbacGroupProtection' `
                    -Operations $script:PulseCompositeChildOperations['intuneRbacGroupProtection'])
        }
        endpointSecurityDiskEncryptionPolicies           = @{
            Command = $endpointSecurityPlan
            RequiresNetwork = $true
            SupportsNetworkAbortState = $true
            Operations = @(ConvertTo-PulseProviderPlanOperations -Dataset 'endpointSecurityDiskEncryptionPolicies' `
                    -Operations $script:PulseCompositeChildOperations['endpointSecurityDiskEncryptionPolicies'])
        }
        endpointSecurityLapsPolicies                     = @{
            Command = $endpointSecurityPlan
            RequiresNetwork = $true
            SupportsNetworkAbortState = $true
            Operations = @(ConvertTo-PulseProviderPlanOperations -Dataset 'endpointSecurityLapsPolicies' `
                    -Operations $script:PulseCompositeChildOperations['endpointSecurityLapsPolicies'])
        }
        securityBaselinesAssignedAndCurrent              = @{
            Command = $securityBaselinePlan
            RequiresNetwork = $true
            SupportsNetworkAbortState = $true
            Operations = @(ConvertTo-PulseProviderPlanOperations -Dataset 'securityBaselinesAssignedAndCurrent' `
                    -Operations $script:PulseCompositeChildOperations['securityBaselinesAssignedAndCurrent'])
        }
    }

    if ($null -ne $Overrides) {
        foreach ($dataset in $Overrides.Keys) {
            $override = $Overrides[$dataset]
            if ($null -eq $override) {
                throw "ProviderPlanRegistry override for '$dataset' cannot be null."
            }

            if ($override -isnot [System.Collections.IDictionary] -or -not $override.Contains('Command')) {
                throw "ProviderPlanRegistry override for '$dataset' must be a registration containing Command and Operations."
            }

            $command = $override['Command']
            if ($null -eq $command) {
                throw "ProviderPlanRegistry override for '$dataset' command cannot be null."
            }
            if (-not $override.Contains('Operations')) {
                throw "ProviderPlanRegistry override for '$dataset' must declare at least one Graph operation."
            }
            if ($command -isnot [scriptblock] -and $command -isnot [System.Management.Automation.CommandInfo]) {
                throw "ProviderPlanRegistry override for '$dataset' command must be a scriptblock or command."
            }

            $operations = @(ConvertTo-PulseProviderPlanOperations -Dataset $dataset -Operations $override['Operations'])
            $registry[$dataset] = @{
                Command         = $command
                RequiresNetwork = $true
                SupportsNetworkAbortState = $false
                Operations      = $operations
            }
        }
    }

    return $registry
}
