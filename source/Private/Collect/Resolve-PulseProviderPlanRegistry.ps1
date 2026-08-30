<#
    Private: compose TenantPulse's built-in provider plans with optional caller overrides.

    The synthetic Pending entries in DatasetMap.psd1 are static manifest placeholders for
    composite datasets, not an operator wiring requirement. Every shipped plan is active in
    the normal public collection path. A caller-supplied entry replaces only the matching
    built-in plan, which keeps the existing test/extension seam without making released
    capability depend on an undocumented parameter.
#>

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
        subscribedSkus                                    = @{ Command = $subscribedSkuLicensePlan; RequiresNetwork = $true; SupportsNetworkAbortState = $true }
        # This disposition is the one built-in plan that is safe to run after an
        # authentication abort: it records a fixed platform outcome and performs no Graph
        # call. Unmarked plans, including caller overrides below, remain network-backed.
        dataProcessorServiceForWindowsFeaturesOnboarding = @{
            Command         = $windowsDataProcessorPlan
            RequiresNetwork = $false
            SupportsNetworkAbortState = $true
        }
        intuneRbacGroupProtection                         = @{ Command = $intuneRbacPlan; RequiresNetwork = $true; SupportsNetworkAbortState = $true }
        endpointSecurityDiskEncryptionPolicies           = @{ Command = $endpointSecurityPlan; RequiresNetwork = $true; SupportsNetworkAbortState = $true }
        endpointSecurityLapsPolicies                     = @{ Command = $endpointSecurityPlan; RequiresNetwork = $true; SupportsNetworkAbortState = $true }
        securityBaselinesAssignedAndCurrent              = @{ Command = $securityBaselinePlan; RequiresNetwork = $true; SupportsNetworkAbortState = $true }
    }

    if ($null -ne $Overrides) {
        foreach ($dataset in $Overrides.Keys) {
            $override = $Overrides[$dataset]
            if ($null -eq $override) {
                throw "ProviderPlanRegistry override for '$dataset' cannot be null."
            }

            # RequiresNetwork = false is reserved for the built-in Windows disposition
            # above. A caller may use the same registration shape to supply its command,
            # but cannot grant its own plan the post-auth-abort exemption.
            if ($override -is [System.Collections.IDictionary] -and $override.Contains('Command')) {
                if ($null -eq $override.Command) {
                    throw "ProviderPlanRegistry override for '$dataset' command cannot be null."
                }

                $registry[$dataset] = @{
                    Command         = $override.Command
                    RequiresNetwork = $true
                }
            } else {
                $registry[$dataset] = $override
            }
        }
    }

    return $registry
}
