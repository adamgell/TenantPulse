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
        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym)
        Invoke-PulseWindowsDataProcessorPlan @PSBoundParameters
    }
    $intuneRbacPlan = {
        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym)
        Invoke-PulseIntuneRbacGroupProtectionPlan @PSBoundParameters
    }
    $endpointSecurityPlan = {
        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym)
        Invoke-PulseEndpointSecurityPolicyPlan @PSBoundParameters
    }
    $securityBaselinePlan = {
        param($Context, $Dataset, $ManifestEntry, $ProfileId, $TenantPseudonym)
        Invoke-PulseSecurityBaselinePlan @PSBoundParameters
    }

    $registry = @{
        dataProcessorServiceForWindowsFeaturesOnboarding = $windowsDataProcessorPlan
        intuneRbacGroupProtection                         = $intuneRbacPlan
        endpointSecurityDiskEncryptionPolicies           = $endpointSecurityPlan
        endpointSecurityLapsPolicies                     = $endpointSecurityPlan
        securityBaselinesAssignedAndCurrent              = $securityBaselinePlan
    }

    if ($null -ne $Overrides) {
        foreach ($dataset in $Overrides.Keys) {
            $override = $Overrides[$dataset]
            if ($null -eq $override) {
                throw "ProviderPlanRegistry override for '$dataset' cannot be null."
            }
            $registry[$dataset] = $override
        }
    }

    return $registry
}
