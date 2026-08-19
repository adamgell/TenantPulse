<#
    Private: collect TP.INT.0029 security-baseline assignment/version state.

    GraphKit 0.2.2 releases the reusable Settings Catalog policy and assignment primitives:
    ConfigurationPolicy.ListBeta and ConfigurationPolicyAssignment.ListBeta. It does not
    release an official, reusable primitive for the security-baseline template family,
    version, or deprecation metadata needed by this check. The old composite Walk descriptor
    is intentionally not a substitute for that missing service contract.

    Until Microsoft exposes a supportable metadata operation and GraphKit releases its exact
    descriptor, this plan returns an explicit PlatformUnavailable outcome. It validates the
    two released primitives before returning, but does not call them and does not invent
    baseline rows from policy or assignment data that cannot establish version state. The
    exact recheck trigger is carried in Detail so an operator can distinguish a platform
    limitation from a package or permission failure.
#>

function Invoke-PulseSecurityBaselinePlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Context,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Dataset,

        [Parameter(Mandatory)]
        [pscustomobject] $ManifestEntry,

        [Parameter(Mandatory)]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [string] $TenantPseudonym
    )

    # These are the only released primitives that can participate in this composite. The
    # assignment response is authoritative for assignment presence, but neither response can
    # establish template version/deprecation, so no network call is honest until that final
    # contract exists.
    $descriptorSpecs = @(
        @{ Type = 'ConfigurationPolicy'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'ConfigurationPolicyAssignment'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    )

    foreach ($spec in $descriptorSpecs) {
        Assert-PulseReadOnlyDescriptor -Type $spec.Type -Operation $spec.Operation -ApiVersion $spec.ApiVersion
    }

    $apiVersion = if ($ManifestEntry.PSObject.Properties['ApiVersion'] -and $ManifestEntry.ApiVersion) {
        [string] $ManifestEntry.ApiVersion
    } else {
        'beta'
    }

    $recheckTrigger = 'Recheck when GraphKit publishes a released read-only security-baseline metadata primitive exposing template family, version, and deprecation state, followed by a controlled live response-shape and permission verification.'

    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Skipped' -Rows @() -Gaps @() `
        -FailureClass 'PlatformUnavailable' -ReasonCode 'platform-unavailable' `
        -Detail @{
            unsupportedContract = 'Security-baseline template family/version/deprecation metadata has no released reusable Graph primitive in GraphKit 0.2.2.'
            releasedDescriptors = @('ConfigurationPolicy.ListBeta', 'ConfigurationPolicyAssignment.ListBeta')
            missingMetadata = @('templateFamily', 'version', 'isDeprecated')
            recheckTrigger = $recheckTrigger
        } `
        -Provider 'GraphKit' -ApiVersion $apiVersion `
        -Operations @('ConfigurationPolicy.ListBeta', 'ConfigurationPolicyAssignment.ListBeta')
}
