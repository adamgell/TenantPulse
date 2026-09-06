<#
    TenantPulse-owned disposition plan for TP.INT.0009's Windows data processor dataset.

    Microsoft Learn publishes the beta resource type and its two Boolean properties, and a
    controlled Ivy24 read-only GET returned the expected singleton shape. It does not publish
    an official GET method page or an application-permission contract for this resource, and
    the exact required GraphKit 0.3.1 maintenance catalog has no matching descriptor. The plan therefore records a
    PlatformUnavailable outcome rather than inventing a descriptor or silently treating a
    missing catalog entry as a transient GraphKit release wait.

    This plan intentionally performs no Graph call. DatasetMap names this TenantPulse plan
    directly and carries no GraphKit Type/Operation/Pending tuple. The observed read is
    retained only as historical LiveProbe evidence; it is not production operation
    metadata and does not authorize a request.
#>

function Invoke-PulseWindowsDataProcessorPlan {
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
        [string] $TenantPseudonym,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $NetworkAbortState = $null
    )

    # Required by the common provider-plan contract; this no-network plan needs only Dataset.
    $null = $Context
    $null = $ManifestEntry
    $null = $ProfileId
    $null = $TenantPseudonym
    $null = $NetworkAbortState

    $detail = [ordered]@{
        Disposition = 'NoReleasedGraphContract'
        Response = [ordered]@{
            ResourceType = 'microsoft.graph.dataProcessorServiceForWindowsFeaturesOnboarding'
            Singleton    = $true
            Fields       = @(
                'hasValidWindowsLicense'
                'areDataProcessorServiceForWindowsFeaturesEnabled'
            )
            NativeBooleanFields = $true
        }
        GraphKit = [ordered]@{
            PackageVersion = '0.3.1'
            Descriptor     = 'Absent from exact required catalog'
        }
        LiveProbe = [ordered]@{
            Environment        = 'Ivy24'
            ReadOnly           = $true
            Method             = 'GET'
            ApiVersion         = 'beta'
            Path               = '/deviceManagement/dataProcessorServiceForWindowsFeaturesOnboarding'
            Outcome            = 'Succeeded'
            ResponseShape      = 'single object'
            NativeBooleanFields = $true
        }
        Permission = [ordered]@{
            Application = 'Unverified'
            Evidence = 'Microsoft Learn publishes no method or permissions contract for this resource; the app-only probe succeeded, but the permission grant analysis did not resolve a named application permission.'
        }
        RecheckTrigger = 'Re-evaluate when Microsoft publishes an official GET method and application-permission metadata, or a later GraphKit package adds this exact descriptor with RequiredPermissions; repeat the controlled read-only Ivy24 probe before removing the platform-unavailable disposition.'
    }

    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Skipped' -Rows @() -Gaps @() `
        -FailureClass 'PlatformUnavailable' -ReasonCode 'platform-unavailable' -Detail $detail `
        -Provider 'TenantPulse' -ApiVersion $null -Operations @()

}
