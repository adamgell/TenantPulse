<#
    Private: Azure RBAC actions and the deferred Intune diagnostic-settings contract.

    ARM authorization is Azure RBAC, not Microsoft Graph application permissions.
    The diagnostic-settings API version stays Unproven until a protected live read
    exists. This function never invents a Graph Type/Operation pair.
#>

function Get-PulseArmRbacRequirement {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [ValidateSet('diagnosticSettings')]
        [string] $Operation = 'diagnosticSettings'
    )

    $null = $Operation
    return [string[]]@('Microsoft.Insights/diagnosticSettings/read')
}

function Get-PulseArmDiagnosticSettingsContract {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [pscustomobject][ordered]@{
        Dataset           = 'intuneDiagnosticSettings'
        Provider          = 'ARM'
        Cloud             = 'Global'
        ResourceId        = '/providers/microsoft.intune'
        ChildProvider     = 'microsoft.insights'
        ChildType         = 'diagnosticSettings'
        Method            = 'GET'
        ApiVersion        = $null
        ApiVersionStatus  = 'Unproven'
        Disposition       = 'DeferredUntilLiveContract'
        ReplayPolicy      = 'Safe'
        ThrottleClass     = 'Read'
        RbacActions       = Get-PulseArmRbacRequirement -Operation 'diagnosticSettings'
        MissingDependency = 'GraphKit.Auth'
        RecheckTrigger    = 'Re-evaluate after GraphKit.Auth exists and a protected read-only diagnostic-settings proof succeeds. Do not add a Graph descriptor or TP.INT.0010 until that proof exists.'
    }
}
