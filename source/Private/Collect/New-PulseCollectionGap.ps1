<#
    Private: construct one provider collection gap.

    A gap is a typed, provider-neutral explanation for missing scope inside a Partial
    collection outcome. Detail is intentionally nullable; all other fields identify the
    missing scope and the operation that could not provide it.
#>

$script:PulseCollectionFailureClasses = @(
    'DescriptorPending'
    'PlatformUnavailable'
    'PermissionDenied'
    'LicenseRequired'
    'GateUnknown'
    'DependencyUnavailable'
    'AuthenticationFailed'
    'DeadlineExpired'
    'Cancelled'
    'InvalidProviderData'
    'ProviderFailed'
    'Indeterminate'
)

function New-PulseCollectionGap {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Scope,

        [Parameter(Mandatory)]
        [ValidateSet('DescriptorPending', 'PlatformUnavailable', 'PermissionDenied', 'LicenseRequired', 'GateUnknown', 'DependencyUnavailable', 'AuthenticationFailed', 'DeadlineExpired', 'Cancelled', 'InvalidProviderData', 'ProviderFailed', 'Indeterminate')]
        [string] $FailureClass,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ReasonCode,

        [Parameter(Mandatory)]
        [AllowNull()]
        [hashtable] $Detail,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Operation,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ApiVersion
    )

    return [pscustomobject][ordered]@{
        Scope        = $Scope
        FailureClass = $FailureClass
        ReasonCode   = $ReasonCode
        Detail       = $Detail
        Operation    = $Operation
        ApiVersion   = $ApiVersion
    }
}
