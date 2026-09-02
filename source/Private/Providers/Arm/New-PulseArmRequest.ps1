<#
    Private: construct one ARM GET request.

    The request carries ARM authority, audience, resource ID, API version, and
    Azure RBAC. It never carries Graph Type/Operation metadata or a token.
#>

function New-PulseArmRequest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ApiVersion,

        [Parameter()]
        [ValidateSet('Global', 'USGov', 'China')]
        [string] $Cloud = 'Global',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ChildProvider = 'microsoft.insights',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ChildType = 'diagnosticSettings',

        [Parameter()]
        [AllowNull()]
        [string] $BoundTenantId = $null,

        [Parameter()]
        [AllowNull()]
        [string] $BoundSubscriptionId = $null
    )

    $null = Test-PulseArmApiVersion -ApiVersion $ApiVersion
    $parsed = Test-PulseArmResourceId -ResourceId $ResourceId -BoundTenantId $BoundTenantId `
        -BoundSubscriptionId $BoundSubscriptionId
    $profile = Get-PulseArmCloudProfile -Cloud $Cloud

    $relative = '{0}/providers/{1}/{2}' -f $parsed.ResourceId, $ChildProvider.Trim('/'), $ChildType.Trim('/')
    $builder = [System.UriBuilder]::new($profile.BaseUri)
    $builder.Path = $relative
    $builder.Query = 'api-version={0}' -f $ApiVersion
    $uri = $builder.Uri
    $null = Test-PulseArmAuthority -Uri $uri -Cloud $Cloud

    return [pscustomobject][ordered]@{
        Provider       = 'ARM'
        Cloud          = $Cloud
        Authority      = $profile.Authority
        Audience       = $profile.Audience
        ResourceId     = $parsed.ResourceId
        ChildProvider  = $ChildProvider
        ChildType      = $ChildType
        Method         = 'GET'
        ApiVersion     = $ApiVersion
        Uri            = $uri
        ReplayPolicy   = 'Safe'
        ThrottleClass  = 'Read'
        RbacActions    = Get-PulseArmRbacRequirement -Operation 'diagnosticSettings'
    }
}
