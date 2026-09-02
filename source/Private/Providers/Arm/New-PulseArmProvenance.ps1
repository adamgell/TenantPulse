<#
    Private: ARM snapshot provenance.

    Graph and ARM provenance stay distinguishable: ARM records authority, audience,
    resource ID, and Azure RBAC, and never Graph Type/Operation or GraphKit row
    stamps.
#>

function New-PulseArmProvenance {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceId,

        [Parameter()]
        [AllowNull()]
        [string] $ApiVersion = $null,

        [Parameter()]
        [ValidateSet('Global', 'USGov', 'China')]
        [string] $Cloud = 'Global',

        [Parameter()]
        [AllowNull()]
        [string] $BoundTenantId = $null,

        [Parameter()]
        [AllowNull()]
        [string] $BoundSubscriptionId = $null
    )

    $profile = Get-PulseArmCloudProfile -Cloud $Cloud
    $parsed = Test-PulseArmResourceId -ResourceId $ResourceId -BoundTenantId $BoundTenantId `
        -BoundSubscriptionId $BoundSubscriptionId

    return [pscustomobject][ordered]@{
        Provider            = 'ARM'
        Cloud               = $Cloud
        Authority           = $profile.Authority
        Audience            = $profile.Audience
        ResourceId          = $parsed.ResourceId
        ApiVersion          = $ApiVersion
        Method              = 'GET'
        ReplayPolicy        = 'Safe'
        ThrottleClass       = 'Read'
        RbacActions         = Get-PulseArmRbacRequirement -Operation 'diagnosticSettings'
        BoundTenantId       = $BoundTenantId
        BoundSubscriptionId = $BoundSubscriptionId
    }
}

function ConvertTo-PulseArmProvenanceHashtable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Provenance
    )

    $table = [ordered]@{}
    foreach ($property in $Provenance.PSObject.Properties) {
        $table[$property.Name] = $property.Value
    }
    return $table
}
