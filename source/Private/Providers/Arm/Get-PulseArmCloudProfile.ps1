<#
    Private: ARM cloud authority and token audience.

    ARM traffic never uses a Microsoft Graph host or Graph permission metadata.
    The audience is the ARM resource application URI with `/.default`.
#>

function Get-PulseArmCloudProfile {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateSet('Global', 'USGov', 'China')]
        [string] $Cloud = 'Global'
    )

    $authority = switch ($Cloud) {
        'Global' { 'management.azure.com' }
        'USGov' { 'management.usgovcloudapi.net' }
        'China' { 'management.chinacloudapi.cn' }
    }

    $baseUri = [uri] ('https://{0}/' -f $authority)
    return [pscustomobject][ordered]@{
        Cloud     = $Cloud
        Authority = $authority
        Audience  = 'https://{0}/.default' -f $authority
        BaseUri   = $baseUri
    }
}
