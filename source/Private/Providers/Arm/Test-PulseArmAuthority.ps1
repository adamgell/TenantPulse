<#
    Private: refuse to attach an ARM credential to any URI that is not the bound
    Resource Manager authority over HTTPS port 443.

    A nextLink is opaque but never trusted. This guard throws on violation and
    never returns `$false`; a silent downgrade would leak an ARM token.
#>

function Get-PulseArmUriAuthority {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [uri] $Uri
    )

    $hostName = $Uri.Host.ToLowerInvariant()
    $defaultPort = if ($Uri.Scheme -eq 'https') { 443 } elseif ($Uri.Scheme -eq 'http') { 80 } else { -1 }
    if ($Uri.Port -ne $defaultPort) {
        return '{0}:{1}' -f $hostName, $Uri.Port
    }

    return $hostName
}

function Test-PulseArmAuthority {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [uri] $Uri,

        [Parameter()]
        [ValidateSet('Global', 'USGov', 'China')]
        [string] $Cloud = 'Global'
    )

    if ($null -eq $Uri -or -not $Uri.IsAbsoluteUri) {
        throw 'Refusing to attach an ARM credential to a relative or empty nextLink; an absolute HTTPS URI is required.'
    }

    if ($Uri.Scheme -ne 'https') {
        throw "Refusing to attach an ARM credential to non-HTTPS authority '{0}'." -f $Uri.Authority
    }

    if ($Uri.Port -ne 443) {
        throw "Refusing to attach an ARM credential to authority '{0}' - only port 443 is permitted." -f $Uri.Authority
    }

    $expected = Get-PulseArmCloudProfile -Cloud $Cloud
    $expectedAuthority = $expected.Authority
    $actualAuthority = Get-PulseArmUriAuthority -Uri $Uri
    if ($actualAuthority -cne $expectedAuthority) {
        throw (
            "Untrusted ARM authority '{0}' - expected '{1}' for cloud '{2}'. " +
            'Refusing to attach a bearer token.'
        ) -f $actualAuthority, $expectedAuthority, $Cloud
    }

    return $true
}
