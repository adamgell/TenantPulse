<#
    Private: validate an Azure resource ID and optional tenant/subscription binding.

    ARM resource IDs are path-shaped, not Graph URIs. A bound subscription or
    tenant mismatch is a hard error so a token for one estate cannot be aimed at
    another.
#>

function Test-PulseArmResourceId {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ResourceId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $BoundTenantId = $null,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $BoundSubscriptionId = $null
    )

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        throw 'ARM resource ID is required.'
    }

    if ($ResourceId.StartsWith('http://', [System.StringComparison]::OrdinalIgnoreCase) -or
        $ResourceId.StartsWith('https://', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "ARM resource ID '{0}' is a URI, not a resource ID." -f $ResourceId
    }

    if (-not $ResourceId.StartsWith('/')) {
        throw "ARM resource ID '{0}' must be an absolute path starting with '/'." -f $ResourceId
    }

    if ($ResourceId.Contains('?') -or $ResourceId.Contains('#') -or $ResourceId.Contains('\') -or
        $ResourceId.Contains('%')) {
        throw "ARM resource ID '{0}' must not include a query, fragment, backslash, or percent-encoding." -f $ResourceId
    }

    if ($ResourceId.Contains('//') -or $ResourceId.Contains('/../') -or $ResourceId.EndsWith('/..') -or
        $ResourceId.StartsWith('/../') -or $ResourceId.Contains('/./') -or $ResourceId.EndsWith('/.')) {
        throw "ARM resource ID '{0}' must not contain empty or traversal segments." -f $ResourceId
    }

    $normalized = $ResourceId.TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($normalized) -or $normalized -eq '/') {
        throw 'ARM resource ID must name a resource, not the root path.'
    }

    $segments = $normalized.Split('/')
    if ($segments.Count -lt 2 -or -not [string]::IsNullOrEmpty($segments[0])) {
        throw "ARM resource ID '{0}' is malformed." -f $ResourceId
    }

    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $index = 1
    $subscriptionId = $null
    $resourceGroup = $null
    $providerNamespace = $null
    $embeddedTenantId = $null

    if ($segments[$index] -eq 'tenants') {
        if (($index + 1) -ge $segments.Count -or $segments[$index + 1] -notmatch $guidPattern) {
            throw "ARM resource ID '{0}' has a malformed tenant segment." -f $ResourceId
        }
        $embeddedTenantId = $segments[$index + 1].ToLowerInvariant()
        $index += 2
    }

    if ($index -lt $segments.Count -and [string]::Equals($segments[$index], 'subscriptions', [System.StringComparison]::OrdinalIgnoreCase)) {
        if (($index + 1) -ge $segments.Count -or $segments[$index + 1] -notmatch $guidPattern) {
            throw "ARM resource ID '{0}' has a malformed subscription segment." -f $ResourceId
        }
        $subscriptionId = $segments[$index + 1].ToLowerInvariant()
        $index += 2
        if ($index -lt $segments.Count -and [string]::Equals($segments[$index], 'resourceGroups', [System.StringComparison]::OrdinalIgnoreCase)) {
            if (($index + 1) -ge $segments.Count -or [string]::IsNullOrWhiteSpace($segments[$index + 1])) {
                throw "ARM resource ID '{0}' has a malformed resource group segment." -f $ResourceId
            }
            $resourceGroup = $segments[$index + 1]
            $index += 2
        }
    }

    if ($index -lt $segments.Count) {
        if (-not [string]::Equals($segments[$index], 'providers', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "ARM resource ID '{0}' is not an ARM path (Graph-shaped and other non-ARM IDs are rejected)." -f $ResourceId
        }
        if (($index + 1) -ge $segments.Count -or $segments[$index + 1] -notmatch '^[A-Za-z0-9]+(\.[A-Za-z0-9]+)+$') {
            throw "ARM resource ID '{0}' has a malformed provider namespace." -f $ResourceId
        }
        $providerNamespace = $segments[$index + 1].ToLowerInvariant()
        $index += 2
        if ((($segments.Count - $index) % 2) -ne 0) {
            throw "ARM resource ID '{0}' has an incomplete type/name pair." -f $ResourceId
        }
    }

    if ($null -eq $providerNamespace -and $null -eq $subscriptionId) {
        throw "ARM resource ID '{0}' must include a provider namespace or a subscription." -f $ResourceId
    }

    if (-not [string]::IsNullOrWhiteSpace($BoundSubscriptionId)) {
        if ($BoundSubscriptionId -notmatch $guidPattern) {
            throw "Bound ARM subscription '{0}' is not a GUID." -f $BoundSubscriptionId
        }
        if (-not [string]::IsNullOrWhiteSpace($subscriptionId) -and
            -not [string]::Equals($subscriptionId, $BoundSubscriptionId, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "ARM resource ID subscription '{0}' does not match the bound subscription '{1}'." -f $subscriptionId, $BoundSubscriptionId
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($BoundTenantId)) {
        if ($BoundTenantId -notmatch $guidPattern) {
            throw "Bound ARM tenant '{0}' is not a GUID." -f $BoundTenantId
        }
        if (-not [string]::IsNullOrWhiteSpace($embeddedTenantId) -and
            -not [string]::Equals($embeddedTenantId, $BoundTenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "ARM resource ID tenant '{0}' does not match the bound tenant '{1}'." -f $embeddedTenantId, $BoundTenantId
        }
    }

    return [pscustomobject][ordered]@{
        ResourceId        = $normalized
        SubscriptionId    = $subscriptionId
        ResourceGroup     = $resourceGroup
        ProviderNamespace = $providerNamespace
        TenantId          = $embeddedTenantId
        IsTenantLevel     = [string]::IsNullOrWhiteSpace($subscriptionId)
    }
}
