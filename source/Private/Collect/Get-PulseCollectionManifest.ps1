<#
    Private: build the deduped, ordinally-sorted collection manifest for a set of checks.

    Every check descriptor names the datasets it needs in Data.Datasets. Multiple checks
    routinely share a dataset (e.g. two Conditional Access checks both reading
    conditionalAccessPolicies) - this walks every check exactly once, resolves each
    dataset name through the shared DatasetMap.psd1 table (the same map
    Import-PulseCheckCatalog cross-checks Data.Datasets against at catalog-load time), and
    returns one entry per DISTINCT dataset name: { Dataset; Type; Operation; ApiVersion;
    Pending }. Pending is carried straight through from the map (see DatasetMap.psd1's
    header) so the collector can classify a pending dataset as Skipped without attempting
    a Graph call or resolving a descriptor that does not exist yet.

    A dataset name a check references that is absent from -DatasetMap is a hard error -
    Import-PulseCheckCatalog should already have caught this at catalog-load time when a
    map is available, but this function re-validates independently (it may be called with
    a manually-constructed -Checks array that bypassed the catalog loader, e.g. in tests)
    and throws naming the offending check's Id so the failure is actionable.

    Ordinal sort: the returned array is sorted by Dataset name using
    [string]::CompareOrdinal via [System.StringComparer]::Ordinal, matching every other
    "deterministic ordering everywhere" sort in this codebase (see
    ConvertTo-PulseCanonicalJson and Import-PulseCheckCatalog) - never a culture-aware
    Sort-Object, which is non-deterministic across locales/hosts.
#>

function Get-PulseCollectionManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Checks,

        [Parameter(Mandatory)]
        [hashtable] $DatasetMap
    )

    $entries = [ordered]@{}

    foreach ($check in $Checks) {
        $datasetNames = @($check.Data.Datasets)

        foreach ($name in $datasetNames) {
            if ($entries.Contains($name)) {
                continue
            }

            if (-not $DatasetMap.ContainsKey($name)) {
                throw "Get-PulseCollectionManifest: check '$($check.Id)' references dataset '$name', which is not present in the shared dataset map."
            }

            $mapEntry = $DatasetMap[$name]
            $isPending = $mapEntry.ContainsKey('Pending') -and [bool] $mapEntry.Pending

            $entries[$name] = [pscustomobject]@{
                Dataset    = $name
                Type       = $mapEntry.Type
                Operation  = $mapEntry.Operation
                ApiVersion = $mapEntry.ApiVersion
                Pending    = $isPending
            }
        }
    }

    if ($entries.Count -eq 0) {
        return @()
    }

    $names = [string[]] @($entries.Keys)
    [System.Array]::Sort($names, [System.StringComparer]::Ordinal)

    return @(foreach ($name in $names) { $entries[$name] })
}
