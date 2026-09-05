<#
    Private: build the deduped, ordinally-sorted collection manifest for a set of checks.

    Every check descriptor names the datasets it needs in Data.Datasets. A check that names
    one or more Data.Gates also implicitly needs subscribedSkus, because Intune/Entra gate
    decisions are derived from that collected license evidence. Multiple checks
    routinely share a dataset (e.g. two Conditional Access checks both reading
    conditionalAccessPolicies) - this walks every check exactly once, resolves each
    dataset name through the shared DatasetMap.psd1 table (the same map
    Import-PulseCheckCatalog cross-checks Data.Datasets against at catalog-load time), and
    returns one entry per DISTINCT dataset name. Direct Graph entries carry
    { Dataset; Type; Operation; ApiVersion; Pending }; provider-plan entries carry
    { Dataset; Provider; Plan; ApiVersion } and explicitly leave Type/Operation null. Pending is
    carried straight through only for direct descriptors so the collector can classify a
    future unreleased descriptor as Skipped without attempting a Graph call. Plan names
    the TenantPulse-owned implementation selected by the dataset-keyed provider registry;
    it is never reinterpreted as a GraphKit Type or Operation.

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

    IdFromDataset (Task 1.9 extension): a map entry may carry `IdFromDataset = '<name>'`,
    meaning that dataset must be collected FIRST and its first row's `id` fed to THIS
    entry's Get-GraphObject call as -Parameters @{ id = ... } (see Invoke-PulseCollection).
    Two things this function guarantees so that extension can rely on them:
        1. The dependency dataset is ALWAYS present in the returned manifest, even if no
           check declared it directly (organizationMdmAuthority needs 'organization'
           collected even though a check might reference only organizationMdmAuthority) -
           dependencies are resolved transitively and added the same way a directly-
           declared dataset would be, including the same "must exist in -DatasetMap or
           throw" check.
        2. Ordering is DEPENDENCY-FIRST: an entry with IdFromDataset is placed after its
           dependency in the returned array. Ties (same dependency depth) still break
           ordinally by Dataset name, so the result is deterministic. A dependency cycle
           (Dataset A depends on B which depends on A) is a hard error - it can never be
           satisfied at collection time.
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

    # Resolves (and, on first sight, ADDS) a dataset name into $entries, recursing to pull
    # in its IdFromDataset dependency (if any) first - so a dependency that no check
    # declared directly (organization, for organizationMdmAuthority) still ends up in the
    # manifest. -Chain tracks the in-progress recursion path so a dependency cycle is
    # reported clearly instead of overflowing the call stack.
    function Resolve-Entry {
        param(
            [string] $Name,
            [string] $RequestedBy,
            [string[]] $Chain = @()
        )

        if ($entries.Contains($Name)) {
            return
        }

        if (-not $DatasetMap.ContainsKey($Name)) {
            throw "Get-PulseCollectionManifest: check '$RequestedBy' references dataset '$Name', which is not present in the shared dataset map."
        }

        if ($Chain -contains $Name) {
            throw "Get-PulseCollectionManifest: dataset dependency cycle detected: $(($Chain + $Name) -join ' -> ')."
        }

        $mapEntry = $DatasetMap[$Name]
        $hasProviderPlan = $mapEntry.ContainsKey('Plan')
        $providerPlan = if ($hasProviderPlan) { [string] $mapEntry.Plan } else { $null }
        $provider = if ($mapEntry.ContainsKey('Provider')) { [string] $mapEntry.Provider } else { $null }
        if ($hasProviderPlan) {
            if ([string]::IsNullOrWhiteSpace($providerPlan)) {
                throw "Get-PulseCollectionManifest: provider-plan dataset '$Name' has an empty Plan value."
            }
            foreach ($forbiddenField in @('Type', 'Operation', 'Pending', 'ExpectedThrottleClass', 'ExpectedReplayPolicy')) {
                if ($mapEntry.ContainsKey($forbiddenField)) {
                    throw "Get-PulseCollectionManifest: provider-plan dataset '$Name' also declares forbidden Graph descriptor metadata '$forbiddenField'."
                }
            }
            if ($mapEntry.ContainsKey('Provider') -and
                -not [string]::Equals($provider, 'TenantPulse', [System.StringComparison]::Ordinal)) {
                throw "Get-PulseCollectionManifest: provider-plan dataset '$Name' declares unsupported Provider '$provider'."
            }
        }

        $isPending = -not $hasProviderPlan -and $mapEntry.ContainsKey('Pending') -and [bool] $mapEntry.Pending
        $idFromDataset = if ($mapEntry.ContainsKey('IdFromDataset')) { [string] $mapEntry.IdFromDataset } else { $null }
        $type = if ($mapEntry.ContainsKey('Type')) { $mapEntry.Type } else { $null }
        $operation = if ($mapEntry.ContainsKey('Operation')) { $mapEntry.Operation } else { $null }
        $apiVersion = if ($mapEntry.ContainsKey('ApiVersion')) { $mapEntry.ApiVersion } else { $null }

        if ($idFromDataset) {
            Resolve-Entry -Name $idFromDataset -RequestedBy $RequestedBy -Chain ($Chain + $Name)
        }

        $entries[$Name] = [pscustomobject]@{
            Dataset       = $Name
            Provider      = $provider
            Type          = $type
            Operation     = $operation
            ApiVersion    = $apiVersion
            Pending       = $isPending
            IdFromDataset = $idFromDataset
            Plan          = $providerPlan
        }
    }

    foreach ($check in $Checks) {
        # Gate evidence is a collection dependency just as real as Data.Datasets. Without
        # this implicit dependency, a narrowed assessment can collect every check dataset
        # successfully and then mark every gated check NotApplicable because subscribedSkus
        # was never requested. Resolve it through the same map so it is deduplicated,
        # validated, and deterministically ordered like every explicit dataset.
        $gateNames = @($check.Data.Gates) | Where-Object { -not [string]::IsNullOrEmpty($_) }
        if ($gateNames.Count -gt 0) {
            Resolve-Entry -Name 'subscribedSkus' -RequestedBy "$($check.Id) gate evidence"
        }

        # Data.Expansions (Task 3.2): an artifact-only check (e.g. TP.INT.0006) has no
        # Data.Datasets at all, so $check.Data.Datasets is $null - `@($null)` wraps that
        # into a one-element array containing $null rather than an empty array (see
        # Invoke-PulseEvaluation's own identical fix/comment for the same PowerShell
        # quirk). This collection manifest ignores Data.Expansions entirely, by design
        # (expansion artifacts derive from the expansion pipeline post-collection, not
        # from anything this manifest requests) - filtering the null here is what makes
        # that "ignores" real rather than a crash.
        $datasetNames = @($check.Data.Datasets) | Where-Object { -not [string]::IsNullOrEmpty($_) }

        foreach ($name in $datasetNames) {
            Resolve-Entry -Name $name -RequestedBy $check.Id
        }
    }

    if ($entries.Count -eq 0) {
        return @()
    }

    # Dependency-first ordering: compute each entry's dependency depth (0 = no
    # IdFromDataset), then sort by (depth, Dataset name ordinal) - a dependency is always
    # depth-lower than its dependent, and ties break the same ordinal way every other sort
    # in this codebase does.
    $depthOf = @{}
    function Get-Depth {
        param([string] $Name)
        if ($depthOf.ContainsKey($Name)) {
            return $depthOf[$Name]
        }
        $entry = $entries[$Name]
        $depth = if ($entry.IdFromDataset) { 1 + (Get-Depth -Name $entry.IdFromDataset) } else { 0 }
        $depthOf[$Name] = $depth
        return $depth
    }

    $names = [string[]] @($entries.Keys)
    foreach ($name in $names) { Get-Depth -Name $name | Out-Null }

    $order = [int[]] (0 .. ($names.Count - 1))
    $comparison = [System.Comparison[int]] {
        param($a, $b)
        $byDepth = $depthOf[$names[$a]].CompareTo($depthOf[$names[$b]])
        if ($byDepth -ne 0) { return $byDepth }
        return [string]::CompareOrdinal($names[$a], $names[$b])
    }
    [System.Array]::Sort($order, $comparison)

    return @(foreach ($i in $order) { $entries[$names[$i]] })
}
