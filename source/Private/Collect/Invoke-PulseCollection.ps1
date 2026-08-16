<#
    Private: attempt-and-classify collection of every dataset in a resolved manifest.

    Iterates a Get-PulseCollectionManifest result (already deduped and sorted ordinally by
    Dataset name - iterated here in the order given, not re-sorted, so that invariant
    lives in exactly one place) and, for every entry:

        - Pending (see DatasetMap.psd1's header): writes Skipped with reason
          'descriptor-pending: awaiting GraphKit release' and makes no Graph call at all -
          there is no descriptor yet to resolve or assert against.
        - Otherwise: asserts the descriptor is read-only (Assert-PulseReadOnlyDescriptor).
          A read-only-predicate violation is fatal and re-thrown, aborting the whole run -
          it is a module-authoring bug. An ApiVersion drift (that function's
          'descriptor-version-drift:'-prefixed message) is NOT fatal: it is caught here
          and downgraded to a per-dataset Failed outcome, then collection continues with
          the next dataset.
        - Otherwise: attempts Get-GraphObject. A clean read writes Collected. A caught
          error is classified via Get-PulseFailureClass:
            * PermissionDenied writes Skipped with reason 'permission-denied: <required
              permissions>' (read from the descriptor's own RequiredPermissions - the
              uncollected-with-reason outcome the spec requires, without a new GraphKit
              permission-preflight API).
            * AuthFailure means no further read in this run can possibly succeed -
              GraphKit's Get-GraphContext performs zero network calls and never acquires a
              token (see its own docstring), so a real authentication failure is only ever
              discovered here, at the first dataset attempt that actually talks to Graph,
              not at context-acquisition time. This dataset is written Failed with the
              redacted failure reason, the snapshot's top-level collectionFailure is set
              to that same reason, every REMAINING (not yet attempted) dataset in the
              manifest is written Failed with reason 'auth-failure: collection aborted'
              with NO further Graph calls (they would all fail identically), and
              collection stops.
            * Anything else writes Failed with the caught exception's (redacted) message
              as the reason.

    Every non-auth-failure dataset is attempted independently - one dataset's 403 or 500
    never stops the rest of the manifest from being attempted (see Get-PulseTenantSnapshot
    for the different, total-failure case where Get-GraphContext itself throws before this
    function is ever called - both paths converge on the same collectionFailure contract).

    IdFromDataset (Task 1.9 extension): when a manifest entry carries IdFromDataset (see
    Get-PulseCollectionManifest's own docstring - it guarantees the dependency dataset is
    ordered earlier in -Manifest), this function reads the id straight out of what it ALREADY
    wrote for that dependency this run (tracked in $collectedRows below - never re-read from
    disk, since the dependency was just written moments ago in this same loop) rather than
    calling Read-PulseDataset. If the dependency was not Collected (Pending/Failed/Skipped,
    or Collected with zero rows, or its first row has no `id`), this entry is written Failed
    with reason 'dependency-unavailable: <dependency dataset name>' and NO Graph call is
    attempted for it - there is no id to call with. Otherwise @(items)[0].id is passed as
    -Parameters @{ id = <id> } on the Get-GraphObject call below; every other classification
    path (permission-denied, auth-failure, generic failure) is unchanged. A dependency that
    is unavailable because ITS OWN dataset is still Pending (post-review, L6) is reported
    with a DIFFERENT, more specific reason - 'dependency-pending: <name> (descriptor not yet
    in released GraphKit)' - than a dependency that genuinely failed to collect
    ('dependency-unavailable: <name>'): the first is an expected, temporary state (nothing
    is broken, the collector is just waiting on a GraphKit release) and the second is a real
    collection failure (permission, throttling, a 500) worth investigating. Conflating them
    under one generic reason would make a routine Pending wait look like an incident.

    Every reason string handed to Write-PulseDataset or Set-PulseManifestEntry -
    unconditionally, even a fixed non-exception-derived string - is routed through
    Protect-PulseReason first: a caught GraphKit exception's message can carry the raw
    -ProfileId (or, once resolved, the raw tenant id) verbatim, and a reason string is
    still part of the snapshot artifact the module-wide pseudonymization rule covers.
    -ProfileId/-TenantId are passed to Protect-PulseReason directly at each call site
    (rather than through a nested closure) so PSScriptAnalyzer's unused-parameter check
    can see they are used - it does not trace usage through nested function closures.
#>

function Invoke-PulseCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Manifest,

        [Parameter(Mandatory)]
        [pscustomobject] $Context,

        [Parameter(Mandatory)]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [string] $TenantPseudonym
    )

    $contextTenantId = $null
    if ($null -ne $Context -and $Context.PSObject.Properties['TenantId'] -and $null -ne $Context.TenantId) {
        $contextTenantId = [string] $Context.TenantId
    }

    # Tracks, for every entry processed so far this run, the rows written for it (only ever
    # consulted by a LATER entry's IdFromDataset - see this file's own docstring). Populated
    # on every Collected outcome; left absent (never looked up as anything but "unavailable")
    # for Pending/Failed/Skipped outcomes, which is exactly the "dependency unavailable"
    # signal a dependent entry needs.
    $collectedRows = @{}

    # Tracks every dataset name written Skipped for being Pending this run - the only extra
    # bookkeeping the L6 dependency-pending-vs-failed distinction below needs (see this
    # file's own docstring).
    $pendingDatasets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    for ($i = 0; $i -lt $Manifest.Count; $i++) {
        $entry = $Manifest[$i]

        if ($entry.Pending) {
            $pendingDatasets.Add($entry.Dataset) | Out-Null
            $reason = Protect-PulseReason -Message 'descriptor-pending: awaiting GraphKit release' -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
            Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Skipped' -Reason $reason
            continue
        }

        $extraParameters = @{}
        if ($entry.PSObject.Properties['IdFromDataset'] -and $entry.IdFromDataset) {
            $dependencyRows = $collectedRows[$entry.IdFromDataset]
            $dependencyId = $null
            if ($null -ne $dependencyRows -and @($dependencyRows).Count -gt 0) {
                $firstRow = @($dependencyRows)[0]
                if ($firstRow.PSObject.Properties['id'] -and $firstRow.id) {
                    $dependencyId = [string] $firstRow.id
                }
            }

            if (-not $dependencyId) {
                $message = if ($pendingDatasets.Contains($entry.IdFromDataset)) {
                    "dependency-pending: $($entry.IdFromDataset) (descriptor not yet in released GraphKit)"
                } else {
                    "dependency-unavailable: $($entry.IdFromDataset)"
                }
                $reason = Protect-PulseReason -Message $message -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' -Reason $reason
                continue
            }

            $extraParameters = @{ id = $dependencyId }
        }

        try {
            Assert-PulseReadOnlyDescriptor -Type $entry.Type -Operation $entry.Operation -ApiVersion $entry.ApiVersion
        } catch {
            if ($_.Exception.Message -match 'descriptor-version-drift') {
                $reason = Protect-PulseReason -Message $_.Exception.Message -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' -Reason $reason
                continue
            }

            # A read-only-predicate violation is a module-authoring bug, not a per-dataset
            # outcome - re-throw to abort the whole run.
            throw
        }

        try {
            $graphObjectParams = @{
                Context     = $Context
                Type        = $entry.Type
                Operation   = $entry.Operation
                ErrorAction = 'Stop'
            }
            if ($extraParameters.Count -gt 0) {
                $graphObjectParams.Parameters = $extraParameters
            }

            $rows = @(Get-GraphObject @graphObjectParams)
            Write-PulseDataset -Store $Store -Name $entry.Dataset -Data $rows -ApiVersion $entry.ApiVersion -Status 'Collected'
            $collectedRows[$entry.Dataset] = $rows
        } catch {
            $failureClass = Get-PulseFailureClass -ErrorRecord $_

            if ($failureClass -eq 'PermissionDenied') {
                $requiredPermissions = $null
                try {
                    $descriptor = Get-GraphOperation -Type $entry.Type -Operation $entry.Operation -ErrorAction Stop
                    if ($null -ne $descriptor -and $descriptor.ContainsKey('RequiredPermissions')) {
                        $requiredPermissions = (@($descriptor.RequiredPermissions) | ForEach-Object {
                            if ($_ -is [System.Collections.IDictionary] -and $_.ContainsKey('Value')) { $_.Value } else { $_ }
                        }) -join ', '
                    }
                } catch {
                    # Best-effort only: a failure to re-resolve the descriptor's required
                    # permissions must never mask the original 403 classification.
                    $requiredPermissions = $null
                }

                $permissionsText = if ([string]::IsNullOrWhiteSpace($requiredPermissions)) { '(unknown)' } else { $requiredPermissions }
                $reason = Protect-PulseReason -Message "permission-denied: $permissionsText" -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Skipped' -Reason $reason
            } elseif ($failureClass -eq 'AuthFailure') {
                $redactedReason = Protect-PulseReason -Message "auth-failure: $($_.Exception.Message)" -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId

                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' -Reason $redactedReason
                Set-PulseManifestEntry -Store $Store -CollectionFailure $redactedReason

                # No further Graph calls: every remaining dataset would fail identically
                # against the same broken auth context.
                $remainingReason = Protect-PulseReason -Message 'auth-failure: collection aborted' -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                for ($j = $i + 1; $j -lt $Manifest.Count; $j++) {
                    $remaining = $Manifest[$j]
                    Write-PulseDataset -Store $Store -Name $remaining.Dataset -ApiVersion $remaining.ApiVersion -Status 'Failed' -Reason $remainingReason
                }

                return
            } else {
                $reason = Protect-PulseReason -Message $_.Exception.Message -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' -Reason $reason
            }
        }
    }
}
