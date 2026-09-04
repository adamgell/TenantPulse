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
          request error is resolved once through Resolve-PulseGraphFailure and writes
          Failed with its canonical FailureClass and ReasonCode. A request-time 403 is
          Failed/PermissionDenied; Skipped is reserved for paths where no request was sent.
            * AuthenticationFailed means no further network-backed read in this run can possibly
              succeed -
              GraphKit's Get-GraphContext performs zero network calls and never acquires a
              token (see its own docstring), so a real authentication failure is only ever
              discovered here, at the first dataset attempt that actually talks to Graph,
              not at context-acquisition time. This dataset is written Failed with the
              redacted failure reason, the snapshot's top-level collectionFailure is set
              to that same reason, every REMAINING (not yet attempted) dataset in the
              manifest is written Failed with reason 'authentication-failed: collection aborted'
              with NO further Graph calls (they would all fail identically). Remaining
              Pending entries keep their normal descriptor-pending Skipped outcome, and a
              built-in provider plan explicitly marked RequiresNetwork = false still runs
              so its fixed, no-network disposition is not overwritten by an unrelated auth
              failure. Unmarked plans and caller overrides remain network-backed.
            * Anything else writes Failed with a bounded reason assembled from the
              canonical failure DTO. Provider exception text is diagnostic only and is
              never persisted in the snapshot.

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

    Every reason string handed to Write-PulseDataset or Set-PulseManifestEntry is routed
    through Protect-PulseReason. Graph/provider exception messages are first replaced by
    bounded canonical reason codes and safe fixed metadata; Protect-PulseReason remains a
    final defense for identifiers carried by fixed descriptor/dependency metadata.
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
        [string] $TenantPseudonym,

        # A deliberately narrow extension seam for TenantPulse-owned composite plans.
        # Keys are dataset names; values are plan commands/scriptblocks. GraphKit remains
        # responsible only for the single-operation calls made by those plans.
        [Parameter()]
        [AllowNull()]
        [hashtable] $ProviderPlanRegistry = @{},

        # Shared with the snapshot's optional expansion phase so authentication failure is
        # one run-wide network-abort signal rather than a collector-local Boolean.
        [Parameter()]
        [AllowNull()]
        [pscustomobject] $NetworkAbortState = $null
    )

    $contextTenantId = $null
    if ($null -ne $Context -and $Context.PSObject.Properties['TenantId'] -and $null -ne $Context.TenantId) {
        $contextTenantId = [string] $Context.TenantId
    }

    # SECRET CONTRACT (C1 fix): loaded ONCE per collection run (not per-dataset) - see
    # Protect-PulseTypedPolicySensitivePayload.ps1's own docstring for the redaction this
    # drives. A load failure is a module-authoring bug (a missing/malformed shipped file),
    # not a per-tenant runtime outcome; it is allowed to propagate, matching every other
    # module-relative Data/ load in this codebase (e.g. Get-PulseTenantSnapshot.ps1's own
    # DatasetMap.psd1 load).
    $moduleBase = if ($MyInvocation.MyCommand.Module) { $MyInvocation.MyCommand.Module.ModuleBase } else { $PSScriptRoot }
    $typedPolicyMaps = Import-PowerShellDataFile -LiteralPath (Join-Path $moduleBase 'Data/TypedPolicyMaps.psd1') -ErrorAction Stop

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

    # Once authentication fails, later network-backed work is classified without invoking
    # it. The state object is passed onward by Get-PulseTenantSnapshot so optional network
    # expansions obey the same abort. Direct private callers receive an equivalent local
    # state automatically.
    if ($null -eq $NetworkAbortState) {
        $NetworkAbortState = [pscustomobject]@{
            AuthenticationAborted = $false
            Reason                = $null
        }
    }

    for ($i = 0; $i -lt $Manifest.Count; $i++) {
        $entry = $Manifest[$i]

        # Composite plans are selected only by the explicit dataset-keyed registry. A
        # registered plan takes precedence over Pending because Pending is a temporary
        # catalog state, not a runtime implementation for a capability with a plan.
        $planCommand = $null
        $planRequiresNetwork = $true
        $planSupportsNetworkAbortState = $false
        if ($null -ne $ProviderPlanRegistry -and $ProviderPlanRegistry.ContainsKey($entry.Dataset)) {
            $planRegistration = $ProviderPlanRegistry[$entry.Dataset]
            if ($planRegistration -is [System.Collections.IDictionary] -and $planRegistration.Contains('Command')) {
                $planCommand = $planRegistration.Command
                if ($planRegistration.Contains('RequiresNetwork') -and $planRegistration.RequiresNetwork -is [bool]) {
                    $planRequiresNetwork = [bool] $planRegistration.RequiresNetwork
                }
                if ($planRegistration.Contains('SupportsNetworkAbortState') -and
                    $planRegistration.SupportsNetworkAbortState -is [bool]) {
                    $planSupportsNetworkAbortState = [bool] $planRegistration.SupportsNetworkAbortState
                }
            } else {
                $planCommand = $planRegistration
            }
        }

        # Registry membership alone does not make a plan safe after auth failure. Only the
        # built-in registration carrying an explicit Boolean RequiresNetwork = false may
        # dispatch; raw scriptblocks/commands (the caller override contract) default true.
        $isPendingWithoutPlan = $entry.Pending -and $null -eq $planCommand
        if ($NetworkAbortState.AuthenticationAborted -and -not $isPendingWithoutPlan -and
            ($null -eq $planCommand -or $planRequiresNetwork)) {
            Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' `
                -Reason $NetworkAbortState.Reason -ReasonCode 'authentication-failed' -Detail @{ status = 'collection aborted' } `
                -FailureClass 'AuthenticationFailed' -Provider 'GraphKit' -Operations @($entry.Operation)
            continue
        }
        if ($null -ne $planCommand) {
            try {
                if ($planCommand -isnot [scriptblock] -and $planCommand -isnot [System.Management.Automation.CommandInfo]) {
                    throw "provider plan registry entry for '$($entry.Dataset)' must be a scriptblock or command."
                }

                $planParameters = @{
                    Context = $Context; Dataset = $entry.Dataset; ManifestEntry = $entry
                    ProfileId = $ProfileId; TenantPseudonym = $TenantPseudonym
                }
                if ($planSupportsNetworkAbortState) { $planParameters.NetworkAbortState = $NetworkAbortState }
                $planResults = @(& $planCommand @planParameters)
                if ($planResults.Count -ne 1 -or $null -eq $planResults[0]) {
                    throw "provider plan for '$($entry.Dataset)' must return exactly one collection outcome."
                }
                $planResult = $planResults[0]
                foreach ($requiredProperty in @('Dataset', 'Status', 'Rows', 'Gaps', 'FailureClass', 'ReasonCode', 'Detail', 'Provider', 'ApiVersion', 'Operations')) {
                    if (-not $planResult.PSObject.Properties[$requiredProperty]) {
                        throw "provider plan for '$($entry.Dataset)' returned an outcome without '$requiredProperty'."
                    }
                }

                # Revalidate through the shared constructor so a plan cannot bypass the
                # provider-neutral status/gap invariants before persistence. A Partial
                # outcome with no usable authoritative rows is not a meaningful partial
                # success: normalize it to an explicit provider outcome while retaining
                # the plan's structured gaps and operation provenance. Valid explicit
                # failure classes are preserved; the normal unresolved-child default is
                # ProviderFailed.
                $planStatus = [string] $planResult.Status
                $planFailureClass = $planResult.FailureClass
                if ($planStatus -eq 'Partial' -and @($planResult.Rows).Count -eq 0) {
                    $planStatus = 'Failed'
                    if ($null -eq $planFailureClass -or [string]::IsNullOrWhiteSpace([string] $planFailureClass)) {
                        $planFailureClass = 'ProviderFailed'
                    }
                }
                $planApiVersion = if ([string]::IsNullOrEmpty([string]$planResult.ApiVersion)) { $entry.ApiVersion } else { $planResult.ApiVersion }
                $outcome = New-PulseCollectionOutcome -Dataset $entry.Dataset -Status $planStatus `
                    -Rows $planResult.Rows -Gaps $planResult.Gaps -FailureClass $planFailureClass `
                    -ReasonCode $planResult.ReasonCode -Detail $planResult.Detail -Provider $planResult.Provider `
                    -ApiVersion $planApiVersion -Operations $planResult.Operations
                $reason = Protect-PulseReason -Message ([string]$outcome.ReasonCode) -ProfileId $ProfileId `
                    -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                Write-PulseDataset -Store $Store -Name $entry.Dataset -Data $outcome.Rows `
                    -ApiVersion $outcome.ApiVersion -Status $outcome.Status -Reason $reason `
                    -ReasonCode $outcome.ReasonCode -Detail $outcome.Detail -FailureClass $outcome.FailureClass `
                    -Provider $outcome.Provider -Operations $outcome.Operations -Gaps $outcome.Gaps `
                    -TenantId $contextTenantId -Pseudonym $TenantPseudonym
                $hasAuthenticationFailure = $outcome.FailureClass -eq 'AuthenticationFailed' -or
                    @($outcome.Gaps | Where-Object { $_.FailureClass -eq 'AuthenticationFailed' }).Count -gt 0
                if ($hasAuthenticationFailure) {
                    $collectionFailureReason = Protect-PulseReason -Message 'authentication-failed' `
                        -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                    Set-PulseManifestEntry -Store $Store -CollectionFailure $collectionFailureReason
                    $NetworkAbortState.AuthenticationAborted = $true
                    $NetworkAbortState.Reason = Protect-PulseReason -Message 'authentication-failed: collection aborted' `
                        -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                }
                if ($outcome.Status -eq 'Collected') {
                    $collectedRows[$entry.Dataset] = @($outcome.Rows)
                }
            } catch {
                $failure = Resolve-PulseGraphFailure -ErrorRecord $_
                $hasCanonicalProviderFailure = $failure.HasStructuredSignal -or
                    $failure.FailureClass -ne 'ProviderFailed' -or
                    $failure.ReasonCode -ne 'provider-failed' -or
                    $failure.AbortCollection
                if ($hasCanonicalProviderFailure) {
                    $statusCodeText = if ($null -eq $failure.StatusCode) { 'unknown' } else { [string] $failure.StatusCode }
                    $canonicalReason = "graph-request-failed: failureClass=$($failure.FailureClass); reasonCode=$($failure.ReasonCode); statusCode=$statusCodeText"
                    $reason = Protect-PulseReason -Message $canonicalReason `
                        -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                    Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion `
                        -Status 'Failed' -Reason $reason -ReasonCode $failure.ReasonCode `
                        -Detail @{ statusCode = $failure.StatusCode; hasStructuredSignal = $failure.HasStructuredSignal } `
                        -FailureClass $failure.FailureClass -Provider 'GraphKit' -Operations @($entry.Operation) `
                        -TenantId $contextTenantId -Pseudonym $TenantPseudonym

                    if ($failure.AbortCollection) {
                        $collectionFailureReason = Protect-PulseReason -Message 'authentication-failed' `
                            -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                        Set-PulseManifestEntry -Store $Store -CollectionFailure $collectionFailureReason
                        $NetworkAbortState.AuthenticationAborted = $true
                        $NetworkAbortState.Reason = Protect-PulseReason -Message 'authentication-failed: collection aborted' `
                            -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                    }
                } else {
                    $reason = Protect-PulseReason -Message 'provider-plan-failed: execution or validation error' `
                        -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                    Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion `
                        -Status 'Failed' -Reason $reason -ReasonCode 'provider-plan-failed' `
                        -Detail @{ dataset = $entry.Dataset } -FailureClass 'ProviderFailed' `
                        -Provider 'GraphKit' -Operations @($entry.Operation) `
                        -TenantId $contextTenantId -Pseudonym $TenantPseudonym
                }
            }
            continue
        }

        if ($entry.Pending) {
            $pendingDatasets.Add($entry.Dataset) | Out-Null
            $reason = Protect-PulseReason -Message 'descriptor-pending: awaiting GraphKit release' -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
            Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Skipped' `
                -Reason $reason -ReasonCode 'descriptor-pending' -Detail @{ status = 'awaiting GraphKit release' } `
                -FailureClass 'DescriptorPending' -Provider 'GraphKit' -Operations @($entry.Operation)
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
                $isPendingDependency = $pendingDatasets.Contains($entry.IdFromDataset)
                $message = if ($isPendingDependency) {
                    "dependency-pending: $($entry.IdFromDataset) (descriptor not yet in released GraphKit)"
                } else {
                    "dependency-unavailable: $($entry.IdFromDataset)"
                }
                $reasonCode = if ($isPendingDependency) { 'dependency-pending' } else { 'dependency-unavailable' }
                $reason = Protect-PulseReason -Message $message -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' `
                    -Reason $reason -ReasonCode $reasonCode -Detail @{ dependency = $entry.IdFromDataset } `
                    -FailureClass 'DependencyUnavailable' -Provider 'GraphKit' -Operations @($entry.Operation)
                continue
            }

            $extraParameters = @{ id = $dependencyId }
        }

        try {
            Assert-PulseReadOnlyDescriptor -Type $entry.Type -Operation $entry.Operation -ApiVersion $entry.ApiVersion
        } catch {
            if ($_.Exception.Message -match 'descriptor-version-drift') {
                $reason = Protect-PulseReason -Message $_.Exception.Message -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' `
                    -Reason $reason -ReasonCode 'descriptor-version-drift' `
                    -Detail @{ type = $entry.Type; operation = $entry.Operation } `
                    -FailureClass 'ProviderFailed' -Provider 'GraphKit' -Operations @($entry.Operation)
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
            # SECRET CONTRACT (C1 fix): Sensitive-flagged properties (per TypedPolicyMaps.psd1
            # - e.g. windows10CustomConfiguration's omaSettings[].value) are redacted
            # BEFORE this row set ever reaches Write-PulseDataset - the raw dataset file
            # must never carry a Sensitive value in cleartext, exactly like the Settings
            # Catalog's own raw-payload redaction (Protect-PulseSettingsCatalogSecretPayload).
            # PASS-THROUGH for every dataset other than deviceCompliancePolicies/
            # deviceConfigurations - see that function's own DATASET SCOPE docstring
            # section for the honest boundary this implies.
            $rows = Protect-PulseTypedPolicySensitivePayload -Data $rows -DatasetName $entry.Dataset -TypedPolicyMaps $typedPolicyMaps
            # -TenantId/-Pseudonym (Task 1.11 GraphKit 0.1.1 live-gate surprise): some Graph
            # payloads carry the raw tenant id as a genuine response field (Organization.id,
            # DirectoryRoleAssignment.principalOrganizationId) - see
            # Protect-PulseGraphRowTenantId's own docstring for the full story. Every
            # Collected write goes through this so no dataset content ever ships the raw
            # tenant id unredacted, not just the two datasets that happened to surface it.
            Write-PulseDataset -Store $Store -Name $entry.Dataset -Data $rows -ApiVersion $entry.ApiVersion -Status 'Collected' -TenantId $contextTenantId -Pseudonym $TenantPseudonym
            $collectedRows[$entry.Dataset] = $rows
        } catch {
            $failure = Resolve-PulseGraphFailure -ErrorRecord $_

            if ($failure.FailureClass -eq 'PermissionDenied') {
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
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' `
                    -Reason $reason -ReasonCode 'permission-denied' -Detail @{ permissions = $permissionsText } `
                    -FailureClass 'PermissionDenied' -Provider 'GraphKit' -Operations @($entry.Operation)
            } else {
                $statusCodeText = if ($null -eq $failure.StatusCode) { 'unknown' } else { [string] $failure.StatusCode }
                $canonicalReason = "graph-request-failed: failureClass=$($failure.FailureClass); reasonCode=$($failure.ReasonCode); statusCode=$statusCodeText"
                $reason = Protect-PulseReason -Message $canonicalReason -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' `
                    -Reason $reason -ReasonCode $failure.ReasonCode `
                    -Detail @{ statusCode = $failure.StatusCode; hasStructuredSignal = $failure.HasStructuredSignal } `
                    -FailureClass $failure.FailureClass -Provider 'GraphKit' -Operations @($entry.Operation)

                if ($failure.AbortCollection) {
                    Set-PulseManifestEntry -Store $Store -CollectionFailure $reason
                    $NetworkAbortState.AuthenticationAborted = $true
                    $NetworkAbortState.Reason = Protect-PulseReason -Message 'authentication-failed: collection aborted' `
                        -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                    continue
                }
            }
        }
    }
}
