<#
    Private: per-policy fan-out + Settings Catalog walk driver.

    For every VALID policy in -Policies (the collector's own `configurationPolicies`
    dataset rows): fetches ConfigurationPolicySetting.ListBeta via -Parameters
    @{id=<policyId>}, walks the result through ConvertTo-PulseSettingRows, and merges every
    policy's rows into one deterministic expanded/settingsCatalog.jsonl.

    ASSIGNMENTS-DEFERRED (G-gate sequencing amendment, P1-12 review fix - now PERSISTED,
    not just a test title): every row carries assignments:null (see ConvertTo-PulseSettingRows's
    own docstring). Every 'Expanded'/'Partial' expansion entry this function writes also
    carries -Reason 'assignments-deferred: awaiting GraphKit release' - the manifest's own
    `reason` field is not status-gated to only the NotExpanded/Failed outcomes (Set-
    PulseExpansionEntry only REQUIRES -Reason for those two), so this is the one place the
    G-gate note is durably recorded on a SUCCESSFUL run's own artifact, not only asserted by
    a test title.

    PREVALIDATION - ORDINAL-UNIQUE, NON-EMPTY POLICY IDS (P0-4 review fix - reproduced: a
    32-duplicate-id probe produced 13 gaps and a manifest/raw-dataset hash divergence,
    because two policies sharing an id both wrote to (and both believed they owned) the
    SAME 'configurationPolicySettings-<id>' dataset name). Every -Policies entry is
    validated BEFORE any fetch or BeginInvoke is issued: an empty/null id gaps immediately
    (category EmptyPolicyId, never fetched); a duplicate of an id already seen earlier in
    -Policies gaps immediately (category DuplicatePolicyId, never fetched) - ONLY the FIRST
    occurrence of a given id is ever eligible to fetch. This is the "one policy = one
    raw-dataset owner" invariant, enforced structurally before any Graph call or dataset
    write can happen, not discovered after the fact.

    WORKER DRAIN (P0-5 review fix - reproduced: an EndInvoke exception on one handle
    propagated out of the whole foreach, orphaning every later handle undisposed and
    aborting the run before publication). Every handle is tagged with its own PolicyId.
    EVERY handle is drained (EndInvoke attempted, Dispose'd) regardless of any other
    handle's outcome - a per-handle try/catch/finally, not one try wrapping the whole
    drain loop. A handle is additionally inspected for InvocationStateInfo.State (must be
    'Completed') and Streams.Error (must be empty) even when EndInvoke itself did not
    throw - a worker that wrote non-terminating errors but still returned SOMETHING is not
    trusted. Result cardinality is checked too: Invoke-PulseSettingsCatalogPolicy always
    returns exactly ONE object; anything else (0, or more than 1, from a pipeline-flattening
    surprise) gaps that policy (category ResultCardinalityMismatch) rather than trusting a
    partial/ambiguous result.

    DUPLICATE ROW IDENTITIES (P1-7 review fix): ConvertTo-PulseSettingRows itself now
    THROWS on an internal instanceId collision (see its own docstring) rather than
    producing a row set this driver would have to police after the fact - a policy whose
    walk throws is caught by Invoke-PulseSettingsCatalogPolicy and returned as a Gap, so a
    duplicate identity can never reach the merge step at all. GAPS ARE SORTED ordinally on
    (policyId, reason) before being written - deterministic gap ordering, independent of
    worker completion order, matching the row merge's own determinism guarantee.

    CRASH-CONSISTENT PUBLICATION (P0-6 review fix - reproduced via fault injection: a crash
    between the old code's file-rename step and its separate manifest-write step left the
    NEW file bytes at the final path describing a manifest entry that still pointed at the
    OLD content - "old-manifest/new-bytes" split-brain). This function no longer renames a
    temp file directly onto the FIXED name 'expanded/<Name>.jsonl' inside Set-
    PulseManifestEntry's mutex (Set-PulseManifestEntry's own -ExpansionPublishTempPath/
    -FinalPath pattern still exists and is used by other callers - Save-
    PulseSettingDefinitionCorpus's Reference-set sibling - for a single, dedicated
    document). Instead: the fully-hashed jsonl is renamed to an IMMUTABLE, GENERATION-NAMED
    path - 'expanded/<Name>.<sha256>.jsonl' - via a plain, un-mutexed File.Move BEFORE the
    manifest mutex is ever acquired (this rename cannot race any other writer: the target
    name is content-addressed, so two writers producing byte-identical content would only
    ever "collide" by writing the same bytes to the same name, which is harmless). ONLY
    THEN does Set-PulseExpansionEntry run, with -Path already pointing at that
    already-durable file - no -PublishFromTempPath, no file-move, inside the manifest
    mutex's critical section for this call: the ENTIRE mutex-guarded step is the single
    atomic manifest.json tmp+rename Set-PulseManifestEntry already performs for every write.
    A crash before the generation file exists leaves the OLD manifest pointing at the OLD
    (still valid) generation file, untouched. A crash after the generation file exists but
    before the manifest switches over leaves the same OLD-but-consistent state, plus one
    harmless orphaned generation file. A crash during the manifest's own atomic write can
    only ever leave the OLD manifest.json (untouched) or the fully-written NEW one (Set-
    PulseAtomicFileContent's existing tmp+rename guarantee) - never a partial one. Old-
    manifest/new-bytes can no longer coexist, by construction: nothing after the generation
    file's own successful, already-complete write can ever leave the new bytes reachable
    without the manifest already pointing at them. STALE GENERATION FILES from a prior
    unpublished or superseded run are not cleaned up by this function (flagged follow-up,
    out of this task's scope - they are harmless orphans, never referenced by any manifest
    once superseded).

    TEMP/HASH CLEANUP (P1-10 review fix - reproduced: a serialization failure mid-stream
    left an orphaned .tmp file under expanded/, and the IncrementalHash was never
    disposed). ONE try/finally wraps the entire staging-through-publication sequence: the
    temp file is deleted in the finally block UNLESS ownership was successfully transferred
    (the generation-file rename succeeded) - tracked via a single boolean flag, not
    inferred from path existence after the fact. The IncrementalHash is disposed in its own
    try/finally regardless of whether GetHashAndReset() was ever reached.

    WORKER POOL (-MaxParallel, default 4) vs -Sequential: -Sequential (or -MaxParallel -le
    1, or a policy list with 1 or fewer ELIGIBLE policies) processes every policy in a plain
    foreach loop - the path every unit test in this module exercises via Mock/Should-
    Invoke. The parallel path (-MaxParallel -gt 1) is REAL production code - a bounded
    RunspacePool sized [1, MaxParallel] - but its own Get-GraphObject calls are outside
    what a same-runspace Mock can observe (see the WORKER DRAIN section above and the
    per-handle PolicyId tagging it depends on). MERGE ORDER NEVER DEPENDS ON WORKER
    COMPLETION ORDER - every row carries its own (policyId, settingPath, instanceId) and
    the merge sorts explicitly on that ordinal triple via [string]::CompareOrdinal, so a
    shuffled completion order produces a byte-identical final file to a sequential run over
    the same input.

    -DefinitionIndex $null (definitions corpus unavailable): writes manifest.expansions.<Name>
    'NotExpanded' with reason 'definitions corpus unavailable' and makes NO Graph call at
    all.
#>

function Protect-PulseSettingsCatalogSecretPayload {
    <#
        Private: redact secret setting VALUES out of a raw ConfigurationPolicySetting.
        ListBeta payload before it is ever persisted to disk.

        P0-2 review fix (shared classifier, whitelist-copy): this function used to run its
        own independent "is this @odata.type a secret" check inline and, for a node it
        judged secret, blanket-copied every OTHER property through unchanged (only the
        `value` property was ever blanked) - both halves of that were real defects the
        review reproduced. Both are fixed here:
          1. Classification now goes through the ONE shared function,
             Resolve-PulseSettingsCatalogValueClassification (see its own docstring for the
             fail-closed rules - missing/unrecognized discriminator, dictionary-shaped
             values, etc. are now all treated as secret, not silently passed through) - the
             exact same function ConvertTo-PulseSettingRows uses, so there is no second,
             independently-drifting notion of "secret" anywhere in this module.
          2. Classification is applied SURGICALLY, only at the two wire-format positions
             that can ever carry a scalar value - a `simpleSettingValue` property, and each
             element of a `simpleSettingCollectionValue` array - never generically at every
             node in the tree (an indiscriminate "unknown shape -> redact" rule applied to
             EVERY object in the payload would have wrongly nuked unrelated structure, e.g.
             `settingInstanceTemplateReference`, which legitimately has no `@odata.type`).
             Everything else in the tree is copied through structurally unchanged, exactly
             as before.
          3. A node classified secret is now WHITELIST-COPIED, not blanket-copied-minus-
             value: the clone keeps only `@odata.type` (verbatim - public schema, not
             content) and a VALIDATED `valueState`, and sets `value` to $null - every other
             property that node might have carried (a hypothetical future `displayValue`,
             `metadata`, or similar field a later Graph version adds) is dropped, per the
             review's explicit "strip valueLabel/metadata too, whitelist-copy only
             known-safe fields" instruction.

        -DefinitionIndex (optional) supplies the SAME IsSecretCapable signal the row walker
        uses, tracked through the recursion via the nearest enclosing settingInstance's own
        `settingDefinitionId` - a $null index (definitions corpus unavailable) still leaves
        every other fail-closed rule (missing/unrecognized discriminator, dictionary shape)
        fully in force; only the definition-level defense-in-depth signal is unavailable.

        DEPTH BUDGET, DERIVED FROM THE WALKER (omp-Medium re-review fix - see
        ConvertTo-PulseSettingRows.ps1's own $script:PulseSettingsCatalogRawPayloadMaxDepth
        docstring for the full accounting, including WHY a bare 4x multiplier with no fixed
        buffer is one off-by-a-few short at the exact boundary): this function counts depth
        per RAW NODE (object AND array each cost one level), while the walker counts depth
        per settingInstance LEVEL. -MaxDepth defaults to the ONE shared constant,
        $script:PulseSettingsCatalogRawPayloadMaxDepth - the SAME constant
        Write-PulseDataset's own -Depth override for the raw configurationPolicySettings
        write uses (see Invoke-PulseSettingsCatalogPolicy.ps1) - so a policy the walker
        would accept as exactly at its own budget can never be misclassified as a
        redaction failure (or, one layer up, a spurious "fetch-failed" gap) by either the
        redaction pass or the raw-dataset serialization pass independently drifting out of
        alignment with the walker's own budget or with EACH OTHER.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Data,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary] $DefinitionIndex,

        [ValidateRange(1, 10000)]
        [int] $MaxDepth = $script:PulseSettingsCatalogRawPayloadMaxDepth
    )

    function Get-PulseIsSecretCapable {
        param([string] $DefinitionId, [System.Collections.IDictionary] $Index)
        if ($null -eq $Index -or [string]::IsNullOrEmpty($DefinitionId)) { return $false }
        if (-not $Index.Contains($DefinitionId)) { return $false }
        $entry = $Index[$DefinitionId]
        if ($null -ne $entry -and $entry -is [System.Collections.IDictionary] -and $entry.Contains('IsSecretCapable')) {
            return [bool] $entry.IsSecretCapable
        }
        return $false
    }

    function New-PulseWhitelistedSecretClone {
        param($Classification)
        $clone = [ordered]@{}
        if (-not [string]::IsNullOrEmpty($Classification.ODataType)) { $clone['@odata.type'] = $Classification.ODataType }
        $clone['value'] = $null
        if ($null -ne $Classification.ValueState) { $clone['valueState'] = $Classification.ValueState }
        return [pscustomobject] $clone
    }

    function Protect-PulseValueNode {
        param($RawValue, [string] $DefinitionId)
        $classification = Resolve-PulseSettingsCatalogValueClassification -SettingValue $RawValue `
            -DefinitionIsSecretCapable (Get-PulseIsSecretCapable -DefinitionId $DefinitionId -Index $DefinitionIndex)
        if ($classification.IsSecret) {
            return New-PulseWhitelistedSecretClone -Classification $classification
        }
        return Protect-PulseGenericNode -Value $RawValue -CurrentDepth 1 -CurrentDefinitionId $DefinitionId
    }

    function Protect-PulseGenericNode {
        param($Value, [int] $CurrentDepth, [string] $CurrentDefinitionId)

        if ($CurrentDepth -gt $MaxDepth) {
            throw "Protect-PulseSettingsCatalogSecretPayload: payload exceeds the maximum redaction depth of $MaxDepth."
        }

        if ($null -eq $Value) { return $Value }

        if ($Value -is [System.Collections.IDictionary]) {
            $definitionIdHere = $CurrentDefinitionId
            if ($Value.Contains('settingDefinitionId')) { $definitionIdHere = [string] $Value['settingDefinitionId'] }

            $clone = [ordered]@{}
            foreach ($key in @($Value.Keys)) {
                if ($key -eq 'simpleSettingValue') {
                    $clone[$key] = Protect-PulseValueNode -RawValue $Value[$key] -DefinitionId $definitionIdHere
                } elseif ($key -eq 'simpleSettingCollectionValue' -and $Value[$key] -is [System.Collections.IEnumerable] -and $Value[$key] -isnot [string]) {
                    $items = @($Value[$key])
                    $clonedItems = [object[]]::new($items.Count)
                    for ($i = 0; $i -lt $items.Count; $i++) {
                        $clonedItems[$i] = Protect-PulseValueNode -RawValue $items[$i] -DefinitionId $definitionIdHere
                    }
                    $clone[$key] = , $clonedItems
                } else {
                    $clone[$key] = Protect-PulseGenericNode -Value $Value[$key] -CurrentDepth ($CurrentDepth + 1) -CurrentDefinitionId $definitionIdHere
                }
            }
            return $clone
        }

        if ($Value -is [System.Management.Automation.PSObject]) {
            $definitionIdHere = $CurrentDefinitionId
            if ($Value.PSObject.Properties['settingDefinitionId']) { $definitionIdHere = [string] $Value.settingDefinitionId }

            $clone = [pscustomobject]@{}
            foreach ($property in @($Value.PSObject.Properties)) {
                $propertyValue = $null
                if ($property.Name -eq 'simpleSettingValue') {
                    $propertyValue = Protect-PulseValueNode -RawValue $property.Value -DefinitionId $definitionIdHere
                } elseif ($property.Name -eq 'simpleSettingCollectionValue' -and $property.Value -is [System.Collections.IEnumerable] -and $property.Value -isnot [string]) {
                    $items = @($property.Value)
                    $clonedItems = [object[]]::new($items.Count)
                    for ($i = 0; $i -lt $items.Count; $i++) {
                        $clonedItems[$i] = Protect-PulseValueNode -RawValue $items[$i] -DefinitionId $definitionIdHere
                    }
                    $propertyValue = , $clonedItems
                } else {
                    $propertyValue = Protect-PulseGenericNode -Value $property.Value -CurrentDepth ($CurrentDepth + 1) -CurrentDefinitionId $definitionIdHere
                }
                Add-Member -InputObject $clone -NotePropertyName $property.Name -NotePropertyValue $propertyValue
            }
            return $clone
        }

        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            $items = @($Value)
            $clonedItems = [object[]]::new($items.Count)
            for ($i = 0; $i -lt $items.Count; $i++) {
                $clonedItems[$i] = Protect-PulseGenericNode -Value $items[$i] -CurrentDepth ($CurrentDepth + 1) -CurrentDefinitionId $CurrentDefinitionId
            }
            return , $clonedItems
        }

        return $Value
    }

    $sourceRows = @($Data)
    $clonedRows = [object[]]::new($sourceRows.Count)
    for ($i = 0; $i -lt $sourceRows.Count; $i++) {
        $clonedRows[$i] = Protect-PulseGenericNode -Value $sourceRows[$i] -CurrentDepth 1 -CurrentDefinitionId $null
    }
    return , $clonedRows
}

function Invoke-PulseSettingsCatalogExpansion {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $Context,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Policies,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary] $DefinitionIndex,

        [Parameter()]
        [string] $Name = 'settingsCatalog',

        [Parameter()]
        [ValidateRange(1, 64)]
        [int] $MaxParallel = 4,

        [Parameter()]
        [switch] $Sequential,

        [Parameter()]
        [switch] $FromCapturedPayloads,

        [Parameter()]
        [string] $ProfileId = '',

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown',

        [Parameter()]
        [AllowNull()]
        [string] $TenantId
    )

    $assignmentsDeferredReason = 'assignments-deferred: awaiting GraphKit release'

    if ($null -eq $DefinitionIndex -or $DefinitionIndex.Count -eq 0) {
        $reason = Protect-PulseReason -Message 'definitions corpus unavailable' -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $reason
        return [pscustomobject]@{
            Status              = 'NotExpanded'
            PolicyCount         = 0
            RowCount            = 0
            UnresolvedNameCount = 0
            RedactedSecretCount = 0
            Gaps                = @()
        }
    }

    $policyList = @($Policies)
    $rawDatasetPrefix = 'configurationPolicySettings-'

    $allRows = [System.Collections.Generic.List[object]]::new()
    $gapEntries = [System.Collections.Generic.List[object]]::new()

    # READ-ONLY ENFORCEMENT (P0/task-review Critical) - TWO ASSERTION POINTS, BY DESIGN, NOT
    # A CONTRADICTION (re-review round 2 fix - a prior revision of this comment claimed the
    # assertion ran "not inside Invoke-PulseSettingsCatalogPolicy", which was never true of
    # the actual code - see that file's own READ-ONLY ENFORCEMENT section for its half):
    #   1. HERE, once, before any per-policy fetch/BeginInvoke is issued at all - a fast-fail
    #      for the common case: if the descriptor is genuinely broken, this catches it before
    #      a single Graph call or worker is spun up, rather than only discovering it after
    #      dispatching some number of policies. Skipped entirely on -FromCapturedPayloads
    #      (that path makes no Graph call at all, so there is no descriptor to assert against
    #      and GraphKit need not even be loaded).
    #   2. ALSO inside Invoke-PulseSettingsCatalogPolicy itself, once per policy, immediately
    #      before ITS OWN Get-GraphObject call - required, not redundant, on the PARALLEL
    #      path: each worker runs in its own RunspacePool runspace and does not inherit
    #      anything this function checked in the parent runspace, so a worker that skipped
    #      its own assertion would have no read-only guard at all. The per-policy check is
    #      the one that actually backs the "never a write-shaped descriptor" guarantee for
    #      every dispatched Graph call; this function's own upfront check is an
    #      early-exit optimization on top of it, not a replacement for it - a broken
    #      descriptor is still caught (as a per-policy gap) by (2) even if some other future
    #      change ever bypassed (1).
    # A genuine read-only-predicate violation is fatal at both points (module-authoring bug,
    # matches Assert-PulseReadOnlyDescriptor's own contract - see Invoke-PulseCollection's
    # identical pattern); a 'descriptor-version-drift' message downgrades to NotExpanded here
    # (nothing has been attempted yet) or to a per-policy gap in Invoke-PulseSettingsCatalogPolicy
    # (that one policy's fetch is abandoned, the rest of the fan-out continues) - exactly
    # like Invoke-PulseCollection downgrades a per-dataset drift to Failed.
    if (-not $FromCapturedPayloads.IsPresent) {
        try {
            Assert-PulseReadOnlyDescriptor -Type 'ConfigurationPolicySetting' -Operation 'ListBeta' -ApiVersion 'beta'
        } catch {
            if ($_.Exception.Message -match 'descriptor-version-drift') {
                $reason = Protect-PulseReason -Message $_.Exception.Message -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $reason
                return [pscustomobject]@{
                    Status              = 'NotExpanded'
                    PolicyCount         = 0
                    RowCount            = 0
                    UnresolvedNameCount = 0
                    RedactedSecretCount = 0
                    Gaps                = @()
                }
            }
            throw
        }
    }

    # PREVALIDATION (P0-4): ordinal-unique, non-empty ids ONLY, decided BEFORE any
    # fetch/BeginInvoke - see this file's own docstring. SHAPE NEUTRAL (P0 re-review): read
    # through the shared accessor, not `.PSObject.Properties[...]` - a hashtable-shaped
    # policy row (GraphKit's real shape) previously always read back a $null id here and
    # gapped EVERY policy as EmptyPolicyId before a single fetch was ever attempted.
    # PolicyId is resolved exactly ONCE per eligible policy and threaded through
    # (never re-read off -Policy later) so the raw-dataset name and every downstream
    # reference to "this policy's id" agree by construction.
    $seenPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $eligiblePolicies = [System.Collections.Generic.List[object]]::new()
    foreach ($policy in $policyList) {
        $rawIdValue = Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'id'
        $rawId = if ($null -ne $rawIdValue) { [string] $rawIdValue } else { $null }
        # IsNullOrWhiteSpace, not IsNullOrEmpty (re-review fix): a whitespace-only id
        # (e.g. '   ') is not empty as a string, so IsNullOrEmpty let it through as
        # "valid" and it would have reached Get-GraphObject as a garbage -Parameters.id.
        # Rejected here, before any fetch, exactly like a null/empty id.
        if ([string]::IsNullOrWhiteSpace($rawId)) {
            $gapEntries.Add([pscustomobject]@{ policyId = ''; reason = 'category:EmptyPolicyId' }) | Out-Null
            continue
        }
        if (-not $seenPolicyIds.Add($rawId)) {
            $gapEntries.Add([pscustomobject]@{ policyId = $rawId; reason = 'category:DuplicatePolicyId' }) | Out-Null
            continue
        }
        $eligiblePolicies.Add([pscustomobject]@{ Policy = $policy; PolicyId = $rawId }) | Out-Null
    }

    $isSequential = $Sequential.IsPresent -or $MaxParallel -le 1 -or $eligiblePolicies.Count -le 1

    if ($isSequential) {
        foreach ($eligible in $eligiblePolicies) {
            $policy = $eligible.Policy
            $rawDatasetName = "$rawDatasetPrefix$($eligible.PolicyId)"
            try {
                $result = Invoke-PulseSettingsCatalogPolicy -Store $Store -Policy $policy -Context $Context -DefinitionIndex $DefinitionIndex `
                    -FromCapturedPayloads $FromCapturedPayloads.IsPresent -RawDatasetName $rawDatasetName `
                    -TenantId $TenantId -Pseudonym $Pseudonym
            } catch {
                # WORKER DRAIN applies to the sequential path too (P0-5's own spirit): an
                # unexpected exception from one policy must not skip publication of every
                # policy already collected.
                Write-Verbose "Invoke-PulseSettingsCatalogExpansion: unexpected exception processing policy '$($eligible.PolicyId)': $($_.Exception.Message)"
                $gapEntries.Add([pscustomobject]@{ policyId = $eligible.PolicyId; reason = 'category:WorkerException' }) | Out-Null
                continue
            }
            foreach ($row in $result.Rows) { $allRows.Add($row) | Out-Null }
            if ($result.Gap) {
                $reason = Protect-PulseReason -Message $result.Gap -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                $gapEntries.Add([pscustomobject]@{ policyId = $result.PolicyId; reason = $reason }) | Out-Null
            }
        }
    } else {
        # PARALLEL PATH - real RunspacePool, not unit-tested via Mock (see docstring).
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $graphKitModule = Get-Module -Name GraphKit
        $tenantPulseModule = Get-Module -Name TenantPulse
        if ($graphKitModule) { $sessionState.ImportPSModule(@($graphKitModule.Path)) }
        if ($tenantPulseModule) { $sessionState.ImportPSModule(@($tenantPulseModule.Path)) }

        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxParallel, $sessionState, $Host)
        $pool.Open()

        # Invoke-PulseSettingsCatalogPolicy is PRIVATE (not Export-ModuleMember'd), so a
        # plain call by name inside the pooled runspace's own script would fail even though
        # that runspace imported TenantPulse - `& $module { ... }` runs the inner
        # scriptblock inside that runspace's own freshly-imported TenantPulse module
        # instance's scope, where the private function is a real, callable member.
        $scriptBlock = {
            param($Store, $Policy, $Context, $DefinitionIndex, $FromCapturedPayloads, $RawDatasetName, $TenantId, $Pseudonym)
            $module = Get-Module -Name TenantPulse
            & $module {
                param($Store, $Policy, $Context, $DefinitionIndex, $FromCapturedPayloads, $RawDatasetName, $TenantId, $Pseudonym)
                Invoke-PulseSettingsCatalogPolicy -Store $Store -Policy $Policy -Context $Context -DefinitionIndex $DefinitionIndex `
                    -FromCapturedPayloads $FromCapturedPayloads -RawDatasetName $RawDatasetName -TenantId $TenantId -Pseudonym $Pseudonym
            } $Store $Policy $Context $DefinitionIndex $FromCapturedPayloads $RawDatasetName $TenantId $Pseudonym
        }

        # WORKER DRAIN (P0-5): every handle is tagged with its own PolicyId up front, and
        # EVERY handle is drained regardless of any other handle's outcome.
        $handles = [System.Collections.Generic.List[object]]::new()
        try {
            foreach ($eligible in $eligiblePolicies) {
                $rawDatasetName = "$rawDatasetPrefix$($eligible.PolicyId)"
                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                [void] $ps.AddScript($scriptBlock).AddArgument($Store).AddArgument($eligible.Policy).AddArgument($Context).AddArgument($DefinitionIndex).AddArgument($FromCapturedPayloads.IsPresent).AddArgument($rawDatasetName).AddArgument($TenantId).AddArgument($Pseudonym)
                $handles.Add([pscustomobject]@{ PolicyId = $eligible.PolicyId; PowerShell = $ps; Handle = $ps.BeginInvoke() }) | Out-Null
            }

            foreach ($h in $handles) {
                try {
                    $results = @($h.PowerShell.EndInvoke($h.Handle))

                    $hasStreamErrors = $h.PowerShell.Streams.Error.Count -gt 0
                    $completedCleanly = $h.PowerShell.InvocationStateInfo.State -eq [System.Management.Automation.PSInvocationState]::Completed

                    if ($hasStreamErrors -or -not $completedCleanly) {
                        foreach ($streamError in $h.PowerShell.Streams.Error) {
                            Write-Verbose "Invoke-PulseSettingsCatalogExpansion: worker for policy '$($h.PolicyId)' reported: $($streamError.ToString())"
                        }
                        $gapEntries.Add([pscustomobject]@{ policyId = $h.PolicyId; reason = 'category:WorkerException' }) | Out-Null
                        continue
                    }

                    if ($results.Count -ne 1) {
                        $gapEntries.Add([pscustomobject]@{ policyId = $h.PolicyId; reason = 'category:ResultCardinalityMismatch' }) | Out-Null
                        continue
                    }

                    $result = $results[0]
                    foreach ($row in $result.Rows) { $allRows.Add($row) | Out-Null }
                    if ($result.Gap) {
                        $reason = Protect-PulseReason -Message $result.Gap -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                        $gapEntries.Add([pscustomobject]@{ policyId = $result.PolicyId; reason = $reason }) | Out-Null
                    }
                } catch {
                    # A terminating exception out of EndInvoke itself (the worker's OWN
                    # script threw, or the pool/runspace faulted) must not escape this loop
                    # and orphan every later handle (P0-5's reproduced defect) - gap this
                    # ONE policy and keep draining.
                    Write-Verbose "Invoke-PulseSettingsCatalogExpansion: EndInvoke failed for policy '$($h.PolicyId)': $($_.Exception.Message)"
                    $gapEntries.Add([pscustomobject]@{ policyId = $h.PolicyId; reason = 'category:WorkerException' }) | Out-Null
                } finally {
                    $h.PowerShell.Dispose()
                }
            }
        } finally {
            $pool.Close()
            $pool.Dispose()
        }
    }

    # DETERMINISTIC MERGE: sort strictly on (policyId, settingPath, instanceId), ordinal -
    # never on worker completion order. Duplicate row identities cannot reach this point
    # (see this file's own docstring - ConvertTo-PulseSettingRows throws internally on a
    # collision, turned into a per-policy Gap upstream), so no further dedup pass is
    # needed here.
    $sortedRows = $allRows.ToArray()
    $rowComparison = [System.Comparison[object]] {
        param($a, $b)
        $c = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
        if ($c -ne 0) { return $c }
        $c = [string]::CompareOrdinal([string] $a.settingPath, [string] $b.settingPath)
        if ($c -ne 0) { return $c }
        return [string]::CompareOrdinal([string] $a.instanceId, [string] $b.instanceId)
    }
    [System.Array]::Sort($sortedRows, $rowComparison)

    # GAPS SORTED ORDINALLY (P1-7) on (policyId, reason) - deterministic regardless of
    # worker completion order or prevalidation-vs-fetch-failure ordering.
    $sortedGaps = $gapEntries.ToArray()
    $gapComparison = [System.Comparison[object]] {
        param($a, $b)
        $c = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
        if ($c -ne 0) { return $c }
        return [string]::CompareOrdinal([string] $a.reason, [string] $b.reason)
    }
    [System.Array]::Sort($sortedGaps, $gapComparison)

    # UNIFIED PUBLICATION (post-T2.3-review retrofit): staging/hash/crash-consistent-publish
    # is now owned by the ONE shared Publish-PulseExpansionRows implementation (see that
    # file's own docstring for the full crash-safety accounting - P0-6's generation-named-
    # file-before-manifest-mutex ordering and P1-10's temp/hash cleanup both live there now,
    # not duplicated here). This function's OWN inline copy of that logic - written for
    # T2.2, before Publish-PulseExpansionRows existed - was an intentional, but UNDISCLOSED,
    # fork: T2.3 (Invoke-PulseTypedPolicyExpansion.ps1) extracted the shared helper rather
    # than copying this function's block, and that fork was never called out as project debt
    # at the time. It is closed here: this call site and Invoke-PulseTypedPolicyExpansion's
    # own now both go through the identical staging/hash/publish code path. The
    # 'assignments-deferred' reason is still passed through and persisted on every
    # successful (Expanded/Partial) write exactly as before (P1-12) - Publish-
    # PulseExpansionRows's own -Reason parameter carries it; the ALL-POLICIES-FAILED ->
    # NotExpanded rule (task-review omp-Medium fix) is also unchanged, just owned by the
    # shared helper now instead of being re-implemented here.
    return Publish-PulseExpansionRows -Store $Store -Name $Name -Rows $sortedRows -Gaps $sortedGaps `
        -PolicyCount $policyList.Count -Reason $assignmentsDeferredReason `
        -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
}
