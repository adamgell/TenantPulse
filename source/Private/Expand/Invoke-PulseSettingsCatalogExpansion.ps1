<#
    Private: per-policy fan-out + Settings Catalog walk driver.

    For every policy in -Policies (the collector's own `configurationPolicies` dataset
    rows - this function never fetches the policy LIST itself, only each policy's
    /settings sub-resource, so it stays decoupled from how the caller obtained the policy
    list): fetches ConfigurationPolicySetting.ListBeta via -Parameters @{ id = <policyId> },
    walks the result through ConvertTo-PulseSettingRows (the pure walk - see its own
    docstring for the row-schema-v1 contract), and merges every policy's rows into one
    deterministic expanded/settingsCatalog.jsonl.

    ASSIGNMENTS-DEFERRED (G-gate sequencing amendment): this function has no assignments
    sub-fetch at all - every row ConvertTo-PulseSettingRows returns already carries
    assignments:null (see that function's own docstring). Phase 2b's
    ConfigurationPolicyAssignment fan-out slots in here later as one more per-policy fetch
    alongside the existing /settings fetch, joined by policyId before the walk - this
    function's per-policy loop shape does not need to change to accommodate it.

    RAW PAYLOAD PERSISTENCE + -FromCapturedPayloads: every policy's raw /settings response
    is persisted as its own DATASET - name 'configurationPolicySettings-<policyId>' (the
    policy's GUID id, hyphens and all - Assert-PulseDatasetName's existing
    `^[A-Za-z0-9][A-Za-z0-9_-]*$` pattern already admits this shape verbatim; no regex
    change was needed, verified against a real GUID rather than assumed), written through
    Write-PulseDataset exactly like every other collected dataset in this module - so each
    one gets the SAME hash-verified-on-read contract every other dataset gets (Read-
    PulseDataset re-hashes the file's actual on-disk bytes against the manifest's recorded
    sha256 and throws on mismatch), rather than a bespoke unverified side file only this one
    feature would have. SECRET-REDACTED at write: Protect-PulseSettingsCatalogSecretPayload
    blanks every secret settingValue's own `value` field to $null before the redacted clone
    is handed to Write-PulseDataset (keeping `valueState`) - this is a SEPARATE redaction
    pass from the walk's own row-level secret handling; the raw payload on disk must never
    carry an unredacted secret either, even though nothing currently reads it back except a
    later -FromCapturedPayloads re-expansion. A later -FromCapturedPayloads call re-expands
    from these datasets (via Read-PulseDataset, hash-verified) with NO Graph call at all:
    the per-policy fetch step below is skipped entirely and each policy's raw payload is
    read back through the normal dataset-read path instead. This is the primitive
    Invoke-PulseAssessment/Get-PulseTenantSnapshot's own -FromSnapshot semantics build on
    (verified expansion artifacts first, else re-expand from these captured payloads, never
    Graph - see the plan's own -FromSnapshot section); this function itself does not decide
    which of those two paths applies, it only implements the "re-expand from captured
    payloads" half via -FromCapturedPayloads.

    TERMINAL STATE PER POLICY: a policy reaches exactly one of two outcomes each fan-out
    run - Expanded (its rows, however many, are in the final artifact with no per-policy
    gap recorded) or a gap-carrying outcome (either the fetch itself failed, or the walk
    found an unknown @odata.type / malformed instance / depth-budget overrun for at least
    one node under it) - the latter contributes ONE {policyId; reason} entry to the
    expansion's aggregate -Gaps and pushes the whole expansion's -Status to 'Partial'.
    A policy whose walk hit a gap still contributes whatever rows it DID manage to walk
    cleanly - a partial walk is not discarded wholesale, matching this module's
    field-absence-lens convention (missing/partial is reported explicitly, not silently
    dropped to nothing).

    WORKER POOL (-MaxParallel, default 4) vs -Sequential: -Sequential (or -MaxParallel -le
    1) processes every policy in a plain foreach loop, in -Policies' own order - this is
    the path every unit test in this module exercises, because Pester's Mock (via
    InModuleScope) only ever intercepts calls made in the CURRENT runspace; a real
    RunspacePool-backed worker runs each policy's Get-GraphObject call in a SEPARATE
    runspace that does not inherit that mock, so it cannot be exercised the same way a
    plain unit test exercises the sequential path. The parallel path (-MaxParallel -gt 1,
    -Sequential not given) is REAL production code - a bounded
    System.Management.Automation.Runspaces.RunspacePool sized [1, MaxParallel], each pooled
    runspace given an InitialSessionState that imports the already-loaded GraphKit and
    TenantPulse modules by their on-disk path (live in-process objects, e.g. -Context,
    cross a same-AppDomain runspace boundary by reference - no remoting/serialization is
    involved) - but its own Get-GraphObject calls are outside what a same-runspace Mock can
    observe, matching the plan's own "performance/concurrency verification lives in a
    dedicated serial perf container, not ordinary unit tests; unit tests prove bounded
    worker caps STRUCTURALLY" scoping. Regardless of which path ran, MERGE ORDER NEVER
    DEPENDS ON WORKER COMPLETION ORDER - every row carries its own (policyId, settingPath,
    instanceId) and the merge step (see below) sorts explicitly on that ordinal triple, so
    a shuffled completion order across workers produces a byte-identical final file to a
    sequential run over the same input, by construction, not by accident of scheduling.

    MERGE + INCREMENTAL HASH: every processed policy's walked rows are held as one
    in-memory list (bounded by the size of one snapshot's settings-catalog rows - not
    fragment files re-read from disk; a future streaming/fragment-file merge for
    very-large-tenant scale is flagged as follow-up, out of this task's time budget), then
    sorted via a single ordinal Comparison over (policyId, settingPath, instanceId) using
    [string]::CompareOrdinal on each key in turn - this is the ONE place row order is
    decided, and it never consults any dictionary/hashtable iteration order. Each sorted
    row is serialized via ConvertTo-PulseCanonicalJsonLine and its UTF8 bytes are both (a)
    written to a temp file beside the final expanded/settingsCatalog.jsonl path (so the
    eventual rename is same-volume/atomic) and (b) fed into a running
    System.Security.Cryptography.IncrementalHash - the final sha256 is therefore computed
    from a genuine streaming pass over the bytes actually written, never a second full-size
    in-memory copy of the whole document purely for hashing (matches
    Save-PulseSettingDefinitionCorpus's own "hash what you write" convention, extended here
    to a true incremental/streaming hash since a settings-catalog jsonl can be far larger
    than the single reference-corpus document that function hashes in one shot).

    -DefinitionIndex $null (definitions corpus unavailable - Save-PulseSettingDefinitionCorpus
    returned $null; see that function's own CAPTURE FAILURE contract): this function writes
    manifest.expansions.<Name> 'NotExpanded' with reason 'definitions corpus unavailable'
    and makes NO Graph call at all (not even the per-policy /settings fetch) - there is no
    point fetching settings this run cannot resolve names/labels against, and the caller
    (Save-PulseSettingDefinitionCorpus's own docstring) already documents this as the
    downstream contract for a failed corpus capture.
#>

function Protect-PulseSettingsCatalogSecretPayload {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Data,

        [ValidateRange(1, 1000)]
        [int] $MaxDepth = 64
    )

    function Protect-PulseSecretValue {
        param($Value, [int] $CurrentDepth, [int] $MaxDepth)

        if ($CurrentDepth -gt $MaxDepth) {
            throw "Protect-PulseSettingsCatalogSecretPayload: payload exceeds the maximum redaction depth of $MaxDepth."
        }

        if ($null -eq $Value) { return $Value }

        if ($Value -is [System.Collections.IDictionary]) {
            $clone = [ordered] @{}
            foreach ($key in @($Value.Keys)) {
                $clone[$key] = Protect-PulseSecretValue -Value $Value[$key] -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
            }
            return $clone
        }

        if ($Value -is [System.Management.Automation.PSObject]) {
            $isSecret = $false
            if ($Value.PSObject.Properties['@odata.type']) {
                $odataType = [string] $Value.'@odata.type'
                if ($odataType -match '(?i)SecretSettingValue$') { $isSecret = $true }
            }

            $clone = [pscustomobject]@{}
            foreach ($property in @($Value.PSObject.Properties)) {
                $propertyValue = if ($isSecret -and $property.Name -eq 'value') {
                    $null
                } else {
                    Protect-PulseSecretValue -Value $property.Value -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
                }
                Add-Member -InputObject $clone -NotePropertyName $property.Name -NotePropertyValue $propertyValue
            }
            return $clone
        }

        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            $items = @($Value)
            $clonedItems = [object[]]::new($items.Count)
            for ($i = 0; $i -lt $items.Count; $i++) {
                $clonedItems[$i] = Protect-PulseSecretValue -Value $items[$i] -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
            }
            return , $clonedItems
        }

        return $Value
    }

    $clonedRows = [object[]]::new(@($Data).Count)
    $sourceRows = @($Data)
    for ($i = 0; $i -lt $sourceRows.Count; $i++) {
        $clonedRows[$i] = Protect-PulseSecretValue -Value $sourceRows[$i] -CurrentDepth 1 -MaxDepth $MaxDepth
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

    if ($null -eq $DefinitionIndex -or $DefinitionIndex.Count -eq 0) {
        $reason = Protect-PulseReason -Message 'definitions corpus unavailable' -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $reason
        return [pscustomobject]@{
            Status               = 'NotExpanded'
            PolicyCount          = 0
            RowCount             = 0
            UnresolvedNameCount  = 0
            RedactedSecretCount  = 0
            Gaps                 = @()
        }
    }

    $policyList = @($Policies)

    $allRows = [System.Collections.Generic.List[object]]::new()
    $rawDatasetPrefix = 'configurationPolicySettings-'
    $gapEntries = [System.Collections.Generic.List[object]]::new()

    $isSequential = $Sequential.IsPresent -or $MaxParallel -le 1

    # Invoke-PulseSettingsCatalogPolicy is a TOP-LEVEL module function (its own file, not a
    # closure nested in here) specifically so the parallel path below can invoke it inside a
    # pooled runspace's own copy of the TenantPulse module (see that function's own
    # docstring for why a nested closure cannot survive a runspace boundary the way a real
    # module function can). Both paths converge on this exact same function - there is only
    # ONE implementation of "how a policy is fetched, redacted, walked and classified"
    # regardless of which path ran it.

    if ($isSequential -or $policyList.Count -le 1) {
        foreach ($policy in $policyList) {
            $rawDatasetName = "$rawDatasetPrefix$([string] $policy.id)"
            $result = Invoke-PulseSettingsCatalogPolicy -Store $Store -Policy $policy -Context $Context -DefinitionIndex $DefinitionIndex `
                -FromCapturedPayloads $FromCapturedPayloads.IsPresent -RawDatasetName $rawDatasetName `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
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
        # that runspace imported TenantPulse - a module's private functions are only
        # reachable from code running IN that module's own scope. `& $module { ... }` runs
        # the inner scriptblock inside the freshly-imported TenantPulse module instance's
        # own scope in THAT runspace, where the private function is a real, callable member.
        $scriptBlock = {
            param($Store, $Policy, $Context, $DefinitionIndex, $FromCapturedPayloads, $RawDatasetName, $ProfileId, $Pseudonym, $TenantId)
            $module = Get-Module -Name TenantPulse
            & $module {
                param($Store, $Policy, $Context, $DefinitionIndex, $FromCapturedPayloads, $RawDatasetName, $ProfileId, $Pseudonym, $TenantId)
                Invoke-PulseSettingsCatalogPolicy -Store $Store -Policy $Policy -Context $Context -DefinitionIndex $DefinitionIndex `
                    -FromCapturedPayloads $FromCapturedPayloads -RawDatasetName $RawDatasetName `
                    -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
            } $Store $Policy $Context $DefinitionIndex $FromCapturedPayloads $RawDatasetName $ProfileId $Pseudonym $TenantId
        }

        $handles = [System.Collections.Generic.List[object]]::new()
        try {
            foreach ($policy in $policyList) {
                $rawDatasetName = "$rawDatasetPrefix$([string] $policy.id)"
                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                [void] $ps.AddScript($scriptBlock).AddArgument($Store).AddArgument($policy).AddArgument($Context).AddArgument($DefinitionIndex).AddArgument($FromCapturedPayloads.IsPresent).AddArgument($rawDatasetName).AddArgument($ProfileId).AddArgument($Pseudonym).AddArgument($TenantId)
                $handles.Add([pscustomobject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }) | Out-Null
            }

            foreach ($h in $handles) {
                try {
                    $results = $h.PowerShell.EndInvoke($h.Handle)
                    foreach ($result in $results) {
                        foreach ($row in $result.Rows) { $allRows.Add($row) | Out-Null }
                        if ($result.Gap) {
                            $reason = Protect-PulseReason -Message $result.Gap -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                            $gapEntries.Add([pscustomobject]@{ policyId = $result.PolicyId; reason = $reason }) | Out-Null
                        }
                    }
                } finally {
                    $h.PowerShell.Dispose()
                }
            }
        } finally {
            $pool.Close()
            $pool.Dispose()
        }
    }

    # DETERMINISTIC MERGE (see docstring): sort strictly on (policyId, settingPath,
    # instanceId), ordinal - never on worker completion order.
    $sortedRows = $allRows.ToArray()
    $comparison = [System.Comparison[object]] {
        param($a, $b)
        $c = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
        if ($c -ne 0) { return $c }
        $c = [string]::CompareOrdinal([string] $a.settingPath, [string] $b.settingPath)
        if ($c -ne 0) { return $c }
        return [string]::CompareOrdinal([string] $a.instanceId, [string] $b.instanceId)
    }
    [System.Array]::Sort($sortedRows, $comparison)

    $unresolvedNameCount = @($sortedRows | Where-Object { -not $_.nameResolved }).Count
    $redactedSecretCount = @($sortedRows | Where-Object { $_.redacted }).Count

    if ($sortedRows.Count -eq 0 -and $gapEntries.Count -eq $policyList.Count -and $policyList.Count -gt 0) {
        # Every policy gapped and nothing at all was produced - still a valid Partial
        # outcome per Set-PulseExpansionEntry's own contract (any non-empty Gaps list with
        # Path/SchemaVersion/etc. supplied), not a Failed: the walk itself did not error,
        # every policy was classified. Falls through to the normal write path below with
        # rowCount 0 - an empty-but-hash-verified jsonl file, not "no artifact at all".
    }

    $tempFileName = "$Name.$([guid]::NewGuid().ToString('N')).tmp"
    $tempPath = Join-Path $Store.ExpandedPath $tempFileName

    $incrementalHash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $fileStream = [System.IO.File]::Open($tempPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    try {
        foreach ($row in $sortedRows) {
            $line = ConvertTo-PulseCanonicalJsonLine -InputObject $row
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
            $fileStream.Write($bytes, 0, $bytes.Length)
            $incrementalHash.AppendData($bytes)
        }
        $fileStream.Flush()
    } finally {
        $fileStream.Dispose()
    }
    $hashBytes = $incrementalHash.GetHashAndReset()
    $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    $status = if ($gapEntries.Count -eq 0) { 'Expanded' } else { 'Partial' }

    $setParams = @{
        Store         = $Store
        Name          = $Name
        Status        = $status
        Path          = "expanded/$Name.jsonl"
        SchemaVersion = '1'
        Sha256        = $sha256
        PolicyCount   = $policyList.Count
        RowCount      = $sortedRows.Count
        UnresolvedNameCount = $unresolvedNameCount
        RedactedSecretCount = $redactedSecretCount
        PublishFromTempPath = $tempPath
    }
    if ($gapEntries.Count -gt 0) {
        $setParams.Gaps = $gapEntries.ToArray()
    }

    Set-PulseExpansionEntry @setParams

    return [pscustomobject]@{
        Status              = $status
        PolicyCount         = $policyList.Count
        RowCount            = $sortedRows.Count
        UnresolvedNameCount = $unresolvedNameCount
        RedactedSecretCount = $redactedSecretCount
        Gaps                = $gapEntries.ToArray()
    }
}
