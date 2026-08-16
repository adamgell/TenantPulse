<#
    Private: capture the full Settings Catalog definitions corpus into a snapshot store and
    hand back a compact, join-ready index - never the full corpus itself.

    STAGING, NOT YET WIRED IN (post-review clarity fix, omp finding #9 - read this first):
    as of Task 2.1, NO production code path calls this function. It exists so Task 2.2's
    per-policy Settings Catalog walk has a working, tested corpus-capture primitive to call
    when that orchestrator lands - Get-PulseTenantSnapshot's own collection pipeline does
    NOT invoke this today, so a snapshot produced by the current shipped collector does
    NOT contain a settingDefinitions reference entry, full stop. This is intentional
    staging (the interface this task was scoped to build), not a claim that snapshot
    definitions-corpus capture is a shipped, end-to-end feature yet - do not represent it
    as one until T2.2's orchestrator actually calls this function from a real collection
    run.

    Fetches via a single Get-GraphObject -Type ConfigurationSettingDefinition -Operation
    ListBeta call (released in GraphKit 0.1.1 - the G-gate's own entry for this descriptor;
    see the plan's Global constraints). The T2.0 spike (Ivy24, 18,227 items) measured this
    fetch at 20-36 s TTFB-dominated and ~1.15-1.2 GB of managed heap to materialize the
    response as PowerShell objects - GraphKit's own materialization cost, not something this
    function adds on top.

    MEMORY FLOOR - CORRECTED, HONEST NUMBER (post-review fix, omp finding #7): the ~1.2 GB
    figure above is GraphKit's OWN response-materialization cost and was, pre-fix,
    incorrectly documented as this function's entire memory floor. It is not - this
    function's own canonicalization step adds a SEPARATE, real, measured cost on top:
    serializing the ~57 MB (wire-size) corpus through ConvertTo-PulseCanonicalJson's
    StringBuilder-based writer was measured to add ROUGHLY 475 MB of ADDITIONAL transient
    managed-heap usage for a corpus this size (StringBuilder growth/reallocation churn plus
    the final large string materialization) before this fix's mitigations (below) were
    applied. Stacked on top of GraphKit's own ~1.2 GB, the HONEST worst-case peak for one
    capture call is closer to ~1.7 GB, not ~1.2 GB - the pre-fix docstring's "1.2 GB is the
    accepted floor" statement undercounted this function's own contribution and is corrected
    here rather than repeated. Two concrete mitigations are applied to keep this from
    growing further, though neither eliminates the canonicalization cost itself (a true fix
    would require a STREAMING canonical-JSON writer that emits directly to a file/hash
    without ever materializing the whole document as one in-memory string - out of scope for
    this task; flagged as follow-up work, not attempted here):
      1. The canonical JSON string ($canonicalJson) is written to disk and then explicitly
         released ($canonicalJson = $null) BEFORE the compact index is built (see ONE PASS
         below) - the big string and the index are never BOTH alive at once past the write
         step, unlike the pre-fix code which kept the string, a separately-materialized
         byte[] copy of it, AND (briefly) the raw $rows all alive simultaneously.
      2. The write-then-hash sequence hashes the file's ACTUAL BYTES ON DISK via a streamed
         read (Get-PulseFileSha256, backed by SHA256.HashData(Stream)) instead of a second,
         full-size in-memory byte[] copy of the same content purely for hashing purposes
         (this also independently fixes the omp finding #2 integrity gap - see that
         function's own docstring).

    Sequence, in order (deliberately: the raw file is durable on disk BEFORE the corpus is
    ever reduced to an index, so a crash after the write but before/during indexing still
    leaves a valid, hash-verified reference/settingDefinitions.json a later run can index
    from without re-fetching):
      1. Get-GraphObject the full corpus (-ErrorAction Stop; a caught exception here is the
         CAPTURE FAILURE path - see below).
      2. Remove-PulseGraphRowProvenance strips GraphKit's four per-row provenance stamps
         defensively - the corpus is public Settings Catalog SCHEMA, not tenant data (no
         Protect-PulseGraphRowTenantId redaction pass on the corpus CONTENT itself: there is
         no tenant GUID to leak out of a schema definition's own fields the way there is in
         actual policy/instance data), but the provenance strip costs nothing and this
         function has no principled reason to be the one place in the codebase that skips
         it.
      3. Canonical-serialize, write to a UNIQUE TEMP FILE (same directory as the final
         reference/settingDefinitions.json, so the eventual rename stays same-volume/
         atomic - NOT yet the final path), then release the canonical string (mitigation #1
         above).
      4. ATOMIC PUBLISH (post-review fix, omp finding #1 - "File+manifest publication is not
         one transaction"): hash the temp file's actual bytes (mitigation #2 above), then
         call Set-PulseReferenceEntry -Status 'Captured' -PublishFromTempPath, which renames
         the temp file to its final path AND records the manifest entry INSIDE Set-
         PulseManifestEntry's single mutex hold - see that function's own docstring for why
         this closes the split-brain window a two-runspace test reproduced when the file
         write and the manifest write were two independently-locked operations (the pre-fix
         shape of this function).
      5. ONE PASS (memory contract, unchanged from the original design): Get-
         PulseSettingDefinitionIndex walks $rows exactly once to build the compact index,
         and this function then sets $rows = $null immediately afterward - the full corpus
         and the index are never both "needed" past this one indexing pass. No forced
         GC.Collect(): releasing the last reference is sufficient for the CLR to reclaim it
         on its own schedule.

    CAPTURE FAILURE (downstream contract for T2.2 - the caller side is not implemented by
    this task): ANY failure in this function's own pipeline - the initial Get-GraphObject
    fetch, OR the write/hash/publish/index steps that follow a successful fetch - records
    manifest.references.settingDefinitions -Status 'Failed' with a reason and returns $null;
    it does NOT re-throw. This mirrors the attempt-and-classify convention
    Invoke-PulseCollection already uses for dataset collection: a corpus-capture failure,
    wherever in this function's pipeline it occurs, is reported through the manifest, not a
    run-aborting exception. A caller (T2.2's per-policy expansion walk, once it exists) that
    receives $null back is expected to write every dependent expansion entry NotExpanded
    with reason 'definitions corpus unavailable' rather than attempt any join against a
    missing corpus.

    FAILURE REASONS ARE REDACTED (post-review fix, omp finding #6): every reason this
    function records is routed through Protect-PulseReason before being written to the
    manifest - a caught GraphKit exception's message can carry -Context's raw ProfileId
    (via $Context.ProfileId, resolved by GraphKit's own Get-GraphContext - e.g. an AADSTS
    error embeds the profile id verbatim) or the raw tenant GUID (via $Context.TenantId)
    just as surely as any dataset-collection failure reason can, and this function has both
    available on -Context without needing its own -ProfileId/-TenantId parameters. The
    pseudonym to substitute is read from the STORE's own manifest `tenant` field (already
    the pseudonym - see New-PulseSnapshotStore's own docstring) via
    Get-PulseSnapshotManifest, never recomputed independently, so a redacted reason always
    matches the same pseudonym every other artifact in this store uses. A store whose
    manifest has no `tenant` value yet (defensive edge case, not expected in the real T2.2
    call path where the store is always created with -Tenant already resolved) falls back to
    a fixed placeholder pseudonym so Protect-PulseReason's -Pseudonym parameter, which is
    Mandatory, always has something to substitute with.

    NO CROSS-RUN CACHE (Phase 2 scope decision - see the plan's Task 2.1 section): every
    call to this function performs a fresh Get-GraphObject fetch. There is no on-disk or
    in-memory cache keyed by tenant/profile that a later run or a later call within the same
    process reuses - freshness semantics for such a cache are explicitly undefined for this
    phase. The corpus is captured per snapshot, and any later offline evaluation of that
    snapshot reads the snapshot's OWN reference/settingDefinitions.json (via
    Get-PulseReferenceData), which is deterministic by construction (canonical JSON, hash-
    verified) - it does not need or benefit from a cross-run cache to be reproducible.
#>

function Save-PulseSettingDefinitionCorpus {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [pscustomobject] $Context
    )

    $referenceName = 'settingDefinitions'
    # Content-shape version of THIS reference file - independent of the snapshot manifest's
    # own schemaVersion field (see Set-PulseReferenceEntry's docstring).
    $referenceSchemaVersion = '1.0.0'

    # Redaction inputs (omp finding #6) - resolved ONCE, up front, since both the
    # Get-GraphObject failure path and the later write/publish failure path need the same
    # values. See this file's own docstring for why ProfileId/TenantId come from -Context
    # and Pseudonym comes from the store's own manifest.
    $storeManifest = Get-PulseSnapshotManifest -Store $Store
    $pseudonym = if ($storeManifest.ContainsKey('tenant') -and -not [string]::IsNullOrEmpty([string] $storeManifest.tenant)) {
        [string] $storeManifest.tenant
    } else {
        'tp-unknown'
    }
    $profileId = ''
    if ($null -ne $Context -and $Context.PSObject.Properties['ProfileId'] -and $Context.ProfileId) {
        $profileId = [string] $Context.ProfileId
    }
    $tenantId = $null
    if ($null -ne $Context -and $Context.PSObject.Properties['TenantId'] -and $Context.TenantId) {
        $tenantId = [string] $Context.TenantId
    }

    try {
        $rows = @(Get-GraphObject -Context $Context -Type 'ConfigurationSettingDefinition' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $reason = Protect-PulseReason -Message "capture-failed: $($_.Exception.Message)" -ProfileId $profileId -Pseudonym $pseudonym -TenantId $tenantId
        Set-PulseReferenceEntry -Store $Store -Name $referenceName -Status 'Failed' -Reason $reason
        return $null
    }

    $tempPath = $null
    try {
        # Defensive provenance strip only - see this function's docstring for why no
        # Protect-PulseGraphRowTenantId pass runs on the corpus content itself.
        $rows = Remove-PulseGraphRowProvenance -Data $rows
        $itemCount = $rows.Count

        $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $rows

        # UNIQUE temp name, same directory as the final path (omp finding #1) - the rename
        # in step 4 below stays same-volume/atomic, and a unique name means two concurrent
        # captures for the same reference name never collide on the SAME temp file.
        $tempFileName = "$referenceName.$([guid]::NewGuid().ToString('N')).tmp"
        $tempPath = Join-Path $Store.ReferencePath $tempFileName
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($tempPath, $canonicalJson, $utf8NoBom)

        # Release the big string NOW (mitigation #1, omp finding #7) - the hash below reads
        # the file back from disk rather than re-using this string or a byte[] copy of it.
        $canonicalJson = $null

        # Hash the ACTUAL bytes on disk, streamed (mitigation #2, omp findings #2 and #7).
        $sha256 = Get-PulseFileSha256 -Path $tempPath

        $retrievedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
        $relativePath = "reference/$referenceName.json"

        # ATOMIC: rename temp -> final AND manifest entry write, inside Set-PulseManifestEntry's
        # single mutex hold (omp finding #1) - see Set-PulseReferenceEntry's own docstring.
        Set-PulseReferenceEntry -Store $Store -Name $referenceName -Status 'Captured' `
            -Path $relativePath -SchemaVersion $referenceSchemaVersion -Sha256 $sha256 `
            -ItemCount $itemCount -RetrievedUtc $retrievedUtc -PublishFromTempPath $tempPath

        # The rename above already moved $tempPath to its final location - nothing left to
        # clean up on the success path.
        $tempPath = $null

        # ONE PASS, then release the full corpus (memory contract, unchanged).
        $index = Get-PulseSettingDefinitionIndex -Data $rows
        $rows = $null

        return $index
    } catch {
        $reason = Protect-PulseReason -Message "capture-failed: $($_.Exception.Message)" -ProfileId $profileId -Pseudonym $pseudonym -TenantId $tenantId
        # Best-effort: if this ALSO throws, there is nothing further this function can do -
        # let that second exception propagate rather than silently swallowing the original
        # failure (matches this codebase's general "do not mask the real error" convention).
        Set-PulseReferenceEntry -Store $Store -Name $referenceName -Status 'Failed' -Reason $reason
        return $null
    } finally {
        # Orphan cleanup: a temp file left over from a failure between "written" and
        # "renamed" (e.g. the hash step or Set-PulseReferenceEntry itself throwing) should
        # not linger in reference/ forever.
        if ($null -ne $tempPath -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
