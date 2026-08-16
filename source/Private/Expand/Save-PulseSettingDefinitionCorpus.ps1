<#
    Private: capture the full Settings Catalog definitions corpus into a snapshot store and
    hand back a compact, join-ready index - never the full corpus itself.

    Fetches via a single Get-GraphObject -Type ConfigurationSettingDefinition -Operation
    ListBeta call (released in GraphKit 0.1.1 - the G-gate's own entry for this descriptor;
    see the plan's Global constraints). The T2.0 spike (Ivy24, 18,227 items) measured this
    fetch at 20-36 s TTFB-dominated and ~1.15-1.2 GB of managed heap to materialize the
    response as PowerShell objects - GraphKit's own materialization cost, not something this
    function adds on top. THIS ~1.2 GB FIGURE IS THE ACCEPTED MEMORY FLOOR for one corpus
    capture: GraphKit owns the response and this function does not copy it wholesale a
    second time anywhere - see the ONE-PASS note below for the one place that could have,
    and does not.

    Sequence, in order (deliberately: the raw file is durable on disk BEFORE the corpus is
    ever reduced to an index, so a crash after the write but before/during indexing still
    leaves a valid, hash-verified reference/settingDefinitions.json a later run can index
    from without re-fetching):
      1. Get-GraphObject the full corpus (-ErrorAction Stop; a caught exception here is the
         ONLY failure path - see CAPTURE FAILURE below).
      2. Remove-PulseGraphRowProvenance strips GraphKit's four per-row provenance stamps
         defensively - the corpus is public Settings Catalog SCHEMA, not tenant data (no
         Protect-PulseGraphRowTenantId redaction pass: there is no tenant GUID to leak out
         of a schema definition's own fields the way there is in actual policy/instance
         data), but the provenance strip costs nothing and this function has no principled
         reason to be the one place in the codebase that skips it.
      3. Canonical-serialize and atomically write reference/settingDefinitions.json
         (Set-PulseAtomicFileContent - same tmp+rename pattern every other snapshot file
         write in this codebase uses).
      4. Hash the written bytes and record the capture via Set-PulseReferenceEntry -Status
         Captured (path/schemaVersion/sha256/itemCount/retrievedUtc) - -SchemaVersion here
         is this reference FILE's own content-shape version ('1.0.0', independent of the
         snapshot manifest's own schemaVersion field - see Set-PulseReferenceEntry's
         docstring), not a GraphKit or GraphAPI version.
      5. ONE PASS (memory contract): Get-PulseSettingDefinitionIndex walks $rows exactly
         once to build the compact index, and this function then sets $rows = $null
         immediately afterward - the only reference this function holds to the full corpus
         is released before returning, so the full corpus and the index are never both
         "needed" past this one indexing pass. This function does not force a GC.Collect();
         releasing the last reference is sufficient for the CLR to reclaim it on its own
         schedule, and forcing collection here would add real wall-clock cost to every
         capture for no correctness benefit.

    CAPTURE FAILURE (downstream contract for T2.2, not implemented by this task): if
    Get-GraphObject throws, this function records manifest.references.settingDefinitions
    -Status Failed with a reason derived from the caught exception (no -TenantId/-Pseudonym
    parameter exists on this function to redact a raw tenant id out of that message - unlike
    Invoke-PulseCollection's dataset path, this corpus capture has no tenant context of its
    own; a caller that has one and cares about redacting it should catch and re-wrap before
    calling this function, or extend it, rather than have this function silently assume no
    redaction is ever needed) and returns $null - it does NOT re-throw. This mirrors the
    attempt-and-classify convention Invoke-PulseCollection already uses for dataset
    collection: a corpus-capture failure is reported through the manifest, not a run-aborting
    exception. A caller (T2.2's per-policy expansion walk) that receives $null back is
    expected to write every dependent expansion entry NotExpanded with reason 'definitions
    corpus unavailable' rather than attempt any join against a missing corpus - that walk is
    out of this task's scope; this function's job ends at recording the Failed reference
    entry and returning $null so the caller can detect the failure.

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
    # Content-shape version of THIS reference file - see this function's own docstring,
    # step 4. Independent of the snapshot manifest's schemaVersion.
    $referenceSchemaVersion = '1.0.0'

    try {
        $rows = @(Get-GraphObject -Context $Context -Type 'ConfigurationSettingDefinition' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $reason = "capture-failed: $($_.Exception.Message)"
        Set-PulseReferenceEntry -Store $Store -Name $referenceName -Status 'Failed' -Reason $reason
        return $null
    }

    # Defensive provenance strip only - see this function's docstring for why no
    # Protect-PulseGraphRowTenantId pass runs here.
    $rows = Remove-PulseGraphRowProvenance -Data $rows

    $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $rows
    $relativePath = "reference/$referenceName.json"
    $referencePath = Join-Path $Store.ReferencePath "$referenceName.json"
    Set-PulseAtomicFileContent -Path $referencePath -Value $canonicalJson

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
    $itemCount = $rows.Count
    $retrievedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)

    Set-PulseReferenceEntry -Store $Store -Name $referenceName -Status 'Captured' `
        -Path $relativePath -SchemaVersion $referenceSchemaVersion -Sha256 $sha256 `
        -ItemCount $itemCount -RetrievedUtc $retrievedUtc

    # ONE PASS, then release the full corpus - see this function's docstring, step 5.
    $index = Get-PulseSettingDefinitionIndex -Data $rows
    $rows = $null

    return $index
}
