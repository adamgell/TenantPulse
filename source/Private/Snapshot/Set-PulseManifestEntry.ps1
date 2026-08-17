<#
    Private: the single funnel for every manifest.json write.

    Two mutually exclusive usages: update one dataset's status/reason/provenance entry
    (the path Write-PulseDataset uses internally for every status, including the
    Failed/Skipped case where no dataset file is written), or set the top-level
    collectionFailure field. No other function in the snapshot store writes manifest.json
    directly - this keeps every mutation going through one canonical-serialization path.

    The whole read-modify-write cycle is guarded by a named Mutex scoped to this store's
    root path, so two writers (same process, different threads, or different processes)
    never interleave a read-modify-write and silently drop one another's update. The write
    itself goes to manifest.json.tmp and is published with an atomic File.Move/replace, so
    a crash mid-write can never leave manifest.json truncated or half-written - readers see
    either the old manifest or the new one, never a partial one.

    REFERENCE/EXPANSION PARAMETER SETS (Task 2.1, schema 1.1.0): two more mutually
    exclusive usages besides Dataset/CollectionFailure - update one manifest.references.<name>
    entry (Set-PulseReferenceEntry's sole implementation) or one manifest.expansions.<name>
    entry (Set-PulseExpansionEntry's sole implementation). Both go through the exact same
    mutex-guarded read-modify-write-then-atomic-publish cycle as the Dataset set, rather than
    forking a second copy of that machinery - this remains the one function that ever writes
    manifest.json.

    REJECTS a 1.0.0-schema store (post-review fix, omp finding #4): a manifest that predates
    schema 1.1.0 has no `references`/`expansions` member AT ALL (see New-PulseSnapshotStore's
    own docstring) - this function used to auto-vivify an empty `[ordered]@{}` for whichever
    namespace was missing and write the entry anyway, which silently promoted a 1.0.0-schema
    manifest to something that LOOKS like 1.1.0 (it now has a `references` or `expansions`
    key) without actually being one - the manifest's own `schemaVersion` field still reads
    '1.0.0', a self-contradictory document no reader was ever designed to handle. A caller
    that tries to write a reference/expansion entry to a store whose manifest lacks that
    namespace now gets an immediate, named throw instead of silent corruption of the
    declared schema shape.

    ATOMIC FILE-PUBLISH-THEN-MANIFEST-UPDATE (post-review fix, omp finding #1 - "File+manifest
    publication is not one transaction"): -PublishTempPath/-PublishFinalPath (Reference and
    Expansion sets only) let a caller stage a reference/expansion FILE at a unique temp path
    ahead of time, then publish it - `[System.IO.File]::Move($PublishTempPath,
    $PublishFinalPath, $true)` - and record the manifest entry describing it, BOTH inside this
    function's single mutex hold, as one indivisible operation from any OTHER writer's point
    of view. Before this fix, Save-PulseSettingDefinitionCorpus wrote its reference FILE via
    its own separate atomic tmp+rename (outside any mutex), THEN separately called
    Set-PulseReferenceEntry to record the manifest entry (a second, independently-mutex-guarded
    operation) - two writers targeting the SAME reference name could interleave their file
    writes and manifest writes across that gap, producing "split-brain": writer A's manifest
    entry (hash, itemCount) describing writer B's file content, reproduced with a two-runspace
    test. Folding the rename into this function's existing mutex hold closes that window
    entirely - no other writer can observe the file and the manifest entry in a
    partially-updated pairing, because no other writer can even acquire the mutex until this
    whole publish (rename + manifest write) has completed. The move happens ONLY once the
    mutex is held and BEFORE the manifest is re-read/rewritten, so the manifest snapshot this
    function serializes always describes the file exactly as it exists on disk at that same
    instant.
#>

function Set-PulseManifestEntry {
    [CmdletBinding(DefaultParameterSetName = 'Dataset')]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory, ParameterSetName = 'Dataset')]
        [string] $Name,

        [Parameter(Mandatory, ParameterSetName = 'Dataset')]
        [ValidateSet('Collected', 'Failed', 'Skipped')]
        [string] $Status,

        # Reason, ApiVersion, Sha256 and CollectedUtc are deliberately left untyped:
        # Write-PulseDataset always passes these explicitly (including an explicit $null
        # for a Failed/Skipped dataset with no reason, or for the fields only Collected
        # populates). A [string] parameter type would coerce an explicit $null argument
        # into an empty string during binding - PowerShell does this even with
        # [AllowNull()] - which would corrupt the null/absent distinction the manifest
        # schema relies on.
        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        $Reason,

        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        $ApiVersion,

        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        $Sha256,

        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        [System.Nullable[int]] $ItemCount,

        [Parameter(ParameterSetName = 'Dataset')]
        [AllowNull()]
        $CollectedUtc,

        [Parameter(Mandatory, ParameterSetName = 'CollectionFailure')]
        [string] $CollectionFailure,

        [Parameter(Mandatory, ParameterSetName = 'Reference')]
        [string] $ReferenceName,

        [Parameter(Mandatory, ParameterSetName = 'Reference')]
        [ValidateSet('Captured', 'Failed')]
        [string] $ReferenceStatus,

        [Parameter(ParameterSetName = 'Reference')]
        [AllowNull()]
        $ReferencePath,

        [Parameter(ParameterSetName = 'Reference')]
        [AllowNull()]
        $ReferenceFormat,

        [Parameter(ParameterSetName = 'Reference')]
        [AllowNull()]
        $ReferenceSchemaVersion,

        [Parameter(ParameterSetName = 'Reference')]
        [AllowNull()]
        $ReferenceSha256,

        [Parameter(ParameterSetName = 'Reference')]
        [AllowNull()]
        [System.Nullable[int]] $ReferenceItemCount,

        [Parameter(ParameterSetName = 'Reference')]
        [AllowNull()]
        $ReferenceRetrievedUtc,

        [Parameter(ParameterSetName = 'Reference')]
        [AllowNull()]
        $ReferenceReason,

        [Parameter(ParameterSetName = 'Reference')]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ReferencePublishTempPath,

        [Parameter(ParameterSetName = 'Reference')]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ReferencePublishFinalPath,

        [Parameter(Mandatory, ParameterSetName = 'Expansion')]
        [string] $ExpansionName,

        [Parameter(Mandatory, ParameterSetName = 'Expansion')]
        [ValidateSet('Expanded', 'Partial', 'NotExpanded', 'Failed')]
        [string] $ExpansionStatus,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        $ExpansionPath,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        $ExpansionFormat,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        $ExpansionSchemaVersion,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        $ExpansionSha256,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        [System.Nullable[int]] $ExpansionPolicyCount,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        [System.Nullable[int]] $ExpansionRowCount,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        [System.Nullable[int]] $ExpansionUnresolvedNameCount,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        [System.Nullable[int]] $ExpansionRedactedSecretCount,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        [object[]] $ExpansionGaps,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        $ExpansionReason,

        # Symmetric with the Reference set's own -ReferencePublishTempPath/-FinalPath (see
        # this file's own docstring) - not yet exercised by any T2.1 caller (Save-
        # PulseSettingDefinitionCorpus only writes a reference, not an expansion), but T2.2's
        # per-policy JSONL walk output needs the identical file+manifest atomicity guarantee,
        # and forking a second copy of this logic later would be exactly the kind of drift
        # this function exists to prevent.
        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ExpansionPublishTempPath,

        [Parameter(ParameterSetName = 'Expansion')]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ExpansionPublishFinalPath
    )

    if ($PSCmdlet.ParameterSetName -eq 'Dataset') {
        Assert-PulseDatasetName -Name $Name
    } elseif ($PSCmdlet.ParameterSetName -eq 'Reference') {
        Assert-PulseDatasetName -Name $ReferenceName -Kind 'reference name'
    } elseif ($PSCmdlet.ParameterSetName -eq 'Expansion') {
        Assert-PulseDatasetName -Name $ExpansionName -Kind 'expansion name'
    }

    # Mutex name is derived from a hash of the store root so every writer targeting the
    # same store - regardless of process - contends on the same named lock, while stores
    # at different paths never block each other.
    $rootHashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Store.Root))
    $rootHash = ([System.BitConverter]::ToString($rootHashBytes) -replace '-', '').ToLowerInvariant()
    $mutex = [System.Threading.Mutex]::new($false, "TenantPulse-SnapshotManifest-$rootHash")
    $acquired = $false

    try {
        $acquired = $mutex.WaitOne([System.TimeSpan]::FromSeconds(30))
        if (-not $acquired) {
            throw "Set-PulseManifestEntry: timed out waiting for the manifest lock on '$($Store.Root)'."
        }

        $manifest = Get-PulseSnapshotManifest -Store $Store

        if ($PSCmdlet.ParameterSetName -eq 'CollectionFailure') {
            $manifest.collectionFailure = $CollectionFailure
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Reference') {
            # REJECT, do not auto-vivify (post-review fix, omp finding #4) - see this file's
            # own docstring. A 1.0.0-schema manifest has no `references` member at all; a
            # reference write here is refused rather than silently promoting the manifest to
            # a self-contradictory "schemaVersion 1.0.0 but has a references key" shape.
            # .Contains, NOT .ContainsKey (here and at the expansions/datasets sites
            # below): this manifest can be an [ordered]@{} (System.Collections.
            # Specialized.OrderedDictionary), which has no ContainsKey method on
            # PowerShell 7.4's runtime - CI's 7.4 legs fail with "does not contain a
            # method named 'ContainsKey'". IDictionary.Contains is key-containment on
            # every shape this path receives (Hashtable, OrderedHashtable, OrderedDictionary).
            if (-not $manifest.Contains('references') -or $manifest.references -isnot [System.Collections.IDictionary]) {
                throw "Set-PulseManifestEntry: cannot write reference entry '$ReferenceName' - '$($Store.Root)' declares schemaVersion '$($manifest.schemaVersion)', which has no 'references' namespace. References were introduced in schema 1.1.0; only a store created (or already upgraded) to that schema accepts Set-PulseReferenceEntry writes."
            }

            # ATOMIC PUBLISH (post-review fix, omp finding #1) - see this file's own
            # docstring: the rename happens HERE, inside the mutex hold, immediately before
            # the manifest that describes it is written, so no other writer targeting this
            # same store can ever observe the file and its manifest entry out of sync.
            if (-not [string]::IsNullOrEmpty($ReferencePublishTempPath)) {
                if ([string]::IsNullOrEmpty($ReferencePublishFinalPath)) {
                    throw "Set-PulseManifestEntry: -ReferencePublishTempPath was supplied without -ReferencePublishFinalPath for reference '$ReferenceName' - both or neither."
                }
                [System.IO.File]::Move($ReferencePublishTempPath, $ReferencePublishFinalPath, $true)
            }

            $manifest.references[$ReferenceName] = [ordered]@{
                status       = $ReferenceStatus
                path         = $ReferencePath
                format       = $ReferenceFormat
                schemaVersion = $ReferenceSchemaVersion
                sha256       = $ReferenceSha256
                itemCount    = $ReferenceItemCount
                retrievedUtc = $ReferenceRetrievedUtc
                reason       = $ReferenceReason
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Expansion') {
            # REJECT, do not auto-vivify - same rule as the Reference set above, see this
            # file's own docstring (omp finding #4).
            if (-not $manifest.Contains('expansions') -or $manifest.expansions -isnot [System.Collections.IDictionary]) {
                throw "Set-PulseManifestEntry: cannot write expansion entry '$ExpansionName' - '$($Store.Root)' declares schemaVersion '$($manifest.schemaVersion)', which has no 'expansions' namespace. Expansions were introduced in schema 1.1.0; only a store created (or already upgraded) to that schema accepts Set-PulseExpansionEntry writes."
            }

            # ATOMIC PUBLISH - symmetric with the Reference set above (see this file's own
            # docstring); not yet exercised by any T2.1 caller.
            if (-not [string]::IsNullOrEmpty($ExpansionPublishTempPath)) {
                if ([string]::IsNullOrEmpty($ExpansionPublishFinalPath)) {
                    throw "Set-PulseManifestEntry: -ExpansionPublishTempPath was supplied without -ExpansionPublishFinalPath for expansion '$ExpansionName' - both or neither."
                }
                [System.IO.File]::Move($ExpansionPublishTempPath, $ExpansionPublishFinalPath, $true)
            }

            # Computed OUTSIDE the hashtable literal below, deliberately: an `if {} else {}`
            # used directly as a hashtable value literal has its "then"/"else" branch output
            # captured through the pipeline, and an empty-array branch's zero-object pipeline
            # output collapses the assigned value to $null, not @() - reproduced (gaps wrote
            # as JSON `null` instead of `[]` for the common case of no -Gaps supplied at all).
            # @($null) is also a trap on its own - it is a ONE-element array containing $null,
            # not an empty array - so the $null check must happen before the @() wrap, not
            # rely on @() to normalize a null away.
            $expansionGapsValue = if ($null -eq $ExpansionGaps) { , @() } else { , @($ExpansionGaps) }

            $manifest.expansions[$ExpansionName] = [ordered]@{
                status              = $ExpansionStatus
                path                = $ExpansionPath
                format              = $ExpansionFormat
                schemaVersion       = $ExpansionSchemaVersion
                sha256              = $ExpansionSha256
                policyCount         = $ExpansionPolicyCount
                rowCount            = $ExpansionRowCount
                unresolvedNameCount = $ExpansionUnresolvedNameCount
                redactedSecretCount = $ExpansionRedactedSecretCount
                gaps                = $expansionGapsValue
                reason              = $ExpansionReason
            }
        }
        else {
            if (-not $manifest.Contains('datasets') -or $null -eq $manifest.datasets) {
                $manifest.datasets = [ordered]@{}
            }

            $manifest.datasets[$Name] = [ordered]@{
                status       = $Status
                apiVersion   = $ApiVersion
                reason       = $Reason
                sha256       = $Sha256
                itemCount    = $ItemCount
                collectedUtc = $CollectedUtc
            }
        }

        $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $manifest

        # Write-then-rename via the shared helper (post-review fix: extracted out of this
        # function so Write-PulseDataset and New-PulseSnapshotStore's initial manifest
        # write reuse the exact same atomic pattern instead of duplicating it) - see
        # Set-PulseAtomicFileContent's own docstring.
        Set-PulseAtomicFileContent -Path $Store.ManifestPath -Value $canonicalJson
    }
    finally {
        if ($acquired) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
}
