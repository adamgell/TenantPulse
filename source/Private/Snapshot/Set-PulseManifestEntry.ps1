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
    manifest.json. A manifest opened here that predates schema 1.1.0 (no `references`/
    `expansions` member at all - see New-PulseSnapshotStore's own docstring) has that member
    initialized to an empty ordered dictionary before the entry is set, exactly like the
    existing `datasets` auto-vivification below.
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
        $ExpansionReason
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
            if (-not $manifest.ContainsKey('references') -or $null -eq $manifest.references) {
                $manifest.references = [ordered]@{}
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
            if (-not $manifest.ContainsKey('expansions') -or $null -eq $manifest.expansions) {
                $manifest.expansions = [ordered]@{}
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
            if (-not $manifest.ContainsKey('datasets') -or $null -eq $manifest.datasets) {
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
