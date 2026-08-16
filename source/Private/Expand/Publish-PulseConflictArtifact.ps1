<#
    Private: crash-consistent staging/hash/publish for Task 2.6's conflicts artifact.
    Sibling of Publish-PulseExpansionRows (T2.2's own shared jsonl helper), reusing the
    identical crash-safety sequencing that file's own docstring documents (write to a
    temp file, hash incrementally, rename to an immutable content-addressed generation
    file BEFORE the manifest mutex is ever touched, THEN call Set-PulseExpansionEntry
    pointing at that durable file) rather than a fresh, independently-reasoned publish
    path - but NOT the same function, because conflicts.json is not row-schema-v1 data:
    it is ONE canonical JSON document (the conflict records array, pretty-printed via
    ConvertTo-PulseCanonicalJson - the exact serializer every other snapshot artifact
    hash depends on), not a line-per-record jsonl file, and Publish-PulseExpansionRows's
    own row comparator/line-serializer are both hard-wired to row-schema-v1's own fields
    (policyId/settingPath/instanceId) which conflict records do not carry. -Conflicts is
    trusted to already be canonically sorted by the caller (ConvertTo-PulseConflictRecords'
    own contract) - this function does not re-sort it, matching Set-PulseExpansionEntry's
    own "callers supply pre-validated data" convention for -Gaps.

    Generation filename is "conflicts.<sha256>.json" (Set-PulseExpansionEntry's own new
    -Format 'json' passthrough records the real format in the manifest, rather than the
    'jsonl' every other producer writes) - readers must not assume every expansion file is
    line-delimited.

    -PolicyCount here is deliberately named -FamilyCount instead: Set-PulseExpansionEntry's
    own -PolicyCount parameter is still used (the same underlying manifest field every
    other expansion entry populates), but this function passes it the number of SOURCE
    expansion families the conflict scan actually drew rows from - "how many things were
    walked to produce this" generalizes cleanly from "how many policies" to "how many
    families" without needing a new manifest field.
#>

function Publish-PulseConflictArtifact {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Conflicts,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Gaps,

        [Parameter(Mandatory)]
        [int] $FamilyCount,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Reason
    )

    $sortedGaps = @($Gaps)

    if ($FamilyCount -eq 0) {
        $notExpandedReason = if ([string]::IsNullOrEmpty($Reason)) {
            'no expansion families available for conflict detection'
        } else { $Reason }
        Set-PulseExpansionEntry -Store $Store -Name 'conflicts' -Status 'NotExpanded' -Reason $notExpandedReason
        return [pscustomobject]@{ Status = 'NotExpanded'; ConflictCount = 0; FamilyCount = 0; Gaps = $sortedGaps }
    }

    $tempFileName = "conflicts.$([guid]::NewGuid().ToString('N')).tmp"
    $tempPath = Join-Path $Store.ExpandedPath $tempFileName
    $tempOwnershipTransferred = $false

    try {
        $documentText = ConvertTo-PulseCanonicalJson -InputObject ([pscustomobject]@{
                schemaVersion = '1'
                conflicts     = $Conflicts
            })
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($documentText)
        [System.IO.File]::WriteAllBytes($tempPath, $bytes)

        $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

        $generationFileName = "conflicts.$sha256.json"
        $generationPath = Join-Path $Store.ExpandedPath $generationFileName
        [System.IO.File]::Move($tempPath, $generationPath, $true)
        $tempOwnershipTransferred = $true

        $status = if ($sortedGaps.Count -eq 0) { 'Expanded' } else { 'Partial' }

        $setParams = @{
            Store         = $Store
            Name          = 'conflicts'
            Status        = $status
            Path          = "expanded/$generationFileName"
            Format        = 'json'
            SchemaVersion = '1'
            Sha256        = $sha256
            PolicyCount   = $FamilyCount
            RowCount      = $Conflicts.Count
        }
        if (-not [string]::IsNullOrEmpty($Reason)) { $setParams.Reason = $Reason }
        if ($sortedGaps.Count -gt 0) { $setParams.Gaps = $sortedGaps }

        Set-PulseExpansionEntry @setParams

        return [pscustomobject]@{ Status = $status; ConflictCount = $Conflicts.Count; FamilyCount = $FamilyCount; Gaps = $sortedGaps }
    } finally {
        if (-not $tempOwnershipTransferred -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
