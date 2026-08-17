<#
    Private: crash-consistent staging/hash/publish for Part A/T3.4's setting-presence-index
    artifact. Sibling of Publish-PulseConflictArtifact (T2.6's own conflicts.json helper),
    reusing the identical crash-safety sequencing that file's own docstring documents
    (write to a temp file, hash incrementally, rename to an immutable content-addressed
    generation file BEFORE the manifest mutex is ever touched, THEN call
    Set-PulseExpansionEntry pointing at that durable file) rather than a fresh,
    independently-reasoned publish path - but not the same function, for the identical
    reason Publish-PulseConflictArtifact is not Publish-PulseExpansionRows: this artifact is
    ONE canonical JSON document (family -> settingDefinitionId -> presence entry), not
    row-schema-v1 line-delimited data.

    Generation filename is "settingPresenceIndex.<sha256>.json" (matches conflicts.json's
    own "<name>.<sha256>.<ext>" convention) - Set-PulseExpansionEntry's -Format 'json'
    records the real format in the manifest, exactly like the conflicts artifact.

    -FamilyCount here is the SAME repurposed field Publish-PulseConflictArtifact's own
    -PolicyCount/-FamilyCount rename docstring already establishes for this artifact
    family: the number of SOURCE expansion families the index actually drew rows from
    (0, 1, 2, or 3), stamped into the manifest's shared PolicyCount field - "how many
    things were walked to produce this", generalized from "how many policies" to "how many
    families" exactly like the conflicts artifact. This is deliberately NOT the distinct
    per-policy count (a family that verifies successfully but happens to contain zero
    policies this snapshot - a legitimate "Expanded, empty" outcome, same as every other
    T2.2/T2.3 producer's own "zero rows is not a gap" rule - must still count as one
    verified family, not zero, or Publish would wrongly downgrade a real, verified,
    just-empty result to NotExpanded). -RowCount carries the number of DISTINCT (family,
    settingDefinitionId) presence entries the index contains - "how big is this index",
    the number Part B's checks would otherwise have to count themselves.

    ZERO FAMILIES AVAILABLE -> NotExpanded, mirroring Publish-PulseConflictArtifact's own
    -FamilyCount 0 path exactly (see the driver, Invoke-PulseSettingPresenceIndexBuild, for
    when this applies).
#>

function Publish-PulseSettingPresenceIndex {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Families,

        [Parameter(Mandatory)]
        [int] $FamilyCount,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Gaps,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Reason
    )

    $sortedGaps = @($Gaps)

    if ($FamilyCount -eq 0) {
        $notExpandedReason = if ([string]::IsNullOrEmpty($Reason)) {
            'no expansion families available for the setting-presence index'
        } else { $Reason }
        Set-PulseExpansionEntry -Store $Store -Name 'settingPresenceIndex' -Status 'NotExpanded' -Reason $notExpandedReason
        return [pscustomobject]@{ Status = 'NotExpanded'; DefinitionCount = 0; FamilyCount = 0; Gaps = $sortedGaps }
    }

    $definitionCount = 0
    foreach ($family in $Families.Keys) { $definitionCount += @($Families[$family].Keys).Count }

    $tempFileName = "settingPresenceIndex.$([guid]::NewGuid().ToString('N')).tmp"
    $tempPath = Join-Path $Store.ExpandedPath $tempFileName
    $tempOwnershipTransferred = $false

    try {
        $documentText = ConvertTo-PulseCanonicalJson -InputObject ([pscustomobject]@{
                schemaVersion = '1'
                families      = $Families
            })
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($documentText)
        [System.IO.File]::WriteAllBytes($tempPath, $bytes)

        $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

        $generationFileName = "settingPresenceIndex.$sha256.json"
        $generationPath = Join-Path $Store.ExpandedPath $generationFileName
        [System.IO.File]::Move($tempPath, $generationPath, $true)
        $tempOwnershipTransferred = $true

        $status = if ($sortedGaps.Count -eq 0) { 'Expanded' } else { 'Partial' }

        $setParams = @{
            Store         = $Store
            Name          = 'settingPresenceIndex'
            Status        = $status
            Path          = "expanded/$generationFileName"
            Format        = 'json'
            SchemaVersion = '1'
            Sha256        = $sha256
            PolicyCount   = $FamilyCount
            RowCount      = $definitionCount
        }
        if (-not [string]::IsNullOrEmpty($Reason)) { $setParams.Reason = $Reason }
        if ($sortedGaps.Count -gt 0) { $setParams.Gaps = $sortedGaps }

        Set-PulseExpansionEntry @setParams

        return [pscustomobject]@{ Status = $status; DefinitionCount = $definitionCount; FamilyCount = $FamilyCount; Gaps = $sortedGaps }
    } finally {
        if (-not $tempOwnershipTransferred -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
