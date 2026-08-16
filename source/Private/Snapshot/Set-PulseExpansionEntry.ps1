<#
    Private: the single writer for one manifest.expansions.<name> entry (schema 1.1.0).

    Thin, domain-typed wrapper over Set-PulseManifestEntry's 'Expansion' parameter set -
    mirrors Set-PulseReferenceEntry/Write-PulseDataset's own wrapper pattern rather than a
    caller poking Set-PulseManifestEntry's generic parameters directly. -Format is fixed to
    'jsonl': every expansion artifact this module writes (a per-policy settings walk, one
    row per resolved setting) is a JSON-Lines file, not a single JSON document, and fixing
    the value here means a caller cannot accidentally record a format the reader does not
    actually know how to parse.

    Four outcomes, not two, because an expansion is a WALK over N policies rather than one
    all-or-nothing fetch:
      - 'Expanded': every targeted policy walked cleanly; -Gaps is empty (or omitted).
      - 'Partial': at least one policy walked cleanly and at least one did not - -Gaps
        carries {policyId; reason} for every policy that did not.
      - 'NotExpanded': no policy could be walked at all - e.g. the definitions corpus this
        walk depends on was never captured (Save-PulseSettingDefinitionCorpus recorded its
        own reference entry Failed) - see that function's own docstring. -PolicyCount/
        -RowCount are typically 0 on this path, but this function does not enforce that;
        the walk that calls this is the source of truth for its own counts.
      - 'Failed': the walk itself errored out before it could classify per-policy gaps.

    -Gaps accepts an array of {policyId; reason} entries (or $null/empty for a clean
    'Expanded' outcome) and is written through unmodified - this function does not validate
    the shape of individual gap entries, matching Set-PulseManifestEntry's own "callers
    supply pre-validated data" convention for structured, deep manifest fields.

    STATUS-DEPENDENT FIELD INVARIANTS (post-review fix, omp finding #5 - same rule
    Set-PulseReferenceEntry now enforces, see its own docstring): -Status 'Expanded' or
    'Partial' both describe a written expansion FILE and require -Path/-SchemaVersion/
    -Sha256/-PolicyCount/-RowCount all be supplied - a caller cannot record either outcome
    without the fields a reader needs to locate and trust the file. -Status 'Partial'
    additionally requires a non-empty -Gaps (a Partial outcome with no gap entries is a
    contradiction - if nothing was ungapped, the outcome is 'Expanded'). -Status
    'NotExpanded' or 'Failed' both describe "no usable file was produced" and require
    -Reason - a caller cannot write either with no explanation.
#>

function Set-PulseExpansionEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('Expanded', 'Partial', 'NotExpanded', 'Failed')]
        [string] $Status,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Path,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $SchemaVersion,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Sha256,

        # Task 2.6 addition: every T2.2/T2.3 producer writes a JSON-Lines expansion file
        # (one row per line), so 'jsonl' stays the default - no existing caller passes this
        # and every one of them keeps recording 'jsonl' exactly as before. The T2.6
        # conflicts artifact is a single canonical JSON DOCUMENT, not a line-delimited file
        # (Publish-PulseConflictArtifact's own docstring explains why a per-conflict jsonl
        # line shape does not fit - conflict records need a whole-document ordinal sort key
        # the row-schema-v1 producers' own comparator does not carry), so it is the one
        # caller that passes -Format 'json'.
        [Parameter()]
        [ValidateSet('jsonl', 'json')]
        [string] $Format = 'jsonl',

        [Parameter()]
        [AllowNull()]
        [System.Nullable[int]] $PolicyCount,

        [Parameter()]
        [AllowNull()]
        [System.Nullable[int]] $RowCount,

        [Parameter()]
        [AllowNull()]
        [System.Nullable[int]] $UnresolvedNameCount,

        [Parameter()]
        [AllowNull()]
        [System.Nullable[int]] $RedactedSecretCount,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Gaps,

        [Parameter()]
        [AllowNull()]
        $Reason,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $PublishFromTempPath
    )

    if ($Status -eq 'Expanded' -or $Status -eq 'Partial') {
        $missing = [System.Collections.Generic.List[string]]::new()
        if ([string]::IsNullOrEmpty($Path)) { $missing.Add('Path') }
        if ([string]::IsNullOrEmpty($SchemaVersion)) { $missing.Add('SchemaVersion') }
        if ([string]::IsNullOrEmpty($Sha256)) { $missing.Add('Sha256') }
        if ($null -eq $PolicyCount) { $missing.Add('PolicyCount') }
        if ($null -eq $RowCount) { $missing.Add('RowCount') }
        if ($missing.Count -gt 0) {
            throw "Set-PulseExpansionEntry: -Status '$Status' for expansion '$Name' requires $($missing -join ', ') to be supplied - an $Status entry missing any of these cannot be trusted or located by a reader."
        }
        # $null -Gaps must count as ZERO gaps, not one - @($null) is a one-element array
        # containing $null, the same trap Set-PulseManifestEntry's own gaps-serialization
        # fix (see its docstring) already had to guard against.
        $suppliedGapsCount = if ($null -eq $Gaps) { 0 } else { @($Gaps).Count }
        if ($Status -eq 'Partial' -and $suppliedGapsCount -eq 0) {
            throw "Set-PulseExpansionEntry: -Status 'Partial' for expansion '$Name' requires a non-empty -Gaps - a Partial outcome with no gap entries is a contradiction (use -Status 'Expanded' if nothing was ungapped)."
        }
    } elseif ($Status -eq 'NotExpanded' -or $Status -eq 'Failed') {
        if ([string]::IsNullOrEmpty([string] $Reason)) {
            throw "Set-PulseExpansionEntry: -Status '$Status' for expansion '$Name' requires -Reason - a $Status entry with no explanation is not actionable."
        }
    }

    $publishParams = @{}
    if (-not [string]::IsNullOrEmpty($PublishFromTempPath)) {
        $finalPath = Join-Path $Store.ExpandedPath "$Name.jsonl"
        $publishParams = @{
            ExpansionPublishTempPath  = $PublishFromTempPath
            ExpansionPublishFinalPath = $finalPath
        }
    }

    Set-PulseManifestEntry -Store $Store -ExpansionName $Name -ExpansionStatus $Status `
        -ExpansionPath $Path -ExpansionFormat $Format -ExpansionSchemaVersion $SchemaVersion `
        -ExpansionSha256 $Sha256 -ExpansionPolicyCount $PolicyCount -ExpansionRowCount $RowCount `
        -ExpansionUnresolvedNameCount $UnresolvedNameCount -ExpansionRedactedSecretCount $RedactedSecretCount `
        -ExpansionGaps $Gaps -ExpansionReason $Reason @publishParams
}
