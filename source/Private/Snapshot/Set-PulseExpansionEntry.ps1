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
        $Reason
    )

    Set-PulseManifestEntry -Store $Store -ExpansionName $Name -ExpansionStatus $Status `
        -ExpansionPath $Path -ExpansionFormat 'jsonl' -ExpansionSchemaVersion $SchemaVersion `
        -ExpansionSha256 $Sha256 -ExpansionPolicyCount $PolicyCount -ExpansionRowCount $RowCount `
        -ExpansionUnresolvedNameCount $UnresolvedNameCount -ExpansionRedactedSecretCount $RedactedSecretCount `
        -ExpansionGaps $Gaps -ExpansionReason $Reason
}
