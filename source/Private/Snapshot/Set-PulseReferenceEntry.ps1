<#
    Private: the single writer for one manifest.references.<name> entry (schema 1.1.0).

    Thin, domain-typed wrapper over Set-PulseManifestEntry's 'Reference' parameter set -
    mirrors how Write-PulseDataset wraps the 'Dataset' set rather than a caller poking
    Set-PulseManifestEntry's generic parameters directly. -Format is fixed to 'json': every
    reference this module captures today (starting with the settings-catalog definitions
    corpus, Save-PulseSettingDefinitionCorpus) is a single canonical-JSON document, and
    fixing the value here means a caller cannot accidentally record a format the reader
    (Get-PulseReferenceData) does not actually know how to parse.

    STATUS-DEPENDENT FIELD INVARIANTS (post-review fix, omp finding #5): -Status 'Captured'
    now REQUIRES -Path/-SchemaVersion/-Sha256/-ItemCount/-RetrievedUtc all be supplied
    (non-null, non-empty) - a caller cannot write a "Captured" entry missing the very fields
    a reader needs to trust and locate the data, which is exactly the shape
    Get-PulseReferenceData's own new status/structural checks assume it can rely on. -Status
    'Failed' REQUIRES -Reason (a caller cannot write a Failed entry with no explanation).
    Violating either throws here, at write time, naming the missing field(s) - not
    discovered later by a reader working from an incomplete entry.

    -PublishFromTempPath (post-review fix, omp finding #1): when supplied together with
    -Status 'Captured', the caller has already staged the reference FILE at this temp path
    (same directory as the final reference/<name>.json, so the rename stays same-volume/
    atomic) and this function computes the final on-disk path
    (reference/<name>.json under Store.ReferencePath) and forwards BOTH to
    Set-PulseManifestEntry's -ReferencePublishTempPath/-ReferencePublishFinalPath, so the
    file rename and the manifest entry that describes it happen inside that function's
    single mutex hold - see its own docstring for why this closes the split-brain window a
    two-runspace test reproduced when the file write and the manifest write were two
    independently-locked operations. Omitting -PublishFromTempPath (e.g. for a -Status
    'Failed' entry, where no file was ever written) skips the rename step entirely -
    Set-PulseManifestEntry only renames when a temp path is actually supplied.
#>

function Set-PulseReferenceEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('Captured', 'Failed')]
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
        [System.Nullable[int]] $ItemCount,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $RetrievedUtc,

        [Parameter()]
        [AllowNull()]
        $Reason,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $PublishFromTempPath
    )

    if ($Status -eq 'Captured') {
        $missing = [System.Collections.Generic.List[string]]::new()
        if ([string]::IsNullOrEmpty($Path)) { $missing.Add('Path') }
        if ([string]::IsNullOrEmpty($SchemaVersion)) { $missing.Add('SchemaVersion') }
        if ([string]::IsNullOrEmpty($Sha256)) { $missing.Add('Sha256') }
        if ($null -eq $ItemCount) { $missing.Add('ItemCount') }
        if ([string]::IsNullOrEmpty($RetrievedUtc)) { $missing.Add('RetrievedUtc') }
        if ($missing.Count -gt 0) {
            throw "Set-PulseReferenceEntry: -Status 'Captured' for reference '$Name' requires $($missing -join ', ') to be supplied - a Captured entry missing any of these cannot be trusted or located by a reader."
        }
    } elseif ($Status -eq 'Failed') {
        if ([string]::IsNullOrEmpty([string] $Reason)) {
            throw "Set-PulseReferenceEntry: -Status 'Failed' for reference '$Name' requires -Reason - a Failed entry with no explanation is not actionable."
        }
    }

    $publishParams = @{}
    if (-not [string]::IsNullOrEmpty($PublishFromTempPath)) {
        $finalPath = Join-Path $Store.ReferencePath "$Name.json"
        $publishParams = @{
            ReferencePublishTempPath  = $PublishFromTempPath
            ReferencePublishFinalPath = $finalPath
        }
    }

    Set-PulseManifestEntry -Store $Store -ReferenceName $Name -ReferenceStatus $Status `
        -ReferencePath $Path -ReferenceFormat 'json' -ReferenceSchemaVersion $SchemaVersion `
        -ReferenceSha256 $Sha256 -ReferenceItemCount $ItemCount -ReferenceRetrievedUtc $RetrievedUtc `
        -ReferenceReason $Reason @publishParams
}
