<#
    Private: the single writer for one manifest.references.<name> entry (schema 1.1.0).

    Thin, domain-typed wrapper over Set-PulseManifestEntry's 'Reference' parameter set -
    mirrors how Write-PulseDataset wraps the 'Dataset' set rather than a caller poking
    Set-PulseManifestEntry's generic parameters directly. -Format is fixed to 'json': every
    reference this module captures today (starting with the settings-catalog definitions
    corpus, Save-PulseSettingDefinitionCorpus) is a single canonical-JSON document, and
    fixing the value here means a caller cannot accidentally record a format the reader
    (Get-PulseReferenceData) does not actually know how to parse.

    -Status 'Captured' is the normal, successful outcome - -Path/-SchemaVersion/-Sha256/
    -ItemCount/-RetrievedUtc are all expected to be supplied together in that case.
    -Status 'Failed' records only -Reason (a capture-time exception message, already
    caller-redacted where the caller has the means to redact) - no file was written, so
    -Path/-Sha256/etc. are left absent, exactly like Write-PulseDataset's own Failed/Skipped
    path for datasets. This is the entry a downstream expansion reader inspects to decide
    whether the definitions corpus is even available before attempting a join against it -
    see Save-PulseSettingDefinitionCorpus's own docstring for the capture-failure contract.
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
        $Reason
    )

    Set-PulseManifestEntry -Store $Store -ReferenceName $Name -ReferenceStatus $Status `
        -ReferencePath $Path -ReferenceFormat 'json' -ReferenceSchemaVersion $SchemaVersion `
        -ReferenceSha256 $Sha256 -ReferenceItemCount $ItemCount -ReferenceRetrievedUtc $RetrievedUtc `
        -ReferenceReason $Reason
}
