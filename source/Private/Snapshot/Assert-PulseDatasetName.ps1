<#
    Private: validate a dataset name before it is used to build a file path or manifest key.

    Dataset names become literal path segments (datasets/<Name>.json) and dictionary keys
    in the manifest. Without validation, a name containing path-traversal segments - for
    example '..\manifest' - could escape the datasets/ directory and overwrite arbitrary
    files in the snapshot store, including manifest.json itself. Every function that takes
    a dataset -Name calls this before touching disk.

    -Kind (Task 2.1): Set-PulseReferenceEntry/Set-PulseExpansionEntry reuse this exact same
    validation for reference/expansion names (same path-segment/manifest-key shape, same
    traversal risk against reference/ and expanded/) rather than forking a copy of the
    regex - -Kind only changes the noun in the thrown message ('dataset name' by default,
    unchanged for every pre-existing caller) so a reference/expansion name rejection reads
    correctly instead of misleadingly calling itself a "dataset name".
#>

function Assert-PulseDatasetName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Name,

        [Parameter()]
        [string] $Kind = 'dataset name'
    )

    if ([string]::IsNullOrEmpty($Name) -or $Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]*$') {
        throw "Invalid $Kind '$Name': ${Kind}s must start with a letter or digit and contain only letters, digits, underscore or hyphen."
    }
}
