<#
    Private: validate a dataset name before it is used to build a file path or manifest key.

    Dataset names become literal path segments (datasets/<Name>.json) and dictionary keys
    in the manifest. Without validation, a name containing path-traversal segments - for
    example '..\manifest' - could escape the datasets/ directory and overwrite arbitrary
    files in the snapshot store, including manifest.json itself. Every function that takes
    a dataset -Name calls this before touching disk.
#>

function Assert-PulseDatasetName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Name
    )

    if ([string]::IsNullOrEmpty($Name) -or $Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]*$') {
        throw "Invalid dataset name '$Name': dataset names must start with a letter or digit and contain only letters, digits, underscore or hyphen."
    }
}
