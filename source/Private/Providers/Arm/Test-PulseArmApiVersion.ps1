<#
    Private: validate an ARM API version string.

    ARM versions are dated (`YYYY-MM-DD` or `YYYY-MM-DD-preview`). Graph `v1.0` /
    `beta` values are contract failures, not a reason to send the request.
#>

function Test-PulseArmApiVersion {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ApiVersion
    )

    if ([string]::IsNullOrWhiteSpace($ApiVersion)) {
        throw 'ARM API version is required.'
    }

    if ($ApiVersion -notmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?$') {
        throw "ARM API version '{0}' is not a dated Resource Manager version (Graph v1.0/beta values are rejected)." -f $ApiVersion
    }

    return $true
}
