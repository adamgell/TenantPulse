<#
    Private: read and validate an operator key file, or return $null if it doesn't exist yet.

    Shared by Get-PulseOperatorKey's normal read path and its "lost the create race"
    fallback path so both enforce the same validation: exactly 32 bytes, or a loud,
    actionable error - never a silently truncated/empty key that would make every
    subsequent pseudonym wrong without any visible failure.
#>

function Get-PulseOperatorKeyFromDisk {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [string] $KeyPath
    )

    if (-not (Test-Path -LiteralPath $KeyPath -PathType Leaf)) {
        return $null
    }

    $bytes = [byte[]] (Get-Content -LiteralPath $KeyPath -AsByteStream -Raw)
    $length = if ($null -eq $bytes) { 0 } else { $bytes.Length }

    if ($length -ne 32) {
        throw "Operator key file is corrupt ($length bytes, expected 32). Delete $KeyPath to regenerate - note regeneration breaks pseudonym stability with prior snapshots."
    }

    return , $bytes
}
