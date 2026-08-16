<#
    Private: pseudonymize a value under the operator key.

    Snapshots and reports must never carry raw tenant IDs or other identifying values.
    This turns any string value into a stable, non-reversible pseudonym: HMAC-SHA256 of
    the UTF8 bytes of the value, keyed by the caller-supplied operator key, rendered as
    lowercase hex and prefixed 'tp-'. The same (value, key) pair always produces the same
    pseudonym; different keys or different values produce different pseudonyms.
#>

function Get-PulsePseudonym {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Value,

        [Parameter(Mandatory)]
        [byte[]] $Key
    )

    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        $valueBytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hashBytes = $hmac.ComputeHash($valueBytes)
    } finally {
        $hmac.Dispose()
    }

    $hex = [System.Convert]::ToHexString($hashBytes).ToLowerInvariant()
    return "tp-$hex"
}
