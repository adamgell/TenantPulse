<#
    Private: compute the SHA-256 of a file's actual on-disk bytes, streamed.

    Extracted (post-review fix, omp findings #2 and #7) as its own function rather than
    inlined at each call site: opens the file as a read stream and hands it directly to
    [System.Security.Cryptography.SHA256]::HashData(Stream) - .NET reads and hashes the
    file in internal fixed-size chunks, so the caller never materializes a byte[] the size
    of the whole file just to hash it. This is what Save-PulseSettingDefinitionCorpus uses
    to hash the settings-catalog reference file (tens of MB) without a second full-size
    array alongside the canonical JSON string that was already the memory-heavy part of
    that operation - see that function's own docstring for the corpus-sized memory budget
    this streaming hash specifically helps with.

    Hashing the file AFTER it has been fully written (rather than hashing bytes in memory
    before/while writing) also closes the omp finding #2 integrity gap directly: this
    function's hash is always of the literal bytes that ended up on disk, never of a
    re-encoded in-memory representation that could drift from what was actually persisted.
#>

function Get-PulseFileSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hashBytes = [System.Security.Cryptography.SHA256]::HashData($stream)
        return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
    } finally {
        $stream.Dispose()
    }
}
