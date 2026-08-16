<#
    Private: write UTF8-no-BOM content to a file atomically (tmp+rename), extracted
    (post-review fix) from Set-PulseManifestEntry's own write-then-rename pattern so every
    file this module writes to a snapshot store - the manifest, a dataset file, the
    manifest's own initial write - goes through exactly one implementation of "never leave
    a truncated or half-written file on disk", instead of three separate copies of the same
    logic that could silently drift apart.

    The temp file is written BESIDE the destination (same directory, so the rename is
    same-volume and therefore atomic on every platform this module supports), then
    published with [System.IO.File]::Move(..., $true) - an atomic replace, not a
    read-then-overwrite. A crash or interruption mid-write can only ever leave the OLD
    destination file (untouched) or the .tmp file (never the destination itself
    truncated/partial) - a reader can never observe a half-written file at the destination
    path. The temp file is always removed by the time this function returns, whether the
    write succeeded or failed.

    -Bytes PARAMETER SET (post-review fix, omp finding #2 - "SHA-256 must hash FILE BYTES
    not re-encoded text"): -Value (a [string]) goes through PowerShell's own Set-Content
    -Encoding utf8NoBOM text encoder to become bytes on disk - a caller that separately
    computed a hash from `[System.Text.Encoding]::UTF8.GetBytes($sameString)` is trusting
    that its own re-encoding matches whatever Set-Content's encoder actually wrote, rather
    than hashing the bytes that are actually persisted. -Bytes lets a caller hand this
    function the EXACT byte array to write - [System.IO.File]::WriteAllBytes(...), no text
    encoder involved at all - so a caller that hashes that same byte array before calling
    this function is guaranteed, not merely likely, to have hashed what ends up on disk.
    Write-PulseDataset uses this parameter set for exactly that reason.
#>

function Set-PulseAtomicFileContent {
    [CmdletBinding(DefaultParameterSetName = 'Text')]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory, ParameterSetName = 'Text')]
        [AllowEmptyString()]
        [string] $Value,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [byte[]] $Bytes
    )

    $tempPath = "$Path.tmp"
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Bytes') {
            [System.IO.File]::WriteAllBytes($tempPath, $Bytes)
        } else {
            Set-Content -LiteralPath $tempPath -Value $Value -NoNewline -Encoding utf8NoBOM
        }
        [System.IO.File]::Move($tempPath, $Path, $true)
    }
    finally {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
