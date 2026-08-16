<#
    Private: write UTF8-no-BOM text content to a file atomically (tmp+rename), extracted
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
#>

function Set-PulseAtomicFileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $tempPath = "$Path.tmp"
    try {
        Set-Content -LiteralPath $tempPath -Value $Value -NoNewline -Encoding utf8NoBOM
        [System.IO.File]::Move($tempPath, $Path, $true)
    }
    finally {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
