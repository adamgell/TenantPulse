<#
    Private: stream canonical JSON to a caller-owned Stream, hashing the exact UTF-8
    bytes written.

    ConvertTo-PulseCanonicalJson materializes the entire document in a StringBuilder.
    Dataset persist and the JSON renderer use this instead so a large array is emitted
    row-by-row through the SAME Write-PulseCanonicalJsonValue ordering/escaping path.
    The builder buffers small Append calls and flushes UTF-8 chunks; Flush must run
    after Write-PulseCanonicalJsonValue returns.

    Returns the lowercase hex SHA-256 of the bytes written (IncrementalHash of those
    bytes, not a re-encoded string).
#>

function New-PulseJsonStreamBuilder {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream,

        [Parameter()]
        [AllowNull()]
        [System.Security.Cryptography.IncrementalHash] $IncrementalHash
    )

    $state = [pscustomobject]@{
        Stream = $Stream
        Hash   = $IncrementalHash
        Buffer = [System.Text.StringBuilder]::new(8192)
    }

    $builder = New-Object System.Management.Automation.PSObject
    $builder | Add-Member -NotePropertyName _pulseJsonStreamState -NotePropertyValue $state
    $builder | Add-Member -MemberType ScriptMethod -Name Append -Value {
        param($value)
        $s = $this._pulseJsonStreamState
        [void] $s.Buffer.Append([string] $value)
        if ($s.Buffer.Length -ge 8192) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($s.Buffer.ToString())
            $s.Stream.Write($bytes, 0, $bytes.Length)
            if ($null -ne $s.Hash) {
                $s.Hash.AppendData($bytes)
            }
            [void] $s.Buffer.Clear()
        }
        return $this
    }
    $builder | Add-Member -MemberType ScriptMethod -Name Flush -Value {
        $s = $this._pulseJsonStreamState
        if ($s.Buffer.Length -eq 0) {
            return
        }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($s.Buffer.ToString())
        $s.Stream.Write($bytes, 0, $bytes.Length)
        if ($null -ne $s.Hash) {
            $s.Hash.AppendData($bytes)
        }
        [void] $s.Buffer.Clear()
    }
    return $builder
}

function Write-PulseCanonicalJsonToStream {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $InputObject,

        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $Depth = 64
    )

    $incrementalHash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $builder = New-PulseJsonStreamBuilder -Stream $Stream -IncrementalHash $incrementalHash
        Write-PulseCanonicalJsonValue -Value $InputObject -Builder $builder -IndentLevel 0 -MaxDepth $Depth -CurrentDepth 0
        $builder.Flush()
        $hashBytes = $incrementalHash.GetHashAndReset()
        return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
    } finally {
        $incrementalHash.Dispose()
    }
}

function Publish-PulseAtomicStreamFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [scriptblock] $WriteAction
    )

    $tempPath = "$Path.tmp"
    $published = $false
    $writeResult = $null
    try {
        $fileStream = [System.IO.File]::Open($tempPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $writeResult = & $WriteAction $fileStream
            $fileStream.Flush()
        } finally {
            $fileStream.Dispose()
        }
        [System.IO.File]::Move($tempPath, $Path, $true)
        $published = $true
        return $writeResult
    } finally {
        if (-not $published -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
