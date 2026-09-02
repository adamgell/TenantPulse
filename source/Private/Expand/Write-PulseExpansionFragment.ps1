<#
    Private: write one identifiable, resumable expansion fragment (jsonl) under
    expanded/fragments/<Name>/.

    FragmentId is a path segment (Assert-PulseDatasetName) so a later merge can name
    every piece and skip a rewrite when the on-disk bytes already match. Rows are
    sorted on (policyId, settingPath, instanceId) with the same ordinal comparison
    Publish-PulseExpansionRows uses, then serialized through ConvertTo-PulseCanonicalJsonLine
    with incremental SHA-256 and an atomic tmp+rename.
#>

function Get-PulseExpansionFragmentDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name
    )

    Assert-PulseDatasetName -Name $Name -Kind 'expansion name'
    return (Join-Path $Store.ExpandedPath (Join-Path 'fragments' $Name))
}

function Get-PulseExpansionFragmentPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $FragmentId
    )

    Assert-PulseDatasetName -Name $FragmentId -Kind 'expansion fragment id'
    return (Join-Path (Get-PulseExpansionFragmentDirectory -Store $Store -Name $Name) "$FragmentId.jsonl")
}

function New-PulseExpansionFragmentId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int] $StartOrdinal,

        [Parameter(Mandatory)]
        [int] $EndOrdinal,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $PolicyIds
    )

    $joined = ($PolicyIds -join ',')
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($joined))
    $hash12 = (([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()).Substring(0, 12)
    return ('{0:D6}-{1:D6}-{2}' -f $StartOrdinal, $EndOrdinal, $hash12)
}

function Write-PulseExpansionFragment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $FragmentId,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Rows
    )

    Assert-PulseDatasetName -Name $Name -Kind 'expansion name'
    Assert-PulseDatasetName -Name $FragmentId -Kind 'expansion fragment id'

    $sortedRows = @($Rows)
    if ($sortedRows.Count -gt 1) {
        $rowComparison = [System.Comparison[object]] {
            param($a, $b)
            $c = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
            if ($c -ne 0) { return $c }
            $c = [string]::CompareOrdinal([string] $a.settingPath, [string] $b.settingPath)
            if ($c -ne 0) { return $c }
            return [string]::CompareOrdinal([string] $a.instanceId, [string] $b.instanceId)
        }
        [System.Array]::Sort($sortedRows, $rowComparison)
    }

    if (-not (Test-Path -LiteralPath $Store.ExpandedPath -PathType Container)) {
        throw "Write-PulseExpansionFragment: expanded directory '$($Store.ExpandedPath)' is missing."
    }
    $directory = Get-PulseExpansionFragmentDirectory -Store $Store -Name $Name
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    $finalPath = Get-PulseExpansionFragmentPath -Store $Store -Name $Name -FragmentId $FragmentId
    $tempPath = "$finalPath.tmp"
    $incrementalHash = $null
    $published = $false
    try {
        $incrementalHash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $fileStream = [System.IO.File]::Open($tempPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            foreach ($row in $sortedRows) {
                $line = ConvertTo-PulseCanonicalJsonLine -InputObject $row
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
                $fileStream.Write($bytes, 0, $bytes.Length)
                $incrementalHash.AppendData($bytes)
            }
            $fileStream.Flush()
        } finally {
            $fileStream.Dispose()
        }
        $hashBytes = $incrementalHash.GetHashAndReset()
        $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

        if (Test-Path -LiteralPath $finalPath -PathType Leaf) {
            $existingBytes = [System.IO.File]::ReadAllBytes($finalPath)
            $existingHashBytes = [System.Security.Cryptography.SHA256]::HashData($existingBytes)
            $existingSha = ([System.BitConverter]::ToString($existingHashBytes) -replace '-', '').ToLowerInvariant()
            if ($existingSha -eq $sha256) {
                Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
                $published = $true
                return [pscustomobject]@{
                    FragmentId = $FragmentId
                    Path       = $finalPath
                    Sha256     = $sha256
                    RowCount   = $sortedRows.Count
                    Resumed    = $true
                }
            }
        }

        [System.IO.File]::Move($tempPath, $finalPath, $true)
        $published = $true
        return [pscustomobject]@{
            FragmentId = $FragmentId
            Path       = $finalPath
            Sha256     = $sha256
            RowCount   = $sortedRows.Count
            Resumed    = $false
        }
    } finally {
        if ($null -ne $incrementalHash) { $incrementalHash.Dispose() }
        if (-not $published -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
