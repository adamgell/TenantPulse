function Get-PulseModuleTreeDigest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ModuleBase
    )

    $root = [System.IO.Path]::GetFullPath($ModuleBase).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    if (-not [System.IO.Directory]::Exists($root)) {
        throw "Staged module directory not found at '$root'."
    }

    $relativeToFullPath = [System.Collections.Generic.Dictionary[string, string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($filePath in [System.IO.Directory]::EnumerateFiles(
        $root,
        '*',
        [System.IO.SearchOption]::AllDirectories
    )) {
        $relativePath = [System.IO.Path]::GetRelativePath($root, $filePath).Replace(
            [System.IO.Path]::DirectorySeparatorChar,
            '/'
        )
        $relativeToFullPath.Add($relativePath, $filePath)
    }

    [string[]] $relativePaths = @($relativeToFullPath.Keys)
    [System.Array]::Sort($relativePaths, [System.StringComparer]::Ordinal)

    $treeHash = [System.Security.Cryptography.IncrementalHash]::CreateHash(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        foreach ($relativePath in $relativePaths) {
            [byte[]] $pathBytes = [System.Text.Encoding]::UTF8.GetBytes($relativePath)
            [byte[]] $pathLength = @(
                [byte] (($pathBytes.Length -shr 24) -band 0xff)
                [byte] (($pathBytes.Length -shr 16) -band 0xff)
                [byte] (($pathBytes.Length -shr 8) -band 0xff)
                [byte] ($pathBytes.Length -band 0xff)
            )
            $treeHash.AppendData($pathLength)
            $treeHash.AppendData($pathBytes)

            [byte[]] $fileHash = [System.Security.Cryptography.SHA256]::HashData(
                [System.IO.File]::ReadAllBytes($relativeToFullPath[$relativePath])
            )
            $treeHash.AppendData($fileHash)
        }

        [System.Convert]::ToHexString($treeHash.GetHashAndReset()).ToLowerInvariant()
    }
    finally {
        $treeHash.Dispose()
    }
}

function Assert-PulseStagedModuleDigest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ModuleName,

        [Parameter(Mandatory)]
        [string] $Version,

        [Parameter(Mandatory)]
        [string] $ModuleBase,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $ExpectedDigests
    )

    $dependencyKey = "$ModuleName|$Version"
    if (-not $ExpectedDigests.Contains($dependencyKey)) {
        throw "Staged runtime dependency '$dependencyKey' has no tracked tree digest."
    }

    $expectedDigest = [string] $ExpectedDigests[$dependencyKey]
    if ($expectedDigest -notmatch '\A[0-9a-fA-F]{64}\z') {
        throw "Tracked tree digest for '$dependencyKey' is malformed."
    }

    $actualDigest = Get-PulseModuleTreeDigest -ModuleBase $ModuleBase
    if (-not $actualDigest.Equals($expectedDigest, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Staged runtime dependency '$dependencyKey' tree digest mismatch."
    }
}
