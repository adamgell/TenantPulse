<#
    Copy_Research_Docs stages the repository research library into the built module so
    packaged TenantPulse bytes resolve the same `docs/research/...#anchor` paths that
    shipping check descriptors declare from the repository root.

    ModuleBuilder CopyPaths only copies directories that live under source/. The research
    files are authored at repo-root `docs/research/` and must keep that relative path
    inside the built module and nupkg.
#>

task Copy_Research_Docs Build_Module_ModuleBuilder, {
    $repoRoot = $BuildRoot
    if ([string]::IsNullOrWhiteSpace($repoRoot)) {
        $repoRoot = Split-Path -Parent $PSScriptRoot
    }

    $source = Join-Path $repoRoot 'docs/research'
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Research library not found at '$source'."
    }

    $moduleBase = $null
    if ($BuiltModuleManifest -and (Test-Path -LiteralPath $BuiltModuleManifest -PathType Leaf)) {
        $moduleBase = Split-Path -Parent $BuiltModuleManifest
    }
    else {
        $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $repoRoot 'source/TenantPulse.psd1')
        $moduleBase = Join-Path $OutputDirectory "module/TenantPulse/$([string] $manifest.ModuleVersion)"
    }

    if (-not (Test-Path -LiteralPath $moduleBase -PathType Container)) {
        throw "Built module directory not found at '$moduleBase'."
    }

    $docsParent = Join-Path $moduleBase 'docs'
    $destination = Join-Path $docsParent 'research'
    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Recurse -Force
    }

    $null = New-Item -ItemType Directory -Path $docsParent -Force
    Copy-Item -LiteralPath $source -Destination $destination -Recurse
}
