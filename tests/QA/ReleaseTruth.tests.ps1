BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $readme = Get-Content -LiteralPath (Join-Path $repoRoot 'README.md') -Raw
    $changelog = Get-Content -LiteralPath (Join-Path $repoRoot 'CHANGELOG.md') -Raw
    $status = Get-Content -LiteralPath (Join-Path $repoRoot 'docs/STATUS.md') -Raw
    $manifest = Import-PowerShellDataFile -Path (Join-Path $repoRoot 'source/TenantPulse.psd1')
}

Describe 'TenantPulse current release truth' -Tag 'QA' {
    It 'records TenantPulse 0.2.0 as the immutable current PSGallery release' {
        $readme | Should -Match 'TenantPulse `0\.2\.0` is the current immutable release on PSGallery'
        $readme | Should -Match 'a0d5ff793b92753ab3efb4db20cf5bcf8b953e3cf81bf1a776c96a3d992417bd'
    }

    It 'records the exact GraphKit 0.3.0 producer release' {
        $readme | Should -Match 'GraphKit `0\.3\.0`'
        $manifest.RequiredModules[0].RequiredVersion | Should -Be '0.3.0'
        [string] $manifest.ModuleVersion | Should -Be '0.3.0'
    }

    It 'records reviewed and merged exact-head CI evidence' {
        $status | Should -Match '24b3d4ebe522d9bf94d9a75c8625be438fa9b768'
        $status | Should -Match 'b2eb7a882cc1fcb7994c39a606c7b9ac22f5a114'
        $status | Should -Match '33295409637'
        $status | Should -Match '33295648250'
        $status | Should -Match '2,277 tests'
    }

    It 'does not call the released 0.2.0 package unpublished' {
        @($readme, $changelog, $status) -join "`n" |
            Should -Not -Match '(?i)0\.2\.0.{0,80}(?:unpublished|candidate)|(?:unpublished|candidate).{0,80}0\.2\.0'
    }

    It 'keeps deterministic CI live and publication evidence distinct' {
        $status | Should -Match 'Deterministic'
        $status | Should -Match 'CI'
        $status | Should -Match 'Live'
        $status | Should -Match 'Published'
    }
}
