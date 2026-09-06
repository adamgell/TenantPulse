BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:coveragePath = Join-Path $script:repoRoot 'docs/contracts/iha-port-coverage-v1.json'
    $script:coverage = Get-Content -LiteralPath $script:coveragePath -Raw | ConvertFrom-Json -Depth 100
    $script:allowedStatus = @('Complete', 'Partial', 'Missing', 'Replaced')
}

Describe 'IHA port coverage register' -Tag 'QA' {
    It 'is a versioned, parseable contract bound to the observed IHA source' {
        $script:coverage.schemaVersion | Should -Be '1'
        $script:coverage.source.repository | Should -Be 'IntuneHealthAutomation'
        $script:coverage.source.revision | Should -Match '^[0-9a-f]{40}$'
        $script:coverage.source.endpointManifestSha256 | Should -Match '^[0-9a-f]{64}$'
        $script:coverage.source.reportDefinitionBasis | Should -Be 'working-tree'
    }

    It 'accounts for all 28 declared IHA Graph endpoint keys exactly once' {
        @($script:coverage.endpoints).Count | Should -Be 28
        @($script:coverage.endpoints.ihaKey | Sort-Object -Unique).Count | Should -Be 28
        @($script:coverage.endpoints.dataKey | Where-Object { [string]::IsNullOrWhiteSpace([string] $_) }).Count | Should -Be 0
    }

    It 'accounts for all 14 active IHA JSON report definitions exactly once' {
        @($script:coverage.reports).Count | Should -Be 14
        @($script:coverage.reports.file | Sort-Object -Unique).Count | Should -Be 14
        foreach ($report in @($script:coverage.reports)) {
            $report.file | Should -Match '\.json$'
            $report.sha256 | Should -Match '^[0-9a-f]{64}$'
        }
    }

    It 'uses only explicit coverage states and makes every incomplete row actionable' {
        foreach ($entry in @($script:coverage.endpoints) + @($script:coverage.reports) + @($script:coverage.crossCutting)) {
            $entry.status | Should -BeIn $script:allowedStatus
            if ($entry.status -in @('Partial', 'Missing')) {
                $action = if (-not [string]::IsNullOrWhiteSpace([string] $entry.gap)) {
                    [string] $entry.gap
                } else {
                    [string] $entry.completionGate
                }
                [string]::IsNullOrWhiteSpace($action) | Should -BeFalse
            }
        }
    }

    It 'does not claim a completed endpoint without successor evidence' {
        foreach ($entry in @($script:coverage.endpoints | Where-Object status -EQ 'Complete')) {
            @($entry.graphKit).Count | Should -BeGreaterThan 0
            @($entry.tenantPulse).Count | Should -BeGreaterThan 0
            @($entry.evidence).Count | Should -BeGreaterThan 0
            foreach ($path in @($entry.evidence)) {
                Test-Path -LiteralPath (Join-Path $script:repoRoot $path) -PathType Leaf | Should -BeTrue
            }
        }
    }

    It 'has replacement evidence for every active report with no unaccounted report gap' {
        $incomplete = @($script:coverage.reports | Where-Object status -In @('Partial', 'Missing'))
        $incomplete.Count | Should -Be 0
        foreach ($entry in @($script:coverage.reports | Where-Object status -In @('Complete', 'Replaced'))) {
            [string]::IsNullOrWhiteSpace([string] $entry.successor) | Should -BeFalse
            @($entry.evidence).Count | Should -BeGreaterThan 0
            foreach ($path in @($entry.evidence)) {
                Test-Path -LiteralPath (Join-Path $script:repoRoot $path) -PathType Leaf | Should -BeTrue
            }
        }
    }

    It 'has no incomplete endpoint port and records evidence for every replacement' {
        @($script:coverage.endpoints | Where-Object status -In @('Partial', 'Missing')).Count | Should -Be 0
        foreach ($entry in @($script:coverage.endpoints | Where-Object status -EQ 'Replaced')) {
            @($entry.evidence).Count | Should -BeGreaterThan 0
            foreach ($path in @($entry.evidence)) {
                Test-Path -LiteralPath (Join-Path $script:repoRoot $path) -PathType Leaf | Should -BeTrue
            }
        }
    }

    It 'closes every in-module cross-cutting gap and leaves only external Office rendering open' {
        $incomplete = @($script:coverage.crossCutting | Where-Object status -In @('Partial', 'Missing'))
        $incomplete.Count | Should -Be 1
        $incomplete[0].capability | Should -Be 'Excel rendering'
        foreach ($entry in @($script:coverage.crossCutting | Where-Object status -EQ 'Replaced')) {
            if ($entry.PSObject.Properties.Name -contains 'evidence') {
                foreach ($path in @($entry.evidence)) {
                    Test-Path -LiteralPath (Join-Path $script:repoRoot $path) -PathType Leaf | Should -BeTrue
                }
            }
        }
    }

    It 'keeps Office rendering outside TenantPulse while tracking its completion gate' {
        $office = @($script:coverage.crossCutting | Where-Object capability -EQ 'Excel rendering')
        $office.Count | Should -Be 1
        $office[0].status | Should -Be 'Missing'
        $office[0].successor | Should -Be 'External Office delivery layer'
    }
}
