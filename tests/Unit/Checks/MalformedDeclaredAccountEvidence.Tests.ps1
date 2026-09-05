BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Malformed declared account evidence identity' {
    It 'returns a bounded operator-keyed alias without carrying the operator-supplied value' {
        $raw = 'not-a-guid@contoso.com'
        $firstKey = [byte[]] (0..31)
        $secondKey = [byte[]] (31..0)

        $aliases = InModuleScope TenantPulse -ArgumentList $raw, $firstKey, $secondKey {
            param($raw, $firstKey, $secondKey)
            @(
                Get-PulseMalformedDeclaredAccountAlias -Value $raw -Key $firstKey
                Get-PulseMalformedDeclaredAccountAlias -Value $raw -Key $secondKey
            )
        }

        $aliases[0] | Should -Match '^malformed-declared-account:[0-9a-f]{24}$'
        $aliases[0] | Should -Not -Be $aliases[1]
        $aliases[0] | Should -Not -Match ([regex]::Escape($raw))
    }

    It 'returns one fixed non-secret alias for null, empty, and whitespace declarations' {
        $key = [byte[]] (0..31)

        $aliases = InModuleScope TenantPulse -ArgumentList (, $key) {
            param($key)
            @(
                Get-PulseMalformedDeclaredAccountAlias -Value $null -Key $key
                Get-PulseMalformedDeclaredAccountAlias -Value '' -Key $key
                Get-PulseMalformedDeclaredAccountAlias -Value '   ' -Key $key
            )
        }

        $aliases | Should -HaveCount 3
        $aliases | Should -Be @(
            'malformed-declared-account:blank'
            'malformed-declared-account:blank'
            'malformed-declared-account:blank'
        )
    }

    It 'canonicalizes case without trimming format-significant whitespace' {
        $key = [byte[]] (0..31)

        $aliases = InModuleScope TenantPulse -ArgumentList (, $key) {
            param($key)
            @(
                Get-PulseMalformedDeclaredAccountAlias -Value 'BreakGlass@Contoso.COM' -Key $key
                Get-PulseMalformedDeclaredAccountAlias -Value 'breakglass@contoso.com' -Key $key
                Get-PulseMalformedDeclaredAccountAlias -Value ' breakglass@contoso.com' -Key $key
            )
        }

        $aliases[0] | Should -Be $aliases[1]
        $aliases[2] | Should -Not -Be $aliases[1]
    }

    It 'uses the same alias for one malformed account across break-glass and all-users MFA checks' {
        $raw = 'BreakGlass@Contoso.COM'
        $key = [byte[]] (0..31)
        $results = InModuleScope TenantPulse -ArgumentList $raw, $key {
            param($raw, $key)
            $datasets = @{ conditionalAccessPolicies = @() }
            $context = @{ BreakGlassAccounts = @($raw) }
            @(
                Test-PulseBreakGlassExcluded -Datasets $datasets -Context $context -OperatorKey $key
                Test-PulseAllUsersMfaEnforced -Datasets $datasets -Context $context -OperatorKey $key
            )
        }

        $firstAlias = @($results[0].Evidence | Where-Object { $_.Identity -like 'malformed-declared-account:*' })[0].Identity
        $secondAlias = @($results[1].Evidence | Where-Object { $_.Identity -like 'malformed-declared-account:*' })[0].Identity
        $firstAlias | Should -Be $secondAlias
    }
}
