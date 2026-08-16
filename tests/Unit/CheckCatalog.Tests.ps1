BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $repoRoot = $script:repoRoot

    # Import the BUILT module (never dot-source source files: they would redefine module
    # classes and Add-Type types in test scope). Pester discovers tests per file, so each
    # file imports it.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:fixturesRoot = Join-Path $repoRoot 'tests/Fixtures/Checks'
}

Describe 'Import-PulseCheckCatalog' {
    BeforeEach {
        $script:tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    }

    AfterEach {
        Remove-Item -LiteralPath $script:tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'loads valid descriptors, sorted by Id, regardless of on-disk filename order' {
        $result = InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'valid') {
            param($path)
            function Test-PulseFixtureRule { $true }
            Import-PulseCheckCatalog -Path $path
        }

        $result.Count | Should -Be 2
        $result[0].Id | Should -Be 'TP.ENT.0001'
        $result[1].Id | Should -Be 'TP.INT.9999'
        $result[0].PSObject.TypeNames | Should -Contain 'TenantPulse.CheckDescriptor'
        $result[0].Title | Should -Not -BeNullOrEmpty
        $result[0].Data.Datasets | Should -Contain 'conditionalAccessPolicies'
        $result[1].Origin.Project | Should -Be 'Maester'
    }

    It 'does not throw and yields zero descriptors for an empty catalog directory' {
        New-Item -Path $script:tempRoot -ItemType Directory -Force | Out-Null

        $result = InModuleScope TenantPulse -ArgumentList $script:tempRoot {
            param($path)
            Import-PulseCheckCatalog -Path $path
        }

        @($result).Count | Should -Be 0
    }

    It 'does not throw and yields zero descriptors when the catalog directory does not exist' {
        $missingPath = Join-Path $script:tempRoot 'does-not-exist'

        $result = InModuleScope TenantPulse -ArgumentList $missingPath {
            param($path)
            Import-PulseCheckCatalog -Path $path
        }

        @($result).Count | Should -Be 0
    }

    It 'yields zero descriptors for the module''s own default catalog path (source/Data/Checks is empty for now)' {
        $result = InModuleScope TenantPulse {
            Import-PulseCheckCatalog
        }

        @($result).Count | Should -Be 0
    }

    It 'throws naming the offending Id and property for a duplicate Id' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/duplicate-id') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*TP.ENT.0010*Id*duplicate*'
    }

    It 'throws naming the offending Id and property for a bad Severity value' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/bad-severity') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*TP.ENT.0011*Severity*'
    }

    It 'throws naming the offending Id and property for a missing References.Research' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/missing-research') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*TP.ENT.0012*References.Research*'
    }

    It 'throws naming the offending Id and property for empty Data.Datasets' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/empty-datasets') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*TP.ENT.0013*Data.Datasets*'
    }

    It 'throws naming the offending Id and property for an unknown Rule.Type' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/unknown-rule-type') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*TP.ENT.0014*Rule.Type*'
    }

    It 'throws naming the offending Id and property when Rule.Function does not resolve at import time' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/bad-rule-function') {
                param($path)
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*TP.ENT.0015*Rule.Function*does not resolve*'
    }

    It 'throws naming the offending (malformed) Id value and property for a malformed Id' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/bad-id') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*NOT-A-VALID-ID*Id*does not match*'
    }

    It 'throws naming the offending Id and property for a missing Consulting field' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/missing-consulting') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*TP.ENT.0016*Consulting.WhyItMatters*'
    }

    It 'skips the dataset-map membership cross-check when no dataset map is present (T1.5 not landed yet)' {
        $result = InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/unknown-dataset-name') {
            param($path)
            function Test-PulseFixtureRule { $true }
            Import-PulseCheckCatalog -Path $path -DatasetMapPath (Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString()))
        }

        @($result).Count | Should -Be 1
        $result[0].Id | Should -Be 'TP.ENT.0017'
    }

    It 'throws naming the offending Id and property when a dataset name is not present in the shared dataset map' {
        $mapPath = Join-Path $script:tempRoot 'DatasetMap.psd1'
        New-Item -Path $script:tempRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath $mapPath -Value "@{ conditionalAccessPolicies = @{} }" -Encoding utf8NoBOM

        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/unknown-dataset-name'), $mapPath {
                param($path, $mapPath)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path -DatasetMapPath $mapPath
            }
        } | Should -Throw -ExpectedMessage '*TP.ENT.0017*Data.Datasets*thisDatasetDoesNotExistInTheMap*not present in the shared dataset map*'
    }

    It 'aggregates errors from every invalid descriptor into a single thrown error, not just the first' {
        $aggregateRoot = Join-Path $script:tempRoot 'aggregate'
        New-Item -Path $aggregateRoot -ItemType Directory -Force | Out-Null
        Copy-Item -Path (Join-Path $script:fixturesRoot 'invalid/bad-severity/bad.psd1') -Destination (Join-Path $aggregateRoot 'bad-severity.psd1')
        Copy-Item -Path (Join-Path $script:fixturesRoot 'invalid/empty-datasets/bad.psd1') -Destination (Join-Path $aggregateRoot 'empty-datasets.psd1')

        $caught = $null
        try {
            InModuleScope TenantPulse -ArgumentList $aggregateRoot {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } catch {
            $caught = $_
        }

        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -Match 'TP\.ENT\.0011'
        $caught.Exception.Message | Should -Match 'TP\.ENT\.0013'
    }
}

Describe 'Test-PulseCheckDescriptor' {
    It 'returns an empty array for a fully valid descriptor' {
        $errors = InModuleScope TenantPulse {
            function Test-PulseFixtureRule { $true }
            $descriptor = @{
                Id         = 'TP.ENT.0099'
                Title      = 'Valid'
                Category   = 'Entra.ConditionalAccess'
                Severity   = 'High'
                Effort     = 'Low'
                Impact     = 'High'
                Data       = @{ Datasets = @('conditionalAccessPolicies'); Gates = @() }
                Rule       = @{ Type = 'Function'; Function = 'Test-PulseFixtureRule' }
                Consulting = @{
                    WhatItMeans  = 'x'
                    WhyItMatters = 'x'
                    Remediation  = @('x')
                    PortalLinks  = @('https://entra.microsoft.com/')
                }
                References = @{ Research = 'docs/x.md#a'; Authorities = @('https://learn.microsoft.com/') }
                Origin     = $null
            }
            Test-PulseCheckDescriptor -Descriptor $descriptor -Label $descriptor.Id
        }

        @($errors).Count | Should -Be 0
    }

    It 'reports one error per problem, each naming the property' {
        $errors = InModuleScope TenantPulse {
            $descriptor = @{
                Id       = 'BAD'
                Severity = 'Extreme'
            }
            Test-PulseCheckDescriptor -Descriptor $descriptor -Label 'BAD'
        }

        @($errors).Count | Should -BeGreaterThan 1
        ($errors -join "`n") | Should -Match 'Id:'
        ($errors -join "`n") | Should -Match 'Severity:'
        ($errors -join "`n") | Should -Match 'Title:'
        ($errors -join "`n") | Should -Match 'Category:'
    }
}
