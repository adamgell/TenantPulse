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
    $script:datasetMapFixturesRoot = Join-Path $repoRoot 'tests/Fixtures/DatasetMap'
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

    It 'loads and validates the module''s own default catalog path cleanly (Task 1.9 seed checks, self-check)' {
        $result = InModuleScope TenantPulse {
            Import-PulseCheckCatalog
        }

        # 10 Phase 1 seed checks + 5 Task 4.2 EIDSCA wave-1 clusters so far (TP.ENT.0006,
        # 0008, 0012, 0013, 0015) = 15.
        @($result).Count | Should -Be 15
        $ids = @($result | ForEach-Object { $_.Id })
        $ids | Should -Contain 'TP.ENT.0001'
        $ids | Should -Contain 'TP.INT.0005'
        $ids | Should -Contain 'TP.ENT.0012'
        $ids | Should -Contain 'TP.ENT.0013'
        $ids | Should -Contain 'TP.ENT.0015'
        $ids | Should -Contain 'TP.ENT.0006'
        $ids | Should -Contain 'TP.ENT.0008'

        # Ordinal-sorted by Id regardless of on-disk filename order (same contract the
        # 'valid' fixture test above already exercises).
        $sortedIds = [string[]] $ids
        [System.Array]::Sort($sortedIds, [System.StringComparer]::Ordinal)
        $ids | Should -Be $sortedIds
    }

    It 'throws naming the file, Id, property and "duplicate" for a duplicate Id' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/duplicate-id') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*two.psd1*TP.ENT.0010*Id*duplicate*'
    }

    It 'throws naming the file, Id, property and "is not one of" for a bad Severity value' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/bad-severity') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0011*Severity*is not one of*'
    }

    It 'throws naming the file, Id, property and "is required" for a missing References.Research' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/missing-research') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0012*References.Research*is required*'
    }

    It 'throws naming the file, Id, property and "must not be empty" for empty Data.Datasets' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/empty-datasets') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0013*Data.Datasets*must not be empty*'
    }

    It 'throws naming the file, Id, property and "is not one of" for an unknown Rule.Type' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/unknown-rule-type') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0014*Rule.Type*is not one of*'
    }

    It 'throws naming the file, Id, property and "does not resolve" when Rule.Function does not resolve at import time' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/bad-rule-function') {
                param($path)
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0015*Rule.Function*does not resolve*'
    }

    It 'throws naming the file, Id, property and "does not parse" for a Rule.Expression with a PowerShell syntax error' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/bad-expression-syntax') {
                param($path)
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0020*Rule.Expression*does not parse*'
    }

    It 'throws naming the file, the (malformed) Id value, property and "does not match" for a malformed Id' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/bad-id') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*bad.psd1*NOT-A-VALID-ID*Id*does not match*'
    }

    It 'throws naming the file, Id, property and "is required" for a missing Consulting field' {
        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/missing-consulting') {
                param($path)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path
            }
        } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0016*Consulting.WhyItMatters*is required*'
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

    It 'throws naming the file, Id, property and "not present in the shared dataset map" when a dataset name is not present in the shared dataset map' {
        $mapPath = Join-Path $script:tempRoot 'DatasetMap.psd1'
        New-Item -Path $script:tempRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath $mapPath -Value "@{ conditionalAccessPolicies = @{} }" -Encoding utf8NoBOM

        {
            InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/unknown-dataset-name'), $mapPath {
                param($path, $mapPath)
                function Test-PulseFixtureRule { $true }
                Import-PulseCheckCatalog -Path $path -DatasetMapPath $mapPath
            }
        } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0017*Data.Datasets*thisDatasetDoesNotExistInTheMap*not present in the shared dataset map*'
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
        $caught.Exception.Message | Should -Match 'bad-severity\.psd1.*TP\.ENT\.0011'
        $caught.Exception.Message | Should -Match 'empty-datasets\.psd1.*TP\.ENT\.0013'
    }

    Context 'type coercion holes (H1/H2)' {
        It 'throws "must be a string" for an array-typed Id, not a silent pattern-match coercion' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/array-id') {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } | Should -Throw -ExpectedMessage '*bad.psd1*Id*must be a string*'
        }

        It 'rejects two array-typed-Id descriptors as independent type errors, not as a silently-accepted duplicate pair' {
            $caught = $null
            try {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/array-id-duplicate') {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } catch {
                $caught = $_
            }

            $caught | Should -Not -BeNullOrEmpty
            $caught.Exception.Message | Should -Match 'one\.psd1.*must be a string'
            $caught.Exception.Message | Should -Match 'two\.psd1.*must be a string'
            $caught.Exception.Message | Should -Not -Match 'duplicate'
        }

        It 'throws "must be a string" for an array-typed Severity' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/array-severity') {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0018*Severity*must be a string*'
        }

        It 'throws "must be a string, got Int32" for a numeric Title' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/numeric-title') {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0019*Title*must be a string, got Int32*'
        }

        It 'throws "must be a string array" for a scalar Data.Datasets' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/scalar-datasets') {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0020*Data.Datasets*must be a string array*'
        }

        It 'throws "must be a string array" for a scalar References.Authorities' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/scalar-authorities') {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0021*References.Authorities*must be a string array*'
        }

        It 'throws "must not be empty" for an empty References.Authorities array' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/empty-authorities') {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0022*References.Authorities*must not be empty*'
        }

        It 'throws "is required" for a missing Rule.Expression when Rule.Type is Expression' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/missing-expression') {
                    param($path)
                    Import-PulseCheckCatalog -Path $path
                }
            } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0023*Rule.Expression*is required*'
        }

        It 'throws "is not one of" for a bad Effort value' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/bad-effort') {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0024*Effort*is not one of*'
        }

        It 'throws "is not one of" for a bad Impact value' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'invalid/bad-impact') {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } | Should -Throw -ExpectedMessage '*bad.psd1*TP.ENT.0025*Impact*is not one of*'
        }
    }

    Context 'parse-failure aggregation (M2/H3)' {
        It 'aggregates a descriptor parse failure alongside other descriptor problems in the same catalog' {
            $mixedRoot = Join-Path $script:tempRoot 'mixed'
            New-Item -Path $mixedRoot -ItemType Directory -Force | Out-Null
            Copy-Item -Path (Join-Path $script:fixturesRoot 'invalid/parse-failure/broken.psd1') -Destination (Join-Path $mixedRoot 'broken.psd1')
            Copy-Item -Path (Join-Path $script:fixturesRoot 'invalid/bad-severity/bad.psd1') -Destination (Join-Path $mixedRoot 'bad-severity.psd1')

            $caught = $null
            try {
                InModuleScope TenantPulse -ArgumentList $mixedRoot {
                    param($path)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path
                }
            } catch {
                $caught = $_
            }

            $caught | Should -Not -BeNullOrEmpty
            $caught.Exception.Message | Should -Match 'broken\.psd1.*failed to parse'
            $caught.Exception.Message | Should -Match 'bad-severity\.psd1.*TP\.ENT\.0011.*Severity.*is not one of'
        }
    }

    Context 'dataset map hoisting and hygiene (M2)' {
        It 'throws naming the map file and "failed to parse" for a malformed DatasetMap.psd1, instead of a raw unrelated error' {
            {
                InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'valid'), (Join-Path $script:datasetMapFixturesRoot 'malformed-syntax.psd1') {
                    param($path, $mapPath)
                    function Test-PulseFixtureRule { $true }
                    Import-PulseCheckCatalog -Path $path -DatasetMapPath $mapPath
                }
            } | Should -Throw -ExpectedMessage '*malformed-syntax.psd1*failed to parse*'
        }

        It 'excludes a file literally named DatasetMap.psd1 inside the catalog directory from descriptor scanning' {
            New-Item -Path $script:tempRoot -ItemType Directory -Force | Out-Null
            Copy-Item -Path (Join-Path $script:fixturesRoot 'valid/b-first.psd1') -Destination (Join-Path $script:tempRoot 'b-first.psd1')
            Set-Content -LiteralPath (Join-Path $script:tempRoot 'DatasetMap.psd1') -Value "@{ conditionalAccessPolicies = @{} }" -Encoding utf8NoBOM

            $result = InModuleScope TenantPulse -ArgumentList $script:tempRoot {
                param($path)
                function Test-PulseFixtureRule { $true }
                # Point -DatasetMapPath somewhere else entirely so the in-directory
                # DatasetMap.psd1 is exercised purely as "must not be scanned as a
                # descriptor", not as the active map.
                Import-PulseCheckCatalog -Path $path -DatasetMapPath (Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString()))
            }

            @($result).Count | Should -Be 1
            $result[0].Id | Should -Be 'TP.ENT.0001'
        }

        It 'parses the dataset map exactly once per catalog load, not once per descriptor' {
            $mapPath = Join-Path $script:tempRoot 'DatasetMap.psd1'
            New-Item -Path $script:tempRoot -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath $mapPath -Value "@{ conditionalAccessPolicies = @{}; deviceCompliancePolicies = @{} }" -Encoding utf8NoBOM

            $callCount = InModuleScope TenantPulse -ArgumentList (Join-Path $script:fixturesRoot 'valid'), $mapPath {
                param($path, $mapPath)
                function Test-PulseFixtureRule { $true }

                $script:mapParseCount = 0
                $realCmdlet = Get-Command -Name Import-PowerShellDataFile -CommandType Cmdlet

                # Shadow the cmdlet with a same-named function for the duration of this
                # scope - PowerShell resolves a function before a cmdlet of the same
                # name, so this intercepts every call site without touching production
                # code, then delegates to the real cmdlet (captured above, before the
                # shadow exists) so behavior is unchanged.
                # No explicit -ErrorAction parameter here: any [Parameter()]-attributed
                # parameter makes a function "advanced", which then auto-adds the
                # -ErrorAction common parameter - declaring it a second time explicitly
                # throws "defined multiple times". $PSBoundParameters forwards it instead.
                function Import-PowerShellDataFile {
                    param(
                        [Parameter(Mandatory)] [string] $LiteralPath
                    )
                    if ($LiteralPath -eq $mapPath) { $script:mapParseCount++ }
                    & $realCmdlet @PSBoundParameters
                }

                try {
                    Import-PulseCheckCatalog -Path $path -DatasetMapPath $mapPath | Out-Null
                    $script:mapParseCount
                } finally {
                    # Remove the shadow so it cannot leak into any other test in this
                    # process/module instance.
                    Remove-Item -LiteralPath 'Function:\Import-PowerShellDataFile' -Force -ErrorAction SilentlyContinue
                }
            }

            $callCount | Should -Be 1
        }
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

    It 'reports exactly one error per problem for a sparse descriptor, each naming the property and problem text' {
        $errors = InModuleScope TenantPulse {
            $descriptor = @{
                Id       = 'BAD'
                Severity = 'Extreme'
            }
            Test-PulseCheckDescriptor -Descriptor $descriptor -Label 'BAD'
        }
        $errors = @($errors)

        # Hand-counted against the descriptor above: Id (pattern), Title (missing),
        # Category (missing), Severity (enum), Effort (missing), Impact (missing), Data
        # (missing), Rule (missing), Consulting (missing), References (missing) = 10.
        # Origin is optional and absent, so it contributes no error. Pinning the exact
        # count (not just >1) catches a validator that stops emitting real errors and
        # substitutes something else entirely, which a bare ">1" assertion would miss.
        $errors.Count | Should -Be 10
        ($errors -join "`n") | Should -Match 'BAD: Id: .*does not match'
        ($errors -join "`n") | Should -Match 'BAD: Title: is required'
        ($errors -join "`n") | Should -Match 'BAD: Category: is required'
        ($errors -join "`n") | Should -Match 'BAD: Severity: .*is not one of'
        ($errors -join "`n") | Should -Match 'BAD: Effort: is required'
        ($errors -join "`n") | Should -Match 'BAD: Impact: is required'
        ($errors -join "`n") | Should -Match 'BAD: Data: is required'
        ($errors -join "`n") | Should -Match 'BAD: Rule: is required'
        ($errors -join "`n") | Should -Match 'BAD: Consulting: is required'
        ($errors -join "`n") | Should -Match 'BAD: References: is required'
    }

    It 'reports the exact must-be-a-type/got-actual-type text for every H1-listed coercion hole' {
        $errors = InModuleScope TenantPulse {
            function Test-PulseFixtureRule { $true }
            $descriptor = @{
                Id         = @('TP.ENT.0001')
                Title      = 42
                Category   = @{ a = 1 }
                Severity   = @('High')
                Effort     = 'Low'
                Impact     = 'High'
                Data       = @{
                    Datasets = 'conditionalAccessPolicies'
                    Gates    = 'not-an-array-either'
                }
                Rule       = @{ Type = @('Function'); Function = @('Test-PulseFixtureRule') }
                Consulting = @{
                    WhatItMeans  = 'x'
                    WhyItMatters = 'x'
                    Remediation  = 'not-an-array'
                    PortalLinks  = @()
                }
                References = @{ Research = 'docs/x.md#a'; Authorities = @('https://learn.microsoft.com/') }
                Origin     = $null
            }
            Test-PulseCheckDescriptor -Descriptor $descriptor -Label 'coercion-holes'
        }
        $joined = (@($errors) -join "`n")

        $joined | Should -Match ([regex]::Escape('coercion-holes: Id: must be a string, got Object[].'))
        $joined | Should -Match ([regex]::Escape('coercion-holes: Title: must be a string, got Int32.'))
        $joined | Should -Match ([regex]::Escape('coercion-holes: Category: must be a string, got Hashtable.'))
        $joined | Should -Match ([regex]::Escape('coercion-holes: Severity: must be a string, got Object[].'))
        $joined | Should -Match ([regex]::Escape('coercion-holes: Data.Datasets: must be a string array, got String.'))
        $joined | Should -Match ([regex]::Escape('coercion-holes: Data.Gates: must be a string array, got String.'))
        $joined | Should -Match ([regex]::Escape('coercion-holes: Rule.Type: must be a string, got Object[].'))
        $joined | Should -Match ([regex]::Escape('coercion-holes: Consulting.Remediation: must be a string array, got String.'))
        $joined | Should -Match ([regex]::Escape('coercion-holes: Consulting.PortalLinks: must not be empty.'))
        # Rule.Function is never reached/reported here: Rule.Type itself already failed its
        # own type check, so the Function-specific branch below it correctly does not run -
        # asserting its ABSENCE guards against a validator that keeps evaluating a field
        # after its type prerequisite already failed.
        $joined | Should -Not -Match 'Rule\.Function'
    }
}
