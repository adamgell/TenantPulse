BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphContext { param() }
        function Get-GraphObject { param() }
        function Invoke-GraphOperation { param() }
        function Get-GraphOperation { param() }
    }

    Mock Get-GraphContext -ModuleName TenantPulse { throw 'Get-GraphContext must be mocked in this test.' }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
    Mock Get-GraphOperation -ModuleName TenantPulse { throw 'Get-GraphOperation must be mocked in this test.' }

    # A function defined via a standalone `InModuleScope { function Foo {} }` call does NOT
    # persist into a LATER, separately-invoked call into the module (see Evaluator.Tests.ps1's
    # own note on this same trap) - it only lives for the duration of that one scriptblock
    # invocation. Get-GraphContext/Get-GraphObject/etc above are fine because Mock installs
    # its own persistent shim once wrapped (Mock's mechanism, not the bare `function`
    # statement, is what survives) - but a rule FUNCTION that must genuinely execute later
    # (never mocked) has no such shim. This helper works around that by defining the fixture
    # rule function AND invoking Invoke-PulseAssessment in the SAME InModuleScope call, so the
    # function is guaranteed to exist at the moment Invoke-PulseCheckEvaluation resolves it.
    function script:Invoke-TestPulseAssessment {
        param([hashtable] $Params)

        InModuleScope TenantPulse -ArgumentList (, $Params) {
            param($Params)

            function Test-PulseFixtureIdentityRule {
                param($Datasets)
                return New-PulseFinding -Status Fail -Reason 'a Conditional Access policy excludes an identity from review' -Evidence @(
                    @{ Identity = 'admin@contoso.onmicrosoft.com'; Detail = 'excluded from MFA policy' }
                )
            }

            Invoke-PulseAssessment @Params
        }
    }

    function script:New-TestReadDescriptor {
        @{
            ThrottleClass       = 'Read'
            ReplayPolicy        = 'Safe'
            ApiVersion          = 'beta'
            RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' })
        }
    }

    function script:New-TestFixtureCatalog {
        @(
            [pscustomobject]@{
                PSTypeName = 'TenantPulse.CheckDescriptor'
                Id         = 'TP.ENT.9001'
                Title      = 'Fixture identity check'
                Category   = 'Entra.ConditionalAccess'
                Severity   = 'High'
                Effort     = 'Low'
                Impact     = 'High'
                Data       = [pscustomobject]@{ Datasets = @('conditionalAccessPolicies'); Gates = @() }
                Rule       = [pscustomobject]@{ Type = 'Function'; Function = 'Test-PulseFixtureIdentityRule' }
                Consulting = [pscustomobject]@{
                    WhatItMeans  = 'What it means.'
                    WhyItMatters = 'Why it matters.'
                    Remediation  = @('Fix it.')
                    PortalLinks  = @('https://example.com/portal')
                }
                References = [pscustomobject]@{
                    Research    = 'docs/research/fixture.md'
                    Authorities = @('MS.FIXTURE.1')
                }
                Origin     = $null
            }
        )
    }

    function script:New-TestOutputRoot {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $root -ItemType Directory -Force | Out-Null
        return $root
    }
}

Describe 'Invoke-PulseAssessment - pipeline plumbing' {
    BeforeEach {
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        $script:outputRoot = New-TestOutputRoot
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'returns a summary object whose paths exist on disk with the expected content' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { New-TestFixtureCatalog }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $summary = Invoke-TestPulseAssessment -Params @{ ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot }

        $summary.PSObject.Properties.Name | Should -Contain 'SnapshotPath'
        $summary.PSObject.Properties.Name | Should -Contain 'FindingsPath'
        $summary.PSObject.Properties.Name | Should -Contain 'ReportPaths'
        $summary.PSObject.Properties.Name | Should -Contain 'Scores'
        $summary.PSObject.Properties.Name | Should -Contain 'Coverage'

        Test-Path -LiteralPath $summary.SnapshotPath -PathType Container | Should -BeTrue
        Test-Path -LiteralPath $summary.FindingsPath -PathType Leaf | Should -BeTrue
        $summary.ReportPaths.Json | Should -Be $summary.FindingsPath

        $doc = Get-Content -LiteralPath $summary.FindingsPath -Raw | ConvertFrom-Json
        $doc.findings.Count | Should -Be 1
        $doc.findings[0].id | Should -Be 'TP.ENT.9001'
        $doc.findings[0].status | Should -Be 'Fail'

        $summary.Scores.overall.possible | Should -Be $doc.scores.overall.possible
        $summary.Coverage.overall.assessed | Should -Be $doc.coverage.overall.assessed
    }

    It '-FromSnapshot skips collection entirely - no GraphKit call is made' {
        # Build the snapshot directly on disk (New-PulseSnapshotStore/Write-PulseDataset),
        # never through Invoke-PulseAssessment's own collect path - so this It's ONLY
        # GraphKit mock registration is the "throws if called" one below. A prior
        # successful collect call in the SAME It would still count toward Should -Invoke's
        # cumulative history even after re-mocking (Mock redefinition does not reset
        # invocation history within one It), which is exactly the false pass this
        # structure avoids.
        $preBuiltStoreRoot = Join-Path $script:outputRoot 'prebuilt-snapshot'
        InModuleScope TenantPulse -ArgumentList $preBuiltStoreRoot {
            param($preBuiltStoreRoot)
            $store = New-PulseSnapshotStore -Path $preBuiltStoreRoot -Tenant 'tp-fixturetenant'
            Write-PulseDataset -Store $store -Name 'conditionalAccessPolicies' -Data @([pscustomobject]@{ id = 'p1' }) -ApiVersion 'beta' -Status 'Collected'
        }

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { New-TestFixtureCatalog }
        Mock Get-GraphContext -ModuleName TenantPulse { throw 'Get-GraphContext must not be called on the -FromSnapshot path.' }
        Mock Get-GraphOperation -ModuleName TenantPulse { throw 'Get-GraphOperation must not be called on the -FromSnapshot path.' }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must not be called on the -FromSnapshot path.' }

        $run = Invoke-TestPulseAssessment -Params @{ OutputPath = $script:outputRoot; FromSnapshot = $preBuiltStoreRoot }

        Should -Invoke Get-GraphContext -ModuleName TenantPulse -Times 0 -Exactly
        Should -Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
        Should -Invoke Get-GraphOperation -ModuleName TenantPulse -Times 0 -Exactly

        $run.SnapshotPath | Should -Be (Resolve-Path -LiteralPath $preBuiltStoreRoot).ProviderPath
        Test-Path -LiteralPath $run.FindingsPath -PathType Leaf | Should -BeTrue
    }

    It '-Redact replaces every evidence identity with its pseudonym, deterministically' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { New-TestFixtureCatalog }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $firstRun = Invoke-TestPulseAssessment -Params @{ ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot; Redact = $true }

        $doc = Get-Content -LiteralPath $firstRun.FindingsPath -Raw | ConvertFrom-Json
        $identity = $doc.findings[0].evidence[0].identity
        $identity | Should -Match '^tp-[0-9a-f]{64}$'
        $identity | Should -Not -Be 'admin@contoso.onmicrosoft.com'

        # Re-evaluating (and re-redacting) the SAME snapshot must produce byte-identical
        # JSON, because the pseudonym HMAC is keyed and stable - a fresh in-memory
        # redaction map every call does not mean different output for the same input.
        $secondRoot = New-TestOutputRoot
        try {
            $secondRun = Invoke-TestPulseAssessment -Params @{ OutputPath = $secondRoot; FromSnapshot = $firstRun.SnapshotPath; Redact = $true }

            $firstRaw = Get-Content -LiteralPath $firstRun.FindingsPath -Raw
            $secondRaw = Get-Content -LiteralPath $secondRun.FindingsPath -Raw
            $secondRaw | Should -Be $firstRaw
        } finally {
            Remove-Item -LiteralPath $secondRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'never leaks the RedactionMap wrapper, and never leaks a raw identity when -Redact was passed' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { New-TestFixtureCatalog }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $summary = Invoke-TestPulseAssessment -Params @{ ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot; Redact = $true }

        $raw = Get-Content -LiteralPath $summary.FindingsPath -Raw
        $raw | Should -Not -Match '"RedactionMap"'
        $raw | Should -Not -Match 'admin@contoso\.onmicrosoft\.com'
    }

    It 'never leaks a tp- pseudonym into evidence identity when -Redact was NOT passed' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { New-TestFixtureCatalog }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $summary = Invoke-TestPulseAssessment -Params @{ ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot }

        $doc = Get-Content -LiteralPath $summary.FindingsPath -Raw | ConvertFrom-Json
        # The document's own `tenant` field IS always a tp- pseudonym regardless of
        # -Redact (tenant identity is always pseudonymized, per the module-wide rule) -
        # this assertion is scoped to EVIDENCE identities specifically, not a blanket
        # substring search over the whole file, which would false-positive on that field.
        $doc.findings[0].evidence[0].identity | Should -Be 'admin@contoso.onmicrosoft.com'
        $doc.findings[0].evidence[0].identity | Should -Not -Match '^tp-'
    }
}

Describe 'Export-PulseJsonReport (private) - choke-point guard and sortKey redaction' {
    BeforeEach {
        $script:outputRoot = New-TestOutputRoot
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'throws if -Document is the Invoke-PulseEvaluation wrapper (has a top-level RedactionMap property) instead of its .Document member' {
        $wrapper = [pscustomobject]@{
            Document     = [pscustomobject]@{ schemaVersion = '1.0'; findings = @() }
            RedactionMap = @{ 'admin@contoso.onmicrosoft.com' = 'tp-deadbeef' }
        }

        {
            InModuleScope TenantPulse -ArgumentList $wrapper, $script:outputRoot {
                param($wrapper, $outputRoot)
                Export-PulseJsonReport -Document $wrapper -OutputPath $outputRoot
            }
        } | Should -Throw -ExpectedMessage '*RedactionMap*'
    }

    It 'redacts a sortKey that equals its evidence''s raw identity to the SAME pseudonym' {
        $document = [pscustomobject]@{
            schemaVersion = '1.0'
            findings      = @(
                [pscustomobject]@{
                    id       = 'TP.ENT.9001'
                    evidence = @(
                        [pscustomobject]@{ identity = 'admin@contoso.onmicrosoft.com'; detail = 'x'; sortKey = 'admin@contoso.onmicrosoft.com' }
                    )
                }
            )
        }
        $redactionMap = @{ 'admin@contoso.onmicrosoft.com' = 'tp-deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' }

        $reportPath = InModuleScope TenantPulse -ArgumentList $document, $script:outputRoot, $redactionMap {
            param($document, $outputRoot, $redactionMap)
            Export-PulseJsonReport -Document $document -OutputPath $outputRoot -RedactionMap $redactionMap
        }

        $rendered = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
        $rendered.findings[0].evidence[0].identity | Should -Be $redactionMap['admin@contoso.onmicrosoft.com']
        $rendered.findings[0].evidence[0].sortKey | Should -Be $redactionMap['admin@contoso.onmicrosoft.com']
    }

    It 'leaves a custom, non-identity sortKey untouched by redaction' {
        $document = [pscustomobject]@{
            schemaVersion = '1.0'
            findings      = @(
                [pscustomobject]@{
                    id       = 'TP.ENT.9001'
                    evidence = @(
                        [pscustomobject]@{ identity = 'admin@contoso.onmicrosoft.com'; detail = 'x'; sortKey = '000-custom-sort-key' }
                    )
                }
            )
        }
        $redactionMap = @{ 'admin@contoso.onmicrosoft.com' = 'tp-deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' }

        $reportPath = InModuleScope TenantPulse -ArgumentList $document, $script:outputRoot, $redactionMap {
            param($document, $outputRoot, $redactionMap)
            Export-PulseJsonReport -Document $document -OutputPath $outputRoot -RedactionMap $redactionMap
        }

        $rendered = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
        $rendered.findings[0].evidence[0].identity | Should -Be $redactionMap['admin@contoso.onmicrosoft.com']
        $rendered.findings[0].evidence[0].sortKey | Should -Be '000-custom-sort-key'
    }
}

Describe 'Export-PulseReport - render-only' {
    BeforeEach {
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        $script:outputRoot = New-TestOutputRoot
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'has no -Redact parameter at all' {
        (Get-Command Export-PulseReport).Parameters.ContainsKey('Redact') | Should -BeFalse
    }

    It 're-rendering an existing findings file is byte-identical to the original' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { New-TestFixtureCatalog }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $original = Invoke-TestPulseAssessment -Params @{ ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot }

        $copyRoot = New-TestOutputRoot
        try {
            $rerendered = Export-PulseReport -FindingsPath $original.FindingsPath -Format Json -OutputPath $copyRoot

            $originalRaw = Get-Content -LiteralPath $original.FindingsPath -Raw
            $rerenderedRaw = Get-Content -LiteralPath $rerendered.ReportPaths.Json -Raw
            $rerenderedRaw | Should -Be $originalRaw
        } finally {
            Remove-Item -LiteralPath $copyRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
