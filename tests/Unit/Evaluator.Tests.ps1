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

    # Plain-PowerShell helper (outside the module) that builds a fixture check descriptor
    # shaped exactly like Import-PulseCheckCatalog's output - marshaled into InModuleScope
    # calls via -ArgumentList, same as fixture data arrays elsewhere in this test suite.
    function script:New-PulseFixtureCheck {
        param(
            [string] $Id,
            [string] $Title = 'Fixture check',
            [string] $Category = 'Fixture.Category',
            [string] $Severity = 'Medium',
            [string[]] $Datasets = @('datasetA'),
            [string[]] $Gates = @(),
            [hashtable] $Rule
        )

        [pscustomobject]@{
            PSTypeName = 'TenantPulse.CheckDescriptor'
            Id         = $Id
            Title      = $Title
            Category   = $Category
            Severity   = $Severity
            Effort     = 'Low'
            Impact     = 'Medium'
            Data       = @{ Datasets = $Datasets; Gates = $Gates }
            Rule       = $Rule
            Consulting = @{
                WhatItMeans  = "What $Id means."
                WhyItMatters = "Why $Id matters."
                Remediation  = @("Fix $Id.")
                PortalLinks  = @('https://example.com/portal')
            }
            References = @{
                Research    = "docs/research/$Id.md"
                Authorities = @('MS.FIXTURE.1')
            }
            Origin     = $null
        }
    }

    # Runs Invoke-PulseEvaluation inside the module's scope, first (re-)defining every
    # fixture rule function this test file uses. A function defined by one InModuleScope
    # call does NOT persist into a later, separate InModuleScope call (each call's
    # scriptblock runs in its own child scope of the module - see CheckCatalog.Tests.ps1's
    # own pattern of redefining its fixture rule per It block), so the definitions are
    # folded into this single shared entry point instead of being repeated at every call
    # site.
    function script:Invoke-PulseFixtureEvaluation {
        param(
            [Parameter(Mandatory)]
            [pscustomobject] $Store,

            [Parameter(Mandatory)]
            [string] $KeyPath,

            [Parameter(Mandatory)]
            [object[]] $Checks
        )

        InModuleScope TenantPulse -ArgumentList $Store, $KeyPath, $Checks {
            param($Store, $KeyPath, $Checks)

            function Test-PulseFixturePassRule {
                param($Datasets)
                return New-PulseFinding -Status Pass -Evidence @(@{ Identity = 'obj-pass-1' })
            }

            function Test-PulseFixtureWarnRule {
                param($Datasets)
                return New-PulseFinding -Status Warn -Reason 'two objects need review' -Evidence @(
                    @{ Identity = 'zzz-last'; Detail = 'z detail' },
                    @{ Identity = 'aaa-first'; Detail = 'a detail'; SortKey = '0-aaa' }
                )
            }

            function Test-PulseFixtureFailRule {
                param($Datasets)
                return New-PulseFinding -Status Fail -Reason 'policy missing' -Evidence @(@{ Identity = 'obj-fail-1' })
            }

            function Test-PulseFixtureThrowingRule {
                param($Datasets)
                throw 'boom: rule blew up unexpectedly'
            }

            function Test-PulseFixtureBadShapeRule {
                param($Datasets)
                return [pscustomobject]@{ NotAStatus = 'nonsense' }
            }

            Invoke-PulseEvaluation -Store $Store -Checks $Checks -OperatorKeyPath $KeyPath
        }
    }
}

Describe 'New-PulseFinding' {
    It 'defaults an evidence entry''s SortKey to its Identity when SortKey is omitted' {
        $result = InModuleScope TenantPulse {
            New-PulseFinding -Status Pass -Evidence @(@{ Identity = 'thing-1' })
        }

        $result.Evidence.Count | Should -Be 1
        $result.Evidence[0].Identity | Should -Be 'thing-1'
        $result.Evidence[0].SortKey | Should -Be 'thing-1'
    }

    It 'preserves an explicit SortKey distinct from Identity' {
        $result = InModuleScope TenantPulse {
            New-PulseFinding -Status Warn -Evidence @(@{ Identity = 'thing-1'; SortKey = '000-first' })
        }

        $result.Evidence[0].SortKey | Should -Be '000-first'
    }

    It 'throws when an evidence entry has no Identity' {
        {
            InModuleScope TenantPulse {
                New-PulseFinding -Status Fail -Evidence @(@{ Detail = 'no identity here' })
            }
        } | Should -Throw -ExpectedMessage '*Identity*'
    }

    It 'produces a PSTypeName ''TenantPulse.RuleResult'' object with Status/Evidence/Reason' {
        $result = InModuleScope TenantPulse {
            New-PulseFinding -Status Pass -Reason 'all good'
        }

        $result.PSObject.TypeNames | Should -Contain 'TenantPulse.RuleResult'
        $result.Status | Should -Be 'Pass'
        $result.Reason | Should -Be 'all good'
        $result.Evidence.Count | Should -Be 0
    }
}

Describe 'Get-PulseGateStatus' {
    It 'returns Unknown for any gate name (Phase 1 stub registry)' {
        $status = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP1' -Manifest @{}
        }

        $status | Should -Be 'Unknown'

        $status2 = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'SomeOtherGate' -Manifest @{}
        }

        $status2 | Should -Be 'Unknown'
    }
}

Describe 'Invoke-PulseEvaluation' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:keyPath = Join-Path $script:storeRoot '.opkey/operator.key'

        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'

            Write-PulseDataset -Store $store -Name 'datasetA' -Data @(
                [pscustomobject]@{ id = 'a-1' }, [pscustomobject]@{ id = 'a-2' }
            ) -ApiVersion 'v1.0' -Status 'Collected'

            Write-PulseDataset -Store $store -Name 'datasetFailed' -ApiVersion 'v1.0' -Status 'Failed' -Reason 'throttled: too many requests'
            Write-PulseDataset -Store $store -Name 'datasetSkipped' -ApiVersion 'v1.0' -Status 'Skipped' -Reason 'permission-denied: DeviceManagementConfiguration.Read.All'

            return $store
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'evaluates an Expression rule that resolves true to Pass with no evidence' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$Datasets.datasetA.Count -gt 0' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Pass'
        $finding.evidence.Count | Should -Be 0
        $finding.reason | Should -BeNullOrEmpty
    }

    It 'evaluates an Expression rule that resolves false to Fail' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$Datasets.datasetA.Count -gt 99' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].status | Should -Be 'Fail'
    }

    It 'returns Error when an Expression rule does not resolve to a boolean' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$Datasets.datasetA.Count' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'boolean'
    }

    It 'evaluates a Function rule returning Warn with evidence' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureWarnRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Be 'two objects need review'
        $finding.evidence.Count | Should -Be 2
    }

    It 'sorts a finding''s evidence ordinally by SortKey then Identity' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureWarnRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evidence = $evaluation.Document.findings[0].evidence
        # 'aaa-first' carries SortKey '0-aaa', which sorts ordinally before 'zzz-last'
        # (whose SortKey defaults to its own Identity) - evidence order must follow SortKey,
        # not insertion order (the fixture rule returns zzz-last first).
        $evidence[0].identity | Should -Be 'aaa-first'
        $evidence[1].identity | Should -Be 'zzz-last'
    }

    It 'returns Error and continues to the next check when a rule throws' {
        $throwing = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureThrowingRule' }
        $passing = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixturePassRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($throwing, $passing)

        $evaluation.Document.findings.Count | Should -Be 2
        $errored = $evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0001' }
        $errored.status | Should -Be 'Error'
        $errored.reason | Should -Match 'boom: rule blew up unexpectedly'

        $stillRan = $evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0002' }
        $stillRan.status | Should -Be 'Pass'
    }

    It 'returns Error when a Function rule does not return a RuleResult-shaped object' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureBadShapeRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].status | Should -Be 'Error'
    }

    It 'degrades to NotApplicable, quoting the manifest reason verbatim, for a Failed dataset' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Datasets @('datasetFailed') -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'throttled: too many requests'
    }

    It 'degrades to NotApplicable, quoting the manifest reason verbatim, for a Skipped dataset' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Datasets @('datasetSkipped') -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: DeviceManagementConfiguration.Read.All'
    }

    It 'degrades to NotApplicable for a dataset entirely missing from the manifest' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Datasets @('datasetNeverCollected') -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'datasetNeverCollected'
    }

    It 'runs the check normally when it declares a gate (Unknown never degrades in Phase 1)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Gates @('EntraP1') -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    It 'sorts findings ordinally by check Id regardless of input order' {
        $checkB = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Expression'; Expression = '$true' }
        $checkA = New-PulseFixtureCheck -Id 'TP.ENT.0001' -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($checkB, $checkA)

        $evaluation.Document.findings[0].id | Should -Be 'TP.ENT.0001'
        $evaluation.Document.findings[1].id | Should -Be 'TP.INT.0002'
    }

    It 'sets generatedUtc to the snapshot manifest''s createdUtc, not wall clock, and it is stable across re-evaluation' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$true' }

        $manifestCreatedUtc = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            (Get-PulseSnapshotManifest -Store $store).createdUtc
        }

        $first = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)
        Start-Sleep -Milliseconds 50
        $second = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $first.Document.generatedUtc | Should -Be $manifestCreatedUtc
        $first.Document.generatedUtc | Should -Be $second.Document.generatedUtc
    }

    It 'carries schemaVersion 1.0, scoringModelVersion 1.0, and null coverage/scores placeholders' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.schemaVersion | Should -Be '1.0'
        $evaluation.Document.producer.scoringModelVersion | Should -Be '1.0'
        $evaluation.Document.producer.tenantPulse | Should -Not -BeNullOrEmpty
        $evaluation.Document.PSObject.Properties.Name | Should -Contain 'coverage'
        $evaluation.Document.coverage | Should -BeNullOrEmpty
        $evaluation.Document.PSObject.Properties.Name | Should -Contain 'scores'
        $evaluation.Document.scores | Should -BeNullOrEmpty
        $evaluation.Document.tenant | Should -Be 'tp-fixturetenant'
    }

    It 'builds a RedactionMap covering every evidence identity, keyed by the raw identity' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureWarnRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.RedactionMap.Keys | Should -Contain 'aaa-first'
        $evaluation.RedactionMap.Keys | Should -Contain 'zzz-last'
        $evaluation.RedactionMap['aaa-first'] | Should -Match '^tp-[0-9a-f]{64}$'
        $evaluation.RedactionMap['zzz-last'] | Should -Match '^tp-[0-9a-f]{64}$'
    }

    It 'never redacts evidence identities in the Document itself and never emits PSTypeName in the serialized findings JSON' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureWarnRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $json = InModuleScope TenantPulse -ArgumentList $evaluation.Document {
            param($doc)
            ConvertTo-PulseCanonicalJson -InputObject $doc
        }

        $json | Should -Match 'aaa-first'
        $json | Should -Match 'zzz-last'
        $json | Should -Not -Match 'tp-[0-9a-f]{64}'
        $json | Should -Not -Match 'PSTypeName'
    }

    It 'serializes the findings document byte-identically across two ConvertTo-PulseCanonicalJson passes' {
        $checkB = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureWarnRule' }
        $checkA = New-PulseFixtureCheck -Id 'TP.ENT.0001' -Datasets @('datasetFailed') -Rule @{ Type = 'Expression'; Expression = '$true' }
        $checkC = New-PulseFixtureCheck -Id 'TP.INT.0003' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureFailRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($checkB, $checkA, $checkC)

        $jsonA = InModuleScope TenantPulse -ArgumentList $evaluation.Document {
            param($doc)
            ConvertTo-PulseCanonicalJson -InputObject $doc
        }
        $jsonB = InModuleScope TenantPulse -ArgumentList $evaluation.Document {
            param($doc)
            ConvertTo-PulseCanonicalJson -InputObject $doc
        }

        $bytesA = [System.Text.Encoding]::UTF8.GetBytes($jsonA)
        $bytesB = [System.Text.Encoding]::UTF8.GetBytes($jsonB)
        $bytesA | Should -Be $bytesB
    }
}
