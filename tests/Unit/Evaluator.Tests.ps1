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

            function Test-PulseFixtureDuckTypedNoIdentityRule {
                param($Datasets)
                # Deliberately NOT built via New-PulseFinding - a hand-shaped duck-typed
                # RuleResult whose one evidence entry has no Identity at all (H2 regression
                # fixture).
                return [pscustomobject]@{
                    PSTypeName = 'TenantPulse.RuleResult'
                    Status     = 'Fail'
                    Evidence   = @([pscustomobject]@{ Detail = 'no identity on this one' })
                    Reason     = 'duck-typed, missing Identity'
                }
            }

            function Test-PulseFixtureDuplicateEvidenceRule {
                param($Datasets)
                return New-PulseFinding -Status Warn -Evidence @(
                    @{ Identity = 'dup-1'; Detail = 'first' },
                    @{ Identity = 'dup-1'; Detail = 'second' }
                )
            }

            function Test-PulseFixtureNonSerializableDetailRule {
                param($Datasets)
                return New-PulseFinding -Status Warn -Evidence @(@{ Identity = 'obj-1'; Detail = [double]::NaN })
            }

            function Test-PulseFixturePSTypeNameDetailRule {
                param($Datasets)
                # A raw hashtable literally KEYED 'PSTypeName' - unlike
                # `[pscustomobject]@{ PSTypeName = 'X'; ... }` (which PowerShell consumes
                # entirely into .PSObject.TypeNames, leaving no visible property - verified
                # empirically, NOT the leak vector), a plain hashtable's 'PSTypeName' key is
                # just an ordinary dictionary key that serializes straight through.
                $detail = @{ PSTypeName = 'Sneaky.Type'; a = 1 }
                return New-PulseFinding -Status Warn -Evidence @(@{ Identity = 'obj-1'; Detail = $detail })
            }

            function Test-PulseFixtureMultiOutputRule {
                param($Datasets)
                Write-Output 'a stray pipeline output before the real result'
                return New-PulseFinding -Status Pass
            }

            function Test-PulseFixtureNoOutputRule {
                param($Datasets)
                # Deliberately emits nothing.
            }

            function Test-PulseFixtureNonTerminatingErrorRule {
                param($Datasets)
                Write-Error 'a non-terminating error the rule forgot to handle' -ErrorAction Continue
                return New-PulseFinding -Status Pass
            }

            function Test-PulseFixtureMutatesDatasetsRule {
                param($Datasets)
                $Datasets.datasetA = @()
                return New-PulseFinding -Status Pass
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
    It 'returns Status Unknown (and no Detail) for any gate name (Phase 1 stub registry)' {
        $status = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP1' -Manifest @{}
        }

        $status.Status | Should -Be 'Unknown'
        $status.Detail | Should -BeNullOrEmpty

        $status2 = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'SomeOtherGate' -Manifest @{}
        }

        $status2.Status | Should -Be 'Unknown'
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

    It 'produces byte-identical documents across two INDEPENDENT Invoke-PulseEvaluation runs against the same snapshot' {
        $checkB = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureWarnRule' }
        $checkA = New-PulseFixtureCheck -Id 'TP.ENT.0001' -Datasets @('datasetFailed') -Rule @{ Type = 'Expression'; Expression = '$true' }

        $firstRun = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($checkB, $checkA)
        $secondRun = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($checkB, $checkA)

        $jsonFirst = InModuleScope TenantPulse -ArgumentList $firstRun.Document {
            param($doc)
            ConvertTo-PulseCanonicalJson -InputObject $doc
        }
        $jsonSecond = InModuleScope TenantPulse -ArgumentList $secondRun.Document {
            param($doc)
            ConvertTo-PulseCanonicalJson -InputObject $doc
        }

        [System.Text.Encoding]::UTF8.GetBytes($jsonFirst) | Should -Be ([System.Text.Encoding]::UTF8.GetBytes($jsonSecond))
    }

    # ---- H2: malformed evidence must degrade only the offending check, never crash the run ----

    It 'degrades a check to Error (not a crash) when a duck-typed RuleResult has an evidence entry with no Identity' {
        $bad = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureDuckTypedNoIdentityRule' }
        $ok = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixturePassRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($bad, $ok)

        $evaluation.Document.findings.Count | Should -Be 2
        $badFinding = $evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0001' }
        $badFinding.status | Should -Be 'Error'
        $badFinding.reason | Should -Match 'Identity'

        $okFinding = $evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0002' }
        $okFinding.status | Should -Be 'Pass'

        # The redaction map must never have been asked to key on a null/empty identity.
        $evaluation.RedactionMap.Keys | Should -Not -Contain $null
        $evaluation.RedactionMap.Keys | Should -Not -Contain ''
    }

    It 'degrades a check to Error when its evidence has a duplicate (SortKey, Identity) pair' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureDuplicateEvidenceRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'duplicate'
    }

    It 'degrades a check to Error when evidence Detail cannot survive ConvertTo-PulseCanonicalJson' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureNonSerializableDetailRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'not serializable'
    }

    It 'degrades a check to Error when evidence Detail itself carries a PSTypeName key' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixturePSTypeNameDetailRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'PSTypeName'
    }

    # ---- do-now minors: multi-output truncation, non-terminating error capture ----

    It 'degrades a check to Error naming the output count when a Function rule emits more than one output' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureMultiOutputRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'emitted 2 output'
    }

    It 'degrades a check to Error naming the output count when a Function rule emits no output' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureNoOutputRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'emitted 0 output'
    }

    It 'captures a Function rule''s non-terminating error into the finding''s reason instead of silently dropping it' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureNonTerminatingErrorRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'a non-terminating error the rule forgot to handle'
    }

    # ---- IMPORTANT: per-check dataset cloning - no rule can affect another check's data ----

    It 'never lets a Function rule''s in-place mutation of $Datasets affect a later check sharing the same dataset' {
        $mutating = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureMutatesDatasetsRule' }
        $observing = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Expression'; Expression = '$Datasets.datasetA.Count -eq 2' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($mutating, $observing)

        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0001' }).status | Should -Be 'Pass'
        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0002' }).status | Should -Be 'Pass'
    }

    It 'never lets an Expression rule''s in-place mutation of $Datasets affect a later check sharing the same dataset' {
        $mutating = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$Datasets.datasetA = @(); $true' }
        $observing = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Expression'; Expression = '$Datasets.datasetA.Count -eq 2' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($mutating, $observing)

        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0001' }).status | Should -Be 'Pass'
        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0002' }).status | Should -Be 'Pass'
    }

    # ---- IMPORTANT: gate wiring - Unavailable now really degrades, Unknown/Available run ----

    It 'degrades to NotApplicable with a reason quoting the gate name and detail when Get-PulseGateStatus reports Unavailable' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Gates @('EntraP1') -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = InModuleScope TenantPulse -ArgumentList $script:store, $script:keyPath, $check {
            param($store, $keyPath, $check)

            # Overrides the real (Phase 1 stub) Get-PulseGateStatus for this scope only, so
            # the evaluator's 'Unavailable' wiring can be exercised even though the stub
            # itself never returns it.
            function Get-PulseGateStatus {
                param($Gate, $Manifest)
                return [pscustomobject]@{ Status = 'Unavailable'; Detail = 'no EntraP1 license data collected' }
            }

            Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
        }

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be "gate 'EntraP1' unavailable: no EntraP1 license data collected"
    }

    # ---- IMPORTANT: reason redaction on the evaluate path ----

    It 'routes an Error reason through Protect-PulseReason (caps at 500 characters)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureThrowingRule' }

        $longThrowCheck = InModuleScope TenantPulse -ArgumentList $script:store, $script:keyPath, $check {
            param($store, $keyPath, $check)

            function Test-PulseFixtureLongThrowRule {
                param($Datasets)
                throw ('x' * 600)
            }
            $check.Rule.Function = 'Test-PulseFixtureLongThrowRule'

            Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
        }

        $reason = $longThrowCheck.Document.findings[0].reason
        $reason.Length | Should -Be 500
    }

    It 'does not route a NotApplicable reason through Protect-PulseReason (quoted verbatim, uncapped by this path)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Datasets @('datasetFailed') -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].reason | Should -Be 'throttled: too many requests'
    }

    # ---- C1: Expression rules run sandboxed - fresh runspace, ConstrainedLanguage, no ambient scope ----

    It 'never lets an Expression rule reach a caller-scope variable via Get-Variable (sandbox isolation)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{
            Type       = 'Expression'
            Expression = '$found = Get-Variable -Name operatorKey -ErrorAction SilentlyContinue; [bool]$found'
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        # $found must be $null/false - operatorKey (the real HMAC key, alive two scopes up
        # in the un-sandboxed implementation) is simply not reachable from inside the
        # sandboxed runspace's own, separate session state.
        $evaluation.Document.findings[0].status | Should -Be 'Fail'
    }

    It 'never lets an Expression rule''s Set-Variable escape into the caller''s process (sandbox isolation)' {
        Remove-Variable -Name PulseSandboxCanary -Scope Global -ErrorAction SilentlyContinue

        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{
            Type       = 'Expression'
            Expression = "Set-Variable -Name PulseSandboxCanary -Value 'leaked-out' -Scope Global; `$true"
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        # The expression succeeds inside its OWN sandboxed session state...
        $evaluation.Document.findings[0].status | Should -Be 'Pass'
        # ...but nothing escaped into this test process's global scope.
        (Get-Variable -Name PulseSandboxCanary -Scope Global -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
    }

    It 'blocks a raw .NET escape attempt under ConstrainedLanguage (sandbox isolation)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{
            Type       = 'Expression'
            Expression = '[System.IO.File]::Exists("/etc/passwd")'
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].status | Should -Be 'Error'
    }

    It 'still evaluates a plain boolean Expression rule normally through the sandbox' {
        $checkTrue = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$Datasets.datasetA.Count -gt 0' }
        $checkFalse = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Expression'; Expression = '$Datasets.datasetA.Count -gt 99' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($checkTrue, $checkFalse)

        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0001' }).status | Should -Be 'Pass'
        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0002' }).status | Should -Be 'Fail'
    }
}

Describe 'Invoke-PulseSandboxedExpression' {
    It 'evaluates a true expression to Pass' {
        $result = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '$Datasets.a.Count -gt 0' -Datasets @{ a = @(1, 2) }
        }
        $result.Status | Should -Be 'Pass'
    }

    It 'evaluates a false expression to Fail' {
        $result = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '$Datasets.a.Count -gt 99' -Datasets @{ a = @(1, 2) }
        }
        $result.Status | Should -Be 'Fail'
    }

    It 'returns Error for a non-boolean result' {
        $result = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '$Datasets.a.Count' -Datasets @{ a = @(1, 2) }
        }
        $result.Status | Should -Be 'Error'
        $result.Reason | Should -Match 'boolean'
    }

    It 'returns Error for a script that fails to parse' {
        $result = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '$Datasets.a -gt (' -Datasets @{ a = @(1, 2) }
        }
        $result.Status | Should -Be 'Error'
    }
}
