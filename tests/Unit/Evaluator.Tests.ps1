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
            [hashtable] $Rule,
            # Cite-only CIS cross-references (Task 4.5) - omitted by default, since
            # real catalog checks carry none today; tests that need to exercise the
            # disclaimer-firing path pass one or more explicit strings here.
            [string[]] $Cis = @()
        )

        $references = @{
            Research    = "docs/research/$Id.md"
            Authorities = @('MS.FIXTURE.1')
        }
        if ($Cis.Count -gt 0) {
            $references.Cis = $Cis
        }

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
            References = $references
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

            function Test-PulseFixtureRuleReturnedNotApplicableRule {
                param($Datasets)
                return New-PulseFinding -Status NotApplicable -Reason 'superseded by a broader control - not evaluated standalone'
            }

            function Test-PulseFixtureDuckTypedNotApplicableNoReasonRule {
                param($Datasets)
                # Deliberately NOT built via New-PulseFinding - a hand-shaped duck-typed
                # RuleResult with Status NotApplicable and no Reason (H2-style regression
                # fixture for the independent engine-side guard).
                return [pscustomobject]@{
                    PSTypeName = 'TenantPulse.RuleResult'
                    Status     = 'NotApplicable'
                    Evidence   = @()
                    Reason     = $null
                }
            }

            function Test-PulseFixtureCutoffBaseRule {
                param($Datasets, $Context)
                return New-PulseFinding -Status Pass -Reason "cutoff=$($Context.SnapshotCreatedUtc)|$($Context.EvaluationCutoffBase)"
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

    It 'accepts Status NotApplicable with a Reason' {
        $result = InModuleScope TenantPulse {
            New-PulseFinding -Status NotApplicable -Reason 'superseded by a broader control'
        }

        $result.Status | Should -Be 'NotApplicable'
        $result.Reason | Should -Be 'superseded by a broader control'
    }

    It 'throws when Status is NotApplicable and -Reason is omitted' {
        {
            InModuleScope TenantPulse {
                New-PulseFinding -Status NotApplicable
            }
        } | Should -Throw -ExpectedMessage '*Reason*mandatory*'
    }

    It 'throws when Status is NotApplicable and -Reason is an empty string' {
        {
            InModuleScope TenantPulse {
                New-PulseFinding -Status NotApplicable -Reason ''
            }
        } | Should -Throw -ExpectedMessage '*Reason*mandatory*'
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

    # Item 12 (final fix wave): gate on `-ne 'Collected'` rather than enumerating known-bad
    # statuses - a novel/unrecognized status string must fail closed the same way
    # Failed/Skipped do, not silently read as collected.
    It 'degrades to NotApplicable for a novel/unrecognized dataset status string, not just Failed/Skipped (final fix wave, item 12)' {
        # Write-PulseDataset/Set-PulseManifestEntry both ValidateSet their -Status, so a
        # truly novel status can only be injected by editing the manifest file directly -
        # exactly the "a future collector status this evaluator has never heard of, or a
        # corrupted manifest value" scenario the fix targets.
        $manifestPath = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $store.ManifestPath
        }
        $manifestText = Get-Content -LiteralPath $manifestPath -Raw
        $manifestJson = $manifestText | ConvertFrom-Json
        $manifestJson.datasets | Add-Member -NotePropertyName 'datasetQuarantined' -NotePropertyValue ([pscustomobject]@{
            status       = 'Quarantined'
            apiVersion   = 'v1.0'
            reason       = $null
            sha256       = $null
            itemCount    = $null
            collectedUtc = $null
        })
        Set-Content -LiteralPath $manifestPath -Value ($manifestJson | ConvertTo-Json -Depth 10) -NoNewline -Encoding utf8

        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Datasets @('datasetQuarantined') -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
    }

    It 'degrades to NotApplicable for a dataset entirely missing from the manifest' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Datasets @('datasetNeverCollected') -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'datasetNeverCollected'
    }

    # ---- post-review: rule-returned NotApplicable (adjudicated engine fix) ----

    It 'accepts a Function rule returning Status NotApplicable with a Reason, unchanged from what the rule set' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureRuleReturnedNotApplicableRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'superseded by a broader control - not evaluated standalone'
    }

    It 'degrades to Error when a duck-typed Function rule returns NotApplicable with no Reason' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureDuckTypedNotApplicableNoReasonRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'NotApplicable'
        $finding.reason | Should -Match 'Reason'
    }

    It 'excludes a rule-returned NotApplicable from Add-PulseScores'' denominator exactly like an engine-assigned one' {
        $ruleNa = New-PulseFixtureCheck -Id 'TP.INT.0001' -Severity 'Critical' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureRuleReturnedNotApplicableRule' }
        $passing = New-PulseFixtureCheck -Id 'TP.INT.0002' -Severity 'Critical' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixturePassRule' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($ruleNa, $passing)

        $scored = InModuleScope TenantPulse -ArgumentList $evaluation.Document {
            param($doc)
            Add-PulseScores -Findings $doc
        }

        # Only the Pass check's weight counts - the rule-returned NA check contributes to
        # neither earned nor possible, same as an engine-assigned NA would.
        $scored.scores.overall.possible | Should -Be 10.0
        $scored.scores.overall.earned | Should -Be 10.0
        $scored.coverage.overall.applicable | Should -Be 2
        $scored.coverage.overall.assessed | Should -Be 1
    }

    # ---- post-review: wall-clock determinism (H2 adjudicated) ----

    It 'threads SnapshotCreatedUtc and EvaluationCutoffBase into $Context unconditionally, from the manifest, even when the caller supplied no -Context at all' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureCutoffBaseRule' }

        $manifestCreatedUtc = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            (Get-PulseSnapshotManifest -Store $store).createdUtc
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].reason | Should -Be "cutoff=$manifestCreatedUtc|$manifestCreatedUtc"
    }

    It 'produces byte-identical documents across two independent evaluations of the same snapshot for a Context-consuming rule (wall-clock determinism)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureCutoffBaseRule' }

        $firstRun = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)
        Start-Sleep -Milliseconds 50
        $secondRun = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

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

    # Part E, T3.4 (manifest createdUtc culture-coercion fix, carried from the T3.3
    # review): end-to-end proof that a 7-digit-fraction createdUtc survives, byte-identical,
    # all the way from manifest.json through Get-PulseSnapshotManifest into BOTH
    # generatedUtc (the findings document) and $Context.SnapshotCreatedUtc/
    # EvaluationCutoffBase (what a staleness-style rule actually compares against) -
    # regardless of the thread's current culture at evaluation time. Pre-fix, plain
    # `ConvertFrom-Json -AsHashtable` parsed createdUtc into a [datetime], dropping the
    # fraction to millisecond precision and formatting with the current thread culture the
    # moment anything downstream cast it back to [string].
    It 'preserves a 7-digit-fraction createdUtc byte-identically into generatedUtc and EvaluationCutoffBase, independent of thread culture' {
        $sevenDigitCreatedUtc = '2026-08-17T00:00:00.0000001Z'
        $rawManifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $rawManifest = $rawManifest -replace '"createdUtc"\s*:\s*"[^"]*"', ('"createdUtc":"' + $sevenDigitCreatedUtc + '"')
        Set-Content -LiteralPath $script:store.ManifestPath -Value $rawManifest -NoNewline

        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureCutoffBaseRule' }

        $originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('en-GB')
            $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
        }

        $evaluation.Document.generatedUtc | Should -Be $sevenDigitCreatedUtc
        $evaluation.Document.findings[0].reason | Should -Be "cutoff=$sevenDigitCreatedUtc|$sevenDigitCreatedUtc"
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

    It 'carries an empty references.cis array on a finding whose check declares no Cis references' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].references.PSObject.Properties.Name | Should -Contain 'cis'
        @($evaluation.Document.findings[0].references.cis).Count | Should -Be 0
    }

    It 'carries a check''s declared References.Cis strings verbatim on its finding' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$true' } -Cis @('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)')

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].references.cis | Should -Be @('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)')
    }

    It 'CIS disclaimer footer (Document.notices.cisDisclaimer): stays $null when no rendered finding carries a CIS reference' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.PSObject.Properties.Name | Should -Contain 'notices'
        $evaluation.Document.notices.PSObject.Properties.Name | Should -Contain 'cisDisclaimer'
        # -BeNull (not -BeNullOrEmpty): the exact contract is `$null`, not merely falsy - an
        # empty string would also satisfy -BeNullOrEmpty but would be the WRONG shape here
        # (see Invoke-PulseEvaluation's own docstring: "Absent entirely ... when no finding
        # cites CIS, so a renderer can gate a footer purely on is-this-property-truthy").
        $evaluation.Document.notices.cisDisclaimer | Should -BeNull
    }

    It 'CIS disclaimer footer: fires (non-null, mentions CIS and "not constitute" a compliance claim) when at least one rendered finding carries a CIS reference' {
        $withCis = New-PulseFixtureCheck -Id 'TP.ENT.0001' -Rule @{ Type = 'Expression'; Expression = '$true' } -Cis @('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)')
        $withoutCis = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$true' }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($withCis, $withoutCis)

        $evaluation.Document.notices.cisDisclaimer | Should -Not -BeNullOrEmpty
        $evaluation.Document.notices.cisDisclaimer | Should -Match 'CIS'
        $evaluation.Document.notices.cisDisclaimer | Should -Match 'not constitute'
    }

    It 'reads References.Cis off a PSCustomObject-shaped References (shape-neutral, matching every other check-descriptor fixture shape in this suite)' {
        $check = InModuleScope TenantPulse {
            [pscustomobject]@{
                PSTypeName = 'TenantPulse.CheckDescriptor'
                Id         = 'TP.INT.0001'
                Title      = 'Fixture check'
                Category   = 'Fixture.Category'
                Severity   = 'Medium'
                Effort     = 'Low'
                Impact     = 'Medium'
                Data       = @{ Datasets = @('datasetA'); Gates = @() }
                Rule       = @{ Type = 'Expression'; Expression = '$true' }
                Consulting = @{ WhatItMeans = 'x'; WhyItMatters = 'x'; Remediation = @('x'); PortalLinks = @('https://example.com') }
                References = [pscustomobject]@{
                    Research    = 'docs/research/TP.INT.0001.md'
                    Authorities = @('MS.FIXTURE.1')
                    Cis         = @('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)')
                }
                Origin     = $null
            }
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].references.cis | Should -Be @('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)')
        $evaluation.Document.notices.cisDisclaimer | Should -Not -BeNullOrEmpty
    }

    It 'CIS disclaimer footer: fires when the ONLY CIS-carrying check is not the first (ordinal-sorted) finding' {
        # Regression-shaped: the disclaimer computation must scan every finding, not just
        # the first, in whatever order they land in $findings.
        $withoutCis = New-PulseFixtureCheck -Id 'TP.ENT.0001' -Rule @{ Type = 'Expression'; Expression = '$true' }
        $withCis = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Expression'; Expression = '$true' } -Cis @('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 4.2.1 (E5 Level 2)')

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($withoutCis, $withCis)

        $evaluation.Document.findings[0].id | Should -Be 'TP.ENT.0001'
        $evaluation.Document.notices.cisDisclaimer | Should -Not -BeNullOrEmpty
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

    It 'produces byte-identical SCORED documents across two independent evaluations once Add-PulseScores (T1.7) runs on each' {
        $checkB = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureWarnRule' }
        $checkA = New-PulseFixtureCheck -Id 'TP.ENT.0001' -Datasets @('datasetFailed') -Rule @{ Type = 'Expression'; Expression = '$true' }
        $checkC = New-PulseFixtureCheck -Id 'TP.INT.0003' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureFailRule' }

        $firstRun = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($checkB, $checkA, $checkC)
        $secondRun = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($checkB, $checkA, $checkC)

        $jsonFirst = InModuleScope TenantPulse -ArgumentList $firstRun.Document {
            param($doc)
            $scored = Add-PulseScores -Findings $doc
            ConvertTo-PulseCanonicalJson -InputObject $scored
        }
        $jsonSecond = InModuleScope TenantPulse -ArgumentList $secondRun.Document {
            param($doc)
            $scored = Add-PulseScores -Findings $doc
            ConvertTo-PulseCanonicalJson -InputObject $scored
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

    # ---- C1: Expression rules run sandboxed - empty ISS + 5-cmdlet allowlist,
    # ConstrainedLanguage, no ambient scope (round 2: CreateDefault2() was proven to load
    # Management/Utility - Get-Content/Set-Content/New-Item/Remove-Item/Invoke-WebRequest/
    # Invoke-RestMethod all executed under it. The fix rebuilds the ISS from an empty
    # ::Create() with an explicit five-cmdlet allowlist instead.) ----

    It 'never lets an Expression rule reach a caller-scope variable via Get-Variable - the cmdlet itself is gone (sandbox isolation)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{
            Type       = 'Expression'
            Expression = '$found = Get-Variable -Name operatorKey -ErrorAction SilentlyContinue; [bool]$found'
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        # Get-Variable is not in the allowlist at all now (round 2) - the expression fails
        # closed as a command-not-found Error, never as a Pass that could imply the real
        # key was found.
        $evaluation.Document.findings[0].status | Should -Be 'Error'
        $evaluation.Document.findings[0].reason | Should -Match 'Get-Variable'
    }

    It 'never lets an Expression rule''s Set-Variable escape into the caller''s process - the cmdlet itself is gone (sandbox isolation)' {
        Remove-Variable -Name PulseSandboxCanary -Scope Global -ErrorAction SilentlyContinue

        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{
            Type       = 'Expression'
            Expression = "Set-Variable -Name PulseSandboxCanary -Value 'leaked-out' -Scope Global; `$true"
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        # Set-Variable is not in the allowlist either (round 2) - fails closed as Error.
        $evaluation.Document.findings[0].status | Should -Be 'Error'
        $evaluation.Document.findings[0].reason | Should -Match 'Set-Variable'
        # And, belt-and-braces: nothing escaped into this test process's global scope.
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

    It 'still evaluates a Where-Object pipeline expression normally through the sandbox (allowlisted cmdlet)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{
            Type       = 'Expression'
            Expression = '@($Datasets.datasetA | Where-Object { $_.id -eq "a-1" }).Count -eq 1'
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    # ---- round 2 re-review probes: these MUST fail closed, and MUST NOT touch the host ----

    It 'never lets an Expression rule write a file to the host via New-Item/Set-Content (round 2 probe)' {
        $probePath = Join-Path ([System.IO.Path]::GetTempPath()) "pulse-sandbox-probe-$([guid]::NewGuid()).txt"
        Remove-Item -LiteralPath $probePath -ErrorAction SilentlyContinue

        $checkNewItem = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{
            Type       = 'Expression'
            Expression = "New-Item -Path '$probePath' -ItemType File -Force; `$true"
        }
        $checkSetContent = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{
            Type       = 'Expression'
            Expression = "Set-Content -LiteralPath '$probePath' -Value 'leaked'; `$true"
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($checkNewItem, $checkSetContent)

        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0001' }).status | Should -Be 'Error'
        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0002' }).status | Should -Be 'Error'
        # The decisive assertion: the file must never actually land on the host.
        Test-Path -LiteralPath $probePath | Should -BeFalse
    }

    It 'never lets an Expression rule read a host file via Get-Content, or let its content influence the result (round 2 probe)' {
        $probePath = Join-Path ([System.IO.Path]::GetTempPath()) "pulse-sandbox-readprobe-$([guid]::NewGuid()).txt"
        Set-Content -LiteralPath $probePath -Value 'known-secret-value' -NoNewline
        try {
            # Probe pattern: an expression that tries to compare against known file
            # content can never legitimately return Pass, because Get-Content is not
            # reachable to produce that content in the first place.
            $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{
                Type       = 'Expression'
                Expression = "(Get-Content -LiteralPath '$probePath' -Raw) -eq 'known-secret-value'"
            }

            $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($check)

            $evaluation.Document.findings[0].status | Should -Be 'Error'
            $evaluation.Document.findings[0].reason | Should -Match 'Get-Content'
        } finally {
            Remove-Item -LiteralPath $probePath -ErrorAction SilentlyContinue
        }
    }

    It 'never lets an Expression rule make an outbound network call via Invoke-WebRequest/Invoke-RestMethod (round 2 probe)' {
        $checkWebRequest = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{
            Type       = 'Expression'
            Expression = '(Invoke-WebRequest -Uri "https://example.com" -UseBasicParsing).StatusCode -eq 200'
        }
        $checkRestMethod = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{
            Type       = 'Expression'
            Expression = '$null -ne (Invoke-RestMethod -Uri "https://example.com")'
        }

        $evaluation = Invoke-PulseFixtureEvaluation -Store $script:store -KeyPath $script:keyPath -Checks @($checkWebRequest, $checkRestMethod)

        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0001' }).status | Should -Be 'Error'
        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0001' }).reason | Should -Match 'Invoke-WebRequest'
        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0002' }).status | Should -Be 'Error'
        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0002' }).reason | Should -Match 'Invoke-RestMethod'
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

    It 'has none of Get-Content/Set-Content/New-Item/Remove-Item/Invoke-WebRequest/Invoke-RestMethod/Get-Variable/Set-Variable/Get-Module reachable' {
        $probeCmdlets = @(
            'Get-Content', 'Set-Content', 'New-Item', 'Remove-Item',
            'Invoke-WebRequest', 'Invoke-RestMethod',
            'Get-Variable', 'Set-Variable', 'Get-Module'
        )

        foreach ($cmdletName in $probeCmdlets) {
            $result = InModuleScope TenantPulse -ArgumentList $cmdletName {
                param($cmdletName)
                Invoke-PulseSandboxedExpression -Expression "$cmdletName" -Datasets @{}
            }
            $result.Status | Should -Be 'Error' -Because "$cmdletName must not resolve inside the sandbox"
            $result.Reason | Should -Match ([regex]::Escape($cmdletName)) -Because "the error should name the unresolved command $cmdletName"
        }
    }

    It 'still resolves the five allowlisted cmdlets (Where-Object, ForEach-Object, Select-Object, Measure-Object, Sort-Object)' {
        $r1 = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '@(1,2,3 | Where-Object { $_ -gt 1 }).Count -eq 2' -Datasets @{}
        }
        $r1.Status | Should -Be 'Pass'

        $r2 = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '@(1,2,3 | ForEach-Object { $_ * 2 }) -join "," -eq "2,4,6"' -Datasets @{}
        }
        $r2.Status | Should -Be 'Pass'

        $r3 = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '(1,2,3 | Select-Object -First 1) -eq 1' -Datasets @{}
        }
        $r3.Status | Should -Be 'Pass'

        $r4 = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '(1,2,3 | Measure-Object).Count -eq 3' -Datasets @{}
        }
        $r4.Status | Should -Be 'Pass'

        $r5 = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '@(3,1,2 | Sort-Object)[0] -eq 1' -Datasets @{}
        }
        $r5.Status | Should -Be 'Pass'
    }

    It 'blocks raw .NET file access under ConstrainedLanguage even with no file cmdlets present' {
        $result = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '[System.IO.File]::Exists("/etc/passwd")' -Datasets @{}
        }
        $result.Status | Should -Be 'Error'
    }
}

Describe 'Invoke-PulseEvaluation -Context' {
    BeforeEach {
        $script:contextStoreRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:contextKeyPath = Join-Path $script:contextStoreRoot '.opkey/operator.key'
    }

    AfterEach {
        Remove-Item -LiteralPath $script:contextStoreRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'threads -Context into a Function rule that opts in by declaring a -Context parameter' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureContextAwareRule' }
        $context = @{ BreakGlassAccounts = @('breakglass@contoso.onmicrosoft.com') }

        $evaluation = InModuleScope TenantPulse -ArgumentList $script:contextStoreRoot, $script:contextKeyPath, @($check), $context {
            param($storeRoot, $keyPath, $checks, $context)

            $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
            Write-PulseDataset -Store $store -Name 'datasetA' -Data @([pscustomobject]@{ id = 'a-1' }) -ApiVersion 'v1.0' -Status 'Collected'

            function Test-PulseFixtureContextAwareRule {
                param($Datasets, $Context)
                $status = if ($Context.BreakGlassAccounts -contains 'breakglass@contoso.onmicrosoft.com') { 'Pass' } else { 'Fail' }
                return New-PulseFinding -Status $status
            }

            Invoke-PulseEvaluation -Store $store -Checks $checks -OperatorKeyPath $keyPath -Context $context
        }

        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    It 'does not pass -Context to a Function rule that never declares the parameter (pre-Task-1.8 rules keep working unchanged)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureNoContextParamRule' }
        $context = @{ BreakGlassAccounts = @('breakglass@contoso.onmicrosoft.com') }

        $evaluation = InModuleScope TenantPulse -ArgumentList $script:contextStoreRoot, $script:contextKeyPath, @($check), $context {
            param($storeRoot, $keyPath, $checks, $context)

            $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
            Write-PulseDataset -Store $store -Name 'datasetA' -Data @([pscustomobject]@{ id = 'a-1' }) -ApiVersion 'v1.0' -Status 'Collected'

            # Deliberately does NOT declare -Context - proves this rule is called exactly
            # as it would have been before -Context existed (no "parameter cannot be
            # found" error).
            function Test-PulseFixtureNoContextParamRule {
                param($Datasets)
                return New-PulseFinding -Status Pass
            }

            Invoke-PulseEvaluation -Store $store -Checks $checks -OperatorKeyPath $keyPath -Context $context
        }

        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    It 'omitting -Context entirely behaves exactly as before this parameter existed' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureNoContextParamRuleTwo' }

        $evaluation = InModuleScope TenantPulse -ArgumentList $script:contextStoreRoot, $script:contextKeyPath, @($check) {
            param($storeRoot, $keyPath, $checks)

            $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
            Write-PulseDataset -Store $store -Name 'datasetA' -Data @([pscustomobject]@{ id = 'a-1' }) -ApiVersion 'v1.0' -Status 'Collected'

            function Test-PulseFixtureNoContextParamRuleTwo {
                param($Datasets)
                return New-PulseFinding -Status Pass
            }

            Invoke-PulseEvaluation -Store $store -Checks $checks -OperatorKeyPath $keyPath
        }

        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    It 'threads -Context into an Expression rule as $Context' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = "`$Context.ServiceAccounts -contains 'svc@contoso.onmicrosoft.com'" }
        $context = @{ ServiceAccounts = @('svc@contoso.onmicrosoft.com') }

        $evaluation = InModuleScope TenantPulse -ArgumentList $script:contextStoreRoot, $script:contextKeyPath, @($check), $context {
            param($storeRoot, $keyPath, $checks, $context)

            $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
            Write-PulseDataset -Store $store -Name 'datasetA' -Data @([pscustomobject]@{ id = 'a-1' }) -ApiVersion 'v1.0' -Status 'Collected'

            Invoke-PulseEvaluation -Store $store -Checks $checks -OperatorKeyPath $keyPath -Context $context
        }

        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    It 'an Expression rule sees an empty $Context when -Context is omitted, never a missing variable error' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$null -eq $Context.ServiceAccounts' }

        $evaluation = InModuleScope TenantPulse -ArgumentList $script:contextStoreRoot, $script:contextKeyPath, @($check) {
            param($storeRoot, $keyPath, $checks)

            $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
            Write-PulseDataset -Store $store -Name 'datasetA' -Data @([pscustomobject]@{ id = 'a-1' }) -ApiVersion 'v1.0' -Status 'Collected'

            Invoke-PulseEvaluation -Store $store -Checks $checks -OperatorKeyPath $keyPath
        }

        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    # ---- Task 3.1 review-fix round: ArtifactReader must never reach an Expression rule ----

    It 'an Expression rule never sees $Context.ArtifactReader, even though Invoke-PulseEvaluation always populates it for Function rules' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$null -eq $Context.ArtifactReader' }

        $evaluation = InModuleScope TenantPulse -ArgumentList $script:contextStoreRoot, $script:contextKeyPath, @($check) {
            param($storeRoot, $keyPath, $checks)

            $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
            Write-PulseDataset -Store $store -Name 'datasetA' -Data @([pscustomobject]@{ id = 'a-1' }) -ApiVersion 'v1.0' -Status 'Collected'

            Invoke-PulseEvaluation -Store $store -Checks $checks -OperatorKeyPath $keyPath
        }

        # 'Pass' here means the expression's own `$null -eq $Context.ArtifactReader`
        # evaluated $true INSIDE the sandbox - i.e. the key is genuinely absent from the
        # $Context variable the sandboxed runspace was given, not merely inaccessible.
        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    It 'an Expression rule never sees a $Context.Store key either (the pre-review-fix design this task replaced)' {
        $check = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Expression'; Expression = '$null -eq $Context.Store' }

        $evaluation = InModuleScope TenantPulse -ArgumentList $script:contextStoreRoot, $script:contextKeyPath, @($check) {
            param($storeRoot, $keyPath, $checks)

            $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
            Write-PulseDataset -Store $store -Name 'datasetA' -Data @([pscustomobject]@{ id = 'a-1' }) -ApiVersion 'v1.0' -Status 'Collected'

            Invoke-PulseEvaluation -Store $store -Checks $checks -OperatorKeyPath $keyPath
        }

        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    It 'a Function rule mutating its own received $Context never corrupts what a LATER check in the same run sees' {
        $mutatingCheck = New-PulseFixtureCheck -Id 'TP.INT.0001' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureContextMutatingRule' }
        $probeCheck = New-PulseFixtureCheck -Id 'TP.INT.0002' -Rule @{ Type = 'Function'; Function = 'Test-PulseFixtureContextProbeRule' }

        $evaluation = InModuleScope TenantPulse -ArgumentList $script:contextStoreRoot, $script:contextKeyPath, @($mutatingCheck, $probeCheck) {
            param($storeRoot, $keyPath, $checks)

            $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
            Write-PulseDataset -Store $store -Name 'datasetA' -Data @([pscustomobject]@{ id = 'a-1' }) -ApiVersion 'v1.0' -Status 'Collected'

            # First check: mutates its OWN received $Context in place - adds a new key,
            # reassigns ArtifactReader to $null - exactly the class of in-place mutation a
            # shared (unclonded) $Context hashtable would let leak into every later check.
            function Test-PulseFixtureContextMutatingRule {
                param($Datasets, $Context)
                $Context.Injected = 'mutated'
                $Context.ArtifactReader = $null
                $Context.Remove('EvaluationCutoffBase')
                return New-PulseFinding -Status Pass
            }

            # Second check: probes for a PRISTINE $Context - no 'Injected' key, a real
            # (non-null) ArtifactReader, and EvaluationCutoffBase still present - proving
            # the first check's in-place mutation never reached the engine's own shared
            # Context state.
            function Test-PulseFixtureContextProbeRule {
                param($Datasets, $Context)
                $pristine = (-not $Context.ContainsKey('Injected')) -and ($null -ne $Context.ArtifactReader) -and $Context.ContainsKey('EvaluationCutoffBase')
                return New-PulseFinding -Status $(if ($pristine) { 'Pass' } else { 'Fail' }) -Reason $(if (-not $pristine) { "Injected=$($Context.ContainsKey('Injected')) ArtifactReader=$($null -ne $Context.ArtifactReader) CutoffBase=$($Context.ContainsKey('EvaluationCutoffBase'))" } else { $null })
            }

            Invoke-PulseEvaluation -Store $store -Checks $checks -OperatorKeyPath $keyPath
        }

        ($evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0001' }).status | Should -Be 'Pass'
        $probeFinding = $evaluation.Document.findings | Where-Object { $_.id -eq 'TP.INT.0002' }
        $probeFinding.status | Should -Be 'Pass' -Because $probeFinding.reason
    }
}

Describe 'Invoke-PulseSandboxedExpression -Context' {
    It 'exposes -Context as $Context inside the sandbox' {
        $result = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '$Context.ServiceAccounts -contains "svc@contoso.onmicrosoft.com"' -Datasets @{} -Context @{ ServiceAccounts = @('svc@contoso.onmicrosoft.com') }
        }

        $result.Status | Should -Be 'Pass'
    }

    It 'defaults to an empty $Context when -Context is omitted' {
        $result = InModuleScope TenantPulse {
            Invoke-PulseSandboxedExpression -Expression '$null -eq $Context.ServiceAccounts' -Datasets @{}
        }

        $result.Status | Should -Be 'Pass'
    }
}
