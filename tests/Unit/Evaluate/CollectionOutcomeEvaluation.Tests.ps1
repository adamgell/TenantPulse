BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Evaluator collection-outcome boundary' {
    It 'exposes Partial as a distinct manifest status with structured gaps rather than an empty successful dataset' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $entry = InModuleScope TenantPulse -ArgumentList $root {
            param($root)
            $store = New-PulseSnapshotStore -Path $root
            $gap = New-PulseCollectionGap -Scope 'child-a' -FailureClass 'DependencyUnavailable' -ReasonCode 'dependency-unavailable' -Detail @{ dependency = 'groups' } -Operation 'List' -ApiVersion 'beta'
            Write-PulseDataset -Store $store -Name 'compositeDataset' -Data @() -ApiVersion 'beta' -Status 'Partial' -ReasonCode 'partial-child' -Detail @{} -Provider 'GraphKit' -Operations @('List') -Gaps @($gap)
            (Get-PulseSnapshotManifest -Store $store).datasets.compositeDataset
        }

        $entry.status | Should -Be 'Partial'
        $entry.status | Should -Not -Be 'Collected'
        $entry.gaps.Count | Should -Be 1
        $entry.gaps[0].failureClass | Should -Be 'DependencyUnavailable'
        $entry.reasonCode | Should -Be 'partial-child'
    }

    It 'keeps collection dependency ordering independent of PartialDatasets' {
        $result = InModuleScope TenantPulse {
            $checks = @(
                [pscustomobject]@{
                    Id   = 'TP.INT.0098'
                    Data = @{
                        Datasets        = @('child')
                        PartialDatasets = @('child')
                    }
                }
            )
            $map = @{
                parent = @{ Type = 'Parent'; Operation = 'List'; ApiVersion = 'v1.0' }
                child  = @{ Type = 'Child'; Operation = 'List'; ApiVersion = 'v1.0'; IdFromDataset = 'parent' }
            }

            @((Get-PulseCollectionManifest -Checks $checks -DatasetMap $map).Dataset)
        }

        $result | Should -Be @('parent', 'child')
    }
}

Describe 'Invoke-PulseCheckEvaluation partial-awareness contract' {
    BeforeAll {
        function script:New-PulsePartialGapFixture {
            param(
                [string] $Scope = 'scope-safe',
                [string] $FailureClass = 'ProviderFailed',
                [string] $ReasonCode = 'provider-failed',
                $Detail = @{ marker = 'gap-detail-canary' },
                [string] $Operation = 'Child.List',
                [string] $ApiVersion = 'beta'
            )

            [pscustomobject][ordered]@{
                Scope        = $Scope
                FailureClass = $FailureClass
                ReasonCode   = $ReasonCode
                Detail       = $Detail
                Operation    = $Operation
                ApiVersion   = $ApiVersion
            }
        }

        function script:New-PulsePartialEntryFixture {
            param(
                [string] $Status = 'Partial',
                $Gaps = @((New-PulsePartialGapFixture)),
                $Operations = @('Parent.List', 'Child.List'),
                $Detail = @{ marker = 'manifest-detail-canary' }
            )

            [ordered]@{
                status       = $Status
                failureClass = $null
                reasonCode   = 'partial'
                detail       = $Detail
                provider     = 'provider-detail-canary'
                apiVersion   = 'beta'
                operations   = $Operations
                gaps         = $Gaps
                reason       = 'manifest-reason-canary'
                sha256       = 'sha256-canary'
                itemCount    = 1
                collectedUtc = '2026-08-30T00:00:00.000Z'
            }
        }

        function script:New-PulseEvaluationCheckFixture {
            param(
                [string] $RuleType = 'Function',
                [string] $RuleFunction = 'Test-PulsePartialAwareFixtureRule',
                [string[]] $Datasets = @('partialA'),
                [AllowNull()]
                [string[]] $PartialDatasets = @('partialA')
            )

            $data = @{ Datasets = $Datasets; Gates = @() }
            if ($null -ne $PartialDatasets) { $data.PartialDatasets = $PartialDatasets }
            $rule = if ($RuleType -eq 'Expression') {
                @{ Type = 'Expression'; Expression = '$true' }
            } else {
                @{ Type = 'Function'; Function = $RuleFunction }
            }

            [pscustomobject]@{ Data = $data; Rule = $rule }
        }
    }

    It 'keeps a non-aware Partial check NotApplicable and emits only dataset name plus aggregate gap count' {
        $check = New-PulseEvaluationCheckFixture -RuleType Expression -PartialDatasets $null
        $entry = New-PulsePartialEntryFixture

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache @{ partialA = @([pscustomobject]@{ id = 'row-1' }) }
        }

        $result.Status | Should -Be 'NotApplicable'
        $result.Reason | Should -Be "dataset 'partialA' is Partial with 1 unresolved gap."
        $result.Reason | Should -Not -Match 'manifest-reason-canary|manifest-detail-canary|gap-detail-canary|provider-detail-canary|scope-safe|Child\.List'
    }

    It 'does not invoke a non-aware Function for Partial and pluralizes only the aggregate gap count' {
        $check = New-PulseEvaluationCheckFixture -PartialDatasets $null
        $entry = New-PulsePartialEntryFixture -Gaps @(
            (New-PulsePartialGapFixture -Scope 'scope-private-one'),
            (New-PulsePartialGapFixture -Scope 'scope-private-two')
        )

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            function Test-PulsePartialAwareFixtureRule {
                param($Datasets, $DatasetOutcomes)
                throw 'non-aware-rule-must-not-run-canary'
            }
            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache @{ partialA = @([pscustomobject]@{ id = 'row-1' }) }
        }

        $result.Status | Should -Be 'NotApplicable'
        $result.Reason | Should -Be "dataset 'partialA' is Partial with 2 unresolved gaps."
        $result.Reason | Should -Not -Match 'scope-private|non-aware-rule-must-not-run-canary|manifest-reason-canary'
    }

    It 'never lets an Expression rule consume Partial rows even when a hand-built descriptor claims PartialDatasets' {
        $check = New-PulseEvaluationCheckFixture -RuleType Expression
        $entry = New-PulsePartialEntryFixture

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache @{ partialA = @([pscustomobject]@{ id = 'row-1' }) }
        }

        $result.Status | Should -Be 'Error'
    }

    It 'fails closed without invoking a rule for missing, Failed, Skipped, or unknown dataset states' -ForEach @(
        @{ Case = 'missing'; Status = $null }
        @{ Case = 'Failed'; Status = 'Failed' }
        @{ Case = 'Skipped'; Status = 'Skipped' }
        @{ Case = 'unknown'; Status = 'Quarantined' }
    ) {
        $check = New-PulseEvaluationCheckFixture
        $entry = if ($null -eq $Status) { $null } else { New-PulsePartialEntryFixture -Status $Status }

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            function Test-PulsePartialAwareFixtureRule {
                param($Datasets, $DatasetOutcomes)
                throw 'rule-must-not-run-canary'
            }
            $datasets = @{}
            if ($null -ne $entry) { $datasets.partialA = $entry }
            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = $datasets } -DatasetCache @{}
        }

        $result.Status | Should -Be 'NotApplicable'
        $result.Reason | Should -Not -Match 'rule-must-not-run-canary'
    }

    It 'returns one bounded reason without copying unsupported persisted status or reason canaries: <Case>' -ForEach @(
        @{ Case = 'scalar status'; StatusValue = 'persisted-status-canary' }
        @{ Case = 'non-scalar status'; StatusValue = @('persisted', 'status-canary') }
    ) {
        $check = New-PulseEvaluationCheckFixture
        $entry = New-PulsePartialEntryFixture
        $entry.status = $StatusValue
        $entry.reason = 'persisted-reason-canary'

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            function Test-PulsePartialAwareFixtureRule {
                param($Datasets, $DatasetOutcomes)
                throw 'rule-must-not-run-canary'
            }
            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } -DatasetCache @{}
        }

        $result.Status | Should -Be 'NotApplicable'
        $result.Reason | Should -BeExactly "dataset 'partialA' has an unsupported collection status."
        $result.Reason | Should -Not -Match 'persisted-status-canary|persisted-reason-canary|System\.Object|rule-must-not-run-canary'
    }

    It 'passes usable Partial rows and an exact independently projected outcome for every declared dataset' {
        $check = New-PulseEvaluationCheckFixture -Datasets @('partialA', 'collectedB')
        $partial = New-PulsePartialEntryFixture
        $collected = New-PulsePartialEntryFixture -Status Collected -Gaps @()
        $collected.reasonCode = 'collected'
        $collected.failureClass = $null

        $result = InModuleScope TenantPulse -ArgumentList $check, $partial, $collected {
            param($check, $partial, $collected)
            function Test-PulsePartialAwareFixtureRule {
                param($Datasets, $DatasetOutcomes)

                $expectedKeys = @('Status', 'FailureClass', 'ReasonCode', 'Detail', 'Provider', 'ApiVersion', 'Operations', 'Gaps')
                $actualA = @($DatasetOutcomes.partialA.Keys)
                $actualB = @($DatasetOutcomes.collectedB.Keys)
                $rootKeys = @($DatasetOutcomes.Keys)
                $forbidden = @('reason', 'sha256', 'itemCount', 'collectedUtc') |
                    Where-Object { $DatasetOutcomes.partialA.ContainsKey($_) -or $DatasetOutcomes.collectedB.ContainsKey($_) }
                $ok = $Datasets.partialA.Count -eq 1 -and
                    $Datasets.collectedB.Count -eq 1 -and
                    $rootKeys.Count -eq 2 -and $rootKeys -contains 'collectedB' -and $rootKeys -contains 'partialA' -and
                    $actualA.Count -eq 8 -and @($expectedKeys | Where-Object { $actualA -cnotcontains $_ }).Count -eq 0 -and
                    $actualB.Count -eq 8 -and @($expectedKeys | Where-Object { $actualB -cnotcontains $_ }).Count -eq 0 -and
                    $DatasetOutcomes.partialA.Status -eq 'Partial' -and
                    $DatasetOutcomes.collectedB.Status -eq 'Collected' -and
                    @($DatasetOutcomes.partialA.Gaps).Count -eq 1 -and
                    @($forbidden).Count -eq 0
                New-PulseFinding -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
                    -Reason "root=$($rootKeys -join ',');a=$($actualA -join ',');b=$($actualB -join ',');forbidden=$($forbidden -join ',')"
            }

            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $partial; collectedB = $collected } } `
                -DatasetCache @{
                    partialA   = @([pscustomobject]@{ id = 'row-a' })
                    collectedB = @([pscustomobject]@{ id = 'row-b' })
                }
        }

        $result.Status | Should -Be 'Pass' -Because $result.Reason
    }

    It 'supports the four independent Function invocation combinations' {
        $result = InModuleScope TenantPulse {
            $collected = [ordered]@{
                status = 'Collected'; failureClass = $null; reasonCode = 'collected'; detail = @{}
                provider = 'GraphKit'; apiVersion = 'v1.0'; operations = @('List'); gaps = @()
                reason = $null; sha256 = 'hash'; itemCount = 1; collectedUtc = '2026-08-30T00:00:00.000Z'
            }
            $partial = [ordered]@{
                status = 'Partial'; failureClass = $null; reasonCode = 'partial'; detail = @{}
                provider = 'GraphKit'; apiVersion = 'beta'; operations = @('List')
                gaps = @([pscustomobject][ordered]@{
                    Scope = 'scope'; FailureClass = 'ProviderFailed'; ReasonCode = 'provider-failed'
                    Detail = @{}; Operation = 'List'; ApiVersion = 'beta'
                })
                reason = $null; sha256 = 'hash'; itemCount = 1; collectedUtc = '2026-08-30T00:00:00.000Z'
            }
            function Test-PulseDatasetsOnly { param($Datasets) New-PulseFinding -Status $(if ($Datasets.collectedA.Count -eq 1) { 'Pass' } else { 'Fail' }) }
            function Test-PulseDatasetsContext { param($Datasets, $Context) New-PulseFinding -Status $(if ($Context.Marker -eq 'context') { 'Pass' } else { 'Fail' }) }
            function Test-PulseDatasetsOutcomes { param($Datasets, $DatasetOutcomes) New-PulseFinding -Status $(if ($DatasetOutcomes.partialA.Status -eq 'Partial') { 'Pass' } else { 'Fail' }) }
            function Test-PulseAllInputs { param($Datasets, $Context, $DatasetOutcomes) New-PulseFinding -Status $(if ($Datasets.partialA.Count -eq 1 -and $Context.Marker -eq 'context' -and $DatasetOutcomes.partialA.Status -eq 'Partial') { 'Pass' } else { 'Fail' }) }

            $baseData = @{ Datasets = @('collectedA'); Gates = @() }
            $partialData = @{ Datasets = @('partialA'); PartialDatasets = @('partialA'); Gates = @() }
            $manifest = @{ datasets = @{ collectedA = $collected; partialA = $partial } }
            $cache = @{ collectedA = @([pscustomobject]@{ id = 'c' }); partialA = @([pscustomobject]@{ id = 'p' }) }
            $checks = @(
                [pscustomobject]@{ Data = $baseData; Rule = @{ Type = 'Function'; Function = 'Test-PulseDatasetsOnly' } }
                [pscustomobject]@{ Data = $baseData; Rule = @{ Type = 'Function'; Function = 'Test-PulseDatasetsContext' } }
                [pscustomobject]@{ Data = $partialData; Rule = @{ Type = 'Function'; Function = 'Test-PulseDatasetsOutcomes' } }
                [pscustomobject]@{ Data = $partialData; Rule = @{ Type = 'Function'; Function = 'Test-PulseAllInputs' } }
            )
            @($checks | ForEach-Object {
                (Invoke-PulseCheckEvaluation -Check $_ -Store ([pscustomobject]@{}) -Manifest $manifest `
                    -DatasetCache $cache -Context @{ Marker = 'context' }).Status
            })
        }

        $result | Should -Be @('Pass', 'Pass', 'Pass', 'Pass')
    }

    It 'does not pass DatasetOutcomes merely because a legacy rule declares a compatible optional parameter' {
        $check = New-PulseEvaluationCheckFixture -PartialDatasets $null -RuleFunction 'Test-PulseUnawareOutcomeParamRule'
        $entry = New-PulsePartialEntryFixture -Status Collected -Gaps @()
        $entry.reasonCode = 'collected'

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            function Test-PulseUnawareOutcomeParamRule {
                param($Datasets, $DatasetOutcomes)
                New-PulseFinding -Status $(if ($PSBoundParameters.ContainsKey('DatasetOutcomes')) { 'Fail' } else { 'Pass' })
            }
            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache @{ partialA = @([pscustomobject]@{ id = 'row-1' }) }
        }

        $result.Status | Should -Be 'Pass'
    }

    It 'returns Error for invalid opted-in Partial state: <Case>' -ForEach @(
        @{ Case = 'zero usable rows'; Kind = 'zero-rows' }
        @{ Case = 'absent gaps'; Kind = 'absent-gaps' }
        @{ Case = 'empty gaps'; Kind = 'empty-gaps' }
        @{ Case = 'null-containing gaps'; Kind = 'null-gap' }
        @{ Case = 'missing gap property'; Kind = 'missing-property' }
        @{ Case = 'blank gap operation'; Kind = 'blank-operation' }
        @{ Case = 'unsupported gap failure'; Kind = 'unsupported-failure' }
        @{ Case = 'non-hashtable gap detail'; Kind = 'bad-detail' }
    ) {
        $check = New-PulseEvaluationCheckFixture
        $Rows = @([pscustomobject]@{ id = 'row-1' })
        $Gaps = @((New-PulsePartialGapFixture))
        switch ($Kind) {
            'zero-rows'           { $Rows = @() }
            'absent-gaps'         { $Gaps = $null }
            'empty-gaps'          { $Gaps = @() }
            'null-gap'            { $Gaps = @($null) }
            'missing-property'    { $Gaps = @([pscustomobject][ordered]@{ Scope = 'scope' }) }
            'blank-operation'     { $Gaps = @((New-PulsePartialGapFixture -Operation '')) }
            'unsupported-failure' { $Gaps = @((New-PulsePartialGapFixture -FailureClass 'UnknownFailure')) }
            'bad-detail'          { $Gaps = @((New-PulsePartialGapFixture -Detail 'gap-detail-canary')) }
        }
        $entry = New-PulsePartialEntryFixture -Gaps $Gaps

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry, $Rows {
            param($check, $entry, $rows)
            function Test-PulsePartialAwareFixtureRule {
                param($Datasets, $DatasetOutcomes)
                New-PulseFinding -Status Pass
            }
            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } -DatasetCache @{ partialA = $rows }
        }

        $result.Status | Should -Be 'Error'
        $result.Reason | Should -Not -Match 'manifest-reason-canary|manifest-detail-canary|gap-detail-canary|provider-detail-canary|scope-safe|Child\.List'
    }

    It 'fails closed before rule invocation for malformed persisted Partial gap shape: <Case>' -ForEach @(
        @{ Case = 'scalar Gaps'; Field = $null }
        @{ Case = 'Int64 Scope'; Field = 'Scope' }
        @{ Case = 'Int64 ReasonCode'; Field = 'ReasonCode' }
        @{ Case = 'Int64 Operation'; Field = 'Operation' }
        @{ Case = 'Int64 ApiVersion'; Field = 'ApiVersion' }
    ) {
        $check = New-PulseEvaluationCheckFixture
        $entry = New-PulsePartialEntryFixture
        if ($null -eq $Field) {
            $entry.gaps = $entry.gaps[0]
        } else {
            $entry.gaps[0].$Field = [long] 7
        }

        $observed = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            $script:PulseMalformedGapRuleInvoked = $false
            function Test-PulsePartialAwareFixtureRule {
                param($Datasets, $DatasetOutcomes)
                $script:PulseMalformedGapRuleInvoked = $true
                New-PulseFinding -Status Pass
            }

            $evaluation = Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache @{ partialA = @([pscustomobject]@{ id = 'row-1' }) }
            [pscustomobject]@{
                Evaluation = $evaluation
                RuleInvoked = $script:PulseMalformedGapRuleInvoked
            }
        }

        $observed.Evaluation.Status | Should -Be 'Error'
        $observed.RuleInvoked | Should -BeFalse
        $observed.Evaluation.Reason | Should -Not -Match 'manifest-reason-canary|manifest-detail-canary|gap-detail-canary|provider-detail-canary|scope-safe|Child\.List'
    }

    It 'fails closed before rule invocation when a Partial dataset contains only one null row' {
        $check = New-PulseEvaluationCheckFixture
        $entry = New-PulsePartialEntryFixture

        $observed = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            $script:PulseNullOnlyRuleInvoked = $false
            function Test-PulsePartialAwareFixtureRule {
                param($Datasets, $DatasetOutcomes)
                $script:PulseNullOnlyRuleInvoked = $true
                New-PulseFinding -Status Pass
            }
            $nullOnlyRows = [object[]]::new(1)

            $evaluation = Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache @{ partialA = $nullOnlyRows }
            [pscustomobject]@{
                Evaluation = $evaluation
                RuleInvoked = $script:PulseNullOnlyRuleInvoked
            }
        }

        $observed.Evaluation.Status | Should -Be 'Error'
        $observed.RuleInvoked | Should -BeFalse
    }

    It 'removes null elements from mixed Partial rows before the rule receives its clone' {
        $check = New-PulseEvaluationCheckFixture
        $entry = New-PulsePartialEntryFixture

        $observed = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            function Test-PulsePartialAwareFixtureRule {
                param($Datasets, $DatasetOutcomes)
                $rows = @($Datasets.partialA)
                $isUsable = $rows.Count -eq 1 -and $null -ne $rows[0] -and $rows[0].id -eq 'row-1'
                New-PulseFinding -Status $(if ($isUsable) { 'Pass' } else { 'Fail' })
            }
            $mixedRows = [object[]]::new(2)
            $mixedRows[1] = [pscustomobject]@{ id = 'row-1' }
            $cache = @{ partialA = $mixedRows }

            $evaluation = Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache $cache
            [pscustomobject]@{
                Evaluation = $evaluation
                CachedRows = $cache.partialA
            }
        }

        $observed.Evaluation.Status | Should -Be 'Pass'
        @($observed.CachedRows).Count | Should -Be 2
        $observed.CachedRows[0] | Should -BeNullOrEmpty
        $observed.CachedRows[1].id | Should -Be 'row-1'
    }

    It 'projects canonical gap objects rather than raw manifest objects with extra keys' {
        $check = New-PulseEvaluationCheckFixture
        $entry = New-PulsePartialEntryFixture
        $entry.gaps[0].PSObject.Properties.Add(
            [System.Management.Automation.PSNoteProperty]::new('PrivateGapCanary', 'must-not-reach-rule')
        )

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            function Test-PulsePartialAwareFixtureRule {
                param($Datasets, $DatasetOutcomes)
                $expected = @('Scope', 'FailureClass', 'ReasonCode', 'Detail', 'Operation', 'ApiVersion')
                $actual = @($DatasetOutcomes.partialA.Gaps[0].Keys)
                $isCanonical = $actual.Count -eq $expected.Count -and
                    @($expected | Where-Object { $actual -cnotcontains $_ }).Count -eq 0
                New-PulseFinding -Status $(if ($isCanonical) { 'Pass' } else { 'Fail' })
            }

            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache @{ partialA = @([pscustomobject]@{ id = 'row-1' }) }
        }

        $result.Status | Should -Be 'Pass'
        $result.Reason | Should -Not -Match 'must-not-reach-rule'
    }

    It 'returns a bounded Error when dataset-row cloning fails' {
        $check = New-PulseEvaluationCheckFixture
        $entry = New-PulsePartialEntryFixture

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            function Test-PulsePartialAwareFixtureRule { param($Datasets, $DatasetOutcomes) New-PulseFinding -Status Pass }
            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache @{ partialA = @([pscustomobject]@{ value = [double]::NaN }) }
        }

        $result.Status | Should -Be 'Error'
        $result.Reason | Should -Not -Match 'NaN|manifest-reason-canary|gap-detail-canary'
    }

    It 'returns a bounded Error when the outcome projection cannot be cloned' {
        $check = New-PulseEvaluationCheckFixture
        $entry = New-PulsePartialEntryFixture -Operations @([double]::NaN)

        $result = InModuleScope TenantPulse -ArgumentList $check, $entry {
            param($check, $entry)
            function Test-PulsePartialAwareFixtureRule { param($Datasets, $DatasetOutcomes) New-PulseFinding -Status Pass }
            Invoke-PulseCheckEvaluation -Check $check -Store ([pscustomobject]@{}) `
                -Manifest @{ datasets = @{ partialA = $entry } } `
                -DatasetCache @{ partialA = @([pscustomobject]@{ id = 'row-1' }) }
        }

        $result.Status | Should -Be 'Error'
        $result.Reason | Should -Not -Match 'NaN|manifest-reason-canary|gap-detail-canary'
    }
}
