BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:New-PulseConflictRecordFixture {
        param(
            [string] $DefinitionId,
            [string] $Overlap,
            [string] $OverlapReason = $null
        )
        [pscustomobject]@{
            settingDefinitionId     = $DefinitionId
            settingName             = "Setting for $DefinitionId"
            nameVariants            = $null
            assignmentOverlap       = $Overlap
            assignmentOverlapReason = $OverlapReason
            values                  = @(
                [pscustomobject]@{ canonicalValue = 'value-a'; redacted = $false; policies = @([pscustomobject]@{ policyId = 'policy-a'; policyName = 'Policy A' }) }
                [pscustomobject]@{ canonicalValue = 'value-b'; redacted = $false; policies = @([pscustomobject]@{ policyId = 'policy-b'; policyName = 'Policy B' }) }
            )
        }
    }

    # Fixture builder: real store functions throughout (New-PulseSnapshotStore,
    # Write-PulseDataset, Publish-PulseConflictArtifact) - only the CONFLICT RECORDS
    # themselves are hand-authored fixture data, matching this task's own
    # "snapshots built via real store functions" requirement. -Conflicts $null means
    # "never publish a conflicts expansion entry at all" (the NotApplicable/no-artifact
    # fixture); an empty array (not $null) publishes a real zero-conflict 'Expanded' entry.
    function script:Invoke-PulseConflictCheckFixture {
        param(
            [AllowNull()]
            [object[]] $Conflicts,
            [switch] $DatasetCollected = $true
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $Conflicts, ([bool] $DatasetCollected) {
                param($storeRoot, $keyPath, $conflicts, $datasetCollected)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0006' }
                if (-not $check) { throw "fixture setup: check 'TP.INT.0006' not found in the catalog." }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'

                if ($datasetCollected) {
                    Write-PulseDataset -Store $store -Name 'configurationPolicies' -ApiVersion 'beta' -Status 'Collected' -Data @()
                } else {
                    Write-PulseDataset -Store $store -Name 'configurationPolicies' -ApiVersion 'beta' -Status 'Failed' -Reason 'throttled: too many requests'
                }

                if ($null -ne $conflicts) {
                    Publish-PulseConflictArtifact -Store $store -Conflicts $conflicts -Gaps @() -FamilyCount 1
                }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP.INT.0006 - Conflicting security-setting values across policies' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0006' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: zero conflicts in a real Expanded conflicts artifact' {
        $finding = Invoke-PulseConflictCheckFixture -Conflicts @()

        $finding.status | Should -Be 'Pass'
        @($finding.evidence).Count | Should -Be 0
        $finding.reason | Should -Match 'No conflicting'
    }

    It 'Warn: conflicts exist but every one has overlap unknown (deferred-assignments state)' {
        $conflicts = @(
            (New-PulseConflictRecordFixture -DefinitionId 'def-unknown-1' -Overlap 'unknown' -OverlapReason 'assignments-deferred: awaiting GraphKit release')
            (New-PulseConflictRecordFixture -DefinitionId 'def-unknown-2' -Overlap 'unknown' -OverlapReason 'assignments-deferred: awaiting GraphKit release')
        )

        $finding = Invoke-PulseConflictCheckFixture -Conflicts $conflicts

        $finding.status | Should -Be 'Warn'
        @($finding.evidence).Count | Should -Be 2
        $finding.reason | Should -Match 'could not be determined'
        ($finding.evidence | Where-Object { $_.identity -eq 'def-unknown-1' }) | Should -Not -BeNullOrEmpty
    }

    It 'Warn: conflicts mixing unknown and none, with no proven/possible present, still degrades to Warn (never a silent Pass)' {
        $conflicts = @(
            (New-PulseConflictRecordFixture -DefinitionId 'def-none-1' -Overlap 'none')
            (New-PulseConflictRecordFixture -DefinitionId 'def-unknown-1' -Overlap 'unknown' -OverlapReason 'assignments-deferred: awaiting GraphKit release')
        )

        $finding = Invoke-PulseConflictCheckFixture -Conflicts $conflicts

        $finding.status | Should -Be 'Warn'
        @($finding.evidence).Count | Should -Be 2
    }

    It 'Fail: a mix of possible/none/unknown conflicts, driven by the possible ones (mirrors the live Ivy24 shape)' {
        $conflicts = @(
            (New-PulseConflictRecordFixture -DefinitionId 'def-possible-1' -Overlap 'possible')
            (New-PulseConflictRecordFixture -DefinitionId 'def-none-1' -Overlap 'none')
            (New-PulseConflictRecordFixture -DefinitionId 'def-unknown-1' -Overlap 'unknown' -OverlapReason 'assignments-deferred: awaiting GraphKit release')
        )

        $finding = Invoke-PulseConflictCheckFixture -Conflicts $conflicts

        $finding.status | Should -Be 'Fail'
        @($finding.evidence).Count | Should -Be 3
        $finding.reason | Should -Match '0 proven, 1 possible, 1 unknown, 1 none' -Because 'reason wording sanity - actual counts below assert the real numbers'
    }

    It 'Fail: a proven conflict alone is sufficient to drive Fail' {
        $conflicts = @((New-PulseConflictRecordFixture -DefinitionId 'def-proven-1' -Overlap 'proven'))

        $finding = Invoke-PulseConflictCheckFixture -Conflicts $conflicts

        $finding.status | Should -Be 'Fail'
    }

    It 'Fail: evidence carries the full four-state detail per conflict (settingName, values, assignmentOverlap)' {
        $conflicts = @((New-PulseConflictRecordFixture -DefinitionId 'def-possible-1' -Overlap 'possible'))

        $finding = Invoke-PulseConflictCheckFixture -Conflicts $conflicts

        $entry = $finding.evidence[0]
        $entry.identity | Should -Be 'def-possible-1'
        $entry.detail.settingName | Should -Be 'Setting for def-possible-1'
        $entry.detail.assignmentOverlap | Should -Be 'possible'
        @($entry.detail.values).Count | Should -Be 2
    }

    It 'NotApplicable: no conflicts expansion entry at all (expansion was never run for this snapshot)' {
        $finding = Invoke-PulseConflictCheckFixture -Conflicts $null

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'expansions.conflicts'
        @($finding.evidence).Count | Should -Be 0
    }

    It 'produces the identical status, reason and evidence count across two evaluations of the SAME snapshot (determinism)' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $conflictFixture = New-PulseConflictRecordFixture -DefinitionId 'def-possible-1' -Overlap 'possible'

            $results = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $conflictFixture {
                param($storeRoot, $keyPath, $conflictFixture)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq 'TP.INT.0006' }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
                Write-PulseDataset -Store $store -Name 'configurationPolicies' -ApiVersion 'beta' -Status 'Collected' -Data @()
                Publish-PulseConflictArtifact -Store $store -Conflicts @($conflictFixture) -Gaps @() -FamilyCount 1

                $first = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
                $second = Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath

                [pscustomobject]@{ First = $first.Document.findings[0]; Second = $second.Document.findings[0] }
            }

            $results.Second.status | Should -Be $results.First.status
            $results.Second.reason | Should -Be $results.First.reason
            @($results.Second.evidence).Count | Should -Be @($results.First.evidence).Count
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
