BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Publish-PulseConflictArtifact' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes NotExpanded with a reason when zero families are available' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $result = Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps @() -FamilyCount 0
            $result.Status | Should -Be 'NotExpanded'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.conflicts.status | Should -Be 'NotExpanded'
        $manifest.expansions.conflicts.reason | Should -Match 'no expansion families'
    }

    It 'zero conflicts from >=1 available family is a valid Expanded outcome, format json' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $result = Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps @() -FamilyCount 1
            $result.Status | Should -Be 'Expanded'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.conflicts.status | Should -Be 'Expanded'
        $manifest.expansions.conflicts.format | Should -Be 'json'
        $manifest.expansions.conflicts.rowCount | Should -Be 0

        $filePath = Join-Path $script:store.Root $manifest.expansions.conflicts.path
        $content = Get-Content -LiteralPath $filePath -Raw | ConvertFrom-Json
        $content.conflicts.Count | Should -Be 0
    }

    It 'writes Partial with gaps when a family was unavailable' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $gaps = @([pscustomobject]@{ policyId = ''; reason = 'category:FamilyUnavailable;family:compliance' })
            $result = Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps $gaps -FamilyCount 1
            $result.Status | Should -Be 'Partial'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.conflicts.status | Should -Be 'Partial'
        $manifest.expansions.conflicts.gaps.Count | Should -Be 1
    }

    It 'is deterministic: identical conflicts input produces byte-identical sha256 across two publishes' {
        $sha1 = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $conflicts = @([pscustomobject]@{ settingDefinitionId = 'def-1'; settingName = 'a'; assignmentOverlap = 'proven'; assignmentOverlapReason = $null; values = @() })
            Publish-PulseConflictArtifact -Store $store -Conflicts $conflicts -Gaps @() -FamilyCount 1 | Out-Null
            (Get-PulseSnapshotManifest -Store $store).expansions.conflicts.sha256
        }

        $storeRoot2 = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $store2 = InModuleScope TenantPulse -ArgumentList $storeRoot2 { param($r) New-PulseSnapshotStore -Path $r }
        $sha2 = InModuleScope TenantPulse -ArgumentList $store2 {
            param($store)
            $conflicts = @([pscustomobject]@{ settingDefinitionId = 'def-1'; settingName = 'a'; assignmentOverlap = 'proven'; assignmentOverlapReason = $null; values = @() })
            Publish-PulseConflictArtifact -Store $store -Conflicts $conflicts -Gaps @() -FamilyCount 1 | Out-Null
            (Get-PulseSnapshotManifest -Store $store).expansions.conflicts.sha256
        }
        Remove-Item -LiteralPath $storeRoot2 -Recurse -Force -ErrorAction SilentlyContinue

        $sha1 | Should -Be $sha2
    }

    It 'never writes the redaction sentinel to disk when a redacted conflict group is published' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $conflicts = @([pscustomobject]@{
                    settingDefinitionId     = 'def-1'
                    settingName             = 'secretSetting'
                    assignmentOverlap       = 'unknown'
                    assignmentOverlapReason = 'assignments-deferred: awaiting GraphKit release'
                    values                  = @(
                        [pscustomobject]@{ canonicalValue = $null; redacted = $true; policies = @([pscustomobject]@{ policyId = 'p1'; policyName = 'P1' }) },
                        [pscustomobject]@{ canonicalValue = 'plain'; redacted = $false; policies = @([pscustomobject]@{ policyId = 'p2'; policyName = 'P2' }) }
                    )
                })
            Publish-PulseConflictArtifact -Store $store -Conflicts $conflicts -Gaps @() -FamilyCount 1
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $filePath = Join-Path $script:store.Root $manifest.expansions.conflicts.path
        $rawText = Get-Content -LiteralPath $filePath -Raw
        $rawText | Should -Not -Match 'REDACTED-SETTING-VALUE'
        $rawText | Should -Match 'plain'
    }
}
