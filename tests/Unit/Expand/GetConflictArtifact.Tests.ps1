BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Get-PulseConflictArtifact' {
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

    It 'NotAvailable, with reason, when the manifest has no expansions.conflicts entry at all' {
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Get-PulseConflictArtifact -Store $store
        }

        $result.Status | Should -Be 'NotAvailable'
        $result.Reason | Should -Match 'no expansions.conflicts entry'
        @($result.Conflicts).Count | Should -Be 0
    }

    It 'NotAvailable, quoting the entry''s own reason verbatim, when the entry is NotExpanded' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps @() -FamilyCount 0
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Get-PulseConflictArtifact -Store $store
        }

        $result.Status | Should -Be 'NotAvailable'
        $result.Reason | Should -Be 'no expansion families available for conflict detection'
    }

    It 'Available with an empty Conflicts array for a real zero-conflict Expanded artifact' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps @() -FamilyCount 1
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Get-PulseConflictArtifact -Store $store
        }

        $result.Status | Should -Be 'Available'
        @($result.Conflicts).Count | Should -Be 0
    }

    It 'Available and returns the parsed conflicts array for a real non-empty Expanded artifact' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $conflicts = @([pscustomobject]@{
                    settingDefinitionId     = 'def-1'
                    settingName             = 'Some Setting'
                    nameVariants            = $null
                    assignmentOverlap       = 'proven'
                    assignmentOverlapReason = $null
                    values                  = @(
                        [pscustomobject]@{ canonicalValue = 'a'; redacted = $false; policies = @([pscustomobject]@{ policyId = 'p1'; policyName = 'P1' }) }
                        [pscustomobject]@{ canonicalValue = 'b'; redacted = $false; policies = @([pscustomobject]@{ policyId = 'p2'; policyName = 'P2' }) }
                    )
                })
            Publish-PulseConflictArtifact -Store $store -Conflicts $conflicts -Gaps @() -FamilyCount 1
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Get-PulseConflictArtifact -Store $store
        }

        $result.Status | Should -Be 'Available'
        @($result.Conflicts).Count | Should -Be 1
        $result.Conflicts[0].settingDefinitionId | Should -Be 'def-1'
        $result.Conflicts[0].assignmentOverlap | Should -Be 'proven'
    }

    It 'throws on a hash mismatch rather than silently reading tampered data' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps @() -FamilyCount 1
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $filePath = Join-Path $script:store.Root $manifest.expansions.conflicts.path
        Set-Content -LiteralPath $filePath -Value '{"schemaVersion":"1","conflicts":[]}TAMPERED' -NoNewline -Encoding utf8

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Get-PulseConflictArtifact -Store $store
            }
        } | Should -Throw '*hash mismatch*'
    }

    It 'throws when the manifest records Expanded but the file itself is missing' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps @() -FamilyCount 1
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $filePath = Join-Path $script:store.Root $manifest.expansions.conflicts.path
        Remove-Item -LiteralPath $filePath -Force

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Get-PulseConflictArtifact -Store $store
            }
        } | Should -Throw '*missing from the snapshot store*'
    }
}
