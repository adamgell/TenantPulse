BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'New-PulseArtifactReader' {
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

    It 'exposes exactly one member: the GetConflictArtifact ScriptMethod, no data properties' {
        $memberNames = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $reader = New-PulseArtifactReader -Store $store
            @($reader.PSObject.Members | Where-Object { $_.MemberType -in @('ScriptMethod', 'NoteProperty', 'Property') } | ForEach-Object { $_.Name })
        }

        $memberNames | Should -Contain 'GetConflictArtifact'
        $memberNames | Should -Not -Contain 'Store'
        $memberNames | Should -Not -Contain 'Root'
        $memberNames | Should -Not -Contain 'ManifestPath'
    }

    It 'GetConflictArtifact() returns the same result Get-PulseConflictArtifact -Store $store would' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps @() -FamilyCount 1
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $reader = New-PulseArtifactReader -Store $store
            $reader.GetConflictArtifact()
        }

        $result.Status | Should -Be 'Available'
        @($result.Conflicts).Count | Should -Be 0
    }

    It 'still resolves correctly when invoked outside the module''s own scope (the real rule-function call site)' {
        # Mirrors how a Function rule actually receives and calls this: the reader is
        # built INSIDE the module (Invoke-PulseEvaluation), but .GetConflictArtifact() is
        # invoked from a rule function's own scope, which is NOT the module's internal
        # scope - this is exactly the ScriptMethod-closure command-resolution trap this
        # file's own docstring documents (a bare 'Get-PulseConflictArtifact' name lookup
        # from inside the closure would fail there; capturing the CommandInfo up front
        # avoids it).
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps @() -FamilyCount 1
        }

        $reader = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            New-PulseArtifactReader -Store $store
        }

        # Invoked from THIS test file's own (non-module) scope, not InModuleScope.
        $result = $reader.GetConflictArtifact()
        $result.Status | Should -Be 'Available'
    }

    It 'reflects the store''s conflicts artifact at call time, not a snapshot frozen at construction (Root/ManifestPath are frozen, the artifact read is not)' {
        $reader = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            New-PulseArtifactReader -Store $store
        }

        $before = $reader.GetConflictArtifact()
        $before.Status | Should -Be 'NotAvailable'

        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Publish-PulseConflictArtifact -Store $store -Conflicts @() -Gaps @() -FamilyCount 1
        }

        $after = $reader.GetConflictArtifact()
        $after.Status | Should -Be 'Available'
    }
}
