<#
    Part A, T3.4 - the per-family setting-presence index. Covers the pure transform
    (ConvertTo-PulseSettingPresenceIndex), the driver (Invoke-PulseSettingPresenceIndexBuild),
    the reader (Get-PulseSettingPresenceIndex), the -FromSnapshot re-derivation wiring
    (Resolve-PulseSettingPresenceIndexSnapshotExpansion), and the ArtifactReader accessor
    (New-PulseArtifactReader's GetSettingPresenceIndex()) - mirroring the established
    conflicts-artifact test suite's own coverage shape (ConflictDetection.Tests.ps1,
    ConflictDetectionPipeline.Tests.ps1, GetConflictArtifact.Tests.ps1) end to end.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:New-PulseFixtureRow {
        param(
            [string] $PolicyId,
            [string] $PolicyType,
            [string] $DefId,
            [string] $SettingName = $DefId,
            $Value = 'v',
            [bool] $Redacted = $false,
            [AllowNull()] [object[]] $Assignments = @()
        )
        [pscustomobject]@{
            schemaVersion = '1'; policyId = $PolicyId; policyType = $PolicyType; policyName = "Policy-$PolicyId"
            templateFamily = $null; isBaseline = $false; settingPath = $DefId; settingDefinitionId = $DefId
            settingName = $SettingName; nameResolved = $true; instanceId = "$PolicyId/p:$DefId"; value = $Value
            valueLabel = $null; labelResolved = $false; redacted = $Redacted; valueState = $null; applicability = $null
            assignments = $Assignments
        }
    }
}

Describe 'ConvertTo-PulseSettingPresenceIndex' {
    It 'groups one setting present in two policies of the same family under one defId entry, with a per-value breakdown' {
        $rows = @(
            (New-PulseFixtureRow -PolicyId 'p1' -PolicyType 'compliance' -DefId 'def-a' -Value 'on' -Assignments @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null }))
            (New-PulseFixtureRow -PolicyId 'p2' -PolicyType 'compliance' -DefId 'def-a' -Value 'off' -Assignments @())
        )
        $result = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseSettingPresenceIndex -Rows $rows
        }

        $entry = $result.compliance['def-a']
        $entry.presentPolicyCount | Should -Be 2
        $entry.anyPresent | Should -BeTrue
        $entry.values.Count | Should -Be 2
        ($entry.values | Where-Object { $_.canonicalValue -eq 'on' }).policyCount | Should -Be 1
        ($entry.values | Where-Object { $_.canonicalValue -eq 'off' }).policyCount | Should -Be 1
    }

    It 'REDACTION DISCIPLINE: a Sensitive/secret-classified row is presence-only - the value group carries redacted:true and canonicalValue:$null, never the raw value (T3.4 fix round 1, IMPORTANT finding - the planted secret is now genuinely present in the row''s own -Value field, not pre-nulled by the fixture, so this test actually exercises the function''s OWN redaction discipline rather than trusting an upstream contract)' {
        $plantedSecret = 'PLANTED-presence-index-secret-zzz'
        $nonSecretDisplayName = 'WiFi Pre-Shared Key Setting'
        $rows = @(
            # HOSTILE ROW: -Value carries the secret DESPITE -Redacted being $true -
            # simulating a malformed/buggy upstream row (a real production row would
            # already carry value:$null per T2.2/T2.3's own row-level contract, but THIS
            # test must not rely on that upstream discipline to prove ITS OWN - a fail-
            # closed function must discard the raw value whenever redacted:true is set,
            # regardless of what garbage happens to still be sitting in .value).
            # settingName carries an ORDINARY (non-secret) display name here, deliberately
            # DIFFERENT from $plantedSecret - settingName is legitimate pass-through
            # metadata, never itself redacted, so asserting it survives is a distinct,
            # non-vacuous check from "the secret VALUE never leaks."
            (New-PulseFixtureRow -PolicyId 'p1' -PolicyType 'deviceConfiguration' -DefId 'secret-def' -SettingName $nonSecretDisplayName -Value $plantedSecret -Redacted $true -Assignments @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null }))
        )
        $result = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseSettingPresenceIndex -Rows $rows
        }

        $entry = $result.deviceConfiguration['secret-def']
        $entry.anyPresent | Should -BeTrue
        $entry.presentPolicyCount | Should -Be 1
        $entry.values.Count | Should -Be 1
        $entry.values[0].redacted | Should -BeTrue
        $entry.values[0].canonicalValue | Should -BeNullOrEmpty
        # Ordinary, non-secret metadata (settingName) DOES survive - proving redaction is
        # surgical (the value group's canonicalValue only), not a blanket wipe of the
        # whole entry.
        $entry.settingName | Should -Be $nonSecretDisplayName

        $serialized = InModuleScope TenantPulse -ArgumentList $result { param($r) ConvertTo-PulseCanonicalJson -InputObject $r }
        # The raw secret VALUE never appears anywhere in the serialized artifact - proven
        # now against a row that genuinely carried the secret in its own -Value field
        # (not a pre-nulled one), so this assertion is no longer vacuous.
        $serialized | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'a redacted-secret value group and a genuinely null (non-secret) value group never collapse into the same bucket' {
        $rows = @(
            (New-PulseFixtureRow -PolicyId 'p1' -PolicyType 'compliance' -DefId 'def-a' -Value $null -Redacted $false)
            (New-PulseFixtureRow -PolicyId 'p2' -PolicyType 'compliance' -DefId 'def-a' -Value $null -Redacted $true)
        )
        $result = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseSettingPresenceIndex -Rows $rows
        }

        $entry = $result.compliance['def-a']
        $entry.values.Count | Should -Be 2
        $entry.presentPolicyCount | Should -Be 2
        (@($entry.values | Where-Object { -not $_.redacted })).Count | Should -Be 1
        (@($entry.values | Where-Object { $_.redacted })).Count | Should -Be 1
    }

    It 'ASSIGNMENT CLASSIFICATION: null assignments (deferred) -> Unknown, empty array -> NotAssigned, non-empty -> Assigned' {
        $rows = @(
            (New-PulseFixtureRow -PolicyId 'p-unknown' -PolicyType 'settingsCatalog' -DefId 'def-a' -Assignments $null)
            (New-PulseFixtureRow -PolicyId 'p-notassigned' -PolicyType 'settingsCatalog' -DefId 'def-a' -Assignments @())
            (New-PulseFixtureRow -PolicyId 'p-assigned' -PolicyType 'settingsCatalog' -DefId 'def-a' -Assignments @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null }))
        )
        $result = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseSettingPresenceIndex -Rows $rows
        }

        $entry = $result.settingsCatalog['def-a']
        $entry.presentPolicyCount | Should -Be 3
        $entry.assignedPolicyCount | Should -Be 1
        $entry.unknownAssignmentPolicyCount | Should -Be 1
        $entry.anyAssigned | Should -BeTrue
        $entry.anyUnknownAssignment | Should -BeTrue
    }

    It 'a setting present ONLY in policies with deferred (null) assignments reports anyAssigned:$false, anyUnknownAssignment:$true - answers "is X present in ANY ASSIGNED policy" honestly' {
        $rows = @(New-PulseFixtureRow -PolicyId 'p1' -PolicyType 'settingsCatalog' -DefId 'def-deferred' -Assignments $null)
        $result = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseSettingPresenceIndex -Rows $rows
        }

        $entry = $result.settingsCatalog['def-deferred']
        $entry.anyPresent | Should -BeTrue
        $entry.anyAssigned | Should -BeFalse
        $entry.anyUnknownAssignment | Should -BeTrue
    }

    It 'DETERMINISM: byte-identical canonical JSON regardless of input row order' {
        $rowsA = @(
            (New-PulseFixtureRow -PolicyId 'p1' -PolicyType 'compliance' -DefId 'def-a' -Value 'x' -SettingName 'Name1')
            (New-PulseFixtureRow -PolicyId 'p2' -PolicyType 'compliance' -DefId 'def-a' -Value 'y' -SettingName 'Name2')
            (New-PulseFixtureRow -PolicyId 'p3' -PolicyType 'deviceConfiguration' -DefId 'def-b' -Value 'z')
        )
        $rowsB = @($rowsA[2], $rowsA[0], $rowsA[1])

        $jsonA = InModuleScope TenantPulse -ArgumentList (, $rowsA) {
            param($rows)
            ConvertTo-PulseCanonicalJson -InputObject (ConvertTo-PulseSettingPresenceIndex -Rows $rows)
        }
        $jsonB = InModuleScope TenantPulse -ArgumentList (, $rowsB) {
            param($rows)
            ConvertTo-PulseCanonicalJson -InputObject (ConvertTo-PulseSettingPresenceIndex -Rows $rows)
        }
        $jsonA | Should -Be $jsonB
    }

    It 'a defId with two distinct resolved names surfaces the ordinal-minimum as settingName and the rest via nameVariants' {
        $rows = @(
            (New-PulseFixtureRow -PolicyId 'p1' -PolicyType 'compliance' -DefId 'def-a' -SettingName 'Zebra Name')
            (New-PulseFixtureRow -PolicyId 'p2' -PolicyType 'compliance' -DefId 'def-a' -SettingName 'Alpha Name')
        )
        $result = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseSettingPresenceIndex -Rows $rows
        }
        $entry = $result.compliance['def-a']
        $entry.settingName | Should -Be 'Alpha Name'
        $entry.nameVariants | Should -Contain 'Zebra Name'
    }

    It 'rows with an empty/missing settingDefinitionId or policyId are skipped, not thrown on' {
        $rows = @(
            [pscustomobject]@{ schemaVersion = '1'; policyId = ''; policyType = 'compliance'; settingDefinitionId = 'def-a'; settingName = 'x'; nameResolved = $true; value = 'v'; redacted = $false; assignments = @() }
            [pscustomobject]@{ schemaVersion = '1'; policyId = 'p1'; policyType = 'compliance'; settingDefinitionId = ''; settingName = 'x'; nameResolved = $true; value = 'v'; redacted = $false; assignments = @() }
            (New-PulseFixtureRow -PolicyId 'p2' -PolicyType 'compliance' -DefId 'def-real')
        )
        $result = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($rows)
            ConvertTo-PulseSettingPresenceIndex -Rows $rows
        }
        $result.compliance.Keys.Count | Should -Be 1
        $result.compliance.Contains('def-real') | Should -BeTrue
    }

    It 'zero rows produces an empty index, not a throw' {
        $result = InModuleScope TenantPulse {
            ConvertTo-PulseSettingPresenceIndex -Rows @()
        }
        $result.Keys.Count | Should -Be 0
    }
}

Describe 'Invoke-PulseSettingPresenceIndexBuild' {
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

    It 'is NotExpanded when no family expansions were ever produced (no gap - expected absence)' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $result = Invoke-PulseSettingPresenceIndexBuild -Store $store
            $result.Status | Should -Be 'NotExpanded'
        }
        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.settingPresenceIndex.status | Should -Be 'NotExpanded'
        $manifest.expansions.PSObject.Properties['settingPresenceIndex'].Value.gaps | Should -BeNullOrEmpty
    }

    It 'publishes Expanded across two families with real data, manifest entry carries the expected fields' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $complianceRows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            $deviceConfigRows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'd1'; policyType = 'deviceConfiguration'; policyName = 'D1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-y'; settingDefinitionId = 'def-y'
                    settingName = 'y'; nameResolved = $true; instanceId = 'd1/p:def-y'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $complianceRows -Gaps @() -PolicyCount 1
            Publish-PulseExpansionRows -Store $store -Name 'deviceConfiguration' -Rows $deviceConfigRows -Gaps @() -PolicyCount 1

            $result = Invoke-PulseSettingPresenceIndexBuild -Store $store
            $result.Status | Should -Be 'Expanded'
            $result.DefinitionCount | Should -Be 2
            $result.FamilyCount | Should -Be 2
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.expansions.settingPresenceIndex
        $entry.status | Should -Be 'Expanded'
        $entry.format | Should -Be 'json'
        $entry.schemaVersion | Should -Be '1'
        $entry.rowCount | Should -Be 2
        $entry.policyCount | Should -Be 2
        $entry.path | Should -Match '^expanded/settingPresenceIndex\.[0-9a-f]{64}\.json$'
    }

    It 'a family expansion that was never run (no manifest entry) is silently skipped, not gapped' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1

            $result = Invoke-PulseSettingPresenceIndexBuild -Store $store
            $result.Status | Should -Be 'Expanded'
            $result.Gaps.Count | Should -Be 0
        }
    }

    It 'a family with status NotExpanded is silently skipped, not gapped, and still contributes zero to FamilyCount' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1
            Set-PulseExpansionEntry -Store $store -Name 'deviceConfiguration' -Status 'NotExpanded' -Reason 'test: nothing to expand'

            $result = Invoke-PulseSettingPresenceIndexBuild -Store $store
            $result.Status | Should -Be 'Expanded'
            $result.FamilyCount | Should -Be 1
            $result.Gaps.Count | Should -Be 0
        }
    }

    It 'gaps a family whose file no longer matches its recorded hash, still succeeds Partial from the other family' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $goodRows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $goodRows -Gaps @() -PolicyCount 1

            $badRows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'd1'; policyType = 'deviceConfiguration'; policyName = 'D1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-y'; settingDefinitionId = 'def-y'
                    settingName = 'y'; nameResolved = $true; instanceId = 'd1/p:def-y'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'deviceConfiguration' -Rows $badRows -Gaps @() -PolicyCount 1

            $manifest = Get-PulseSnapshotManifest -Store $store
            $badFilePath = Join-Path $store.Root $manifest.expansions.deviceConfiguration.path
            Add-Content -LiteralPath $badFilePath -Value 'tampered' -NoNewline

            $result = Invoke-PulseSettingPresenceIndexBuild -Store $store
            $result.Status | Should -Be 'Partial'
            $result.Gaps.Count | Should -Be 1
            $result.Gaps[0].reason | Should -Match 'FamilyUnavailable'
        }
    }

    It 'a family that verifies successfully but produced zero rows still counts as one verified family - Expanded, not NotExpanded (Publish-PulseSettingPresenceIndex own -FamilyCount vs. row/policy-count distinction)' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            # An Expanded family with a genuinely empty row set - a legitimate outcome
            # (T2.2/T2.3's own "zero rows is not a gap" rule).
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows @() -Gaps @() -PolicyCount 0

            $result = Invoke-PulseSettingPresenceIndexBuild -Store $store
            $result.Status | Should -Be 'Expanded'
            $result.FamilyCount | Should -Be 1
            $result.DefinitionCount | Should -Be 0
        }
    }
}

Describe 'Get-PulseSettingPresenceIndex' {
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

    It 'NotAvailable, with a reason, when no settingPresenceIndex entry exists at all' {
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Get-PulseSettingPresenceIndex -Store $store
        }
        $result.Status | Should -Be 'NotAvailable'
        $result.Reason | Should -Match 'no expansions.settingPresenceIndex entry'
    }

    It 'NotAvailable, quoting the entry''s own reason verbatim, for a NotExpanded entry' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Set-PulseExpansionEntry -Store $store -Name 'settingPresenceIndex' -Status 'NotExpanded' -Reason 'test: no families available'
        }
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Get-PulseSettingPresenceIndex -Store $store
        }
        $result.Status | Should -Be 'NotAvailable'
        $result.Reason | Should -Be 'test: no families available'
    }

    It 'THROWS on a hash mismatch (fail-closed, mirrors Get-PulseConflictArtifact)' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1
            Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null
        }
        # Read via InModuleScope for the private accessor.
        $entryPath = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            (Get-PulseSnapshotManifest -Store $store).expansions.settingPresenceIndex.path
        }
        $filePath = Join-Path $script:store.Root $entryPath
        Add-Content -LiteralPath $filePath -Value 'tampered' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Get-PulseSettingPresenceIndex -Store $store
            }
        } | Should -Throw -ExpectedMessage '*hash mismatch*'
    }

    It 'Available, with the parsed Families tree, for a verified Expanded entry' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @([pscustomobject]@{ intent = $null; targetType = 'group'; groupId = 'g1'; filterId = $null; filterType = $null })
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1
            Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Get-PulseSettingPresenceIndex -Store $store
        }
        $result.Status | Should -Be 'Available'
        $result.Families.compliance.'def-x'.anyPresent | Should -BeTrue
        $result.Families.compliance.'def-x'.anyAssigned | Should -BeTrue
    }
}

Describe 'New-PulseArtifactReader - GetSettingPresenceIndex' {
    It 'the returned reader exposes GetSettingPresenceIndex() reading the same data Get-PulseSettingPresenceIndex would' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $result = InModuleScope TenantPulse -ArgumentList $storeRoot {
                param($storeRoot)
                $store = New-PulseSnapshotStore -Path $storeRoot
                $rows = @([pscustomobject]@{
                        schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                        templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                        settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                        valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                        assignments = @()
                    })
                Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1 | Out-Null
                Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null

                $reader = New-PulseArtifactReader -Store $store
                return $reader.GetSettingPresenceIndex()
            }
            $result.Status | Should -Be 'Available'
            $result.Families.compliance.'def-x'.anyPresent | Should -BeTrue
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'a reader built before an artifact exists still reads it correctly if the artifact is published later against the SAME on-disk store (frozen path, not frozen content)' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $result = InModuleScope TenantPulse -ArgumentList $storeRoot {
                param($storeRoot)
                $store = New-PulseSnapshotStore -Path $storeRoot
                $reader = New-PulseArtifactReader -Store $store

                $before = $reader.GetSettingPresenceIndex()

                $rows = @([pscustomobject]@{
                        schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                        templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                        settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                        valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                        assignments = @()
                    })
                Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1 | Out-Null
                Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null

                $after = $reader.GetSettingPresenceIndex()
                [pscustomobject]@{ Before = $before.Status; After = $after.Status }
            }
            $result.Before | Should -Be 'NotAvailable'
            $result.After | Should -Be 'Available'
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Resolve-PulseSettingPresenceIndexSnapshotExpansion' {
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

    It 'is a no-op when the existing settingPresenceIndex artifact still verifies' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1
            Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null

            $before = (Get-PulseSnapshotManifest -Store $store).expansions.settingPresenceIndex.sha256

            Resolve-PulseSettingPresenceIndexSnapshotExpansion -Store $store

            $after = (Get-PulseSnapshotManifest -Store $store).expansions.settingPresenceIndex.sha256
            $after | Should -Be $before
        }
    }

    It 're-derives from the family jsonl artifacts, never Graph, when no settingPresenceIndex entry exists yet' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1

            Resolve-PulseSettingPresenceIndexSnapshotExpansion -Store $store

            $manifest = Get-PulseSnapshotManifest -Store $store
            $manifest.expansions.ContainsKey('settingPresenceIndex') | Should -BeTrue
            $manifest.expansions.settingPresenceIndex.status | Should -Be 'Expanded'
        }
    }

    It 're-derives when the recorded file no longer matches its hash (tampered)' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $rows = @([pscustomobject]@{
                    schemaVersion = '1'; policyId = 'c1'; policyType = 'compliance'; policyName = 'C1'
                    templateFamily = $null; isBaseline = $false; settingPath = 'def-x'; settingDefinitionId = 'def-x'
                    settingName = 'x'; nameResolved = $true; instanceId = 'c1/p:def-x'; value = 'v'
                    valueLabel = $null; labelResolved = $false; redacted = $false; valueState = $null; applicability = $null
                    assignments = @()
                })
            Publish-PulseExpansionRows -Store $store -Name 'compliance' -Rows $rows -Gaps @() -PolicyCount 1
            Invoke-PulseSettingPresenceIndexBuild -Store $store | Out-Null

            $manifestBefore = Get-PulseSnapshotManifest -Store $store
            $filePath = Join-Path $store.Root $manifestBefore.expansions.settingPresenceIndex.path
            Add-Content -LiteralPath $filePath -Value 'tampered' -NoNewline

            Resolve-PulseSettingPresenceIndexSnapshotExpansion -Store $store

            # The rebuild is deterministic (same source family rows in, same canonical JSON
            # out), so the recorded sha256 is EXPECTED to come back identical to what it
            # was before tampering - re-derivation is not required to produce different
            # bytes, only CORRECT ones. The actual proof of "it really re-derived" is that
            # the on-disk file, which was tampered (no longer matching), verifies again -
            # the tampered bytes are gone, replaced by a correct rewrite.
            $manifestAfter = Get-PulseSnapshotManifest -Store $store
            $manifestAfter.expansions.settingPresenceIndex.status | Should -Be 'Expanded'
            $rewrittenPath = Join-Path $store.Root $manifestAfter.expansions.settingPresenceIndex.path
            (Get-PulseFileSha256 -Path $rewrittenPath) | Should -Be $manifestAfter.expansions.settingPresenceIndex.sha256
            (Get-Content -LiteralPath $rewrittenPath -Raw) | Should -Not -Match 'tampered'
        }
    }
}

Describe 'Get-PulseTenantSnapshot -ExpandSettings wiring' {
    BeforeAll {
        InModuleScope TenantPulse {
            function Get-GraphContext { param() }
            function Get-GraphObject { param() }
        }
    }

    BeforeEach {
        $script:outputRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'the setting-presence index is published (manifest.expansions.settingPresenceIndex exists) alongside conflicts when -ExpandSettings runs the full family pipeline end to end' {
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ TenantId = 'tenant-guid-presence-index-e2e'; ProfileId = 'contoso-presence-index' } }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationPolicy' } { @() }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { @() }
        Mock Get-GraphObject -ModuleName TenantPulse { @() }

        $store = InModuleScope TenantPulse -ArgumentList $script:outputRoot {
            param($outputRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-presence-index' -OutputPath $outputRoot -IncludeCheck 'TP.ENT.0001' -ExpandSettings
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        # Same shape as the sibling 'conflicts' expansion: with every underlying Graph call
        # mocked to return an empty array, every family expands to zero policies/rows, so
        # this artifact's own driver sees zero verified families and correctly writes
        # NotExpanded - the point of this test is that the ENTRY EXISTS AT ALL (the call
        # site wiring fired), not any particular status.
        ($manifest.expansions.PSObject.Properties.Name -contains 'settingPresenceIndex') | Should -BeTrue
        ($manifest.expansions.PSObject.Properties.Name -contains 'conflicts') | Should -BeTrue
    }

    It 'is OFF by default (no -ExpandSettings): no settingPresenceIndex expansion entry is written, mirroring the conflicts sibling' {
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ TenantId = 'tenant-guid-presence-index-off'; ProfileId = 'contoso-presence-index-off' } }
        Mock Get-GraphObject -ModuleName TenantPulse { @() }

        $store = InModuleScope TenantPulse -ArgumentList $script:outputRoot {
            param($outputRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-presence-index-off' -OutputPath $outputRoot -IncludeCheck 'TP.ENT.0001'
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        ($manifest.expansions.PSObject.Properties.Name -contains 'settingPresenceIndex') | Should -BeFalse
    }
}
