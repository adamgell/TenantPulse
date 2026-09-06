BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'TP10A: streaming dataset persist and read' {
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

    It 'streams a dataset to the same canonical bytes as ConvertTo-PulseCanonicalJson' {
        $rows = 1..6 | ForEach-Object {
            [pscustomobject]@{ id = ('{0:D2}' -f $_); name = "row-$_"; nested = [pscustomobject]@{ n = $_ } }
        }

        $expectedSha = InModuleScope TenantPulse -ArgumentList (,$rows) {
            param($rows)
            $json = ConvertTo-PulseCanonicalJson -InputObject $rows
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
            ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $rows {
            param($store, $rows)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $rows -ApiVersion 'v1.0' -Status 'Collected'
        }

        $onDisk = [System.IO.File]::ReadAllBytes((Join-Path $script:store.DatasetsPath 'Sample.json'))
        $actualSha = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($onDisk)) -replace '-', '').ToLowerInvariant()
        $actualSha | Should -Be $expectedSha
        Test-Path -LiteralPath ((Join-Path $script:store.DatasetsPath 'Sample.json') + '.tmp') | Should -BeFalse

        $readBack = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'Sample'
        }
        $readBack.Count | Should -Be 6
        $readBack[5].id | Should -Be '06'
    }

    It 'preserves row order and values across the bounded 128-row read-batch boundary' {
        $rows = [object[]] @(
            for ($i = 0; $i -lt 257; $i++) {
                [pscustomobject]@{ id = ('row-{0:D3}' -f $i); value = $i; nullable = $(if ($i -eq 128) { $null } else { "v-$i" }) }
            }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $rows {
            param($store, $rows)
            Write-PulseDataset -Store $store -Name 'BatchBoundary' -Data $rows -ApiVersion 'v1.0' -Status 'Collected'
        }
        $readBack = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'BatchBoundary'
        }

        $readBack.Count | Should -Be 257
        $readBack[0].id | Should -Be 'row-000'
        $readBack[127].id | Should -Be 'row-127'
        $readBack[128].id | Should -Be 'row-128'
        $readBack[128].nullable | Should -BeNullOrEmpty
        $readBack[256].id | Should -Be 'row-256'
        $readBack[256].value | Should -Be 256
    }

    It 'throws on itemCount mismatch instead of silently returning a prefix' {
        $rows = @(
            [pscustomobject]@{ id = 'a' }
            [pscustomobject]@{ id = 'b' }
        )
        InModuleScope TenantPulse -ArgumentList $script:store, $rows {
            param($store, $rows)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $rows -ApiVersion 'v1.0' -Status 'Collected'
        }

        $shorter = InModuleScope TenantPulse {
            ConvertTo-PulseCanonicalJson -InputObject @([pscustomobject]@{ id = 'a' })
        }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($shorter)
        [System.IO.File]::WriteAllBytes((Join-Path $script:store.DatasetsPath 'Sample.json'), $bytes)
        $sha = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($bytes)) -replace '-', '').ToLowerInvariant()
        InModuleScope TenantPulse -ArgumentList $script:store, $sha {
            param($store, $sha)
            $manifest = Get-PulseSnapshotManifest -Store $store
            $manifest.datasets['Sample']['sha256'] = $sha
            Set-PulseAtomicFileContent -Path $store.ManifestPath -Value (ConvertTo-PulseCanonicalJson -InputObject $manifest)
        }

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Read-PulseDataset -Store $store -Name 'Sample'
            }
        } | Should -Throw -ExpectedMessage '*itemCount mismatch*'
    }

    It 'throws on truncated JSON rather than returning a partial array' {
        $rows = @(
            [pscustomobject]@{ id = 'a' }
            [pscustomobject]@{ id = 'b' }
        )
        InModuleScope TenantPulse -ArgumentList $script:store, $rows {
            param($store, $rows)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $rows -ApiVersion 'v1.0' -Status 'Collected'
        }

        $path = Join-Path $script:store.DatasetsPath 'Sample.json'
        $full = [System.IO.File]::ReadAllBytes($path)
        $truncated = $full[0..([Math]::Max(0, $full.Length - 8))]
        [System.IO.File]::WriteAllBytes($path, [byte[]] $truncated)
        $sha = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData([byte[]] $truncated)) -replace '-', '').ToLowerInvariant()
        InModuleScope TenantPulse -ArgumentList $script:store, $sha {
            param($store, $sha)
            $manifest = Get-PulseSnapshotManifest -Store $store
            $manifest.datasets['Sample'].sha256 = $sha
            Set-PulseAtomicFileContent -Path $store.ManifestPath -Value (ConvertTo-PulseCanonicalJson -InputObject $manifest)
        }

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Read-PulseDataset -Store $store -Name 'Sample'
            }
        } | Should -Throw
    }
}

Describe 'TP10A: batched manifest replacement' {
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

    It 'defers per-write manifest rewrites and applies N entries in one replacement' {
        $batch = [System.Collections.Generic.List[object]]::new()
        $rows = @([pscustomobject]@{ id = 'x' })

        InModuleScope TenantPulse -ArgumentList $script:store, $rows, $batch {
            param($store, $rows, $batch)
            for ($i = 1; $i -le 5; $i++) {
                Write-PulseDataset -Store $store -Name ("Batch$i") -Data $rows -ApiVersion 'v1.0' -Status 'Collected' -ManifestBatch $batch
            }
        }

        $manifestBefore = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        @($manifestBefore.datasets.PSObject.Properties).Count | Should -Be 0
        $batch.Count | Should -Be 5

        InModuleScope TenantPulse -ArgumentList $script:store, $batch {
            param($store, $batch)
            Set-PulseManifestEntry -Store $store -DatasetEntries $batch.ToArray()
        }

        $manifestAfter = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifestAfter.datasets.Batch1.itemCount | Should -Be 1
        $manifestAfter.datasets.Batch5.status | Should -Be 'Collected'
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'Batch3.json') | Should -BeTrue
    }
}

Describe 'TP10A: fragment-and-merge expansion' {
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

    It 'merges identifiable fragments to the same bytes across chunk boundaries and resumes matching fragments' {
        $makeRow = {
            param($policyId, $n)
            [pscustomobject]@{
                policyId     = $policyId
                settingPath  = "s/$n"
                instanceId   = '0'
                nameResolved = $true
                redacted     = $false
            }
        }

        $rows = @(
            & $makeRow 'p-a' 1
            & $makeRow 'p-a' 2
            & $makeRow 'p-b' 1
            & $makeRow 'p-c' 1
            & $makeRow 'p-c' 2
            & $makeRow 'p-d' 1
        )

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $rows {
            param($store, $rows)
            $twoThenFour = @(
                (New-PulseExpansionFragmentId -StartOrdinal 0 -EndOrdinal 1 -PolicyIds @('p-a', 'p-b')),
                (New-PulseExpansionFragmentId -StartOrdinal 2 -EndOrdinal 3 -PolicyIds @('p-c', 'p-d'))
            )
            $first = Write-PulseExpansionFragment -Store $store -Name 'settingsCatalog' -FragmentId $twoThenFour[0] -Rows @($rows[0], $rows[1], $rows[2])
            $first.Resumed | Should -BeFalse
            $resume = Write-PulseExpansionFragment -Store $store -Name 'settingsCatalog' -FragmentId $twoThenFour[0] -Rows @($rows[0], $rows[1], $rows[2])
            $resume.Resumed | Should -BeTrue
            $null = Write-PulseExpansionFragment -Store $store -Name 'settingsCatalog' -FragmentId $twoThenFour[1] -Rows @($rows[3], $rows[4], $rows[5])

            $mergedA = Merge-PulseExpansionFragments -Store $store -Name 'settingsCatalog' -FragmentIds $twoThenFour -Gaps @() -PolicyCount 4
            $pathA = (Get-PulseSnapshotManifest -Store $store).expansions.settingsCatalog.path
            $bytesA = [System.IO.File]::ReadAllBytes((Join-Path $store.Root $pathA))

            $threes = @(
                (New-PulseExpansionFragmentId -StartOrdinal 0 -EndOrdinal 0 -PolicyIds @('p-a')),
                (New-PulseExpansionFragmentId -StartOrdinal 1 -EndOrdinal 2 -PolicyIds @('p-b', 'p-c')),
                (New-PulseExpansionFragmentId -StartOrdinal 3 -EndOrdinal 3 -PolicyIds @('p-d'))
            )
            $null = Write-PulseExpansionFragment -Store $store -Name 'settingsCatalog' -FragmentId $threes[0] -Rows @($rows[0], $rows[1])
            $null = Write-PulseExpansionFragment -Store $store -Name 'settingsCatalog' -FragmentId $threes[1] -Rows @($rows[2], $rows[3], $rows[4])
            $null = Write-PulseExpansionFragment -Store $store -Name 'settingsCatalog' -FragmentId $threes[2] -Rows @($rows[5])
            $mergedB = Merge-PulseExpansionFragments -Store $store -Name 'settingsCatalog' -FragmentIds $threes -Gaps @() -PolicyCount 4
            $pathB = (Get-PulseSnapshotManifest -Store $store).expansions.settingsCatalog.path
            $bytesB = [System.IO.File]::ReadAllBytes((Join-Path $store.Root $pathB))

            [pscustomobject]@{
                StatusA     = $mergedA.Status
                RowCountA   = $mergedA.RowCount
                StatusB     = $mergedB.Status
                RowCountB   = $mergedB.RowCount
                BytesEqual  = [System.Linq.Enumerable]::SequenceEqual($bytesA, $bytesB)
                FragmentDir = Test-Path -LiteralPath (Join-Path $store.ExpandedPath 'fragments/settingsCatalog') -PathType Container
            }
        }

        $result.StatusA | Should -Be 'Expanded'
        $result.RowCountA | Should -Be 6
        $result.StatusB | Should -Be 'Expanded'
        $result.RowCountB | Should -Be 6
        $result.BytesEqual | Should -BeTrue
        $result.FragmentDir | Should -BeTrue
    }

    It 'refuses to merge when a named fragment is missing' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Merge-PulseExpansionFragments -Store $store -Name 'settingsCatalog' -FragmentIds @('000000-000001-aaaaaaaaaaaa') -Gaps @() -PolicyCount 2
            }
        } | Should -Throw -ExpectedMessage '*missing*'
    }

    It 'ignores whitespace-only fragment lines instead of publishing null rows' {
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $fragmentId = '000000-000000-whitespace'
            $row = [pscustomobject]@{
                policyId     = 'policy-a'
                settingPath  = 'setting-a'
                instanceId   = '0'
                nameResolved = $true
                redacted     = $false
            }
            $null = Write-PulseExpansionFragment -Store $store -Name 'settingsCatalog' -FragmentId $fragmentId -Rows @($row)
            $fragmentPath = Get-PulseExpansionFragmentPath -Store $store -Name 'settingsCatalog' -FragmentId $fragmentId
            [System.IO.File]::AppendAllText($fragmentPath, "   `n`t`r`n")

            $fragmentRows = Read-PulseExpansionFragmentRows -Path $fragmentPath
            $merged = Merge-PulseExpansionFragments -Store $store -Name 'settingsCatalog' -FragmentIds @($fragmentId) -Gaps @() -PolicyCount 1
            $publishedRows = Get-PulseExpansionRows -Store $store -Name 'settingsCatalog'
            [pscustomobject]@{
                FragmentCount = @($fragmentRows).Count
                FragmentId    = $fragmentRows[0].policyId
                MergedCount   = $merged.RowCount
                PublishedCount = @($publishedRows).Count
                PublishedId   = $publishedRows[0].policyId
            }
        }

        $result.FragmentCount | Should -Be 1
        $result.FragmentId | Should -Be 'policy-a'
        $result.MergedCount | Should -Be 1
        $result.PublishedCount | Should -Be 1
        $result.PublishedId | Should -Be 'policy-a'
    }

    It 'flushes 65 policies as three non-overlapping 32-policy fragments' {
        $policies = 0..64 | ForEach-Object {
            [pscustomobject]@{ id = ('policy-{0:D3}' -f $_) }
        }
        $policyIds = [string[]] @($policies.id)
        $expectedFragmentIds = @(
            foreach ($bounds in @(@(0, 31), @(32, 63), @(64, 64))) {
                $ids = [string[]] @($policyIds[$bounds[0]..$bounds[1]])
                $joined = $ids -join ','
                $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($joined))
                $hash12 = (([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()).Substring(0, 12)
                '{0:D6}-{1:D6}-{2}' -f $bounds[0], $bounds[1], $hash12
            }
        )
        $index = [ordered]@{
            'setting-a' = [ordered]@{
                Name            = 'setting-a'
                DisplayName     = 'Setting A'
                RootDefinitionId = $null
                OptionLabels    = [ordered]@{}
                Applicability   = $null
                IsSecretCapable = $false
            }
        }
        $settingsPayload = [object[]] @(
            [pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                    settingDefinitionId = 'setting-a'
                    simpleSettingValue  = [pscustomobject]@{
                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                        value         = 'enabled'
                    }
                }
            }
        )
        $capturedManifest = [ordered]@{
            schemaVersion = '2.0.0'
            datasets      = [ordered]@{}
            references    = [ordered]@{}
            expansions    = [ordered]@{}
        }

        Mock Get-PulseSnapshotManifest -ModuleName TenantPulse { $capturedManifest }
        Mock Read-PulseDataset -ModuleName TenantPulse -ParameterFilter {
            $Name -like 'configurationPolicySettings-*'
        } {
            return , [object[]] @($settingsPayload)
        }
        Mock Read-PulseDataset -ModuleName TenantPulse -ParameterFilter {
            $Name -like 'configurationPolicyAssignments-*'
        } {
            return , [object[]] @()
        }
        Mock Write-PulseExpansionFragment -ModuleName TenantPulse {
            [pscustomobject]@{ FragmentId = $FragmentId; RowCount = @($Rows).Count }
        }
        Mock Merge-PulseExpansionFragments -ModuleName TenantPulse {
            [pscustomobject]@{
                Status              = 'Expanded'
                PolicyCount         = $PolicyCount
                RowCount            = 65
                UnresolvedNameCount = 0
                RedactedSecretCount = 0
                Gaps                = @()
            }
        }

        $summary = InModuleScope TenantPulse -ArgumentList $script:store, $policies, $index {
            param($store, $policies, $index)
            Invoke-PulseSettingsCatalogExpansion -Store $store -Policies $policies -DefinitionIndex $index -FromCapturedPayloads
        }

        $summary.RowCount | Should -Be 65
        Should-Invoke Get-PulseSnapshotManifest -ModuleName TenantPulse -Times 1 -Exactly
        Should-Invoke Read-PulseDataset -ModuleName TenantPulse -Times 130 -Exactly -ParameterFilter {
            [object]::ReferenceEquals($ManifestSnapshot, $capturedManifest)
        }
        Should-Invoke Read-PulseDataset -ModuleName TenantPulse -Times 65 -Exactly -ParameterFilter {
            $Name -like 'configurationPolicySettings-*' -and
            [object]::ReferenceEquals($ManifestSnapshot, $capturedManifest)
        }
        Should-Invoke Read-PulseDataset -ModuleName TenantPulse -Times 65 -Exactly -ParameterFilter {
            $Name -like 'configurationPolicyAssignments-*' -and
            [object]::ReferenceEquals($ManifestSnapshot, $capturedManifest)
        }
        Should-Invoke Write-PulseExpansionFragment -ModuleName TenantPulse -Times 3 -Exactly
        Should-Invoke Write-PulseExpansionFragment -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $FragmentId -eq $expectedFragmentIds[0] -and
            @($Rows).Count -eq 32 -and
            $Rows[0].policyId -eq 'policy-000' -and
            $Rows[31].policyId -eq 'policy-031'
        }
        Should-Invoke Write-PulseExpansionFragment -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $FragmentId -eq $expectedFragmentIds[1] -and
            @($Rows).Count -eq 32 -and
            $Rows[0].policyId -eq 'policy-032' -and
            $Rows[31].policyId -eq 'policy-063'
        }
        Should-Invoke Write-PulseExpansionFragment -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $FragmentId -eq $expectedFragmentIds[2] -and
            @($Rows).Count -eq 1 -and
            $Rows[0].policyId -eq 'policy-064'
        }
        Should-Invoke Merge-PulseExpansionFragments -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            @($FragmentIds).Count -eq 3 -and
            $FragmentIds[0] -eq $expectedFragmentIds[0] -and
            $FragmentIds[1] -eq $expectedFragmentIds[1] -and
            $FragmentIds[2] -eq $expectedFragmentIds[2]
        }
    }
}

Describe 'TP10A: evaluator projection without deep clones' {
    It 'copies top-level row properties without a JSON round-trip type change to hashtable' {
        $original = [pscustomobject]@{ id = 'keep'; nested = [pscustomobject]@{ n = 1 } }
        $datasets = @{ Sample = @($original) }

        $projected = InModuleScope TenantPulse -ArgumentList $datasets {
            param($datasets)
            ConvertTo-PulseClonedDatasets -Datasets $datasets
        }

        $projected['Sample'][0].id | Should -Be 'keep'
        $projected['Sample'][0]['id'] | Should -Be 'keep'
        $projected['Sample'][0].id = 'mutated'
        $original.id | Should -Be 'keep'
        $projected.ContainsKey('Sample') | Should -BeTrue
        $projected['other'] = @()
        $datasets.ContainsKey('other') | Should -BeFalse
    }
}

Describe 'TP10A: bounded JSON renderer input and atomic publish' {
    It 'rejects a snapshot-store wrapper and writes findings through atomic rename' {
        $output = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $document = [pscustomobject]@{
                schemaVersion = '1.0'
                generatedUtc  = '2026-08-16T00:00:00.000Z'
                tenant        = 'tp-test'
                producer      = [pscustomobject]@{ tenantPulse = '0.3.0' }
                coverage      = $null
                scores        = $null
                findings      = @()
            }

            $path = InModuleScope TenantPulse -ArgumentList $document, $output {
                param($document, $output)
                Export-PulseJsonReport -Document $document -OutputPath $output
            }

            Test-Path -LiteralPath $path -PathType Leaf | Should -BeTrue
            Test-Path -LiteralPath ($path + '.tmp') | Should -BeFalse
            (Get-Content -LiteralPath $path -Raw) | Should -Match '"schemaVersion": "1.0"'

            $cmd = InModuleScope TenantPulse { Get-Command Export-PulseJsonReport }
            $cmd.Parameters.ContainsKey('Store') | Should -BeFalse
            $cmd.Parameters.ContainsKey('Document') | Should -BeTrue

            {
                InModuleScope TenantPulse -ArgumentList $output {
                    param($output)
                    $wrapper = [pscustomobject]@{ Document = [pscustomobject]@{ schemaVersion = '1.0' }; RedactionMap = @{ a = 'b' } }
                    Export-PulseJsonReport -Document $wrapper -OutputPath $output
                }
            } | Should -Throw -ExpectedMessage '*RedactionMap*'
        } finally {
            Remove-Item -LiteralPath $output -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP10A: expansion stays opt-in and sequential' {
    It 'leaves ExpandSettings default off and has no MaxParallel live pool' {
        $snap = Get-Command Get-PulseTenantSnapshot -Module TenantPulse
        $snap.Parameters['ExpandSettings'].SwitchParameter | Should -BeTrue
        $snap.Parameters['ExpandSettings'].ParameterType.FullName | Should -Be 'System.Management.Automation.SwitchParameter'

        $assess = Get-Command Invoke-PulseAssessment -Module TenantPulse
        $assess.Parameters['ExpandSettings'].SwitchParameter | Should -BeTrue

        InModuleScope TenantPulse {
            $expand = Get-Command Invoke-PulseSettingsCatalogExpansion
            $expand.Parameters.ContainsKey('MaxParallel') | Should -BeFalse
            $expand.Parameters.ContainsKey('Sequential') | Should -BeFalse
        }
    }
}
