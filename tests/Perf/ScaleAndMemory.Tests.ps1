<#
    Task 2.7: the dedicated, SERIAL scale/memory perf container. NOT part of the default
    `./build.ps1`/`test` workflow - see build.yaml's own explicit Pester.Configuration.Run.Path
    (tests/QA + tests/Unit only) and .build/PerfTest.tasks.ps1's own docstring. Invoke via
    `./build.ps1 -Tasks build,perftest`.

    METHOD (recorded here, once, for every Describe below - see each It's own comment for
    per-assertion detail): every wall-time/memory number this file asserts against was
    measured on the hardware and PowerShell version recorded in
    docs/spike/2026-08-16-t27-perf-container.md. The BUDGET each It asserts is the MAX of
    three quiescent samples x 1.5 - never a guessed number. A budget FAILURE means a
    regression against that recorded baseline, not an external SLA; materially different
    runner hardware must be measured and recorded before changing these limits.

    MOCKED GRAPH, REAL COMPUTE (the plan's own instruction for the 5k-policy pipeline): a
    5,000-policy corpus fetch is meaningless to structurally re-time here - GraphKit's own
    per-policy latency (T2.0 spike: mean 298ms, p99 430ms) is a NETWORK number, not
    something this process controls or should be asserted against in a unit-style perf
    test. Every Describe below therefore either (a) uses -FromCapturedPayloads (no Graph
    call at all - the fixture-seeding phase that stands in for "the fetch already
    happened" is explicitly EXCLUDED from the measured/budgeted window, see each It's own
    comment for where the stopwatch actually starts), or (b) exercises Write-PulseDataset/
    Read-PulseDataset directly with synthetic data, which likewise never touches Graph.

    MEMORY METRIC: [System.GC]::GetTotalMemory($true) (forced full collection immediately
    before the "before" snapshot, un-forced immediately after the measured operation) is
    the metric of record - the managed-heap delta directly attributable to the operation
    under test. [System.Diagnostics.Process]::PeakWorkingSet64 was ALSO captured during
    this file's own baseline measurement but returned 0 (unreliable/unsupported) on the
    sandboxed measurement host it was first run on - see docs/spike's own recorded-numbers
    table for that caveat. This file does not assert against PeakWorkingSet64 for that
    reason; a future re-baseline on a host where it reports non-zero may add it back.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function Get-PulsePerfManagedMemoryMB {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        return [System.GC]::GetTotalMemory($true) / 1MB
    }

    # BUDGETS = [measured baseline] x 1.5 headroom, per the plan's own instruction. Every
    # baseline number below is recorded VERBATIM, alongside hardware/PowerShell-version and
    # full method, in docs/spike/2026-08-16-t27-perf-container.md - do not adjust a budget
    # here without re-measuring and updating that file's own table in the same change.
    #
    # Rebaseline source: commit 115b299, measured quiescently on Apple Silicon, 18 logical
    # CPUs, 128GB RAM, macOS 26.6.2, PowerShell 7.6.5. The corrected fixture proves both
    # required captured datasets per policy (settings + assignments), so the manifest has
    # exactly 10,000 entries rather than the historical invalid 5,000-entry fixture.
    # Samples (full precision is recorded in the spike document):
    #   pipeline MAX: expand 19.2793692s; conflict 8.5926654s; 135.0012817MB
    #   index MAX: 6.8465455s; 140.3563614MB
    #   50k dataset MAX: write 50.0731926s/220.1258163MB;
    #                    read 2.7434971s/511.7775497MB
    #   200 unbatched writes MAX: 13.7353299s
    $script:PulsePerfExpandBudgetSeconds = 29.0          # 19.2793692 x 1.5, rounded up
    $script:PulsePerfConflictBudgetSeconds = 13.0        # 8.5926654 x 1.5, rounded up
    $script:PulsePerfComputeMemoryBudgetMB = 203.0       # 135.0012817 x 1.5, rounded up
    $script:PulsePerfWriteMemoryBudgetMB = 331.0         # 220.1258163 x 1.5, rounded up
    $script:PulsePerfReadMemoryBudgetMB = 768.0          # 511.7775497 x 1.5, rounded up
    $script:PulsePerfWriteSecondsBudget = 75.2           # 50.0731926 x 1.5, rounded up
    $script:PulsePerfReadSecondsBudget = 4.2             # 2.7434971 x 1.5, rounded up
    $script:PulsePerfManifestWriteBudgetSeconds = 21.0   # 13.7353299 x 1.5, rounded up

    # Setting-presence index over that same corrected 5,000-policy/10,000-dataset corpus.
    # Each full pipeline run records the MAX of three back-to-back index builds; the budget
    # uses the largest such value across the three independent full runs.
    $script:PulsePerfIndexBudgetSeconds = 10.3    # 6.8465455 x 1.5, rounded up
    $script:PulsePerfIndexMemoryBudgetMB = 211.0  # 140.3563614 x 1.5, rounded up
}

Describe 'Perf: 5,000-policy Settings Catalog expansion + conflict-detection compute (mocked Graph)' {
    # Budget derivation: see docs/spike/2026-08-16-t27-perf-container.md's own recorded
    # table for the measured baseline this It's budgets are [measured] x 1.5 of.
    It 'expands 5,000 captured-payload policies and runs conflict detection within the recorded compute + memory budget' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $result = InModuleScope TenantPulse -ArgumentList $storeRoot {
                param($storeRoot)

                $N = 5000
                $store = New-PulseSnapshotStore -Path $storeRoot
                $defIds = 0..49 | ForEach-Object { "setting-$_" }
                $index = [ordered]@{}
                foreach ($d in $defIds) {
                    $index[$d] = [ordered]@{ Name = $d; DisplayName = $d; RootDefinitionId = $null; OptionLabels = [ordered]@{}; Applicability = $null; IsSecretCapable = $false }
                }

                # --- SEED (NOT part of the measured window - see this file's own MOCKED
                # GRAPH docstring section). Bulk-writes the raw captured-payload dataset
                # files and a SINGLE manifest update directly (bypassing Write-PulseDataset's
                # own per-call manifest read-modify-write - see this repo's T2.7 perf
                # findings for why that per-call cost is a SEPARATE, already-documented
                # O(n)-per-write characteristic this Describe does not re-measure) - this
                # harness's target metric is the walk/merge/conflict COMPUTE stage only,
                # standing in for "5,000 policies' worth of Settings Catalog payloads have
                # already been fetched and are sitting in the snapshot store", exactly as
                # the plan's own instruction frames it ("mocked Graph, real
                # expansion+conflicts").
                $policies = [System.Collections.Generic.List[object]]::new()
                $datasetsEntries = [ordered]@{}
                $emptyAssignmentJson = ConvertTo-PulseCanonicalJson -InputObject @()
                $emptyAssignmentBytes = [System.Text.Encoding]::UTF8.GetBytes($emptyAssignmentJson)
                $emptyAssignmentHashBytes = [System.Security.Cryptography.SHA256]::HashData($emptyAssignmentBytes)
                $emptyAssignmentSha256 = ([System.BitConverter]::ToString($emptyAssignmentHashBytes) -replace '-', '').ToLowerInvariant()
                for ($i = 1; $i -le $N; $i++) {
                    $id = '{0:D8}-0000-0000-0000-000000000000' -f $i
                    $defId = $defIds[$i % $defIds.Count]
                    # Cycling across 3 distinct values per definitionId guarantees real,
                    # detectable conflicts (>= 2 policies disagreeing on the same
                    # settingDefinitionId) rather than an all-agree corpus that would let
                    # conflict detection's own grouping pass run over an artificially easy,
                    # single-group-per-defId input.
                    $value = "value-$($i % 3)"
                    $policies.Add([pscustomobject]@{ id = $id; name = "Policy-$i"; templateReference = [pscustomobject]@{ templateId = ''; templateFamily = 'none' } }) | Out-Null

                    $response = @(
                        [pscustomobject]@{
                            id              = '0'
                            settingInstance = [pscustomobject]@{
                                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                                settingDefinitionId = $defId
                                simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = $value }
                            }
                        }
                    )
                    $json = ConvertTo-PulseCanonicalJson -InputObject $response
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
                    $name = "configurationPolicySettings-$id"
                    [System.IO.File]::WriteAllBytes((Join-Path $store.DatasetsPath "$name.json"), $bytes)
                    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
                    $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
                    $datasetsEntries[$name] = [ordered]@{ status = 'Collected'; apiVersion = 'beta'; sha256 = $sha256; itemCount = $response.Count; collectedUtc = '2026-08-16T00:00:00.000Z'; reason = $null }

                    # Assignment capture is mandatory for a trustworthy expanded row.
                    # Seed a real, hash-governed empty assignment payload for every policy;
                    # absence must remain distinguishable from a proven empty assignment.
                    $assignmentName = "configurationPolicyAssignments-$id"
                    [System.IO.File]::WriteAllBytes((Join-Path $store.DatasetsPath "$assignmentName.json"), $emptyAssignmentBytes)
                    $datasetsEntries[$assignmentName] = [ordered]@{ status = 'Collected'; apiVersion = 'beta'; sha256 = $emptyAssignmentSha256; itemCount = 0; collectedUtc = '2026-08-16T00:00:00.000Z'; reason = $null }
                }
                $manifest = Get-PulseSnapshotManifest -Store $store
                foreach ($k in $datasetsEntries.Keys) { $manifest.datasets[$k] = $datasetsEntries[$k] }
                Set-PulseAtomicFileContent -Path $store.ManifestPath -Value (ConvertTo-PulseCanonicalJson -InputObject $manifest)
                $manifestDatasetCount = $manifest.datasets.Count

                # The seed builder is not part of a real re-expansion caller's live set.
                # Release its duplicate manifest/entry graph before the forced-GC baseline
                # so the measured window reflects only the store, policies, and definition
                # index that production actually carries into this operation.
                $datasetsEntries = $null
                $manifest = $null
                $json = $null
                $bytes = $null
                $hashBytes = $null

                # --- MEASURED WINDOW STARTS HERE ---
                [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                $memBefore = [System.GC]::GetTotalMemory($true)

                $expandSw = [System.Diagnostics.Stopwatch]::StartNew()
                $expandSummary = Invoke-PulseSettingsCatalogExpansion -Store $store -Policies $policies.ToArray() -DefinitionIndex $index -FromCapturedPayloads
                $expandSw.Stop()

                $conflictSw = [System.Diagnostics.Stopwatch]::StartNew()
                $conflictSummary = Invoke-PulseConflictDetection -Store $store
                $conflictSw.Stop()

                $memAfter = [System.GC]::GetTotalMemory($false)
                # --- MEASURED WINDOW ENDS HERE (expand + conflict, UNCHANGED by Part A) ---

                # --- Part A, T3.4: setting-presence index, ISOLATED measurement window.
                # Invoke-PulseSettingPresenceIndexBuild is idempotent (re-publishes a fresh
                # content-addressed generation file each call, over the SAME already-
                # published settingsCatalog/conflicts family artifacts from above - no
                # re-seed needed) - called 3 times back-to-back here, each with its own
                # forced-GC before/after memory delta and its own stopwatch, taking the MAX
                # of each independently, matching this file's own established "MAX of >=3
                # runs x1.5" methodology (see this file's own BeforeAll docstring for why a
                # single-sample budget previously flaked here) - cheaper to gather 3 real
                # samples this way than 3 full fresh expand+conflict+index runs, and
                # isolates THIS step's own variance from the (unrelated, unchanged) expand/
                # conflict steps' own.
                $indexSeconds = [System.Collections.Generic.List[double]]::new()
                $indexMemoryDeltasMB = [System.Collections.Generic.List[double]]::new()
                $indexDefinitionCount = 0
                $indexStatus = $null
                for ($sample = 1; $sample -le 3; $sample++) {
                    [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                    $indexMemBefore = [System.GC]::GetTotalMemory($true)
                    $indexSw = [System.Diagnostics.Stopwatch]::StartNew()
                    $indexSummary = Invoke-PulseSettingPresenceIndexBuild -Store $store
                    $indexSw.Stop()
                    $indexMemAfter = [System.GC]::GetTotalMemory($false)

                    $indexSeconds.Add($indexSw.Elapsed.TotalSeconds) | Out-Null
                    $indexMemoryDeltasMB.Add(($indexMemAfter - $indexMemBefore) / 1MB) | Out-Null
                    $indexStatus = $indexSummary.Status
                    $indexDefinitionCount = $indexSummary.DefinitionCount
                }

                [pscustomobject]@{
                    ExpandStatus            = $expandSummary.Status
                    ExpandRowCount          = $expandSummary.RowCount
                    ExpandGapCount          = @($expandSummary.Gaps).Count
                    ExpandSeconds           = $expandSw.Elapsed.TotalSeconds
                    ConflictStatus          = $conflictSummary.Status
                    ConflictCount           = $conflictSummary.ConflictCount
                    ConflictGapCount        = @($conflictSummary.Gaps).Count
                    ConflictSeconds         = $conflictSw.Elapsed.TotalSeconds
                    MemoryDeltaMB           = ($memAfter - $memBefore) / 1MB
                    IndexStatus             = $indexStatus
                    IndexDefinitionCount    = $indexDefinitionCount
                    IndexGapCount           = @($indexSummary.Gaps).Count
                    IndexMaxSeconds         = ($indexSeconds | Measure-Object -Maximum).Maximum
                    IndexMaxMemoryDeltaMB   = ($indexMemoryDeltasMB | Measure-Object -Maximum).Maximum
                    ManifestDatasetCount    = $manifestDatasetCount
                }
            }

            Write-Host ('TENANTPULSE_PERF pipeline ' + ($result | ConvertTo-Json -Compress))

            # Correctness sanity (not the perf point, but a silent budget "pass" over a
            # broken/empty run would be worse than useless):
            $result.ExpandStatus | Should -Be 'Expanded'
            $result.ExpandRowCount | Should -Be 5000
            $result.ExpandGapCount | Should -Be 0
            $result.ManifestDatasetCount | Should -Be 10000
            $result.ConflictStatus | Should -Be 'Expanded'
            $result.ConflictCount | Should -Be 50
            $result.ConflictGapCount | Should -Be 0
            $result.IndexStatus | Should -Be 'Expanded'
            $result.IndexDefinitionCount | Should -BeGreaterThan 0
            $result.IndexGapCount | Should -Be 0

            # Budgets: see docs/spike/2026-08-16-t27-perf-container.md's recorded table.
            $result.ExpandSeconds | Should -BeLessThan $script:PulsePerfExpandBudgetSeconds
            $result.ConflictSeconds | Should -BeLessThan $script:PulsePerfConflictBudgetSeconds
            $result.MemoryDeltaMB | Should -BeLessThan $script:PulsePerfComputeMemoryBudgetMB
            $result.IndexMaxSeconds | Should -BeLessThan $script:PulsePerfIndexBudgetSeconds
            $result.IndexMaxMemoryDeltaMB | Should -BeLessThan $script:PulsePerfIndexMemoryBudgetMB
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Perf: 50,000-row managedDevices dataset write+read memory ceiling' {
    It 'writes and reads a 50,000-row dataset within the recorded memory budget' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $result = InModuleScope TenantPulse -ArgumentList $storeRoot {
                param($storeRoot)

                $N = 50000
                $store = New-PulseSnapshotStore -Path $storeRoot

                $devices = [object[]]::new($N)
                for ($i = 0; $i -lt $N; $i++) {
                    $devices[$i] = [pscustomobject]@{
                        id                    = [guid]::NewGuid().ToString()
                        deviceName            = "DESKTOP-$i"
                        operatingSystem       = 'Windows'
                        osVersion             = '10.0.19045.4046'
                        complianceState       = 'compliant'
                        managementAgent       = 'mdm'
                        azureADDeviceId       = [guid]::NewGuid().ToString()
                        userId                = [guid]::NewGuid().ToString()
                        userPrincipalName     = "user$i@contoso.example"
                        enrolledDateTime      = '2025-01-01T00:00:00Z'
                        lastSyncDateTime      = '2026-08-01T00:00:00Z'
                        model                 = 'Virtual Machine'
                        manufacturer          = 'Contoso'
                        serialNumber          = "SN-$i-0000000"
                        isEncrypted           = $true
                        jailBroken            = 'False'
                        managementState       = 'managed'
                        deviceEnrollmentType  = 'windowsAzureADJoin'
                    }
                }

                [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                $memBeforeWrite = [System.GC]::GetTotalMemory($true)
                $writeSw = [System.Diagnostics.Stopwatch]::StartNew()
                Write-PulseDataset -Store $store -Name 'managedDevices' -Data $devices -ApiVersion 'v1.0' -Status 'Collected'
                $writeSw.Stop()
                $memAfterWrite = [System.GC]::GetTotalMemory($false)

                $fileBytes = (Get-Item (Join-Path $store.DatasetsPath 'managedDevices.json')).Length

                $devices = $null
                [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                $memBeforeRead = [System.GC]::GetTotalMemory($true)
                $readSw = [System.Diagnostics.Stopwatch]::StartNew()
                $readBack = Read-PulseDataset -Store $store -Name 'managedDevices'
                $readSw.Stop()
                $memAfterRead = [System.GC]::GetTotalMemory($false)

                [pscustomobject]@{
                    FileBytes        = $fileBytes
                    WriteSeconds     = $writeSw.Elapsed.TotalSeconds
                    WriteDeltaMB     = ($memAfterWrite - $memBeforeWrite) / 1MB
                    ReadSeconds      = $readSw.Elapsed.TotalSeconds
                    ReadDeltaMB      = ($memAfterRead - $memBeforeRead) / 1MB
                    ReadBackCount    = $readBack.Count
                }
            }

            Write-Host ('TENANTPULSE_PERF dataset ' + ($result | ConvertTo-Json -Compress))

            $result.ReadBackCount | Should -Be 50000

            # Write-PulseDataset serializes directly to the atomic output stream. The read
            # path hashes the literal bytes and parses bounded 128-row JSON text batches,
            # avoiding one whole-document UTF-16 string, but its public contract still
            # returns a materialized object array. These are honest measured x1.5 capacity
            # ceilings at this exact 50,000-row/~35MB scale, not arbitrary-size guarantees.
            $result.WriteDeltaMB | Should -BeLessThan $script:PulsePerfWriteMemoryBudgetMB
            $result.ReadDeltaMB | Should -BeLessThan $script:PulsePerfReadMemoryBudgetMB
            $result.WriteSeconds | Should -BeLessThan $script:PulsePerfWriteSecondsBudget
            $result.ReadSeconds | Should -BeLessThan $script:PulsePerfReadSecondsBudget
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Perf: unbatched dataset write characterization' {
    # Each raw Write-PulseDataset call without -ManifestBatch still performs an atomic
    # full-manifest update. This is a fixed-size regression characterization for that
    # compatibility path. It is not the Settings Catalog production path: that collector
    # batches its per-policy entries and flushes one manifest update per expansion chunk.
    It 'writes 200 raw per-policy datasets sequentially within the recorded budget' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $elapsedSeconds = InModuleScope TenantPulse -ArgumentList $storeRoot {
                param($storeRoot)
                $store = New-PulseSnapshotStore -Path $storeRoot
                $response = @(
                    [pscustomobject]@{
                        id              = '0'
                        settingInstance = [pscustomobject]@{
                            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                            settingDefinitionId = 'setting-a'
                            simpleSettingValue  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = 'v' }
                        }
                    }
                )
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                for ($i = 1; $i -le 200; $i++) {
                    $id = '{0:D8}-0000-0000-0000-000000000000' -f $i
                    Write-PulseDataset -Store $store -Name "configurationPolicySettings-$id" -Data $response -ApiVersion 'beta' -Status 'Collected'
                }
                $sw.Stop()
                return $sw.Elapsed.TotalSeconds
            }
            Write-Host ('TENANTPULSE_PERF unbatchedManifestWrites ' + ($elapsedSeconds | ConvertTo-Json -Compress))
            $elapsedSeconds | Should -BeLessThan $script:PulsePerfManifestWriteBudgetSeconds
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'TP10A: streaming persist, batched manifest, fragments, renderer bounds (no invented budget)' {
    It 'round-trips a streamed dataset, batches manifest entries, and keeps ExpandSettings off' {
        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $result = InModuleScope TenantPulse -ArgumentList $storeRoot {
                param($storeRoot)
                $store = New-PulseSnapshotStore -Path $storeRoot
                $rows = 1..8 | ForEach-Object { [pscustomobject]@{ id = "$_"; v = $_ } }
                $expected = ConvertTo-PulseCanonicalJson -InputObject $rows
                Write-PulseDataset -Store $store -Name 'Sample' -Data $rows -ApiVersion 'v1.0' -Status 'Collected'
                $onDisk = [System.IO.File]::ReadAllText((Join-Path $store.DatasetsPath 'Sample.json'))
                $readBack = Read-PulseDataset -Store $store -Name 'Sample'

                $batch = [System.Collections.Generic.List[object]]::new()
                Write-PulseDataset -Store $store -Name 'BatchA' -Data @([pscustomobject]@{ id = 'a' }) -ApiVersion 'v1.0' -Status 'Collected' -ManifestBatch $batch
                Write-PulseDataset -Store $store -Name 'BatchB' -Data @([pscustomobject]@{ id = 'b' }) -ApiVersion 'v1.0' -Status 'Collected' -ManifestBatch $batch
                $beforeBatch = Get-PulseSnapshotManifest -Store $store
                Set-PulseManifestEntry -Store $store -DatasetEntries $batch.ToArray()
                $afterBatch = Get-PulseSnapshotManifest -Store $store

                $fragRows = @(
                    [pscustomobject]@{ policyId = 'p1'; settingPath = 's/1'; instanceId = '0'; nameResolved = $true; redacted = $false }
                    [pscustomobject]@{ policyId = 'p2'; settingPath = 's/1'; instanceId = '0'; nameResolved = $true; redacted = $false }
                )
                $fid = New-PulseExpansionFragmentId -StartOrdinal 0 -EndOrdinal 1 -PolicyIds @('p1', 'p2')
                $null = Write-PulseExpansionFragment -Store $store -Name 'settingsCatalog' -FragmentId $fid -Rows $fragRows
                $merged = Merge-PulseExpansionFragments -Store $store -Name 'settingsCatalog' -FragmentIds @($fid) -Gaps @() -PolicyCount 2

                [pscustomobject]@{
                    BytesMatch     = ($onDisk -eq $expected)
                    ReadCount      = $readBack.Count
                    BatchDeferred  = -not $beforeBatch.datasets.Contains('BatchA')
                    BatchApplied   = $afterBatch.datasets.Contains('BatchA') -and $afterBatch.datasets.Contains('BatchB')
                    MergeRows      = $merged.RowCount
                    ExpandSwitch   = (Get-Command Get-PulseTenantSnapshot).Parameters['ExpandSettings'].SwitchParameter
                    NoMaxParallel  = -not (Get-Command Invoke-PulseSettingsCatalogExpansion).Parameters.ContainsKey('MaxParallel')
                }
            }

            $result.BytesMatch | Should -BeTrue
            $result.ReadCount | Should -Be 8
            $result.BatchDeferred | Should -BeTrue
            $result.BatchApplied | Should -BeTrue
            $result.MergeRows | Should -Be 2
            $result.ExpandSwitch | Should -BeTrue
            $result.NoMaxParallel | Should -BeTrue
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
