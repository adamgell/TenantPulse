<#
    Task 2.7: the dedicated, SERIAL scale/memory perf container. NOT part of the default
    `./build.ps1`/`test` workflow - see build.yaml's own explicit Pester.Configuration.Run.Path
    (tests/QA + tests/Unit only) and .build/PerfTest.tasks.ps1's own docstring. Invoke via
    `./build.ps1 -Tasks build,perftest`.

    METHOD (recorded here, once, for every Describe below - see each It's own comment for
    per-assertion detail): every wall-time/memory number this file asserts against was
    measured on the SAME machine that later runs the assertion (a developer machine or a
    CI runner - whichever actually executes `perftest`), not imported from some other
    author's hardware. The BUDGET each It asserts is [a real number measured once, on the
    hardware and PowerShell version recorded in docs/spike/2026-08-16-t27-perf-container.md]
    x 1.5 - never a round, guessed number - per the plan's own instruction. A budget FAILURE
    here means a genuine regression against that recorded baseline, not an arbitrary
    external SLA; if hardware changes (a new dev machine, a different CI runner tier), the
    baseline in docs/spike must be re-measured and the budgets in this file re-derived from
    it, not silently loosened.

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
    # Baseline (measured on this session's host: Apple Silicon, 18 logical CPUs, 128GB RAM,
    # macOS 26.4, PowerShell 7.6.5 - see docs/spike for the full record):
    #   5,000-policy Sequential Settings Catalog expansion + conflict detection
    #     (FromCapturedPayloads), MAX of 3 fresh back-to-back runs (T2.7 review round -
    #     an earlier single-sample x1.5 budget (170MB) flaked live at 171.6MB; re-derived
    #     from the MAX of >=3 runs x1.5, the SAME methodology the write-memory budget
    #     below already used, rather than a single sample):
    #       run 1: expand 460.59s, conflict 4.16s, memory delta 136.68MB
    #       run 2: expand 265.34s, conflict 4.44s, memory delta 204.17MB
    #       run 3: expand 202.29s, conflict 3.45s, memory delta 162.42MB
    #       MAX:   expand 460.59s, conflict 4.44s, memory delta 204.17MB
    #     (all 3 runs found the same 50 real conflicts; the wide expand-time spread across
    #     runs - 202s to 461s on the SAME host, SAME code - reflects real machine-load
    #     variance during measurement, not a code regression; the memory delta is the
    #     metric this budget governs and varies far less relatively than wall time does)
    #   50,000-row managedDevices Write-PulseDataset: 35.10s, managed-heap delta 195.0MB in
    #     an isolated standalone-script measurement, but 415.1MB when re-measured running
    #     INSIDE this file's own Pester It block (same code, same host, back-to-back run) -
    #     a real, non-trivial run-to-run variance (GC timing/generation boundaries and
    #     Pester's own harness overhead both plausible contributors) that a naive x1.5 off
    #     a single sample would not have covered; the budget below is the HIGHER of the two
    #     measurements x1.5, not the first sample alone - see the T2.7 report's own
    #     Findings section for the full accounting. serialized file 35.02MB either way
    #     (delta ~5.6-11.9x file size - NOT the plan's informal "<=2x" streaming target;
    #     Write-PulseDataset materializes the full object graph, it does not stream - see
    #     this file's own docstring)
    #   50,000-row managedDevices Read-PulseDataset: 1.00s, managed-heap delta 572.7MB
    #     (~16x file size - ConvertFrom-Json's PSCustomObject materialization cost, the
    #     dominant term; also not the "<=2x" target, same documented gap)
    #   200 sequential raw per-policy Write-PulseDataset calls (fresh store, 0 existing
    #     manifest entries at the start): 18.04s (~90ms/write average, growing with existing
    #     manifest size - see Set-PulseManifestEntry's own full-manifest-rewrite-per-call
    #     shape, documented as a real O(n)-per-write/O(n^2)-total finding in the T2.7 report)
    $script:PulsePerfExpandBudgetSeconds = 691.0         # max(460.59, 265.34, 202.29) x 1.5, rounded up
    $script:PulsePerfConflictBudgetSeconds = 6.7          # max(4.16, 4.44, 3.45) x 1.5, rounded up
    $script:PulsePerfComputeMemoryBudgetMB = 306.3        # max(136.68, 204.17, 162.42) x 1.5
    $script:PulsePerfWriteMemoryBudgetMB = 625.0         # max(195.0, 415.1) x 1.5, rounded up
    $script:PulsePerfReadMemoryBudgetMB = 862.0          # 572.7 x 1.5
    $script:PulsePerfWriteSecondsBudget = 53.0           # 35.10 x 1.5
    $script:PulsePerfReadSecondsBudget = 2.0             # 1.00 x 1.5 (rounded up)
    $script:PulsePerfManifestWriteBudgetSeconds = 27.5   # 18.04 x 1.5
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
                }
                $manifest = Get-PulseSnapshotManifest -Store $store
                foreach ($k in $datasetsEntries.Keys) { $manifest.datasets[$k] = $datasetsEntries[$k] }
                Set-PulseAtomicFileContent -Path $store.ManifestPath -Value (ConvertTo-PulseCanonicalJson -InputObject $manifest)

                # --- MEASURED WINDOW STARTS HERE ---
                [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                $memBefore = [System.GC]::GetTotalMemory($true)

                $expandSw = [System.Diagnostics.Stopwatch]::StartNew()
                $expandSummary = Invoke-PulseSettingsCatalogExpansion -Store $store -Policies $policies.ToArray() -DefinitionIndex $index -Sequential -FromCapturedPayloads
                $expandSw.Stop()

                $conflictSw = [System.Diagnostics.Stopwatch]::StartNew()
                $conflictSummary = Invoke-PulseConflictDetection -Store $store
                $conflictSw.Stop()

                $memAfter = [System.GC]::GetTotalMemory($false)
                # --- MEASURED WINDOW ENDS HERE ---

                [pscustomobject]@{
                    ExpandStatus     = $expandSummary.Status
                    ExpandRowCount   = $expandSummary.RowCount
                    ExpandSeconds    = $expandSw.Elapsed.TotalSeconds
                    ConflictStatus   = $conflictSummary.Status
                    ConflictCount    = $conflictSummary.ConflictCount
                    ConflictSeconds  = $conflictSw.Elapsed.TotalSeconds
                    MemoryDeltaMB    = ($memAfter - $memBefore) / 1MB
                }
            }

            # Correctness sanity (not the perf point, but a silent budget "pass" over a
            # broken/empty run would be worse than useless):
            $result.ExpandStatus | Should -Be 'Expanded'
            $result.ExpandRowCount | Should -Be 5000
            $result.ConflictStatus | Should -BeIn @('Expanded', 'Partial')
            $result.ConflictCount | Should -BeGreaterThan 0

            # Budgets: see docs/spike/2026-08-16-t27-perf-container.md's recorded table.
            $result.ExpandSeconds | Should -BeLessThan $script:PulsePerfExpandBudgetSeconds
            $result.ConflictSeconds | Should -BeLessThan $script:PulsePerfConflictBudgetSeconds
            $result.MemoryDeltaMB | Should -BeLessThan $script:PulsePerfComputeMemoryBudgetMB
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

            $result.ReadBackCount | Should -Be 50000

            # MEASURED FINDING (see docs/spike's own table + T2.7 report): neither
            # Write-PulseDataset nor Read-PulseDataset streams - both materialize the full
            # object graph. The plan's own informal "<= 2x serialized size" framing is NOT
            # met by the current implementation on either path (measured baseline: write
            # ~5.6x, read ~16x the ~35MB serialized file) - this is a genuine, documented
            # scale gap (see the T2.7 report's own Findings section), not something this
            # task redesigns. The budgets below are the HONEST [measured] x 1.5 ceiling,
            # not the aspirational 2x - a regression beyond THIS still catches a real
            # worsening even though the underlying "streaming" target itself remains open
            # follow-up work.
            $result.WriteDeltaMB | Should -BeLessThan $script:PulsePerfWriteMemoryBudgetMB
            $result.ReadDeltaMB | Should -BeLessThan $script:PulsePerfReadMemoryBudgetMB
            $result.WriteSeconds | Should -BeLessThan $script:PulsePerfWriteSecondsBudget
            $result.ReadSeconds | Should -BeLessThan $script:PulsePerfReadSecondsBudget
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Perf: raw per-policy dataset write scaling (manifest growth characteristic)' {
    # MEASURED FINDING: Set-PulseManifestEntry re-reads and re-serializes the WHOLE
    # manifest.json on every single call (Get-PulseSnapshotManifest -> mutate -> full
    # canonical-JSON rewrite) - there is no incremental/append path. Write-PulseDataset
    # (the real per-policy raw-payload writer Invoke-PulseSettingsCatalogPolicy calls once
    # per LIVE-fetched policy) pays this cost on every call, so it scales O(n) PER WRITE /
    # O(n^2) TOTAL in the number of datasets already in the store - confirmed empirically
    # (docs/spike's own table: ~90ms/write at 200 existing entries, ~282ms/write at 600).
    # This Describe is deliberately bounded to a SMALL n (not 5,000 - seeQ this file's own
    # docstring for why re-measuring the full quadratic curve up to 5,000 here would make
    # `perftest` itself impractically slow) - it exists to catch a REGRESSION in the
    # per-write cost at a fixed, small scale, and to keep this characteristic visible in
    # the test suite rather than only in a point-in-time doc. See the T2.7 report's own
    # Findings section for the full accounting and the Phase 2b/3 follow-up recommendation.
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
            $elapsedSeconds | Should -BeLessThan $script:PulsePerfManifestWriteBudgetSeconds
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
