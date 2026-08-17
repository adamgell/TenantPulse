# Task 2.7 perf/scale/memory container - measured baseline

Hardware/method for every budget asserted in `tests/Perf/ScaleAndMemory.Tests.ps1`
(`./build.ps1 -Tasks build,perftest`, not part of the default test workflow). Every budget
in that file is `[a number measured here] x 1.5` headroom, per the plan's own instruction -
never a guessed round number.

## Hardware / environment

- Apple Silicon Mac, 18 logical CPUs, 128 GB RAM, macOS 26.4 (build 25E246), arm64.
- PowerShell 7.6.5.
- TenantPulse module built from this task's own source tree (`./build.ps1 -Tasks build`).
- Method: `-FromCapturedPayloads` (mocked Graph - no network call) for the 5,000-policy
  compute test; a bulk-seeded raw-dataset fixture (writing dataset files + one manifest
  update directly, bypassing `Write-PulseDataset`'s own per-call cost - see below for why
  that per-call cost is measured SEPARATELY, not folded into this number) stands in for
  "the fetch already happened." Memory metric: `[System.GC]::GetTotalMemory($true)` delta
  (forced full collection before/after) - the managed-heap cost directly attributable to
  the operation. `[System.Diagnostics.Process]::PeakWorkingSet64` was also captured but
  consistently returned 0 on this measurement host (unsupported/unreliable in this
  sandboxed environment) - not used as a budget metric for that reason.

## 1. 5,000-policy Settings Catalog expansion + conflict detection (mocked Graph, real compute)

**Budget methodology (T2.7 review round)**: a single-sample `x1.5` budget (from an earlier
202.05s/170MB baseline) flaked live in CI at 171.6MB against a 170MB budget - one sample's
`x1.5` headroom did not cover this host's own real run-to-run variance. Re-derived from the
**MAX of 3 fresh, independent, back-to-back runs, `x1.5`** - the same methodology section 2's
write-memory budget already used (that one also needed the max of two runs, not one, for the
identical reason). Three full runs, same host, same build, run consecutively with no other
change in between:

| Run | `Invoke-PulseSettingsCatalogExpansion` elapsed | `Invoke-PulseConflictDetection` elapsed | Managed-heap delta (expand start -> conflict end) | Conflicts found |
|---|---|---|---|---|
| 1 | 460.59 s | 4.16 s | 136.68 MB | 50 |
| 2 | 265.34 s | 4.44 s | 204.17 MB | 50 |
| 3 | 202.29 s | 3.45 s | 162.42 MB | 50 |
| **MAX** | **460.59 s** | **4.44 s** | **204.17 MB** | - |
| **Budget (`MAX x1.5`)** | **691 s** | **6.7 s** | **306.3 MB** | - |

All three runs are 5,000 policies, 1 setting each, 50 distinct `settingDefinitionId`s
cycling 3 values each (guarantees real conflicts, and all three runs found the identical 50
- correctness is stable even though timing is not). The wide expand-time spread across runs
on the exact same host and code (202s-461s, a >2x range) is real machine-load variance
during measurement (this host was running other concurrent work at the time), not a code
regression - see the memory-delta column, which is the metric this budget actually governs
and which varies far less, relatively, than wall time does across the same three runs.

**5,000 x ~300ms-fetch-if-it-were-real would be ~25 minutes (T2.0 spike math) - that time is
entirely the mocked-away network fetch.** The number that matters here is the
EXPANSION+MERGE+CONFLICTS compute alone, no network at all.

**Real finding, NOT folded into the above**: this measurement deliberately bulk-seeds the
5,000 raw per-policy captured-payload files directly (bypassing `Write-PulseDataset`'s own
manifest read-modify-write) because that per-write cost is itself a separate, real,
O(n)-per-write characteristic - see section 3.

## 2. 50,000-row `managedDevices` dataset write+read memory ceiling

**Characterization (T2.7 review clarification)**: this is a CAPACITY BASELINE at one
tested scale (50,000 rows), not a peak-footprint GUARANTEE for arbitrary dataset sizes.
The numbers below describe what this specific, representative synthetic dataset costs on
this specific host, with headroom applied on top of that one measurement (widened to two
measurements for the write side after observing real run-to-run variance - see below); they
do not establish a validated linear (or any other) scaling law all the way from 0 to 50,000
rows, and they must not be read as "this module never exceeds ~600 MB no matter how large a
`managedDevices` dataset gets." A materially larger real tenant's `managedDevices` dataset
(more rows, and/or more/larger properties per row than this test's 18 synthetic ones) should
be expected to cost proportionally more, not to be capped by this budget - re-measure at the
actual scale in question before relying on a number from this table for capacity planning
beyond the ~50,000-row/~35 MB regime it was measured at.

| Stage | Elapsed | Managed-heap delta | File size |
|---|---|---|---|
| `Write-PulseDataset` (50,000 synthetic device rows, 18 properties each) | 35.10 s (standalone script) / 39.57-40.39 s (in-Pester) | **195.0 MB** (standalone script) / **415.1 MB** (in-Pester, same code, same host, back-to-back) | 35.02 MB |
| `Read-PulseDataset` | 1.00 s | **572.7 MB** | (same file) |

**Real, non-trivial run-to-run variance on the write side** (195 MB vs 415 MB for the exact
same operation) - plausible contributors are GC generation-boundary timing and Pester's own
harness overhead; the committed budget uses the HIGHER of the two measurements x1.5
(625 MB), not the first sample alone, specifically because a single-sample x1.5 would not
have covered the second run.

**MEASURED FINDING - the plan's own informal "<=2x serialized size" streaming target is NOT
met by the current implementation, on EITHER path**: write costs ~5.6-11.9x the serialized
file size, read costs ~16x. Neither `Write-PulseDataset` nor `Read-PulseDataset` streams -
both materialize the full object graph (`ConvertTo-PulseCanonicalJson`'s `StringBuilder` +
UTF8 byte array on write; `ConvertFrom-Json`'s full `PSCustomObject` graph on read, which is
the dominant cost). This is a genuine, documented scale gap for a future task, not
something T2.7 redesigns - the perf container's own budgets are the HONEST measured
ceiling (with headroom), not the aspirational 2x, so a future regression is still caught
even though the underlying "make this actually stream" work remains open.

## 3. Raw per-policy dataset write scaling (manifest growth characteristic)

Measured by timing successive `Write-PulseDataset` calls into a store whose `manifest.json`
already holds N prior dataset entries (each call re-reads, mutates, and re-serializes the
WHOLE manifest - `Set-PulseManifestEntry`'s own `Get-PulseSnapshotManifest` -> mutate ->
`ConvertTo-PulseCanonicalJson` -> atomic rewrite, unconditionally, every call - there is no
incremental/append path):

| Existing manifest entries at call time | Elapsed for that write | Elapsed / write across the run |
|---|---|---|
| ~0 -> 200 | 18.04 s for 200 writes | 90.19 ms/write average |
| 200 -> 400 | 16.78 s for 200 writes | 174.07 ms/write average |
| 400 -> 600 | 21.61 s for 200 writes | 282.14 ms/write average |

Roughly linear per-write growth (~0.42-0.47 ms per existing manifest entry), i.e. **O(n) per
write / O(n^2) total** as a snapshot's own manifest grows. `perftest`'s own committed
regression (`tests/Perf/ScaleAndMemory.Tests.ps1`) is bounded to 200 writes from an empty
store (18.04 s baseline, 27.5 s budget) rather than re-running the full curve up to 5,000 -
at the ~0.42-0.47 ms/entry growth rate measured above, extrapolating this O(n^2) curve out
to a 5,000-dataset store would run the perf container itself for many minutes on every
`perftest` invocation, which is not a workable regression-test cost for a characteristic
this section already establishes analytically.

**This is a real, production-relevant characteristic, not just a test-harness artifact**:
`Invoke-PulseSettingsCatalogPolicy` calls `Write-PulseDataset` once per LIVE-fetched policy
(the redacted raw `configurationPolicySettings-<id>` write), so a real tenant run pays this
cost on every policy, growing as the run progresses. See `docs/STATUS.md`'s own Phase 2
live-gate section for the real-tenant numbers this produced against Ivy24 (781 policies).

## 4. Bounded-worker measurement: confirming `-MaxParallel 4`'s default

No live-network unit test can honestly reproduce GraphKit's own real per-call latency and
throttling inside `perftest` (perf tests must stay network-free per this file's own MOCKED
GRAPH docstring) - the default is instead justified analytically, from two already-measured
sources plus one live-gate finding that changes the recommendation:

- GraphKit's own `GraphThrottleCoordinator` (`source/Private/GraphThrottleCoordinator.ps1`)
  starts each throttle scope (tenant+app+ThrottleClass) at `InitialConcurrency = 2`, floors
  at 1, and caps at 8 (`Cap = 8`) - `-MaxParallel 4` sits comfortably inside that adaptive
  range, above the initial 2 and with headroom under the 8 cap for the coordinator's own
  additive-increase-on-success behavior.
- T2.0's own spike measured Ivy24's real per-policy `/settings` latency at mean 298 ms / p99
  430 ms - network-latency-bound, not CPU-bound - so parallelism's theoretical benefit is
  hiding that latency, up to the coordinator's own concurrency ceiling.

**T2.7 live-gate finding, supersedes the theoretical case above**: `-MaxParallel 4` against
the REAL Ivy24 tenant did not complete even a 20-policy slice within 9m35s (killed) - the
RunspacePool's own worker isolation means each worker re-imports GraphKit into its own
runspace (`$sessionState.ImportPSModule`), which almost certainly means GraphKit's
token-cache and `GraphThrottleCoordinator` state are NOT shared across workers (each is a
fresh, per-runspace module instance) - four independently-unaware workers hammering the
same tenant with no shared adaptive backoff is a plausible root cause for severe real
throttling/backoff, though this was not fully root-caused within this task (see the T2.7
report's own Findings section). The SAME 20-policy slice completed via `-Sequential` in
2.30 s (0.12 s/policy - even better than the T2.0 spike's own mean). **Recommendation,
pending a proper fix**: prefer `-Sequential` for any live-tenant Settings Catalog expansion
until the RunspacePool/shared-state issue is understood and fixed; this task does not
change `-MaxParallel`'s own default (still 4, and still correct/fast against
`-FromCapturedPayloads` mocked data, which is what `perftest` and most of the existing unit
suite exercise) but does NOT recommend relying on it for a live run today.
