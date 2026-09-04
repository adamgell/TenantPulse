# TenantPulse scale/performance container - measured baselines

This document is the evidence source for every numeric limit in
`tests/Perf/ScaleAndMemory.Tests.ps1`. The active limits are regression budgets for one
recorded machine and workload, not service-level objectives or guarantees for arbitrary
tenant sizes. Each limit is the largest of three quiescent samples multiplied by `1.5` and
rounded upward.

Run the serial container with:

```powershell
./build.ps1 -Tasks build,perftest
```

It is intentionally excluded from the default `test` task. If the runner hardware or the
fixture contract changes materially, take three new quiet samples, record the exact source
revision and environment here, and derive the limits from those measurements. Do not
silently loosen a failing limit.

## Active rebaseline - 2026-09-04

### Source and environment

- Source revision: `115b299` (`fix: bound captured expansion manifest work`).
- Apple Silicon Mac, arm64, 18 logical CPUs, 128 GB RAM.
- macOS 26.6.2 (build 25G83).
- PowerShell 7.6.5.
- Three complete, consecutive `perftest` executions with no other heavy test suite running.
- Graph was mocked by using `-FromCapturedPayloads`; fixture seeding occurred before each
  measured window.
- Managed-memory metric: forced full collection before the baseline, then
  `[System.GC]::GetTotalMemory($false)` after the measured operation.
- `PeakWorkingSet64` is not a budget metric because it returned zero on the original
  measurement host and was therefore not a reliable cross-run signal.

### Fixture correctness contract

The Settings Catalog fixture contains 5,000 policies and 50 distinct setting definition
IDs. Every policy has both mandatory captured inputs:

- `configurationPolicySettings-<policyId>`
- `configurationPolicyAssignments-<policyId>`

That means the manifest contains exactly 10,000 governed datasets. Each run must produce
5,000 expanded rows, 50 conflicts, a 50-definition presence index, and zero expansion,
conflict, or index gaps. A fast run with missing inputs is a failed correctness run, not a
performance sample.

### Recorded samples

| Run | Expand seconds | Conflict seconds | Expand + conflict heap delta | Index max seconds | Index max heap delta |
|---|---:|---:|---:|---:|---:|
| 1 | 19.2793692 | 8.5926654 | 132.3634262 MB | 6.1008933 | 139.2332306 MB |
| 2 | 16.5498380 | 8.0327255 | 135.0012817 MB | 6.8465455 | 140.3563614 MB |
| 3 | 16.5622394 | 7.2613224 | 130.4871292 MB | 5.9603543 | 138.9642029 MB |
| **MAX** | **19.2793692** | **8.5926654** | **135.0012817 MB** | **6.8465455** | **140.3563614 MB** |

Each `Index max` cell is itself the maximum of three back-to-back index builds over the
already-produced expansion family in that full run.

The 50,000-row synthetic `managedDevices` dataset serialized to exactly 36,716,672 bytes:

| Run | Write seconds | Write heap delta | Read seconds | Read heap delta | Rows returned |
|---|---:|---:|---:|---:|---:|
| 1 | 44.5210701 | 220.0756989 MB | 2.2988119 | 511.7446976 MB | 50,000 |
| 2 | 50.0731926 | 220.1258163 MB | 2.7434971 | 511.7775497 MB | 50,000 |
| 3 | 45.0939744 | 154.9232712 MB | 2.4049486 | 506.4495010 MB | 50,000 |
| **MAX** | **50.0731926** | **220.1258163 MB** | **2.7434971** | **511.7775497 MB** | **50,000** |

The compatibility-path characterization that performs 200 sequential dataset writes
without `-ManifestBatch` measured 11.4581116, 13.7353299, and 12.4438527 seconds. Its
maximum is 13.7353299 seconds.

### Active budgets

| Metric | Recorded maximum | `MAX x 1.5`, rounded upward |
|---|---:|---:|
| Settings expansion | 19.2793692 s | 29.0 s |
| Conflict detection | 8.5926654 s | 13.0 s |
| Expansion + conflict heap delta | 135.0012817 MB | 203.0 MB |
| Presence-index build | 6.8465455 s | 10.3 s |
| Presence-index heap delta | 140.3563614 MB | 211.0 MB |
| 50,000-row write | 50.0731926 s | 75.2 s |
| 50,000-row write heap delta | 220.1258163 MB | 331.0 MB |
| 50,000-row read | 2.7434971 s | 4.2 s |
| 50,000-row read heap delta | 511.7775497 MB | 768.0 MB |
| 200 unbatched writes | 13.7353299 s | 21.0 s |

### Interpretation

The expansion improvement is structural. Captured expansion now pins one validated,
call-scoped manifest snapshot and reuses it for settings and assignment reads instead of
reparsing and adapting the same 2.67 MB manifest for every dataset. Native dictionary
access also replaced the former property-accessor shim whose repeated adaptation became
quadratic at this scale.

The corrected fixture is intentionally more expensive for conflict and index work than
the earlier fixture: proven-empty assignment payloads are now present for every policy, so
the pipeline performs the real assignment-aware fold rather than treating half the inputs
as absent. The stricter 10,000-entry fixture is the one the active budgets govern.

`Write-PulseDataset` publishes canonical JSON directly to an atomic file stream and hashes
the bytes written. It still receives a materialized PowerShell object collection, so the
write number is a capacity measurement at this specific row/property shape, not proof of
constant-memory behavior.

`Read-PulseDataset` first hashes the literal file bytes, then parses from a file stream.
Array elements are converted from JSON in bounded 128-row text batches, avoiding a single
whole-document UTF-16 string and the former 50,000 individual cmdlet invocations. The
public contract still returns all 50,000 objects as one materialized array, which is why
the read heap delta remains much larger than the serialized file. The 768 MB limit is an
honest regression ceiling at this exact ~35 MB scale, not a claim that larger datasets are
bounded by 768 MB.

The 200-write test describes the unbatched compatibility path. It is not the production
Settings Catalog expansion path: that path passes a `ManifestBatch` through each policy
write and publishes one manifest update per expansion chunk. The historical claim that
Settings Catalog necessarily paid one full manifest rewrite per policy is no longer true.

## Superseded 2026-08-16 baseline

The original baseline remains summarized here for provenance but does not set current
limits. It was measured on macOS 26.4 (build 25E246), PowerShell 7.6.5, and an older source
revision. Most importantly, its 5,000-policy fixture recorded only the settings payload,
not the now-mandatory assignment payload, so it exercised 5,000 manifest entries rather
than the current 10,000-entry contract.

| Historical metric | Recorded value | Former budget |
|---|---:|---:|
| Expansion max of three | 460.59 s | 691 s |
| Conflict max of three | 4.44 s | 6.7 s |
| Expansion + conflict heap max | 204.17 MB | 306.3 MB |
| Presence-index max | 3.244 s / 116.23 MB | 4.9 s / 174.5 MB |
| 50,000-row write | 35.10 s / 195.0 MB standalone; 415.1 MB in Pester | 53 s / 625 MB |
| 50,000-row read | 1.00 s / 572.7 MB | 2 s / 862 MB |
| 200 unbatched writes | 18.04 s | 27.5 s |

Those values are not comparable to the active measurements as performance deltas because
the source, operating system, parser, manifest access strategy, and fixture correctness
contract all changed. They are retained only to explain why the test previously carried
much wider and, in several places, stale limits.

## Historical live-worker note

An early live Ivy24 experiment found that the then-available `-MaxParallel 4` Settings
Catalog path did not complete a 20-policy slice within 9m35s, while `-Sequential` completed
the slice in 2.30s. The runspace implementation and both switches were later removed, so
this result is historical context rather than a current runner recommendation. No live
tenant was accessed for the 2026-09-04 rebaseline.
