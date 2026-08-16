# TenantPulse

TenantPulse is a read-only tenant health engine for Microsoft Intune and Entra. It
evaluates a tenant against a versioned set of checks and produces a deterministic,
pseudonymized, scored snapshot.

TenantPulse reads a tenant exclusively through [GraphKit](https://github.com/AdamGell/GraphKit)'s
read-class descriptors. It does not use the Microsoft Graph PowerShell SDK, does not call
`Connect-MgGraph`, and does not construct Graph URIs of its own.

## Status

**Phase 1 engine: complete.** Collection, evaluation, scoring, and the deterministic
pseudonymized JSON report all work end to end through `Invoke-PulseAssessment`, and the
whole pipeline has been **live-smoke verified against a real tenant** (the Ivy24 lab
tenant, Task 1.11): a fresh `Invoke-PulseAssessment -ProfileId ivy24` run collected real
Intune data (`deviceCompliancePolicies`, `deviceConfigurations`, `deviceManagementSettings`,
`managedDevices`), degraded a permission gap honestly (`conditionalAccessPolicies` Skipped
with reason `permission-denied: Policy.Read.All`, its dependent checks NotApplicable rather
than silently wrong), left every not-yet-released GraphKit descriptor Skipped with
`descriptor-pending`, produced real Pass findings from the data that did collect, and
re-evaluating the same snapshot via `-FromSnapshot` reproduced a byte-identical findings
JSON. The tenant identifier appeared nowhere in the output tree except as its `tp-...`
pseudonym. The live run also surfaced a real GraphKit 0.1.0 error-shape gap (its
`Get-GraphObject` throw carries no structured status code or `403`/`forbidden` text on
failure) that made a genuine permission denial misclassify as a generic failure instead of
the honest-degradation path above; that gap is now fixed in the collector (a supplemental,
read-only `Invoke-GraphOperation` call recovers the real status code) with a regression
test pinning the fix against the real shape.

**Not yet done - three things, all operator actions, none of them code:**

1. **GraphKit 0.1.1 release.** TenantPulse currently pins GraphKit 0.1.0 (see
   Requirements below); the live gate above ran clean against 0.1.0 as installed, so this
   is a version-bump/republish step, not a blocking defect.
2. **`Policy.Read.All` grant on the Ivy24 lab app registration.** Without it,
   Conditional-Access-backed checks (`TP.ENT.0003`-`0005`) stay honestly NotApplicable
   rather than assessed - the pipeline proved it degrades correctly here, but coverage on
   that category stays at 0% until the grant lands.
3. **First publish to PSGallery**, which needs a PSGallery API key. Publish tooling is
   ready (`scripts/Publish-TenantPulsePackage.ps1`, ported from GraphKit's own publish
   script and adapted to PSGallery) but defaults to a dry run and refuses to publish
   without an explicit `-NuGetApiKey` and `-Confirm`; Adam runs it.

## Requirements

- PowerShell 7.4 or later
- [GraphKit](https://github.com/AdamGell/GraphKit) 0.1.0 or later (published to PSGallery)

## Development

Dependencies and build tools are restored through the repository scripts. Run the test
suite through the build entry point rather than invoking Pester directly:

```powershell
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -Tasks build
./build.ps1 -Tasks test
./build.ps1 -Tasks pack
```

The `pack` task produces the package from the tested build output. Generated artifacts
are written under `output/` and should not be edited directly.

`scripts/Publish-TenantPulsePackage.ps1` publishes an already-packed `.nupkg` to
PSGallery. It never builds and enforces pack-first-then-verify: it compares the SHA-256
of the `TenantPulse.psm1` inside the package against the SHA-256 of the built module the
test run actually imported, and refuses to publish on a mismatch (packaging bytes nothing
tested is exactly the failure this exists to prevent). It defaults to a dry run - it
prints what it would publish and does not call PSGallery - and only publishes for real
when given both an explicit `-NuGetApiKey` and `-Confirm`. **Adam runs this step**; it is
not part of `./build.ps1` or CI.

GraphKit is declared as a runtime dependency in the module manifest
(`source/TenantPulse.psd1`) and pinned to the same version in `RequiredModules.psd1`
(the Sampler build-dependency file), so `./build.ps1 -ResolveDependency` resolves it from
PSGallery like every other build dependency - no manual `$env:PSModulePath` setup needed.

Unit tests never import real GraphKit: every GraphKit command TenantPulse calls
(`Get-GraphContext`, `Get-GraphObject`, `Invoke-GraphOperation`, `Get-GraphOperation`) is
stubbed inside the TenantPulse module scope in each test file's `BeforeAll`, with a
default mock that throws registered before any test-specific mock (GraphKit's own test
convention). GraphKit is still importable in the test environment (it is a
`RequiredModules` dependency of TenantPulse itself), but the module-scope stubs shadow it
for every call TenantPulse's own code makes - that shadowing, not the absence of
GraphKit, is what keeps the tests deterministic and independent of a live tenant.

## Project layout

- `source/` — module source (Sampler/ModuleBuilder layout)
- `source/Data/` — check descriptors and other non-code data assets
- `tests/QA/` — module quality gates (manifest validity, clean-process import, changelog format)
- `scripts/` — standalone operational scripts

## License

MIT. See [LICENSE](LICENSE).
