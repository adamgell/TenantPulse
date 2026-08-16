# TenantPulse

TenantPulse is a read-only tenant health engine for Microsoft Intune and Entra. It
evaluates a tenant against a versioned set of checks and produces a deterministic,
pseudonymized, scored snapshot.

TenantPulse reads a tenant exclusively through [GraphKit](https://github.com/AdamGell/GraphKit)'s
read-class descriptors. It does not use the Microsoft Graph PowerShell SDK, does not call
`Connect-MgGraph`, and does not construct Graph URIs of its own.

## Status

This module is under active development. The public surface, check catalog, and scoring
model are not yet stable.

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
