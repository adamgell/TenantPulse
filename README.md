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
- [GraphKit](https://github.com/AdamGell/GraphKit) (not yet published to PSGallery; see
  Development below)

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
(`source/TenantPulse.psd1`) but is intentionally omitted from `RequiredModules.psd1`
(the Sampler build-dependency file): GraphKit is not yet published to PSGallery, so
`Resolve-Dependency` cannot resolve it there. Until GraphKit is published, make it
available on `$env:PSModulePath` locally (for example, by building GraphKit and adding
its `output/module/GraphKit` directory to the path) before importing TenantPulse.

## Project layout

- `source/` — module source (Sampler/ModuleBuilder layout)
- `source/Data/` — check descriptors and other non-code data assets
- `tests/QA/` — module quality gates (manifest validity, clean-process import, changelog format)
- `scripts/` — standalone operational scripts

## License

MIT. See [LICENSE](LICENSE).
