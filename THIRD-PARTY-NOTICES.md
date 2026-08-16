# Third-Party Notices

TenantPulse depends on third-party software. This file lists those dependencies and their
licenses. It is a stub: no runtime dependencies have shipped code embedded in this
repository yet, so there are no entries below beyond the modules TenantPulse requires at
install/import time.

## Runtime dependencies

| Component | License | Notes |
|-----------|---------|-------|
| [GraphKit](https://github.com/AdamGell/GraphKit) | MIT | Required module; provides Graph read access. |

## Build/test-only dependencies

Build and test tooling (Sampler, InvokeBuild, ModuleBuilder, Pester, PSScriptAnalyzer,
ChangelogManagement) is resolved via `RequiredModules.psd1` and is not distributed as
part of the built module. See each project's own repository for license terms.
