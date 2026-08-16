BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Export-PulseReport' {
    BeforeEach {
        $script:outputRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $script:outputRoot -ItemType Directory -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'throws for a -FindingsPath that does not exist' {
        { Export-PulseReport -FindingsPath (Join-Path $script:outputRoot 'missing.json') -Format Json -OutputPath $script:outputRoot } | Should -Throw
    }

    It 'rejects a -Format value other than Json' {
        $findingsPath = Join-Path $script:outputRoot 'tenantpulse-findings.json'
        Set-Content -LiteralPath $findingsPath -Value '{}' -NoNewline

        { Export-PulseReport -FindingsPath $findingsPath -Format 'Xml' -OutputPath $script:outputRoot } | Should -Throw
    }

    It 'writes tenantpulse-findings.json under -OutputPath, creating the directory if needed' {
        $sourceDocument = InModuleScope TenantPulse {
            ConvertTo-PulseCanonicalJson -InputObject ([pscustomobject]@{
                schemaVersion = '1.0'
                findings      = @()
            })
        }
        $findingsPath = Join-Path $script:outputRoot 'source-findings.json'
        Set-Content -LiteralPath $findingsPath -Value $sourceDocument -NoNewline

        $newOutputPath = Join-Path $script:outputRoot 'nested/output'
        $result = Export-PulseReport -FindingsPath $findingsPath -Format Json -OutputPath $newOutputPath

        $expectedPath = Join-Path $newOutputPath 'tenantpulse-findings.json'
        $result.ReportPaths.Json | Should -Be $expectedPath
        Test-Path -LiteralPath $expectedPath -PathType Leaf | Should -BeTrue
    }

    # Item 2 (final fix wave): parity with Invoke-PulseAssessment's return object.
    It 'returns a FindingsPath property equal to the file it read' {
        $findingsPath = Join-Path $script:outputRoot 'source-findings.json'
        Set-Content -LiteralPath $findingsPath -Value '{}' -NoNewline

        $result = Export-PulseReport -FindingsPath $findingsPath -Format Json -OutputPath $script:outputRoot

        $result.FindingsPath | Should -Be $findingsPath
    }

    # Item 6 (final fix wave): a 7-digit-fraction timestamp must round-trip byte-identical -
    # ConvertFrom-Json's default behavior parses an ISO-8601-looking string into [datetime],
    # which the canonical serializer then reformats at millisecond precision, silently
    # dropping the extra fractional digits.
    It 'round-trips a 7-digit-fraction timestamp byte-identical through the rendered report (final fix wave, item 6)' {
        $sourceDocument = InModuleScope TenantPulse {
            ConvertTo-PulseCanonicalJson -InputObject ([pscustomobject]@{
                schemaVersion = '1.0'
                generatedUtc  = '2026-08-15T00:00:00.1234567Z'
                findings      = @()
            })
        }
        $findingsPath = Join-Path $script:outputRoot 'source-findings.json'
        Set-Content -LiteralPath $findingsPath -Value $sourceDocument -NoNewline

        $result = Export-PulseReport -FindingsPath $findingsPath -Format Json -OutputPath $script:outputRoot

        $renderedRaw = Get-Content -LiteralPath $result.ReportPaths.Json -Raw
        $renderedRaw | Should -Match '2026-08-15T00:00:00\.1234567Z'
        $renderedRaw | Should -Be $sourceDocument
    }

    # CI BLOCKER fix: ConvertFrom-Json's -DateKind parameter does not exist at all on the
    # module's PS 7.4 floor (it shipped in 7.5), so every -DateKind call site is routed
    # through ConvertFrom-PulseJsonPreservingStrings, which feature-detects once and falls
    # back to a JsonDocument-based reader on < 7.5. These tests force BOTH branches to run
    # - regardless of which PowerShell version is actually executing them - by stubbing the
    # feature-detect function's own cache variable directly, and assert the two branches
    # produce BYTE-IDENTICAL canonical-JSON output for the same findings JSON: a 7-digit-
    # fraction timestamp, a unicode string, numbers written as both '1.0' and '1', and
    # empty arrays/objects.
    Context 'ConvertFrom-PulseJsonPreservingStrings: native -DateKind branch vs. JsonDocument fallback branch' {
        BeforeAll {
            $script:findingsJsonForBranchParity = InModuleScope TenantPulse {
                ConvertTo-PulseCanonicalJson -InputObject ([pscustomobject]@{
                    schemaVersion = '1.0'
                    generatedUtc  = '2026-08-15T00:00:00.1234567Z'
                    unicodeText   = 'café ☃ 日本語'
                    numberAsWhole = 1
                    numberAsFloat = 1.0
                    emptyArray    = @()
                    emptyObject   = [pscustomobject]@{}
                    findings      = @(
                        [pscustomobject]@{
                            id       = 'F1'
                            evidence = @(
                                [pscustomobject]@{ identity = 'user@contoso.example'; sortKey = 'user@contoso.example'; detail = [pscustomobject]@{ observedUtc = '2026-08-15T00:00:00.7654321Z' } }
                            )
                        }
                    )
                })
            }
        }

        AfterEach {
            # Reset the feature-detect cache so stubbing one test's branch never leaks into
            # another It block or another test file that imports the same module instance.
            InModuleScope TenantPulse {
                $script:PulseConvertFromJsonSupportsDateKind = $null
            }
        }

        It 'the native -DateKind branch (forced) parses without throwing and preserves the 7-digit timestamp' {
            $rendered = InModuleScope TenantPulse -ArgumentList $script:findingsJsonForBranchParity {
                param($json)
                $script:PulseConvertFromJsonSupportsDateKind = $true
                $document = ConvertFrom-PulseJsonPreservingStrings -Json $json -Depth 64
                ConvertTo-PulseCanonicalJson -InputObject $document
            }

            $rendered | Should -Match '2026-08-15T00:00:00\.1234567Z'
            $rendered | Should -Match '2026-08-15T00:00:00\.7654321Z'
        }

        It 'the JsonDocument fallback branch (forced, regardless of the local PowerShell version) parses without throwing and preserves the 7-digit timestamp' {
            $rendered = InModuleScope TenantPulse -ArgumentList $script:findingsJsonForBranchParity {
                param($json)
                $script:PulseConvertFromJsonSupportsDateKind = $false
                $document = ConvertFrom-PulseJsonPreservingStrings -Json $json -Depth 64
                ConvertTo-PulseCanonicalJson -InputObject $document
            }

            $rendered | Should -Match '2026-08-15T00:00:00\.1234567Z'
            $rendered | Should -Match '2026-08-15T00:00:00\.7654321Z'
        }

        It 'both branches produce byte-identical canonical JSON for the same input (timestamps, unicode, 1 vs 1.0, empty arrays/objects)' {
            $renderedFromNativeBranch = InModuleScope TenantPulse -ArgumentList $script:findingsJsonForBranchParity {
                param($json)
                $script:PulseConvertFromJsonSupportsDateKind = $true
                $document = ConvertFrom-PulseJsonPreservingStrings -Json $json -Depth 64
                ConvertTo-PulseCanonicalJson -InputObject $document
            }
            InModuleScope TenantPulse { $script:PulseConvertFromJsonSupportsDateKind = $null }
            $renderedFromFallbackBranch = InModuleScope TenantPulse -ArgumentList $script:findingsJsonForBranchParity {
                param($json)
                $script:PulseConvertFromJsonSupportsDateKind = $false
                $document = ConvertFrom-PulseJsonPreservingStrings -Json $json -Depth 64
                ConvertTo-PulseCanonicalJson -InputObject $document
            }

            $renderedFromFallbackBranch | Should -Be $renderedFromNativeBranch
        }

        It 'Export-PulseReport itself round-trips byte-identical through the FORCED fallback branch, exactly like the native branch' {
            $findingsPath = Join-Path $script:outputRoot 'branch-parity-findings.json'
            Set-Content -LiteralPath $findingsPath -Value $script:findingsJsonForBranchParity -NoNewline

            InModuleScope TenantPulse { $script:PulseConvertFromJsonSupportsDateKind = $false }
            $result = Export-PulseReport -FindingsPath $findingsPath -Format Json -OutputPath $script:outputRoot
            $renderedRaw = Get-Content -LiteralPath $result.ReportPaths.Json -Raw

            $renderedRaw | Should -Be $script:findingsJsonForBranchParity
        }
    }
}
