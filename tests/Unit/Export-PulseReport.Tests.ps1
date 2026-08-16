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
}
