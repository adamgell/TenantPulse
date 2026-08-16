BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphContext { param() }
        function Get-GraphObject { param() }
        function Invoke-GraphOperation { param() }
        function Get-GraphOperation { param() }
    }

    Mock Get-GraphContext -ModuleName TenantPulse { throw 'Get-GraphContext must be mocked in this test.' }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
    Mock Get-GraphOperation -ModuleName TenantPulse { throw 'Get-GraphOperation must be mocked in this test.' }

    # See PublicSurface.Tests.ps1's own note on this same trap: a rule function that must
    # genuinely execute (never mocked) has to be defined in the SAME InModuleScope call that
    # invokes the pipeline, or it will not resolve when Invoke-PulseCheckEvaluation looks it
    # up later.
    function script:Invoke-TestPulseCheck {
        param([hashtable] $Params)

        InModuleScope TenantPulse -ArgumentList (, $Params) {
            param($Params)

            function Test-PulseFixtureInvokeCheckPassRule {
                param($Datasets)
                return New-PulseFinding -Status Pass -Evidence @(@{ Identity = 'policy-1' })
            }

            Invoke-PulseCheck @Params
        }
    }

    function script:New-TestInvokeCheckCatalog {
        @(
            [pscustomobject]@{
                PSTypeName = 'TenantPulse.CheckDescriptor'
                Id         = 'TP.ENT.9001'
                Title      = 'Fixture invoke-check check'
                Category   = 'Entra.ConditionalAccess'
                Severity   = 'Medium'
                Effort     = 'Low'
                Impact     = 'Medium'
                Data       = [pscustomobject]@{ Datasets = @('conditionalAccessPolicies'); Gates = @() }
                Rule       = [pscustomobject]@{ Type = 'Function'; Function = 'Test-PulseFixtureInvokeCheckPassRule' }
                Consulting = [pscustomobject]@{
                    WhatItMeans  = 'What it means.'
                    WhyItMatters = 'Why it matters.'
                    Remediation  = @('Fix it.')
                    PortalLinks  = @('https://example.com/portal')
                }
                References = [pscustomobject]@{ Research = 'docs/research/fixture.md'; Authorities = @('MS.FIXTURE.1') }
                Origin     = $null
            }
            [pscustomobject]@{
                PSTypeName = 'TenantPulse.CheckDescriptor'
                Id         = 'TP.INT.9002'
                Title      = 'Fixture out-of-scope check'
                Category   = 'Intune.Compliance'
                Severity   = 'Medium'
                Effort     = 'Low'
                Impact     = 'Medium'
                Data       = [pscustomobject]@{ Datasets = @('deviceCompliancePolicies'); Gates = @() }
                Rule       = [pscustomobject]@{ Type = 'Function'; Function = 'Test-PulseFixtureInvokeCheckPassRule' }
                Consulting = [pscustomobject]@{
                    WhatItMeans  = 'What it means.'
                    WhyItMatters = 'Why it matters.'
                    Remediation  = @('Fix it.')
                    PortalLinks  = @('https://example.com/portal')
                }
                References = [pscustomobject]@{ Research = 'docs/research/fixture.md'; Authorities = @('MS.FIXTURE.1') }
                Origin     = $null
            }
        )
    }
}

Describe 'Invoke-PulseCheck' {
    BeforeEach {
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        $script:outputRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $script:outputRoot -ItemType Directory -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'throws when neither -Id nor -Category is supplied' {
        { Invoke-PulseCheck -ProfileId 'contoso-tenant-id' -OutputPath $script:outputRoot } | Should -Throw
    }

    It 'throws when -Id is supplied as an empty array' {
        { Invoke-PulseCheck -Id @() -ProfileId 'contoso-tenant-id' -OutputPath $script:outputRoot } | Should -Throw
    }

    It 'scopes collection and evaluation to just the named -Id' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { New-TestInvokeCheckCatalog }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' }) } }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $summary = Invoke-TestPulseCheck -Params @{ Id = @('TP.ENT.9001'); ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot }

        $doc = Get-Content -LiteralPath $summary.FindingsPath -Raw | ConvertFrom-Json
        $doc.findings.Count | Should -Be 1
        $doc.findings[0].id | Should -Be 'TP.ENT.9001'

        $manifest = Get-Content -LiteralPath (Join-Path $summary.SnapshotPath 'manifest.json') -Raw | ConvertFrom-Json
        $manifest.datasets.PSObject.Properties.Name | Should -Not -Contain 'deviceCompliancePolicies'
    }

    It 'scopes collection and evaluation to just the named -Category' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { New-TestInvokeCheckCatalog }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' }) } }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $summary = Invoke-TestPulseCheck -Params @{ Category = @('Intune.Compliance'); ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot }

        $doc = Get-Content -LiteralPath $summary.FindingsPath -Raw | ConvertFrom-Json
        $doc.findings.Count | Should -Be 1
        $doc.findings[0].id | Should -Be 'TP.INT.9002'
    }

    It 'returns the same summary shape as Invoke-PulseAssessment' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { New-TestInvokeCheckCatalog }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' }) } }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $summary = Invoke-TestPulseCheck -Params @{ Id = @('TP.ENT.9001'); ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot }

        $summary.PSObject.Properties.Name | Should -Contain 'SnapshotPath'
        $summary.PSObject.Properties.Name | Should -Contain 'FindingsPath'
        $summary.PSObject.Properties.Name | Should -Contain 'ReportPaths'
        $summary.PSObject.Properties.Name | Should -Contain 'Scores'
        $summary.PSObject.Properties.Name | Should -Contain 'Coverage'
    }
}
