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
    function script:Invoke-TestPulseAssessment {
        param([hashtable] $Params)

        InModuleScope TenantPulse -ArgumentList (, $Params) {
            param($Params)

            function Test-PulseFixtureAssessmentPassRule {
                param($Datasets)
                return New-PulseFinding -Status Pass -Evidence @(@{ Identity = 'policy-1' })
            }

            Invoke-PulseAssessment @Params
        }
    }

    function script:New-TestAssessmentCatalog {
        param(
            [string] $Id = 'TP.ENT.9001',
            [string] $Category = 'Entra.ConditionalAccess',
            [string[]] $Datasets = @('conditionalAccessPolicies')
        )
        @(
            [pscustomobject]@{
                PSTypeName = 'TenantPulse.CheckDescriptor'
                Id         = $Id
                Title      = 'Fixture assessment check'
                Category   = $Category
                Severity   = 'Medium'
                Effort     = 'Low'
                Impact     = 'Medium'
                Data       = [pscustomobject]@{ Datasets = $Datasets; Gates = @() }
                Rule       = [pscustomobject]@{ Type = 'Function'; Function = 'Test-PulseFixtureAssessmentPassRule' }
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

Describe 'Invoke-PulseAssessment' {
    BeforeEach {
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        $script:outputRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $script:outputRoot -ItemType Directory -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'throws for an empty -ProfileId' {
        { Invoke-PulseAssessment -ProfileId '' -OutputPath $script:outputRoot } | Should -Throw
    }

    It 'throws for an empty -OutputPath' {
        { Invoke-PulseAssessment -ProfileId 'contoso-tenant-id' -OutputPath '' } | Should -Throw
    }

    It 'rejects a -Format value other than Json' {
        { Invoke-PulseAssessment -ProfileId 'contoso-tenant-id' -OutputPath $script:outputRoot -Format 'Xml' } | Should -Throw
    }

    It 'only collects the datasets the selected checks need, driven by the SAME selection used for evaluation' {
        $inScope = (New-TestAssessmentCatalog -Id 'TP.ENT.9001' -Category 'Entra.ConditionalAccess' -Datasets @('conditionalAccessPolicies'))[0]
        $outOfScope = (New-TestAssessmentCatalog -Id 'TP.INT.9002' -Category 'Intune.Compliance' -Datasets @('deviceCompliancePolicies'))[0]

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($inScope, $outOfScope) }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' }) } }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $summary = Invoke-TestPulseAssessment -Params @{ ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot; IncludeCategory = @('Entra.ConditionalAccess') }

        $manifest = Get-Content -LiteralPath (Join-Path $summary.SnapshotPath 'manifest.json') -Raw | ConvertFrom-Json
        $manifest.datasets.PSObject.Properties.Name | Should -Contain 'conditionalAccessPolicies'
        $manifest.datasets.PSObject.Properties.Name | Should -Not -Contain 'deviceCompliancePolicies'

        $doc = Get-Content -LiteralPath $summary.FindingsPath -Raw | ConvertFrom-Json
        $doc.findings.Count | Should -Be 1
        $doc.findings[0].id | Should -Be 'TP.ENT.9001'
    }

    It 'an empty selection produces zero findings rather than silently evaluating the whole catalog' {
        $checks = @(New-TestAssessmentCatalog)

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { $checks }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { @{ ThrottleClass = 'Read'; ReplayPolicy = 'Safe'; ApiVersion = 'beta'; RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' }) } }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $summary = Invoke-TestPulseAssessment -Params @{ ProfileId = 'contoso-tenant-id'; OutputPath = $script:outputRoot; IncludeCheck = @('TP.NOPE.0000') }

        $doc = Get-Content -LiteralPath $summary.FindingsPath -Raw | ConvertFrom-Json
        $doc.findings.Count | Should -Be 0
    }
}
