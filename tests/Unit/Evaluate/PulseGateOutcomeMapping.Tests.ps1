BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Pulse gate outcome mapping' {
    BeforeEach {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:keyRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:keyPath = Join-Path $script:keyRoot 'operator.key'
        $script:store = InModuleScope TenantPulse -ArgumentList $script:root {
            param($root)
            New-PulseSnapshotStore -Path $root -Tenant 'tp-gate-fixture'
        }
        $script:check = [pscustomobject]@{
            Id = 'TP.ENT.0022'
            Title = 'PIM permanent assignments'
            Category = 'Entra'
            Severity = 'High'
            Effort = 'Medium'
            Impact = 'High'
            Data = [pscustomobject]@{ Gates = @('EntraP2'); Datasets = @() }
            Rule = [pscustomobject]@{ Type = 'Expression'; Expression = '$true' }
            Consulting = [pscustomobject]@{ WhatItMeans = 'fixture'; WhyItMatters = 'fixture'; Remediation = @('fixture'); PortalLinks = @() }
            References = [pscustomobject]@{ Research = $null; Authorities = @(); Cis = @() }
            Origin = $null
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $script:keyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'maps Unavailable to NotApplicable while preserving the LicenseRequired provider outcome' {
        $evaluation = InModuleScope TenantPulse -ArgumentList $script:store, $script:keyPath, $script:check {
            param($store, $keyPath, $check)
            Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -GateProvider {
                param($Gate, $Manifest)
                [pscustomobject]@{ Status = 'Unavailable'; Detail = 'P2 is not licensed.' }
            }
        }

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be "gate 'EntraP2' unavailable: P2 is not licensed."
    }

    It 'maps Unknown to NotApplicable and never evaluates the rule as Pass' {
        $evaluation = InModuleScope TenantPulse -ArgumentList $script:store, $script:keyPath, $script:check {
            param($store, $keyPath, $check)
            Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -GateProvider {
                param($Gate, $Manifest)
                [pscustomobject]@{ Status = 'Unknown'; Detail = 'License evidence unavailable.' }
            }
        }

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.status | Should -Not -Be 'Pass'
        $finding.reason | Should -Be "gate 'EntraP2' unknown: License evidence unavailable."
    }
    It 'maps the default Unknown gate to NotApplicable without evaluating the rule' {
        $evaluation = InModuleScope TenantPulse -ArgumentList $script:store, $script:keyPath, $script:check {
            param($store, $keyPath, $check)
            Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
        }

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.status | Should -Not -Be 'Pass'
        $finding.reason | Should -Be "gate 'EntraP2' unknown: no detail provided"
    }


    It 'allows the existing rule to evaluate normally when EntraP2 is Available' {
        $evaluation = InModuleScope TenantPulse -ArgumentList $script:store, $script:keyPath, $script:check {
            param($store, $keyPath, $check)
            Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -GateProvider {
                param($Gate, $Manifest)
                [pscustomobject]@{ Status = 'Available'; Detail = 'P2 is licensed.' }
            }
        }

        $evaluation.Document.findings[0].status | Should -Be 'Pass'
    }

    It 'keeps a permission-denied dataset outcome distinct from a license gate outcome' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Write-PulseDataset -Store $store -Name 'permissionDataset' -ApiVersion 'v1.0' -Status 'Skipped' `
                -FailureClass 'PermissionDenied' -ReasonCode 'permission-denied' -Reason 'permission-denied: Directory.Read.All'
        }

        $check = $script:check.PSObject.Copy()
        $check.Data = [pscustomobject]@{ Gates = @('EntraP2'); Datasets = @('permissionDataset') }
        $evaluation = InModuleScope TenantPulse -ArgumentList $script:store, $script:keyPath, $check {
            param($store, $keyPath, $check)
            Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath -GateProvider {
                param($Gate, $Manifest)
                [pscustomobject]@{ Status = 'Available'; Detail = 'P2 is licensed.' }
            }
        }

        $finding = $evaluation.Document.findings[0]
        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: Directory.Read.All'
        $finding.reason | Should -Not -Match 'LicenseRequired'
    }
}
