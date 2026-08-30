BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Windows data processor provider disposition' {
    It 'returns an explicit platform-unavailable outcome with the exact contract evidence' {
        $outcome = InModuleScope TenantPulse {
            Invoke-PulseWindowsDataProcessorPlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'dataProcessorServiceForWindowsFeaturesOnboarding' `
                -ManifestEntry ([pscustomobject]@{
                    Dataset = 'dataProcessorServiceForWindowsFeaturesOnboarding'
                    Type = 'DataProcessorServiceForWindowsFeaturesOnboarding'
                    Operation = 'Get'
                    ApiVersion = 'beta'
                    Pending = $true
                }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'
        }

        $outcome.PSObject.Properties.Name | Should -Be @(
            'Dataset'
            'Status'
            'Rows'
            'Gaps'
            'FailureClass'
            'ReasonCode'
            'Detail'
            'Provider'
            'ApiVersion'
            'Operations'
        )
        $outcome.Dataset | Should -Be 'dataProcessorServiceForWindowsFeaturesOnboarding'
        $outcome.Status | Should -Be 'Skipped'
        @($outcome.Rows).Count | Should -Be 0
        @($outcome.Gaps).Count | Should -Be 0
        $outcome.FailureClass | Should -Be 'PlatformUnavailable'
        $outcome.ReasonCode | Should -Be 'platform-unavailable'
        $outcome.Provider | Should -Be 'GraphKit'
        $outcome.ApiVersion | Should -Be 'beta'
        $outcome.Operations | Should -Be @('Get')

        $outcome.Detail.Contract | Should -Be 'DataProcessorServiceForWindowsFeaturesOnboarding.Get'
        $outcome.Detail.Method | Should -Be 'GET'
        $outcome.Detail.Path | Should -Be '/deviceManagement/dataProcessorServiceForWindowsFeaturesOnboarding'
        $outcome.Detail.ApiVersion | Should -Be 'beta'
        $outcome.Detail.GraphKit.PackageVersion | Should -Be '0.3.0'
        $outcome.Detail.GraphKit.Descriptor | Should -Be 'Absent from released catalog'
        $outcome.Detail.LiveProbe.Outcome | Should -Be 'Succeeded'
        $outcome.Detail.LiveProbe.ReadOnly | Should -BeTrue
        $outcome.Detail.LiveProbe.NativeBooleanFields | Should -BeTrue
        $outcome.Detail.Response.Fields | Should -Be @(
            'hasValidWindowsLicense'
            'areDataProcessorServiceForWindowsFeaturesEnabled'
        )
        $outcome.Detail.RecheckTrigger | Should -Match 'official GET method and application-permission metadata'
    }

    It 'does not call GraphKit while reporting the unsupported catalog contract' {
        InModuleScope TenantPulse {
            function Get-GraphObject { param() }
            function Get-GraphOperation { param() }
        }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must not be called.' }
        Mock Get-GraphOperation -ModuleName TenantPulse { throw 'Get-GraphOperation must not be called.' }

        InModuleScope TenantPulse {
            $result = Invoke-PulseWindowsDataProcessorPlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'dataProcessorServiceForWindowsFeaturesOnboarding' `
                -ManifestEntry ([pscustomobject]@{ Dataset = 'dataProcessorServiceForWindowsFeaturesOnboarding'; ApiVersion = 'beta' }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'
            $result.Status | Should -Be 'Skipped'
        }

        Should-NotInvoke Get-GraphObject -ModuleName TenantPulse
        Should-NotInvoke Get-GraphOperation -ModuleName TenantPulse
    }
}
