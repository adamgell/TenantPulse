BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphContext { param() }
        function Get-GraphObject { param() }
        function Get-GraphOperation { param() }
        function Test-GraphPermission { param() }
    }
}

Describe 'TenantPulse audit inventory report-data profile' {
    BeforeEach {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:capturedManifest = @()
        $tenantId = @('00000000', '1111', '2222', '3333', '444444444444') -join '-'
        $script:context = [pscustomobject]@{
            ProfileId = 'fixture'
            TenantId  = $tenantId
            ClientId  = [guid] '22222222-2222-2222-2222-222222222222'
        }

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
        Mock Get-GraphContext -ModuleName TenantPulse { $script:context }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'No Graph request is expected in this controller wiring test.' }
        Mock Invoke-PulsePermissionPreflight -ModuleName TenantPulse {
            [pscustomobject]@{ Operations = @(); Findings = @(); Decisions = @() }
        }
        Mock Invoke-PulseCollection -ModuleName TenantPulse {
            $script:capturedManifest = @($Manifest)
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'is available on both fresh-collection surfaces and not on FromSnapshot' {
        $snapshotParameter = (Get-Command Get-PulseTenantSnapshot).Parameters['ReportData']
        $assessmentParameter = (Get-Command Invoke-PulseAssessment).Parameters['ReportData']
        @($snapshotParameter.Attributes.ValidValues) | Should -Contain 'Inventory'
        @($assessmentParameter.Attributes.ValidValues) | Should -Contain 'Inventory'
        @($assessmentParameter.Attributes.ParameterSetName) | Should -Contain 'Collect'
        @($assessmentParameter.Attributes.ParameterSetName) | Should -Not -Contain 'FromSnapshot'
    }

    It 'selects the exact 25 neutral source datasets independently of check selection' {
        $expected = @(
            'androidEnrollmentProfiles', 'appProtectionPolicies', 'authenticationMethodsPolicy',
            'conditionalAccessPolicies', 'depOnboardingSettings', 'deviceCategories',
            'deviceCompliancePolicies', 'deviceConfigurations', 'deviceEnrollmentConfigurations',
            'deviceManagementScripts', 'deviceManagementSettings', 'domainConnectors', 'domains',
            'groups', 'managedDeviceCleanupRules', 'managedDevices', 'mobileAppCategories',
            'mobileAppConfigurations', 'ndesConnectors', 'roleAssignmentScheduleInstances',
            'roleEligibilityScheduleInstances', 'subscribedSkus', 'vppTokens',
            'windowsAutopilotDeviceIdentities', 'windowsUpdateCatalogItems'
        ) | Sort-Object

        $null = Get-PulseTenantSnapshot -ProfileId fixture -OutputPath $script:root -ReportData Inventory

        @($script:capturedManifest.Dataset) | Should -Be $expected
        @($script:capturedManifest.Dataset | Select-Object -Unique).Count | Should -Be 25
        Should-Invoke Invoke-PulsePermissionPreflight -ModuleName TenantPulse -Times 1 -Exactly
        Should-Invoke Invoke-PulseCollection -ModuleName TenantPulse -Times 1 -Exactly
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'deduplicates managedDevices when Devices and Inventory are requested together' {
        $null = Get-PulseTenantSnapshot -ProfileId fixture -OutputPath $script:root -ReportData Inventory,Devices
        @($script:capturedManifest.Dataset | Where-Object { $_ -eq 'managedDevices' }).Count | Should -Be 1
    }
}
