BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'Get-PulseGateStatus' {
    It 'returns Available with no failure outcome when an injected provider proves EntraP2' {
        $status = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{} -Provider {
                param($Gate, $Manifest)
                [pscustomobject]@{ Status = 'Available'; Detail = 'AAD_PREMIUM_P2 is provisioned.' }
            }
        }

        $status.Status | Should -Be 'Available'
        $status.Detail | Should -Be 'AAD_PREMIUM_P2 is provisioned.'
        $status.FailureClass | Should -BeNullOrEmpty
        $status.Outcome | Should -BeNullOrEmpty
    }

    It 'returns Unavailable and maps a proven license failure to a Skipped LicenseRequired outcome' {
        $status = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{} -Provider {
                param($Gate, $Manifest)
                [pscustomobject]@{ Status = 'Unavailable'; Detail = 'AAD_PREMIUM_P2 is not provisioned.' }
            }
        }

        $status.Status | Should -Be 'Unavailable'
        $status.FailureClass | Should -Be 'LicenseRequired'
        $status.Outcome.Status | Should -Be 'Skipped'
        $status.Outcome.FailureClass | Should -Be 'LicenseRequired'
    }

    It 'returns Unknown and maps an indeterminate gate to a Skipped GateUnknown outcome' {
        $status = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{} -Provider {
                param($Gate, $Manifest)
                [pscustomobject]@{ Status = 'Unknown'; Detail = 'No license evidence was collected.' }
            }
        }

        $status.Status | Should -Be 'Unknown'
        $status.FailureClass | Should -Be 'GateUnknown'
        $status.Outcome.Status | Should -Be 'Skipped'
        $status.Outcome.FailureClass | Should -Be 'GateUnknown'
    }

    It 'does not infer Unavailable from a missing license dataset' {
        $status = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{ datasets = @{} }
        }

        $status.Status | Should -Be 'Unknown'
        $status.FailureClass | Should -Be 'GateUnknown'
        $status.Status | Should -Not -Be 'Unavailable'
    }

    It 'does not turn a permission-denied license read into LicenseRequired' {
        $status = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{
                datasets = @{
                    subscribedSkus = @{
                        status = 'Skipped'
                        failureClass = 'PermissionDenied'
                        reason = 'permission-denied: Directory.Read.All'
                    }
                }
            }
        }

        $status.Status | Should -Be 'Unknown'
        $status.FailureClass | Should -Be 'PermissionDenied'
        $status.FailureClass | Should -Not -Be 'LicenseRequired'
    }
    It 'does not trust stale license detail from a non-collected subscribedSkus outcome' {
        $cases = @(
            @{
                Name = 'failed'
                Dataset = @{
                    status = 'Failed'
                    detail = @{ Status = 'Available'; Detail = 'stale available detail' }
                }
                FailureClass = 'GateUnknown'
            }
            @{
                Name = 'skipped'
                Dataset = @{
                    status = 'Skipped'
                    detail = @{ Status = 'Unavailable'; Detail = 'stale unavailable detail' }
                }
                FailureClass = 'GateUnknown'
            }
            @{
                Name = 'partial'
                Dataset = @{
                    status = 'Partial'
                    detail = @{ Status = 'Available'; Detail = 'stale available detail' }
                }
                FailureClass = 'GateUnknown'
            }
            @{
                Name = 'permission-denied'
                Dataset = @{
                    status = 'Skipped'
                    failureClass = 'PermissionDenied'
                    reason = 'permission-denied: Directory.Read.All'
                    detail = @{ Status = 'Available'; Detail = 'stale available detail' }
                }
                FailureClass = 'PermissionDenied'
            }
        )

        foreach ($case in $cases) {
            $status = InModuleScope TenantPulse -ArgumentList $case.Dataset {
                param($dataset)
                Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{
                    datasets = @{ subscribedSkus = $dataset }
                }
            }

            $status.Status | Should -Be 'Unknown' -Because $case.Name
            $status.FailureClass | Should -Be $case.FailureClass -Because $case.Name
            $status.Status | Should -Not -Be 'Available' -Because $case.Name
            $status.FailureClass | Should -Not -Be 'LicenseRequired' -Because $case.Name
        }
    }

    It 'uses gate detail only when subscribedSkus evidence was collected' {
        $available = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{
                datasets = @{
                    subscribedSkus = @{
                        status = 'Collected'
                        detail = @{
                            Status = 'Available'
                            Detail = 'collected service-plan evidence'
                        }
                    }
                }
            }
        }
        $unavailable = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{
                datasets = @{
                    subscribedSkus = @{
                        status = 'Collected'
                        detail = @{
                            Status = 'Unavailable'
                            Detail = 'no qualifying P2 service plan'
                        }
                    }
                }
            }
        }

        $available.Status | Should -Be 'Available'
        $available.FailureClass | Should -BeNullOrEmpty
        $unavailable.Status | Should -Be 'Unavailable'
        $unavailable.FailureClass | Should -Be 'LicenseRequired'
    }

    It 'uses an explicit collected license-evidence decision when present' {
        $available = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{
                licenseEvidence = @{
                    EntraP2 = @{ Status = 'Available'; Detail = 'collected service-plan evidence' }
                }
            }
        }
        $unavailable = InModuleScope TenantPulse {
            Get-PulseGateStatus -Gate 'EntraP2' -Manifest @{
                licenseEvidence = @{
                    EntraP2 = @{ Status = 'Unavailable'; Detail = 'no qualifying P2 service plan' }
                }
            }
        }

        $available.Status | Should -Be 'Available'
        $unavailable.Status | Should -Be 'Unavailable'
        $unavailable.FailureClass | Should -Be 'LicenseRequired'
    }
}
