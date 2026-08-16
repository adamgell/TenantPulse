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

Describe 'Get-PulseCheckCatalog' {
    It 'projects each descriptor to {id;title;category;severity;authorities}' {
        $fixtureChecks = @(
            [pscustomobject]@{
                PSTypeName = 'TenantPulse.CheckDescriptor'
                Id         = 'TP.ENT.0001'
                Title      = 'Conditional Access baseline exists'
                Category   = 'Entra.ConditionalAccess'
                Severity   = 'High'
                References = [pscustomobject]@{ Authorities = @('https://learn.microsoft.com/entra/ca') }
            }
        )

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { $fixtureChecks }

        $result = @(Get-PulseCheckCatalog)

        $result.Count | Should -Be 1
        $result[0].id | Should -Be 'TP.ENT.0001'
        $result[0].title | Should -Be 'Conditional Access baseline exists'
        $result[0].category | Should -Be 'Entra.ConditionalAccess'
        $result[0].severity | Should -Be 'High'
        $result[0].authorities | Should -Be @('https://learn.microsoft.com/entra/ca')
    }

    It 'keeps authorities as an array even when empty' {
        $fixtureChecks = @(
            [pscustomobject]@{
                PSTypeName = 'TenantPulse.CheckDescriptor'
                Id         = 'TP.INT.0002'
                Title      = 'Device compliance policy exists'
                Category   = 'Intune.Compliance'
                Severity   = 'Medium'
                References = [pscustomobject]@{ Authorities = @() }
            }
        )

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { $fixtureChecks }

        $result = @(Get-PulseCheckCatalog)

        , $result[0].authorities | Should -BeOfType [array]
        $result[0].authorities.Count | Should -Be 0
    }

    It 'returns an empty array for an empty catalog, never throws' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }

        $result = @(Get-PulseCheckCatalog)

        $result.Count | Should -Be 0
    }

    It 'passes -Path and -DatasetMapPath through to Import-PulseCheckCatalog when bound' {
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @() }

        Get-PulseCheckCatalog -Path 'C:/fake/checks' -DatasetMapPath 'C:/fake/DatasetMap.psd1' | Out-Null

        Should -Invoke Import-PulseCheckCatalog -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Path -eq 'C:/fake/checks' -and $DatasetMapPath -eq 'C:/fake/DatasetMap.psd1'
        }
    }
}
