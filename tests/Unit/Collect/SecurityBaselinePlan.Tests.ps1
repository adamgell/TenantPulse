BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:Invoke-SecurityBaselinePlanFixture {
        param(
            [Parameter()] [AllowEmptyCollection()] [object[]] $Policies = @(),
            [Parameter()] [hashtable] $Assignments = @{},
            [Parameter()] [hashtable] $AssignmentErrors = @{}
        )

        $fixture = @{
            Policies         = $Policies
            Assignments      = $Assignments
            AssignmentErrors = $AssignmentErrors
        }

        InModuleScope TenantPulse -ArgumentList $fixture {
            param($fixture)
            $script:SecurityBaselineFixture = $fixture
            $script:SecurityBaselineCalls = [System.Collections.Generic.List[object]]::new()

            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {
                param($Type, $Operation, $ApiVersion)
                $script:SecurityBaselineCalls.Add([pscustomobject]@{
                    Kind       = 'Descriptor'
                    Type       = $Type
                    Operation  = $Operation
                    ApiVersion = $ApiVersion
                })
            }
            Mock Get-GraphObject -ModuleName TenantPulse {
                param($Context, $Type, $Operation, $Parameters)
                $script:SecurityBaselineCalls.Add([pscustomobject]@{
                    Kind      = 'Graph'
                    Type      = $Type
                    Operation = $Operation
                    Id        = if ($null -ne $Parameters) { [string] $Parameters.id } else { $null }
                })

                if ($Type -eq 'ConfigurationPolicy') {
                    return @($script:SecurityBaselineFixture.Policies)
                }
                if ($Type -eq 'ConfigurationPolicyAssignment') {
                    $id = [string] $Parameters.id
                    if ($script:SecurityBaselineFixture.AssignmentErrors.ContainsKey($id)) {
                        throw $script:SecurityBaselineFixture.AssignmentErrors[$id]
                    }
                    return @($script:SecurityBaselineFixture.Assignments[$id])
                }
                throw "Unexpected Graph call '$Type/$Operation'."
            }

            $outcome = Invoke-PulseSecurityBaselinePlan `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Dataset 'securityBaselinesAssignedAndCurrent' `
                -ManifestEntry ([pscustomobject]@{
                    Dataset    = 'securityBaselinesAssignedAndCurrent'
                    Type       = 'SecurityBaselineAssignedAndCurrentWalk'
                    Operation  = 'Walk'
                    ApiVersion = 'beta'
                }) `
                -ProfileId 'fixture' `
                -TenantPseudonym 'tp-fixture'

            [pscustomobject]@{
                Outcome = $outcome
                Calls   = @($script:SecurityBaselineCalls)
            }
        }
    }

    function script:Invoke-SecurityBaselineCheckFixture {
        param([AllowEmptyCollection()] [object[]] $Rows)
        $rowsArgument = if ($null -eq $Rows) { [object[]]@() } else { [object[]]@($Rows) }
        InModuleScope TenantPulse -ArgumentList (,$rowsArgument) {
            param($Rows)
            $datasetRows = if ($null -eq $Rows) { [object[]]@() } else { [object[]]@($Rows) }
            Test-PulseSecurityBaselinesAssignedAndCurrent -Datasets @{ securityBaselinesAssignedAndCurrent = $datasetRows }
        }
    }
}

Describe 'Invoke-PulseSecurityBaselinePlan' {
    It 'returns platform unavailable without inventing a template metadata descriptor' {
        $result = Invoke-SecurityBaselinePlanFixture -Policies @(
            [pscustomobject]@{ id = 'baseline-1'; name = 'Windows baseline'; templateFamily = 'baseline' }
        )

        $result.Outcome.Status | Should -Be 'Skipped'
        $result.Outcome.FailureClass | Should -Be 'PlatformUnavailable'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 0
        $result.Outcome.Detail.recheckTrigger | Should -Match 'released.*metadata primitive'
        @($result.Calls | Where-Object Kind -eq 'Descriptor' | ForEach-Object { "$($_.Type)/$($_.Operation)/$($_.ApiVersion)" }) | Should -Be @(
            'ConfigurationPolicy/ListBeta/beta'
            'ConfigurationPolicyAssignment/ListBeta/beta'
        )
        @($result.Calls | Where-Object Kind -eq 'Graph').Count | Should -Be 0
    }
}

Describe 'TP.INT.0029 security-baseline row fixtures' {
    It 'evaluates assigned/current rows as Pass' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @(
            [pscustomobject]@{ id = 'b1'; name = 'Windows baseline'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $false }
        )
        $finding.Status | Should -Be 'Pass'
    }

    It 'evaluates unassigned/current rows as Fail' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @(
            [pscustomobject]@{ id = 'b1'; name = 'Windows baseline'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false }
        )
        $finding.Status | Should -Be 'Fail'
    }

    It 'evaluates assigned/deprecated rows as Fail' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @(
            [pscustomobject]@{ id = 'b1'; name = 'Windows baseline'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $true }
        )
        $finding.Status | Should -Be 'Fail'
    }

    It 'fails mixed rows when any baseline is unassigned or deprecated' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @(
            [pscustomobject]@{ id = 'b-current'; name = 'Current'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $false }
            [pscustomobject]@{ id = 'b-unassigned'; name = 'Unassigned'; templateFamily = 'baseline'; hasAssignment = $false; isDeprecated = $false }
            [pscustomobject]@{ id = 'b-deprecated'; name = 'Deprecated'; templateFamily = 'baseline'; hasAssignment = $true; isDeprecated = $true }
        )
        $finding.Status | Should -Be 'Fail'
        @($finding.Evidence).Count | Should -Be 2
    }

    It 'keeps zero baselines as the existing NotApplicable result' {
        $finding = Invoke-SecurityBaselineCheckFixture -Rows @()
        $finding.Status | Should -Be 'NotApplicable'
    }

    It 'rejects non-Boolean provider values rather than coercing them' {
        {
            Invoke-SecurityBaselineCheckFixture -Rows @(
                [pscustomobject]@{ id = 'b1'; name = 'Invalid'; templateFamily = 'baseline'; hasAssignment = 'false'; isDeprecated = $false }
            )
        } | Should -Throw '*native boolean*'
    }

    It 'does not turn a partial child-read fixture into a successful check input' {
        $result = Invoke-SecurityBaselinePlanFixture `
            -Policies @(
                [pscustomobject]@{ id = 'baseline-1'; name = 'Readable'; templateFamily = 'baseline' }
                [pscustomobject]@{ id = 'baseline-2'; name = 'Assignment read failed'; templateFamily = 'baseline' }
            ) `
            -AssignmentErrors @{ 'baseline-2' = '403 Forbidden' }

        $result.Outcome.Status | Should -Be 'Skipped'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 0
        @($result.Calls | Where-Object Kind -eq 'Graph').Count | Should -Be 0
    }
}
