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
            [Parameter()] [AllowEmptyCollection()] [object[]] $Templates = @(),
            [Parameter()] [AllowEmptyCollection()] [object[]] $Intents = @(),
            [Parameter()] [AllowNull()] $TemplateError,
            [Parameter()] [AllowNull()] $IntentError
        )

        $fixture = @{
            Templates     = $Templates
            Intents       = $Intents
            TemplateError = $TemplateError
            IntentError   = $IntentError
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

                if ($Type -eq 'DeviceManagementTemplate') {
                    if ($null -ne $script:SecurityBaselineFixture.TemplateError) {
                        throw $script:SecurityBaselineFixture.TemplateError
                    }
                    return @($script:SecurityBaselineFixture.Templates)
                }
                if ($Type -eq 'DeviceManagementIntent') {
                    if ($null -ne $script:SecurityBaselineFixture.IntentError) {
                        throw $script:SecurityBaselineFixture.IntentError
                    }
                    return @($script:SecurityBaselineFixture.Intents)
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
    It 'joins security-baseline intents to template disposition and preserves native assignment state' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = 'template-current'; displayName = 'Windows baseline'; templateType = 'securityBaseline'; versionInfo = '24H2'; isDeprecated = $false }
            [pscustomobject]@{ id = 'template-old'; displayName = 'Edge baseline'; templateType = 'microsoftEdgeSecurityBaseline'; versionInfo = 'v1'; isDeprecated = $true }
            [pscustomobject]@{ id = 'template-other'; displayName = 'Office settings'; templateType = 'deviceConfigurationForOffice365'; versionInfo = 'v1'; isDeprecated = $false }
        ) -Intents @(
            [pscustomobject]@{ id = 'intent-current'; displayName = 'Windows profile'; templateId = 'template-current'; isAssigned = $true }
            [pscustomobject]@{ id = 'intent-old'; displayName = 'Edge profile'; templateId = 'template-old'; isAssigned = $false }
            [pscustomobject]@{ id = 'intent-other'; displayName = 'Office profile'; templateId = 'template-other'; isAssigned = $true }
        )

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 2
        @($result.Outcome.Gaps).Count | Should -Be 0
        $result.Outcome.Rows[0].id | Should -Be 'intent-current'
        $result.Outcome.Rows[0].templateFamily | Should -Be 'securityBaseline'
        $result.Outcome.Rows[0].hasAssignment | Should -BeTrue
        $result.Outcome.Rows[0].isDeprecated | Should -BeFalse
        $result.Outcome.Rows[1].id | Should -Be 'intent-old'
        $result.Outcome.Rows[1].templateFamily | Should -Be 'microsoftEdgeSecurityBaseline'
        $result.Outcome.Rows[1].hasAssignment | Should -BeFalse
        $result.Outcome.Rows[1].isDeprecated | Should -BeTrue
        @($result.Calls | Where-Object Kind -eq 'Descriptor' | ForEach-Object { "$($_.Type)/$($_.Operation)/$($_.ApiVersion)" }) | Should -Be @(
            'DeviceManagementTemplate/ListBeta/beta'
            'DeviceManagementIntent/ListBeta/beta'
        )
        @($result.Calls | Where-Object Kind -eq 'Graph' | ForEach-Object { "$($_.Type)/$($_.Operation)" }) | Should -Be @(
            'DeviceManagementTemplate/ListBeta'
            'DeviceManagementIntent/ListBeta'
        )
    }

    It 'returns an authoritative empty collection when no baseline intent exists' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = 'template-current'; displayName = 'Windows baseline'; templateType = 'securityBaseline'; versionInfo = '24H2'; isDeprecated = $false }
        ) -Intents @()

        $result.Outcome.Status | Should -Be 'Collected'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 0
    }

    It 'fails closed when an intent cannot be joined to template disposition metadata' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = 'template-current'; displayName = 'Windows baseline'; templateType = 'securityBaseline'; versionInfo = '24H2'; isDeprecated = $false }
        ) -Intents @(
            [pscustomobject]@{ id = 'intent-unknown'; displayName = 'Unknown profile'; templateId = 'missing-template'; isAssigned = $true }
        )

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'classifies a template collection permission failure without attempting intents' {
        $result = Invoke-SecurityBaselinePlanFixture -TemplateError ([System.UnauthorizedAccessException]::new('fixture permission denied'))

        $result.Outcome.Status | Should -Be 'Failed'
        $result.Outcome.FailureClass | Should -BeIn @('PermissionDenied', 'ProviderFailed')
        @($result.Calls | Where-Object Kind -eq 'Graph').Count | Should -Be 1
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

    It 'does not turn a malformed native assignment value into successful check input' {
        $result = Invoke-SecurityBaselinePlanFixture -Templates @(
            [pscustomobject]@{ id = 'template-current'; displayName = 'Windows baseline'; templateType = 'securityBaseline'; versionInfo = '24H2'; isDeprecated = $false }
        ) -Intents @(
            [pscustomobject]@{ id = 'intent-invalid'; displayName = 'Invalid'; templateId = 'template-current'; isAssigned = 'true' }
        )

        $result.Outcome.Status | Should -Be 'Failed'
        @($result.Outcome.Rows).Count | Should -Be 0
        @($result.Outcome.Gaps).Count | Should -Be 1
        $result.Outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
    }
}
