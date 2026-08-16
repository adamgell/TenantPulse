BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $repoRoot = $script:repoRoot

    # Import the BUILT module (never dot-source source files: they would redefine module
    # classes and Add-Type types in test scope). Pester discovers tests per file, so each
    # file imports it.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    # GraphKit 0.0.2 has a known import-side bug and must never be relied on inside a unit
    # test. Every GraphKit command TenantPulse calls is stubbed directly inside the
    # TenantPulse module scope - matching GraphKit's own test convention - so these tests
    # pass on a machine with no GraphKit installed. A default mock that throws is
    # registered first for each stub; every test below layers a more specific mock on top
    # (Pester resolves the most specific/most-recently-defined mock first), so any call
    # path this file does not deliberately exercise fails loudly instead of silently
    # hitting a real transport.
    InModuleScope TenantPulse {
        function Get-GraphContext { param() }
        function Get-GraphObject { param() }
        function Invoke-GraphOperation { param() }
        function Get-GraphOperation { param() }
    }

    Mock Get-GraphContext -ModuleName TenantPulse { throw 'Get-GraphContext must be mocked in this test.' }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }
    Mock Invoke-GraphOperation -ModuleName TenantPulse { throw 'Invoke-GraphOperation must be mocked in this test.' }
    Mock Get-GraphOperation -ModuleName TenantPulse { throw 'Get-GraphOperation must be mocked in this test.' }

    function New-TestCheck {
        param(
            [string] $Id = 'TP.INT.0001',
            [string[]] $Datasets = @('conditionalAccessPolicies'),
            [string] $Category = 'Entra.ConditionalAccess'
        )

        [pscustomobject]@{
            PSTypeName = 'TenantPulse.CheckDescriptor'
            Id         = $Id
            Category   = $Category
            Data       = [pscustomobject]@{ Datasets = $Datasets }
        }
    }

    function New-TestReadDescriptor {
        param(
            [string] $ApiVersion = 'v1.0',
            [object[]] $RequiredPermissions = @(@{ Type = 'Application'; Value = 'Policy.Read.All' })
        )

        @{
            ThrottleClass       = 'Read'
            ReplayPolicy        = 'Safe'
            ApiVersion          = $ApiVersion
            RequiredPermissions = $RequiredPermissions
        }
    }
}

Describe 'Get-PulseCollectionManifest' {
    It 'dedups a dataset shared by two checks into one manifest entry' {
        $checkOne = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('conditionalAccessPolicies')
        $checkTwo = New-TestCheck -Id 'TP.ENT.0002' -Datasets @('conditionalAccessPolicies')
        $map = @{ conditionalAccessPolicies = @{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' } }

        $manifest = InModuleScope TenantPulse -ArgumentList @($checkOne, $checkTwo), $map {
            param($checks, $map)
            Get-PulseCollectionManifest -Checks $checks -DatasetMap $map
        }

        @($manifest).Count | Should -Be 1
        $manifest[0].Dataset | Should -Be 'conditionalAccessPolicies'
        $manifest[0].Type | Should -Be 'ConditionalAccessPolicy'
        $manifest[0].Operation | Should -Be 'List'
        $manifest[0].ApiVersion | Should -Be 'beta'
    }

    It 'unions distinct datasets from multiple checks into separate entries' {
        $checkOne = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('conditionalAccessPolicies')
        $checkTwo = New-TestCheck -Id 'TP.INT.0002' -Datasets @('deviceCompliancePolicies')
        $map = @{
            conditionalAccessPolicies = @{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' }
            deviceCompliancePolicies  = @{ Type = 'DeviceCompliancePolicy'; Operation = 'List'; ApiVersion = 'v1.0' }
        }

        $manifest = InModuleScope TenantPulse -ArgumentList @($checkOne, $checkTwo), $map {
            param($checks, $map)
            Get-PulseCollectionManifest -Checks $checks -DatasetMap $map
        }

        @($manifest).Count | Should -Be 2
        ($manifest | ForEach-Object Dataset) | Should -Contain 'conditionalAccessPolicies'
        ($manifest | ForEach-Object Dataset) | Should -Contain 'deviceCompliancePolicies'
    }

    It 'throws naming the check id when a check references an unknown dataset' {
        $check = New-TestCheck -Id 'TP.ENT.0099' -Datasets @('notInTheMap')
        $map = @{ conditionalAccessPolicies = @{ Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta' } }

        {
            InModuleScope TenantPulse -ArgumentList @($check), $map {
                param($checks, $map)
                Get-PulseCollectionManifest -Checks $checks -DatasetMap $map
            }
        } | Should -Throw -ExpectedMessage '*TP.ENT.0099*notInTheMap*'
    }

    It 'sorts the returned entries ordinally by dataset name' {
        $checkOne = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('zebra')
        $checkTwo = New-TestCheck -Id 'TP.ENT.0002' -Datasets @('Apple')
        $map = @{
            zebra = @{ Type = 'Zebra'; Operation = 'List'; ApiVersion = 'v1.0' }
            Apple = @{ Type = 'Apple'; Operation = 'List'; ApiVersion = 'v1.0' }
        }

        $manifest = InModuleScope TenantPulse -ArgumentList @($checkOne, $checkTwo), $map {
            param($checks, $map)
            Get-PulseCollectionManifest -Checks $checks -DatasetMap $map
        }

        # Ordinal: uppercase 'Apple' sorts before lowercase 'zebra'.
        $manifest[0].Dataset | Should -Be 'Apple'
        $manifest[1].Dataset | Should -Be 'zebra'
    }

    It 'carries the Pending flag through from the dataset map' {
        $check = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('mdmAuthority')
        $map = @{ mdmAuthority = @{ Type = 'Organization'; Operation = 'Get'; ApiVersion = 'v1.0'; Pending = $true } }

        $manifest = InModuleScope TenantPulse -ArgumentList @($check), $map {
            param($checks, $map)
            Get-PulseCollectionManifest -Checks $checks -DatasetMap $map
        }

        $manifest[0].Pending | Should -BeTrue
    }

    It 'returns an empty array for zero checks' {
        $manifest = InModuleScope TenantPulse -ArgumentList @(), @{} {
            param($checks, $map)
            Get-PulseCollectionManifest -Checks $checks -DatasetMap $map
        }

        @($manifest).Count | Should -Be 0
    }
}

Describe 'Assert-PulseReadOnlyDescriptor' {
    It 'throws for a Write ThrottleClass' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor | ForEach-Object { $_.ThrottleClass = 'Write'; $_ } }

        {
            InModuleScope TenantPulse {
                Assert-PulseReadOnlyDescriptor -Type 'SomeWriteOp' -Operation 'Update'
            }
        } | Should -Throw -ExpectedMessage '*not a read-only descriptor*'
    }

    It 'throws for a NeverReplay ReplayPolicy' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor | ForEach-Object { $_.ReplayPolicy = 'NeverReplay'; $_ } }

        {
            InModuleScope TenantPulse {
                Assert-PulseReadOnlyDescriptor -Type 'SomeOp' -Operation 'List'
            }
        } | Should -Throw -ExpectedMessage '*not a read-only descriptor*'
    }

    It 'does not throw for Read + Safe' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }

        {
            InModuleScope TenantPulse {
                Assert-PulseReadOnlyDescriptor -Type 'ConditionalAccessPolicy' -Operation 'List'
            }
        } | Should -Not -Throw
    }
}

Describe 'Get-PulseFailureClass' {
    It 'classifies a StatusCode 403 exception property as PermissionDenied' {
        $exception = [System.Management.Automation.RuntimeException]::new('boom')
        Add-Member -InputObject $exception -NotePropertyName 'StatusCode' -NotePropertyValue 403
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'Boom', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'PermissionDenied'
    }

    It 'classifies a StatusCode 500 exception property as Failed' {
        $exception = [System.Management.Automation.RuntimeException]::new('boom')
        Add-Member -InputObject $exception -NotePropertyName 'StatusCode' -NotePropertyValue 500
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'Boom', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'Failed'
    }

    It 'falls back to message text ("403") when no structured status is present' {
        $errorRecord = $null
        try {
            throw "Get-GraphObject failed for 'ConditionalAccessPolicy/List': Outcome 'Failed', Certainty 'Known' (403 Forbidden)."
        } catch {
            $errorRecord = $_
        }

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'PermissionDenied'
    }

    It 'classifies an unrelated message as Failed' {
        $errorRecord = $null
        try {
            throw 'Get-GraphObject failed: 500 Internal Server Error.'
        } catch {
            $errorRecord = $_
        }

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'Failed'
    }
}

Describe 'Invoke-PulseCollection' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes Collected for a clean read, Skipped with a permission reason for a 403, and Failed for a 500 - each dataset attempted independently' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -RequiredPermissions @(@{ Type = 'Application'; Value = 'Policy.Read.All' }, @{ Type = 'Application'; Value = 'Directory.Read.All' }) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } { @([pscustomobject]@{ id = 'p1' }) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicy' } { throw "Get-GraphObject failed for 'DeviceCompliancePolicy/List': 403 Forbidden." }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceConfiguration' } { throw "Get-GraphObject failed for 'DeviceConfiguration/List': 500 Internal Server Error." }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'deviceCompliancePolicies'; Type = 'DeviceCompliancePolicy'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false }
            [pscustomobject]@{ Dataset = 'deviceConfigurations'; Type = 'DeviceConfiguration'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json

        $result.datasets.conditionalAccessPolicies.status | Should -Be 'Collected'

        $result.datasets.deviceCompliancePolicies.status | Should -Be 'Skipped'
        $result.datasets.deviceCompliancePolicies.reason | Should -Match '^permission-denied:'
        $result.datasets.deviceCompliancePolicies.reason | Should -Match 'Policy.Read.All'
        $result.datasets.deviceCompliancePolicies.reason | Should -Match 'Directory.Read.All'

        $result.datasets.deviceConfigurations.status | Should -Be 'Failed'
        $result.datasets.deviceConfigurations.reason | Should -Match '500 Internal Server Error'
    }

    It 'writes Skipped with a descriptor-pending reason and never calls Get-GraphObject for a Pending dataset' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must not be called for a Pending dataset.' }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'mdmAuthority'; Type = 'Organization'; Operation = 'Get'; ApiVersion = 'v1.0'; Pending = $true }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $result.datasets.mdmAuthority.status | Should -Be 'Skipped'
        $result.datasets.mdmAuthority.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }
}

Describe 'Get-PulseTenantSnapshot' {
    BeforeEach {
        $script:snapshotRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:keyRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())

        # Avoid touching the real ~/.tenantpulse/operator.key from a unit test: the
        # operator key is TenantPulse's own private function, not GraphKit's, so it is
        # mocked directly (no shadow-stub dance needed).
        Mock Get-PulseOperatorKey -ModuleName TenantPulse { [byte[]] (0..31) }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:snapshotRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $script:keyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes a snapshot whose tenant field is the pseudonym, never the raw profile id, and classifies each dataset' {
        $checkOne = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('conditionalAccessPolicies')
        $checkTwo = New-TestCheck -Id 'TP.INT.0002' -Datasets @('deviceCompliancePolicies')

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($checkOne, $checkTwo) }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } { @([pscustomobject]@{ id = 'p1' }) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicy' } { throw "Get-GraphObject failed: 403 Forbidden." }

        $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot {
            param($snapshotRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot
        }

        $expectedPseudonym = InModuleScope TenantPulse {
            Get-PulsePseudonym -Value 'contoso-tenant-id' -Key ([byte[]] (0..31))
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.tenant | Should -Be $expectedPseudonym
        $manifest.tenant | Should -Not -Match 'contoso-tenant-id'

        $manifest.datasets.conditionalAccessPolicies.status | Should -Be 'Collected'
        $manifest.datasets.deviceCompliancePolicies.status | Should -Be 'Skipped'
        $manifest.datasets.deviceCompliancePolicies.reason | Should -Match '^permission-denied:'
    }

    It 'still writes the snapshot with every dataset Failed and collectionFailure set when acquiring a GraphKit context fails outright' {
        $checkOne = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('conditionalAccessPolicies')

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($checkOne) }
        Mock Get-GraphContext -ModuleName TenantPulse { throw 'token acquisition failed: invalid_client' }

        $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot {
            param($snapshotRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot
        }

        Test-Path -LiteralPath $store.ManifestPath -PathType Leaf | Should -BeTrue

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.collectionFailure | Should -Not -BeNullOrEmpty
        $manifest.collectionFailure | Should -Match 'invalid_client'
        $manifest.datasets.conditionalAccessPolicies.status | Should -Be 'Failed'
        $manifest.datasets.conditionalAccessPolicies.reason | Should -Match 'invalid_client'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'excludes checks outside -IncludeCategory from the collected dataset set' {
        $inScope = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('conditionalAccessPolicies') -Category 'Entra.ConditionalAccess'
        $outOfScope = New-TestCheck -Id 'TP.INT.0002' -Datasets @('deviceCompliancePolicies') -Category 'Intune.Compliance'

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($inScope, $outOfScope) }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot {
            param($snapshotRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot -IncludeCategory 'Entra.ConditionalAccess'
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.PSObject.Properties.Name | Should -Contain 'conditionalAccessPolicies'
        $manifest.datasets.PSObject.Properties.Name | Should -Not -Contain 'deviceCompliancePolicies'
    }
}
