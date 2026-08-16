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

    # GraphKit 0.1.0 is a real, importable RequiredModules dependency of TenantPulse
    # itself (published to PSGallery) and IS present in this test environment. These
    # tests still never depend on real GraphKit behavior: every GraphKit command
    # TenantPulse calls is stubbed directly inside the TenantPulse module scope -
    # matching GraphKit's own test convention - which shadows the real command for every
    # call TenantPulse's own code makes from within its module scope, regardless of
    # whether GraphKit itself is installed. A default mock that throws is registered
    # first for each stub; every test below layers a more specific mock on top (Pester
    # resolves the most specific/most-recently-defined mock first), so any call path this
    # file does not deliberately exercise fails loudly instead of silently hitting a real
    # transport.
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

    It 'IdFromDataset: auto-adds the dependency dataset even though no check declared it directly, ordered before its dependent' {
        $check = New-TestCheck -Id 'TP.INT.0001' -Datasets @('organizationMdmAuthority')
        $map = @{
            organization              = @{ Type = 'Organization'; Operation = 'List'; ApiVersion = 'v1.0' }
            organizationMdmAuthority  = @{ Type = 'Organization'; Operation = 'GetMdmAuthority'; ApiVersion = 'v1.0'; IdFromDataset = 'organization' }
        }

        $manifest = InModuleScope TenantPulse -ArgumentList @($check), $map {
            param($checks, $map)
            Get-PulseCollectionManifest -Checks $checks -DatasetMap $map
        }

        @($manifest).Count | Should -Be 2
        $manifest[0].Dataset | Should -Be 'organization'
        $manifest[1].Dataset | Should -Be 'organizationMdmAuthority'
        $manifest[1].IdFromDataset | Should -Be 'organization'
    }

    It 'IdFromDataset: throws naming the dependency chain for a dependency cycle' {
        $check = New-TestCheck -Id 'TP.INT.0001' -Datasets @('a')
        $map = @{
            a = @{ Type = 'A'; Operation = 'Get'; ApiVersion = 'v1.0'; IdFromDataset = 'b' }
            b = @{ Type = 'B'; Operation = 'Get'; ApiVersion = 'v1.0'; IdFromDataset = 'a' }
        }

        {
            InModuleScope TenantPulse -ArgumentList @($check), $map {
                param($checks, $map)
                Get-PulseCollectionManifest -Checks $checks -DatasetMap $map
            }
        } | Should -Throw -ExpectedMessage '*cycle*'
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

    It 'does not throw for Read + Safe with no -ApiVersion supplied' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor }

        {
            InModuleScope TenantPulse {
                Assert-PulseReadOnlyDescriptor -Type 'ConditionalAccessPolicy' -Operation 'List'
            }
        } | Should -Not -Throw
    }

    It 'does not throw when -ApiVersion matches the resolved descriptor' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'beta' }

        {
            InModuleScope TenantPulse {
                Assert-PulseReadOnlyDescriptor -Type 'ConditionalAccessPolicy' -Operation 'List' -ApiVersion 'beta'
            }
        } | Should -Not -Throw
    }

    It 'throws a descriptor-version-drift error when -ApiVersion does not match the resolved descriptor' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'v1.0' }

        {
            InModuleScope TenantPulse {
                Assert-PulseReadOnlyDescriptor -Type 'ConditionalAccessPolicy' -Operation 'List' -ApiVersion 'beta'
            }
        } | Should -Throw -ExpectedMessage '*descriptor-version-drift*'
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

    It 'classifies a StatusCode 401 exception property as AuthFailure' {
        $exception = [System.Management.Automation.RuntimeException]::new('boom')
        Add-Member -InputObject $exception -NotePropertyName 'StatusCode' -NotePropertyValue 401
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'Boom', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'AuthFailure'
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

    It 'falls back to message text (AADSTS code) as AuthFailure when no structured status is present' {
        $errorRecord = $null
        try {
            throw 'Get-GraphContext token acquisition failed: AADSTS700016: Application not found in the directory.'
        } catch {
            $errorRecord = $_
        }

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'AuthFailure'
    }

    It 'falls back to message text ("token acquisition") as AuthFailure when no AADSTS code is present' {
        $errorRecord = $null
        try {
            throw 'token acquisition failed: invalid_client'
        } catch {
            $errorRecord = $_
        }

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'AuthFailure'
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

    It 'is total: a string StatusCode ("403 Forbidden") never throws and classifies rather than raw-casting' {
        $exception = [System.Management.Automation.RuntimeException]::new('Request failed: 403 Forbidden')
        Add-Member -InputObject $exception -NotePropertyName 'StatusCode' -NotePropertyValue '403 Forbidden'
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'Boom', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)

        {
            InModuleScope TenantPulse -ArgumentList $errorRecord {
                param($errorRecord)
                Get-PulseFailureClass -ErrorRecord $errorRecord
            }
        } | Should -Not -Throw

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        # TryParse on the non-numeric StatusCode string fails cleanly, so this falls
        # through to the message-text fallback, which still catches the '403'.
        $class | Should -Be 'PermissionDenied'
    }

    It 'is total: a garbage-typed Response.StatusCode value never throws' {
        $exception = [System.Management.Automation.RuntimeException]::new('boom')
        $garbageResponse = [pscustomobject]@{ StatusCode = [pscustomobject]@{ Nonsense = @(1, 2, 3) } }
        Add-Member -InputObject $exception -NotePropertyName 'Response' -NotePropertyValue $garbageResponse
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'Boom', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)

        {
            InModuleScope TenantPulse -ArgumentList $errorRecord {
                param($errorRecord)
                Get-PulseFailureClass -ErrorRecord $errorRecord
            }
        } | Should -Not -Throw

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'Failed'
    }

    It 'is total: a $null ErrorRecord never throws and classifies Failed' {
        {
            InModuleScope TenantPulse {
                Get-PulseFailureClass -ErrorRecord $null
            }
        } | Should -Not -Throw

        $class = InModuleScope TenantPulse {
            Get-PulseFailureClass -ErrorRecord $null
        }

        $class | Should -Be 'Failed'
    }
}

Describe 'Protect-PulseReason' {
    It 'replaces every occurrence of ProfileId with the pseudonym' {
        $result = InModuleScope TenantPulse {
            Protect-PulseReason -Message "profile 'contoso-tenant-id' not found; retried for contoso-tenant-id" -ProfileId 'contoso-tenant-id' -Pseudonym 'tp-abc123'
        }

        $result | Should -Be "profile 'tp-abc123' not found; retried for tp-abc123"
        $result | Should -Not -Match 'contoso-tenant-id'
    }

    It 'also replaces every occurrence of -TenantId with the pseudonym when supplied' {
        $result = InModuleScope TenantPulse {
            Protect-PulseReason -Message 'AADSTS700016: tenant 11111111-1111-1111-1111-111111111111 not found' `
                -ProfileId 'contoso' -Pseudonym 'tp-abc123' -TenantId '11111111-1111-1111-1111-111111111111'
        }

        $result | Should -Not -Match '11111111-1111-1111-1111-111111111111'
        $result | Should -Match 'tp-abc123'
    }

    It 'caps the redacted message at 500 characters' {
        $longMessage = 'x' * 1000

        $result = InModuleScope TenantPulse -ArgumentList $longMessage {
            param($longMessage)
            Protect-PulseReason -Message $longMessage -ProfileId 'contoso' -Pseudonym 'tp-abc123'
        }

        $result.Length | Should -Be 500
    }

    It 'never throws on an empty message' {
        {
            InModuleScope TenantPulse {
                Protect-PulseReason -Message '' -ProfileId 'contoso' -Pseudonym 'tp-abc123'
            }
        } | Should -Not -Throw
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
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } { New-TestReadDescriptor -ApiVersion 'beta' }
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicy' } { New-TestReadDescriptor -ApiVersion 'v1.0' -RequiredPermissions @(@{ Type = 'Application'; Value = 'Policy.Read.All' }, @{ Type = 'Application'; Value = 'Directory.Read.All' }) }
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceConfiguration' } { New-TestReadDescriptor -ApiVersion 'v1.0' }
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
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
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
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $result.datasets.mdmAuthority.status | Should -Be 'Skipped'
        $result.datasets.mdmAuthority.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'downgrades an ApiVersion drift to a per-dataset Failed outcome instead of aborting the run' {
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } { New-TestReadDescriptor -ApiVersion 'v1.0' }
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicy' } { New-TestReadDescriptor -ApiVersion 'v1.0' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicy' } { @([pscustomobject]@{ id = 'p1' }) }

        # conditionalAccessPolicies' map ApiVersion ('beta') deliberately does not match
        # the mocked resolved descriptor's ApiVersion ('v1.0') above.
        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'deviceCompliancePolicies'; Type = 'DeviceCompliancePolicy'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $result.datasets.conditionalAccessPolicies.status | Should -Be 'Failed'
        $result.datasets.conditionalAccessPolicies.reason | Should -Match 'descriptor-version-drift'

        # The read-only predicate violation stays fatal, but a version drift must not
        # abort collection of the remaining, unrelated dataset.
        $result.datasets.deviceCompliancePolicies.status | Should -Be 'Collected'
    }

    It 'on an AuthFailure at the first dataset: sets collectionFailure, fails every remaining dataset with no further Graph calls, and returns' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'beta' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } {
            throw 'Get-GraphObject failed: AADSTS700016: Application not found in the directory.'
        }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'deviceCompliancePolicies'; Type = 'DeviceCompliancePolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'deviceConfigurations'; Type = 'DeviceConfiguration'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json

        $result.collectionFailure | Should -Not -BeNullOrEmpty
        $result.collectionFailure | Should -Match 'AADSTS700016'

        $result.datasets.conditionalAccessPolicies.status | Should -Be 'Failed'
        $result.datasets.conditionalAccessPolicies.reason | Should -Match 'AADSTS700016'

        $result.datasets.deviceCompliancePolicies.status | Should -Be 'Failed'
        $result.datasets.deviceCompliancePolicies.reason | Should -Be 'auth-failure: collection aborted'
        $result.datasets.deviceConfigurations.status | Should -Be 'Failed'
        $result.datasets.deviceConfigurations.reason | Should -Be 'auth-failure: collection aborted'

        # Only the first dataset's Get-GraphObject call happened; the two remaining
        # datasets must never have been attempted against Graph.
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'redacts the raw ProfileId out of a Failed reason' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'beta' }
        Mock Get-GraphObject -ModuleName TenantPulse { throw "Resource lookup failed for profile 'contoso-secret-tenant'." }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso-secret-tenant' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso-secret-tenant' -TenantPseudonym 'tp-abc123'
        }

        $raw = Get-Content -LiteralPath $script:store.ManifestPath -Raw
        $raw | Should -Not -Match 'contoso-secret-tenant'

        $result = $raw | ConvertFrom-Json
        $result.datasets.conditionalAccessPolicies.reason | Should -Match 'tp-abc123'
    }

    It 'IdFromDataset: resolves the dependency''s first row id and passes it as -Parameters @{ id = ... }' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'v1.0' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Operation -eq 'List' } { @([pscustomobject]@{ id = 'org-1' }) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Operation -eq 'GetMdmAuthority' } { @([pscustomobject]@{ mobileDeviceManagementAuthority = 'intune' }) }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'organization'; Type = 'Organization'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = $null }
            [pscustomobject]@{ Dataset = 'organizationMdmAuthority'; Type = 'Organization'; Operation = 'GetMdmAuthority'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = 'organization' }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Operation -eq 'GetMdmAuthority' -and $Parameters.id -eq 'org-1'
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $result.datasets.organization.status | Should -Be 'Collected'
        $result.datasets.organizationMdmAuthority.status | Should -Be 'Collected'
    }

    It 'IdFromDataset: writes Failed with a dependency-unavailable reason and never calls Get-GraphObject when the dependency dataset is empty' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'v1.0' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Operation -eq 'List' } { @() }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Operation -eq 'GetMdmAuthority' } { throw 'Get-GraphObject must not be called when the dependency is unavailable.' }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'organization'; Type = 'Organization'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = $null }
            [pscustomobject]@{ Dataset = 'organizationMdmAuthority'; Type = 'Organization'; Operation = 'GetMdmAuthority'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = 'organization' }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $result.datasets.organization.status | Should -Be 'Collected'
        $result.datasets.organizationMdmAuthority.status | Should -Be 'Failed'
        $result.datasets.organizationMdmAuthority.reason | Should -Be 'dependency-unavailable: organization'

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Operation -eq 'GetMdmAuthority' } -Times 0 -Exactly
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
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } { New-TestReadDescriptor -ApiVersion 'beta' }
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicy' } { New-TestReadDescriptor -ApiVersion 'v1.0' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } { @([pscustomobject]@{ id = 'p1' }) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'DeviceCompliancePolicy' } { throw "Get-GraphObject failed: 403 Forbidden." }

        $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot {
            param($snapshotRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot
        }

        $expectedPseudonym = InModuleScope TenantPulse {
            Get-PulsePseudonym -Value 'contoso-tenant-id' -Key ([byte[]] (0..31))
        }

        $manifestRaw = Get-Content -LiteralPath $store.ManifestPath -Raw
        $manifest = $manifestRaw | ConvertFrom-Json
        $manifest.tenant | Should -Be $expectedPseudonym
        $manifestRaw | Should -Not -Match 'contoso-tenant-id'

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

    It 'still writes the snapshot with collectionFailure set when the FIRST dataset attempt (not context acquisition) discovers an auth failure' {
        # GraphKit's Get-GraphContext performs zero network calls (see its own docstring)
        # - a real auth failure is only ever discovered at the first Get-GraphObject call.
        # Get-GraphContext succeeds here; the auth failure surfaces at collection time.
        $checkOne = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('conditionalAccessPolicies')
        $checkTwo = New-TestCheck -Id 'TP.INT.0002' -Datasets @('deviceCompliancePolicies')

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($checkOne, $checkTwo) }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'beta' }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'AADSTS700016: Application not found in the directory.' }

        $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot {
            param($snapshotRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.collectionFailure | Should -Not -BeNullOrEmpty
        $manifest.collectionFailure | Should -Match 'AADSTS700016'

        $failedCount = @($manifest.datasets.PSObject.Properties | Where-Object { $_.Value.status -eq 'Failed' }).Count
        $failedCount | Should -Be 2

        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'excludes checks outside -IncludeCategory from the collected dataset set' {
        $inScope = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('conditionalAccessPolicies') -Category 'Entra.ConditionalAccess'
        $outOfScope = New-TestCheck -Id 'TP.INT.0002' -Datasets @('deviceCompliancePolicies') -Category 'Intune.Compliance'

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($inScope, $outOfScope) }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'beta' }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot {
            param($snapshotRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot -IncludeCategory 'Entra.ConditionalAccess'
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.PSObject.Properties.Name | Should -Contain 'conditionalAccessPolicies'
        $manifest.datasets.PSObject.Properties.Name | Should -Not -Contain 'deviceCompliancePolicies'
    }

    It 'throws for an empty -ProfileId' {
        {
            InModuleScope TenantPulse -ArgumentList $script:snapshotRoot {
                param($snapshotRoot)
                Get-PulseTenantSnapshot -ProfileId '' -Path $snapshotRoot
            }
        } | Should -Throw
    }

    It 'throws for an empty -Path' {
        {
            InModuleScope TenantPulse {
                Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path ''
            }
        } | Should -Throw
    }
}
