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
    BeforeAll {
        # GraphKit 0.1.1: Get-GraphObject's failure ErrorRecord now carries structured
        # CategoryInfo.Category (mapped by GraphKit from the HTTP status) and a
        # TargetObject that is the whole GraphKit.OperationResult envelope, so
        # @($_.TargetObject.Telemetry) carries the per-attempt StatusCode/GraphErrorCode
        # history. New-TestGraphFailureRecord below builds an ErrorRecord in exactly that
        # shape - the same shape New-GraphOperationFailureRecord builds inside GraphKit
        # itself. Defined in BeforeAll (not directly in the Describe body) so it is
        # available in every It block's run-phase scope, not just Discovery.
        function script:New-TestGraphFailureRecord {
            param(
                [string] $Message = 'boom',
                [System.Management.Automation.ErrorCategory] $Category = [System.Management.Automation.ErrorCategory]::NotSpecified,
                [object[]] $Telemetry = $null,
                [string] $ErrorId = 'GraphKit.OperationFailed.0'
            )

            $exception = [System.InvalidOperationException]::new($Message)
            $targetObject = if ($null -ne $Telemetry) {
                [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Failed'; Certainty = 'Known'; Telemetry = $Telemetry }
            } else {
                $null
            }
            [System.Management.Automation.ErrorRecord]::new($exception, $ErrorId, $Category, $targetObject)
        }
    }

    It 'classifies CategoryInfo.Category PermissionDenied as PermissionDenied (signal 1, GraphKit 0.1.1)' {
        $errorRecord = New-TestGraphFailureRecord -Message "Get-GraphObject failed for 'ConditionalAccessPolicy/List': Outcome 'Failed', Certainty 'Known', HTTP 403." -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied) -Telemetry @([pscustomobject]@{ Attempt = 1; StatusCode = 403 }) -ErrorId 'GraphKit.OperationFailed.403'

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'PermissionDenied'
    }

    It 'classifies CategoryInfo.Category AuthenticationError as AuthFailure (signal 1, GraphKit 0.1.1)' {
        $errorRecord = New-TestGraphFailureRecord -Message "Get-GraphObject failed for 'ConditionalAccessPolicy/List': Outcome 'Failed', Certainty 'Known', HTTP 401." -Category ([System.Management.Automation.ErrorCategory]::AuthenticationError) -Telemetry @([pscustomobject]@{ Attempt = 1; StatusCode = 401 }) -ErrorId 'GraphKit.OperationFailed.401'

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'AuthFailure'
    }

    It 'classifies a CategoryInfo.Category this function does not map (ResourceUnavailable, 5xx) as Failed' {
        $errorRecord = New-TestGraphFailureRecord -Message "Get-GraphObject failed for 'DeviceConfiguration/List': Outcome 'Failed', Certainty 'Known', HTTP 500." -Category ([System.Management.Automation.ErrorCategory]::ResourceUnavailable) -Telemetry @([pscustomobject]@{ Attempt = 1; StatusCode = 500 }) -ErrorId 'GraphKit.OperationFailed.500'

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'Failed'
    }

    It 'falls back to the Telemetry last-attempt StatusCode (signal 2) when CategoryInfo.Category is NotSpecified' {
        $errorRecord = New-TestGraphFailureRecord -Message 'boom' -Category ([System.Management.Automation.ErrorCategory]::NotSpecified) -Telemetry @(
            [pscustomobject]@{ Attempt = 1; StatusCode = 429 }
            [pscustomobject]@{ Attempt = 2; StatusCode = 403 }
        )

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'PermissionDenied'
    }

    # Enum-typed Telemetry StatusCode must be cast to [int] directly - [string] on an enum
    # renders its NAME ('Forbidden'), not its numeric value ('403').
    It 'classifies an enum-typed Telemetry StatusCode ([System.Net.HttpStatusCode]::Forbidden) as PermissionDenied via signal 2' {
        $errorRecord = New-TestGraphFailureRecord -Category ([System.Management.Automation.ErrorCategory]::NotSpecified) -Telemetry @([pscustomobject]@{ Attempt = 1; StatusCode = [System.Net.HttpStatusCode]::Forbidden })

        $class = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Get-PulseFailureClass -ErrorRecord $errorRecord
        }

        $class | Should -Be 'PermissionDenied'
    }

    It 'falls back to message text ("403") when no CategoryInfo.Category or Telemetry status is present' {
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

    It 'falls back to message text (AADSTS code) as AuthFailure when no structured signal is present' {
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

    It 'is total: a string Telemetry StatusCode ("403 Forbidden") never throws and classifies rather than raw-casting' {
        $errorRecord = New-TestGraphFailureRecord -Message 'Request failed: 403 Forbidden' -Category ([System.Management.Automation.ErrorCategory]::NotSpecified) -Telemetry @([pscustomobject]@{ Attempt = 1; StatusCode = '403 Forbidden' })

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

        # TryParse on the non-numeric Telemetry StatusCode string fails cleanly, so this
        # falls through to the message-text fallback, which still catches the '403'.
        $class | Should -Be 'PermissionDenied'
    }

    It 'is total: a garbage-typed TargetObject.Telemetry value never throws' {
        $errorRecord = New-TestGraphFailureRecord -Category ([System.Management.Automation.ErrorCategory]::NotSpecified) -Telemetry @([pscustomobject]@{ Attempt = 1; StatusCode = [pscustomobject]@{ Nonsense = @(1, 2, 3) } })

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

Describe 'Test-PulseErrorRecordHasStructuredSignal' {
    It 'returns $true when CategoryInfo.Category is a mapped, non-default category' {
        $exception = [System.InvalidOperationException]::new('boom')
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'GraphKit.OperationFailed.403', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)

        $result = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Test-PulseErrorRecordHasStructuredSignal -ErrorRecord $errorRecord
        }

        $result | Should -BeTrue
    }

    It 'returns $true when TargetObject.Telemetry carries a readable last-attempt StatusCode' {
        $exception = [System.InvalidOperationException]::new('boom')
        $targetObject = [pscustomobject]@{ Telemetry = @([pscustomobject]@{ StatusCode = 500 }) }
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'GraphKit.OperationFailed.500', [System.Management.Automation.ErrorCategory]::NotSpecified, $targetObject)

        $result = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Test-PulseErrorRecordHasStructuredSignal -ErrorRecord $errorRecord
        }

        $result | Should -BeTrue
    }

    It 'returns $false for a plain string-thrown ErrorRecord with no CategoryInfo.Category or Telemetry' {
        $errorRecord = $null
        try {
            throw 'Get-GraphObject failed: 500 Internal Server Error.'
        } catch {
            $errorRecord = $_
        }

        $result = InModuleScope TenantPulse -ArgumentList $errorRecord {
            param($errorRecord)
            Test-PulseErrorRecordHasStructuredSignal -ErrorRecord $errorRecord
        }

        $result | Should -BeFalse
    }

    It 'is total: a $null ErrorRecord returns $false rather than throwing' {
        {
            InModuleScope TenantPulse {
                Test-PulseErrorRecordHasStructuredSignal -ErrorRecord $null
            }
        } | Should -Not -Throw

        $result = InModuleScope TenantPulse {
            Test-PulseErrorRecordHasStructuredSignal -ErrorRecord $null
        }

        $result | Should -BeFalse
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

    # Task 1.11 live gate regression (Ivy24 lab tenant, no Policy.Read.All grant): a real
    # Get-GraphObject 403 throws ONLY "Get-GraphObject failed for '<Type>/<Operation>':
    # Outcome 'Failed', Certainty 'Known'." - no '403 Forbidden' text, unlike every other
    # test in this Describe block, which mocks that text into the thrown message. Without
    # the supplemental Invoke-GraphOperation classification call this dataset landed
    # Failed, not the Skipped/permission-denied honest-degradation contract the design
    # promises - this test pins the fix against the real shape, not the assumed one.
    It 'classifies a real-shaped GraphKit 0.1.1 Get-GraphObject 403 ErrorRecord (CategoryInfo.Category PermissionDenied) as Skipped/permission-denied' {
        Mock Get-GraphOperation -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } { New-TestReadDescriptor -ApiVersion 'beta' -RequiredPermissions @(@{ Type = 'Application'; Value = 'Policy.Read.All' }) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } {
            $exception = [System.InvalidOperationException]::new("Get-GraphObject failed for 'ConditionalAccessPolicy/List': Outcome 'Failed', Certainty 'Known', HTTP 403.")
            $targetObject = [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Failed'; Certainty = 'Known'; Telemetry = @([pscustomobject]@{ Attempt = 1; StatusCode = 403 }) }
            $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'GraphKit.OperationFailed.403', [System.Management.Automation.ErrorCategory]::PermissionDenied, $targetObject)
            throw $errorRecord
        }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $result.datasets.conditionalAccessPolicies.status | Should -Be 'Skipped'
        $result.datasets.conditionalAccessPolicies.reason | Should -Match '^permission-denied:'
        $result.datasets.conditionalAccessPolicies.reason | Should -Match 'Policy.Read.All'

        # Mock-seam proof (Task 1.11 GraphKit 0.1.1 migration): confirm the mocked
        # Get-GraphObject 403 ErrorRecord is what this test actually exercised, not some
        # other path that happened to land on the same reason string.
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' }
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

        # Mock-seam proof (Task 1.11 review round 2): three independently-filtered
        # Get-GraphObject mocks are staged above (one per Type) - prove each one actually
        # fired exactly once, rather than trusting the manifest's final reason strings to
        # imply it.
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' }
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter { $Type -eq 'DeviceCompliancePolicy' }
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter { $Type -eq 'DeviceConfiguration' }
    }

    # GraphKit 0.1.1 migration: '(status unknown)' now means the ErrorRecord itself
    # carried NO structured signal at all - no CategoryInfo.Category this classifier maps
    # and no readable Telemetry StatusCode (see Test-PulseErrorRecordHasStructuredSignal) -
    # not (as under GraphKit 0.1.0) that a separate out-of-band recovery call failed. A
    # plain `throw "<message>"` (no ErrorRecord constructed with a mapped category or a
    # TargetObject) is exactly that shape.
    It 'appends "(status unknown)" to a Failed reason when the ErrorRecord carries no structured signal' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'v1.0' }
        Mock Get-GraphObject -ModuleName TenantPulse { throw "Get-GraphObject failed for 'DeviceConfiguration/List': 500 Internal Server Error." }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'deviceConfigurations'; Type = 'DeviceConfiguration'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $result.datasets.deviceConfigurations.status | Should -Be 'Failed'
        $result.datasets.deviceConfigurations.reason | Should -Match '\(status unknown\)$'
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

        # Mock-seam proof (Task 1.11 review round 2): the version-drift dataset must never
        # reach Get-GraphObject at all (Assert-PulseReadOnlyDescriptor throws first), while
        # the unrelated dataset must reach it exactly once.
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 0 -Exactly -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' }
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter { $Type -eq 'DeviceCompliancePolicy' }
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

    # Item 14 (final fix wave): a Pending dataset caught by the auth-abort loop must keep
    # its own descriptor-pending reason, not get overwritten to auth-failure.
    It 'on an AuthFailure: a remaining Pending dataset keeps its descriptor-pending reason, not auth-failure (final fix wave, item 14)' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'beta' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConditionalAccessPolicy' } {
            throw 'Get-GraphObject failed: AADSTS700016: Application not found in the directory.'
        }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'conditionalAccessPolicies'; Type = 'ConditionalAccessPolicy'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
            [pscustomobject]@{ Dataset = 'entraDevices'; Type = 'EntraDevice'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $true }
            [pscustomobject]@{ Dataset = 'deviceConfigurations'; Type = 'DeviceConfiguration'; Operation = 'List'; ApiVersion = 'beta'; Pending = $false }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json

        $result.datasets.entraDevices.status | Should -Be 'Skipped'
        $result.datasets.entraDevices.reason | Should -Match '^descriptor-pending:'

        $result.datasets.deviceConfigurations.status | Should -Be 'Failed'
        $result.datasets.deviceConfigurations.reason | Should -Be 'auth-failure: collection aborted'
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

        # Mock-seam proof (Task 1.11 review round 2): unfiltered mocks can't have a
        # ParameterFilter mismatch, but confirming the call count still proves this test
        # actually reached Get-GraphObject rather than short-circuiting somewhere earlier.
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly
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
        # Mock-seam proof (Task 1.11 review round 2): the dependency call itself must also
        # be confirmed - without this, a broken dependency-id lookup that happened to fall
        # through to some other mocked value could still coincidentally satisfy the
        # assertion above.
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter { $Operation -eq 'List' }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $result.datasets.organization.status | Should -Be 'Collected'
        $result.datasets.organizationMdmAuthority.status | Should -Be 'Collected'
    }

    # Task 1.11 GraphKit 0.1.1 live-gate surprise (Ivy24 lab tenant): Organization.id IS
    # the raw tenant GUID. Write-PulseDataset now redacts the tenant GUID out of the
    # organization.json FILE content (see Snapshot.Tests.ps1's Write-PulseDataset
    # coverage) - this test pins that the IdFromDataset dependency lookup still reads the
    # REAL id off the in-memory row (not the file-redacted pseudonym) so the dependent
    # organizationMdmAuthority Graph call is parameterized correctly, not with a pseudonym
    # Graph would reject.
    It 'IdFromDataset: the dependency lookup uses the REAL id even when the dependency row''s id equals the context TenantId (redacted only in the written file)' {
        $tenantId = 'REDACTED-TENANT-GUID'
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'v1.0' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Operation -eq 'List' } { @([pscustomobject]@{ id = $tenantId }) }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Operation -eq 'GetMdmAuthority' } { @([pscustomobject]@{ mobileDeviceManagementAuthority = 'intune' }) }

        $manifest = @(
            [pscustomobject]@{ Dataset = 'organization'; Type = 'Organization'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = $null }
            [pscustomobject]@{ Dataset = 'organizationMdmAuthority'; Type = 'Organization'; Operation = 'GetMdmAuthority'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = 'organization' }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso'; TenantId = $tenantId }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        # The dependent call must have received the REAL tenant GUID, not the pseudonym.
        Should-Invoke Get-GraphObject -ModuleName TenantPulse -Times 1 -Exactly -ParameterFilter {
            $Operation -eq 'GetMdmAuthority' -and $Parameters.id -eq $tenantId
        }

        # But the written organization.json file itself must carry the pseudonym, not the
        # raw tenant GUID - the redaction still applies to what actually gets persisted.
        $writtenJson = Get-Content -LiteralPath (Join-Path $script:store.DatasetsPath 'organization.json') -Raw
        $writtenJson | Should -Not -Match ([regex]::Escape($tenantId))
        $writtenJson | Should -Match 'tp-abc123'
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

    It 'IdFromDataset (L6): distinguishes dependency-pending from a genuine dependency-unavailable failure' {
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'v1.0' }
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Operation -eq 'GetMdmAuthority' } { throw 'Get-GraphObject must not be called when the dependency is Pending.' }

        # The dependency ('organization') is itself Pending - never attempted, never
        # collected - which is a materially different situation from the dependency having
        # been attempted and genuinely failed/returned nothing (the sibling test above).
        $manifest = @(
            [pscustomobject]@{ Dataset = 'organization'; Type = 'Organization'; Operation = 'List'; ApiVersion = 'v1.0'; Pending = $true; IdFromDataset = $null }
            [pscustomobject]@{ Dataset = 'organizationMdmAuthority'; Type = 'Organization'; Operation = 'GetMdmAuthority'; ApiVersion = 'v1.0'; Pending = $false; IdFromDataset = 'organization' }
        )
        $context = [pscustomobject]@{ ProfileId = 'contoso' }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $context {
            param($store, $manifest, $context)
            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId 'contoso' -TenantPseudonym 'tp-abc123'
        }

        $result = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $result.datasets.organization.status | Should -Be 'Skipped'
        $result.datasets.organization.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'

        $result.datasets.organizationMdmAuthority.status | Should -Be 'Failed'
        $result.datasets.organizationMdmAuthority.reason | Should -Be 'dependency-pending: organization (descriptor not yet in released GraphKit)'

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
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id'; TenantId = 'contoso-tenant-id' } }
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

    # Item 1 (final fix wave, spec 2a): the pseudonym is keyed on the resolved TENANT ID,
    # never -ProfileId - the same tenant reached under two differently-named profiles must
    # pseudonymize identically, and renaming a profile must never change the pseudonym.
    It 'pseudonymizes the same tenant identically across two differently-named GraphKit profiles' {
        $checkOne = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('conditionalAccessPolicies')
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($checkOne) }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'beta' }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        # Two distinct ProfileIds ('contoso-prod' and 'contoso-renamed') resolving to the
        # SAME synthetic tenant id - as if the same tenant were reached under a
        # differently-named GraphKit profile, or the profile were renamed between runs.
        $sameTenantId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Mock Get-GraphContext -ModuleName TenantPulse -ParameterFilter { $ProfileId -eq 'contoso-prod' } {
            [pscustomobject]@{ ProfileId = 'contoso-prod'; TenantId = $sameTenantId }
        }
        Mock Get-GraphContext -ModuleName TenantPulse -ParameterFilter { $ProfileId -eq 'contoso-renamed' } {
            [pscustomobject]@{ ProfileId = 'contoso-renamed'; TenantId = $sameTenantId }
        }

        $storeRootA = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $storeRootB = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            $storeA = InModuleScope TenantPulse -ArgumentList $storeRootA {
                param($root)
                Get-PulseTenantSnapshot -ProfileId 'contoso-prod' -OutputPath $root
            }
            $storeB = InModuleScope TenantPulse -ArgumentList $storeRootB {
                param($root)
                Get-PulseTenantSnapshot -ProfileId 'contoso-renamed' -OutputPath $root
            }

            $manifestA = Get-Content -LiteralPath $storeA.ManifestPath -Raw | ConvertFrom-Json
            $manifestB = Get-Content -LiteralPath $storeB.ManifestPath -Raw | ConvertFrom-Json

            $manifestA.tenant | Should -Not -BeNullOrEmpty
            $manifestA.tenant | Should -Be $manifestB.tenant
        } finally {
            Remove-Item -LiteralPath $storeRootA -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $storeRootB -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Task 1.11 review follow-up: GraphKit's Get-GraphObject stamps every row with
    # _Tenant (the ProfileId - an operator-chosen label, not the raw tenant GUID, but
    # still an identifier with no place in a pseudonymized artifact), _RetrievedUtc,
    # _GraphPath and _ApiVersion. Write-PulseDataset now strips all four before
    # serialization (see Remove-PulseGraphRowProvenance). This test reproduces the live
    # gate's own verification method - grep the whole output tree for the raw ProfileId -
    # against a snapshot built from rows carrying every stamp, so a future regression in
    # the strip would fail here before it ever reaches a live tenant again.
    It 'strips GraphKit''s per-row provenance stamps before writing dataset files - a grep for the raw ProfileId across the whole output tree finds nothing' {
        $checkOne = New-TestCheck -Id 'TP.INT.0002' -Datasets @('deviceCompliancePolicies')

        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($checkOne) }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id'; TenantId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'v1.0' }
        Mock Get-GraphObject -ModuleName TenantPulse {
            # Reproduces exactly what Get-GraphObject stamps onto a real returned row.
            [pscustomobject]@{
                id            = 'p1'
                _Tenant       = 'contoso-tenant-id'
                _RetrievedUtc = [datetime]::UtcNow
                _GraphPath    = '/deviceManagement/deviceCompliancePolicies'
                _ApiVersion   = 'v1.0'
            }
        }

        $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot {
            param($snapshotRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot
        }

        $datasetFile = Join-Path $store.DatasetsPath 'deviceCompliancePolicies.json'
        Test-Path -LiteralPath $datasetFile -PathType Leaf | Should -BeTrue

        $writtenRows = Get-Content -LiteralPath $datasetFile -Raw | ConvertFrom-Json
        $writtenRows[0].id | Should -Be 'p1'
        $writtenRows[0].PSObject.Properties.Name | Should -Not -Contain '_Tenant'
        $writtenRows[0].PSObject.Properties.Name | Should -Not -Contain '_RetrievedUtc'
        $writtenRows[0].PSObject.Properties.Name | Should -Not -Contain '_GraphPath'
        $writtenRows[0].PSObject.Properties.Name | Should -Not -Contain '_ApiVersion'

        # The whole-tree grep the live gate itself used: the raw ProfileId must not
        # survive anywhere under the snapshot root - not the manifest (already covered
        # above), and now not any dataset file either.
        $rawOutputTree = Get-ChildItem -LiteralPath $script:snapshotRoot -Recurse -File |
            ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }
        $rawOutputTree -join "`n" | Should -Not -Match 'contoso-tenant-id'
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
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id'; TenantId = 'contoso-tenant-id' } }
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
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id'; TenantId = 'contoso-tenant-id' } }
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

    # Item 2 (final fix wave): -Path renamed to -OutputPath; -Path kept as a deprecated
    # alias for one release and must still work.
    It '-Path still works as a deprecated alias for -OutputPath' {
        $checkOne = New-TestCheck -Id 'TP.ENT.0001' -Datasets @('conditionalAccessPolicies')
        Mock Import-PulseCheckCatalog -ModuleName TenantPulse { @($checkOne) }
        Mock Get-GraphContext -ModuleName TenantPulse { [pscustomobject]@{ ProfileId = 'contoso-tenant-id'; TenantId = 'contoso-tenant-id' } }
        Mock Get-GraphOperation -ModuleName TenantPulse { New-TestReadDescriptor -ApiVersion 'beta' }
        Mock Get-GraphObject -ModuleName TenantPulse { @([pscustomobject]@{ id = 'p1' }) }

        $store = InModuleScope TenantPulse -ArgumentList $script:snapshotRoot {
            param($snapshotRoot)
            Get-PulseTenantSnapshot -ProfileId 'contoso-tenant-id' -Path $snapshotRoot
        }

        Test-Path -LiteralPath $store.ManifestPath -PathType Leaf | Should -BeTrue
    }
}
