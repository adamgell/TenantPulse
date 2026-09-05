BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks pack first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphObject { param() }
    }

    function New-TestGraphEnvelope {
        param(
            [string] $Outcome = 'Succeeded',
            [string] $Certainty = 'Known',
            [object] $Truncated = $false,
            [AllowNull()] $Data = @(),
            [int] $PageCount = 1
        )

        [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome    = $Outcome
            Certainty  = $Certainty
            Truncated  = $Truncated
            Data       = $Data
            PageCount  = $PageCount
            Telemetry  = @()
            Provenance = @{}
        }
    }

    function New-TestAuthorizationDecision {
        $decisions = [ordered]@{}
        $decisions['MobileApp/ListBeta'] = [pscustomobject]@{
            Type                = 'MobileApp'
            Operation           = 'ListBeta'
            ApiVersion          = 'beta'
            Stability           = 'BetaPreferred'
            Decision            = 'Granted'
            ReasonCode          = 'granted'
            RequiredPermissions = @('DeviceManagementApps.Read.All')
        }

        [pscustomobject]@{
            PSTypeName  = 'TenantPulse.PermissionPreflight'
            TargetAppId = 'fixture-client-id'
            Decision    = 'Granted'
            ReasonCode  = 'granted'
            Decisions   = $decisions
            Findings    = @()
        }
    }
}

Describe 'GraphKit collection envelope validation' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($path)
            New-PulseSnapshotStore -Path $path -Tenant 'tp-envelope-test'
        }
        $script:manifest = @([pscustomobject]@{
                Dataset = 'mobileApps'; Type = 'MobileApp'; Operation = 'ListBeta'; ApiVersion = 'beta'; Pending = $false
            })
        $script:context = [pscustomobject]@{
            TenantId = '22222222-2222-2222-2222-222222222222'; ProfileId = 'profile-1'
        }
        $script:authorization = New-TestAuthorizationDecision
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'fails closed and never persists <Case> as Collected' -ForEach @(
        @{ Case = 'null output'; Fixture = 'Null' }
        @{ Case = 'rows-only output'; Fixture = 'RowsOnly' }
        @{ Case = 'an untyped envelope lookalike'; Fixture = 'UntypedEnvelope' }
        @{ Case = 'a lookalike with a PSTypeName data field'; Fixture = 'SpoofedTypeNameField' }
        @{ Case = 'multiple envelopes'; Fixture = 'Multiple' }
        @{ Case = 'an envelope missing Data'; Fixture = 'MissingData' }
        @{ Case = 'an envelope with null Data'; Fixture = 'NullData' }
        @{ Case = 'an envelope containing a null Data element'; Fixture = 'NullDataElement' }
        @{ Case = 'an envelope missing Truncated'; Fixture = 'MissingTruncated' }
        @{ Case = 'an envelope with an invalid Outcome'; Fixture = 'InvalidOutcome' }
        @{ Case = 'an envelope with an invalid Certainty'; Fixture = 'InvalidCertainty' }
        @{ Case = 'an envelope with non-Boolean Truncated'; Fixture = 'InvalidTruncated' }
    ) {
        InModuleScope TenantPulse -ArgumentList $script:store, $script:manifest, $script:context, $script:authorization, $Fixture {
            param($store, $manifest, $context, $authorization, $fixture)

            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse {
                switch ($fixture) {
                    'Null' { return $null }
                    'RowsOnly' { return [pscustomobject]@{ id = 'row-only' } }
                    'UntypedEnvelope' {
                        return [pscustomobject]@{ Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = @(); PageCount = 1 }
                    }
                    'SpoofedTypeNameField' {
                        return @{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = @(); PageCount = 1 }
                    }
                    'Multiple' {
                        [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = @(); PageCount = 1 }
                        [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = @(); PageCount = 1 }
                    }
                    'MissingData' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; PageCount = 1 }
                    }
                    'NullData' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = $null; PageCount = 1 }
                    }
                    'NullDataElement' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = @($null); PageCount = 1 }
                    }
                    'MissingTruncated' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Data = @(); PageCount = 1 }
                    }
                    'InvalidOutcome' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Maybe'; Certainty = 'Known'; Truncated = $false; Data = @(); PageCount = 1 }
                    }
                    'InvalidCertainty' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Probably'; Truncated = $false; Data = @(); PageCount = 1 }
                    }
                    'InvalidTruncated' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = 'false'; Data = @(); PageCount = 1 }
                    }
                }
            }

            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-envelope-test' -AuthorizationDecision $authorization
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $saved.datasets.mobileApps
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'InvalidProviderData'
        $entry.reasonCode | Should -Be 'invalid-provider-data'
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'mobileApps.json') | Should -BeFalse
    }

    It 'persists one complete empty GraphKit.OperationResult as authoritative Collected evidence' {
        $envelope = New-TestGraphEnvelope -Data @()
        InModuleScope TenantPulse -ArgumentList $script:store, $script:manifest, $script:context, $script:authorization, $envelope {
            param($store, $manifest, $context, $authorization, $envelope)
            $script:GraphEnvelope = $envelope
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse { return $script:GraphEnvelope }

            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-envelope-test' -AuthorizationDecision $authorization
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $saved.datasets.mobileApps
        $entry.status | Should -Be 'Collected'
        $entry.itemCount | Should -Be 0
        $entry.detail.outcome | Should -Be 'Succeeded'
        $entry.detail.certainty | Should -Be 'Known'
        $entry.detail.truncated | Should -BeFalse
        (Get-Content -LiteralPath (Join-Path $script:store.DatasetsPath 'mobileApps.json') -Raw) | Should -Be '[]'
    }

    It 'accepts the immutable GraphKit 0.3.0 non-paged envelope shape with neither Truncated nor PageCount' {
        $envelope = [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Data       = @([ordered]@{ id = 'graphkit-030-row' })
            Telemetry  = @()
            Provenance = @{}
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $envelope {
            param($envelope)
            ConvertTo-PulseDatasetOutcomeFromGraphEnvelope -Envelope $envelope `
                -Dataset 'legacyNonPaged' -ApiVersion 'v1.0' -Operations @('Group.Get') `
                -PagingStrategy 'None'
        }

        $outcome.Status | Should -Be 'Collected'
        $outcome.Rows.Count | Should -Be 1
        $outcome.Rows[0].id | Should -Be 'graphkit-030-row'
        $outcome.Detail.truncated | Should -BeFalse
        $outcome.Detail.PSObject.Properties.Name | Should -Not -Contain 'pageCount'
    }

    It 'persists a non-paged GraphKit 0.3.0 envelope through collection when the descriptor declares None' {
        $manifest = @([pscustomobject]@{
                Dataset = 'organization'; Type = 'Organization'; Operation = 'Get'; ApiVersion = 'v1.0'; Pending = $false
            })
        $authorization = [pscustomobject]@{
            PSTypeName  = 'TenantPulse.PermissionPreflight'
            TargetAppId = 'fixture-client-id'
            Decision    = 'Granted'
            ReasonCode  = 'granted'
            Decisions   = [ordered]@{
                'Organization/Get' = [pscustomobject]@{
                    Type = 'Organization'; Operation = 'Get'; ApiVersion = 'v1.0'
                    Stability = 'Stable'; Decision = 'Granted'; ReasonCode = 'granted'
                    RequiredPermissions = @('Organization.Read.All')
                }
            }
            Findings = @()
        }
        $envelope = [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Data       = @([ordered]@{ id = 'organization-row' })
            Telemetry  = @()
            Provenance = @{}
        }

        InModuleScope TenantPulse -ArgumentList $script:store, $manifest, $script:context, $authorization, $envelope {
            param($store, $manifest, $context, $authorization, $envelope)
            $script:GraphEnvelope = $envelope
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {
                [pscustomobject]@{
                    Type = 'Organization'; Operation = 'Get'; ApiVersion = 'v1.0'
                    PagingStrategy = 'None'; ThrottleClass = 'Read'; ReplayPolicy = 'Safe'
                }
            }
            Mock Get-GraphObject -ModuleName TenantPulse { return $script:GraphEnvelope }

            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-envelope-test' -AuthorizationDecision $authorization
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $saved.datasets.organization
        $entry.status | Should -Be 'Collected'
        $entry.itemCount | Should -Be 1
        $entry.detail.PSObject.Properties.Name | Should -Not -Contain 'pageCount'
        @((Get-Content -LiteralPath (Join-Path $script:store.DatasetsPath 'organization.json') -Raw | ConvertFrom-Json)).Count | Should -Be 1
    }

    It 'rejects a paged GraphKit envelope when both completeness members are missing' {
        $envelope = [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Data       = @([ordered]@{ id = 'must-not-be-authoritative' })
            Telemetry  = @()
            Provenance = @{}
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $envelope {
            param($envelope)
            ConvertTo-PulseDatasetOutcomeFromGraphEnvelope -Envelope $envelope `
                -Dataset 'damagedPagedResult' -ApiVersion 'beta' -Operations @('MobileApp.ListBeta')
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be 'InvalidProviderData'
        @($outcome.Rows).Count | Should -Be 0
    }

    It 'rejects a paged GraphKit envelope when PageCount is missing despite Truncated being present' {
        $envelope = [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Truncated  = $false
            Data       = @([ordered]@{ id = 'must-not-be-authoritative' })
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $envelope {
            param($envelope)
            ConvertTo-PulseDatasetOutcomeFromGraphEnvelope -Envelope $envelope `
                -Dataset 'damagedPagedResult' -ApiVersion 'beta' -Operations @('MobileApp.ListBeta')
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'rejects a paged GraphKit envelope whose PageCount is a non-native <Shape>' -ForEach @(
        @{ Shape = 'string'; Value = '1' }
        @{ Shape = 'Boolean'; Value = $true }
        @{ Shape = 'fraction'; Value = 1.5 }
    ) {
        $envelope = [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Truncated  = $false
            PageCount  = $Value
            Data       = @([ordered]@{ id = 'must-not-be-authoritative' })
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $envelope {
            param($envelope)
            ConvertTo-PulseDatasetOutcomeFromGraphEnvelope -Envelope $envelope `
                -Dataset 'malformedPagedResult' -ApiVersion 'beta' -Operations @('MobileApp.ListBeta')
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be 'InvalidProviderData'
    }

    It 'maps the exact GraphKit paged <Outcome> envelope without success-only paging members' -ForEach @(
        @{ Outcome = 'Failed'; ExpectedFailureClass = 'ProviderFailed'; ExpectedReasonCode = 'provider-failed' }
        @{ Outcome = 'Cancelled'; ExpectedFailureClass = 'Cancelled'; ExpectedReasonCode = 'cancelled' }
        @{ Outcome = 'DeadlineExpired'; ExpectedFailureClass = 'DeadlineExpired'; ExpectedReasonCode = 'deadline-expired' }
    ) {
        # Invoke-GraphPaging returns this exact shape when a page operation is not
        # successful. Truncated and PageCount describe successful traversal completeness
        # and are therefore absent on GraphKit's terminal failure envelope.
        $envelope = [pscustomobject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome    = $Outcome
            Certainty  = 'Indeterminate'
            Data       = @()
            Telemetry  = @()
            Provenance = @{}
        }

        $outcome = InModuleScope TenantPulse -ArgumentList $envelope {
            param($envelope)
            ConvertTo-PulseDatasetOutcomeFromGraphEnvelope -Envelope $envelope `
                -Dataset 'failedEnvelope' -ApiVersion 'v1.0' -Operations @('Group.Get')
        }

        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be $ExpectedFailureClass
        $outcome.ReasonCode | Should -Be $ExpectedReasonCode
        @($outcome.Rows).Count | Should -Be 0
        $outcome.Detail.truncated | Should -BeFalse
        $outcome.Detail.PSObject.Properties.Name | Should -Not -Contain 'pageCount'
    }

    It 'persists Succeeded/Indeterminate/non-truncated rows as Partial with indeterminate detail' {
        $envelope = New-TestGraphEnvelope -Certainty 'Indeterminate' -Truncated $false `
            -Data @([pscustomobject]@{ id = 'safe-row' }) -PageCount 1
        InModuleScope TenantPulse -ArgumentList $script:store, $script:manifest, $script:context, $script:authorization, $envelope {
            param($store, $manifest, $context, $authorization, $envelope)
            $script:GraphEnvelope = $envelope
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse { return $script:GraphEnvelope }

            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-envelope-test' -AuthorizationDecision $authorization
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $saved.datasets.mobileApps
        $entry.status | Should -Be 'Partial'
        $entry.reasonCode | Should -Be 'indeterminate'
        $entry.reason | Should -BeExactly 'indeterminate'
        $entry.detail.truncated | Should -BeFalse
        $entry.detail.pageCount | Should -Be 1
        @($entry.gaps)[0].reasonCode | Should -Be 'indeterminate'
        @($entry.gaps)[0].detail.truncated | Should -BeFalse
        @($entry.gaps)[0].detail.pageCount | Should -Be 1
        @((Get-Content -LiteralPath (Join-Path $script:store.DatasetsPath 'mobileApps.json') -Raw | ConvertFrom-Json)).Count | Should -Be 1
    }

    It 'fails a rowless Succeeded/Indeterminate/non-truncated envelope with reason indeterminate, not truncated' {
        $envelope = New-TestGraphEnvelope -Certainty 'Indeterminate' -Truncated $false -Data @() -PageCount 1
        InModuleScope TenantPulse -ArgumentList $script:store, $script:manifest, $script:context, $script:authorization, $envelope {
            param($store, $manifest, $context, $authorization, $envelope)
            $script:GraphEnvelope = $envelope
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse { return $script:GraphEnvelope }

            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-envelope-test' -AuthorizationDecision $authorization
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $saved.datasets.mobileApps
        $entry.status | Should -Be 'Failed'
        $entry.failureClass | Should -Be 'Indeterminate'
        $entry.reasonCode | Should -Be 'indeterminate'
        $entry.reason | Should -BeExactly 'indeterminate'
        $entry.detail.truncated | Should -BeFalse
        $entry.detail.pageCount | Should -Be 1
        Test-Path -LiteralPath (Join-Path $script:store.DatasetsPath 'mobileApps.json') | Should -BeFalse
    }

    It 'preserves page-cap evidence instead of collapsing it to generic truncation' {
        $envelope = New-TestGraphEnvelope -Certainty 'Indeterminate' -Truncated $true `
            -Data @([pscustomobject]@{ id = 'safe-row' }) -PageCount 200
        InModuleScope TenantPulse -ArgumentList $script:store, $script:manifest, $script:context, $script:authorization, $envelope {
            param($store, $manifest, $context, $authorization, $envelope)
            $script:GraphEnvelope = $envelope
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {}
            Mock Get-GraphObject -ModuleName TenantPulse { return $script:GraphEnvelope }

            Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context `
                -ProfileId 'profile-1' -TenantPseudonym 'tp-envelope-test' -AuthorizationDecision $authorization
        }

        $saved = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $saved.datasets.mobileApps
        $entry.status | Should -Be 'Partial'
        $entry.reasonCode | Should -Be 'page-cap'
        $entry.detail.truncated | Should -BeTrue
        $entry.detail.pageCount | Should -Be 200
        @($entry.gaps)[0].reasonCode | Should -Be 'page-cap'
        @($entry.gaps)[0].detail.pageCount | Should -Be 200
    }
}

Describe 'GraphKit expansion envelope validation' {
    It 'returns rows only from one complete GraphKit.OperationResult' {
        $envelope = New-TestGraphEnvelope -Data @([pscustomobject]@{ id = 'row-1' })
        $rows = InModuleScope TenantPulse -ArgumentList $envelope {
            param($envelope)
            $script:GraphEnvelope = $envelope
            Mock Get-GraphObject -ModuleName TenantPulse { return $script:GraphEnvelope }
            @(Invoke-PulseGraphRead -Context ([pscustomobject]@{}) -Type 'MobileApp' -Operation 'ListBeta')
        }

        $rows.Count | Should -Be 1
        $rows[0].id | Should -Be 'row-1'
    }

    It 'throws before returning rows for <Case>' -ForEach @(
        @{ Case = 'null output'; Fixture = 'Null' }
        @{ Case = 'rows-only output'; Fixture = 'RowsOnly' }
        @{ Case = 'multiple envelopes'; Fixture = 'Multiple' }
        @{ Case = 'a malformed envelope'; Fixture = 'Malformed' }
        @{ Case = 'an envelope with null Data'; Fixture = 'NullData' }
        @{ Case = 'an envelope containing a null Data element'; Fixture = 'NullDataElement' }
        @{ Case = 'a returned failed envelope'; Fixture = 'Failed' }
        @{ Case = 'an indeterminate envelope'; Fixture = 'Indeterminate' }
        @{ Case = 'a truncated envelope'; Fixture = 'Truncated' }
    ) {
        InModuleScope TenantPulse -ArgumentList $Fixture {
            param($fixture)
            Mock Get-GraphObject -ModuleName TenantPulse {
                switch ($fixture) {
                    'Null' { return $null }
                    'RowsOnly' { return [pscustomobject]@{ id = 'row-only' } }
                    'Multiple' {
                        [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = @(); PageCount = 1 }
                        [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = @(); PageCount = 1 }
                    }
                    'Malformed' {
                        # A paged result always carries PageCount. Omitting Truncated while
                        # retaining that paging signal is malformed; the immutable 0.3.0
                        # non-paged shape legitimately carries neither property.
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Data = @(); PageCount = 1 }
                    }
                    'NullData' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = $null }
                    }
                    'NullDataElement' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Known'; Truncated = $false; Data = @($null); PageCount = 1 }
                    }
                    'Failed' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Failed'; Certainty = 'Known'; Truncated = $false; Data = @(); PageCount = 1 }
                    }
                    'Indeterminate' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Indeterminate'; Truncated = $false; Data = @([pscustomobject]@{ id = 'unsafe-to-expand' }); PageCount = 1 }
                    }
                    'Truncated' {
                        return [pscustomobject]@{ PSTypeName = 'GraphKit.OperationResult'; Outcome = 'Succeeded'; Certainty = 'Indeterminate'; Truncated = $true; Data = @([pscustomobject]@{ id = 'unsafe-to-expand' }); PageCount = 200 }
                    }
                }
            }

            {
                Invoke-PulseGraphRead -Context ([pscustomobject]@{}) -Type 'MobileApp' -Operation 'ListBeta'
            } | Should -Throw -ExpectedMessage '*Graph envelope incomplete*'
        }
    }
}
