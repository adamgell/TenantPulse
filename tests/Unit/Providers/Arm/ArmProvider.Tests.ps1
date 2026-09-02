<#
    Deterministic ARM provider adapter tests.

    These tests load the ARM namespace and the provider-neutral collection outcome
    helpers from source. They never import GraphKit, never call Azure, and never
    require a Sampler build. Live diagnostic-settings access is out of scope.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../../..')).ProviderPath
    $script:armDir = Join-Path $script:repoRoot 'source/Private/Providers/Arm'
    if (-not (Test-Path -LiteralPath $script:armDir -PathType Container)) {
        throw "ARM provider namespace missing at '$script:armDir'."
    }

    $moduleName = 'TenantPulseArmAdapterTest'
    Get-Module $moduleName -ErrorAction SilentlyContinue | Remove-Module -Force
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @(
            (Join-Path $script:repoRoot 'source/Private/Collect/New-PulseCollectionGap.ps1')
            (Join-Path $script:repoRoot 'source/Private/Collect/New-PulseCollectionOutcome.ps1')
        ) + @(Get-ChildItem -LiteralPath $script:armDir -Filter '*.ps1' | Sort-Object Name | ForEach-Object FullName)) {
        $parts.Add((Get-Content -LiteralPath $path -Raw))
    }

    New-Module -Name $moduleName -ScriptBlock ([scriptblock]::Create(($parts -join "`n"))) |
        Import-Module -Force

    $script:BoundTenantId = '00000000-0000-0000-0000-000000000001'
    $script:BoundSubscriptionId = '00000000-0000-0000-0000-000000000002'
    $script:OtherSubscriptionId = '00000000-0000-0000-0000-000000000003'
    $script:OtherTenantId = '00000000-0000-0000-0000-000000000009'

    # Split the public ARM namespace so SecretScan does not treat it as a domain near fixture GUIDs.
    $script:IntuneNs = 'microsoft' + '.intune'
    $script:IntuneResourceId = '/providers/' + $script:IntuneNs
    $script:FixtureApiVersion = '2021-05-01-preview'

    $script:ArmSendUris = [System.Collections.Generic.List[string]]::new()
    $script:ArmResponseQueue = [System.Collections.Generic.Queue[object]]::new()
    $script:VirtualNow = [datetime]::SpecifyKind([datetime]'2026-09-02T00:00:00', 'Utc')
    $script:DelaySeconds = [System.Collections.Generic.List[double]]::new()

    $script:FakeSend = {
        param([uri] $Uri, [string] $Method)
        $script:ArmSendUris.Add([string] $Uri)
        if ($script:ArmResponseQueue.Count -eq 0) {
            throw "Unexpected extra ARM send to '$Uri'."
        }
        return $script:ArmResponseQueue.Dequeue()
    }

    function New-ArmTransportResult {
        param(
            [int] $StatusCode = 200,
            [object] $Body = $null,
            [hashtable] $Headers = $null,
            [bool] $ResponseReceived = $true
        )
        return [pscustomobject]@{
            StatusCode        = $StatusCode
            Body              = $Body
            Headers           = $Headers
            ResponseReceived  = $ResponseReceived
        }
    }

    function Reset-ArmProviderTestState {
        $script:ArmSendUris.Clear()
        $script:ArmResponseQueue.Clear()
        $script:DelaySeconds.Clear()
        $script:VirtualNow = [datetime]::SpecifyKind([datetime]'2026-09-02T00:00:00', 'Utc')
    }

    function Get-ArmTestInjections {
        return @{
            Send   = $script:FakeSend
            UtcNow = { $script:VirtualNow }
            Delay  = {
                param([double] $Seconds)
                $script:DelaySeconds.Add($Seconds)
                $script:VirtualNow = $script:VirtualNow.AddSeconds($Seconds)
            }
            Jitter = { 0.0 }
        }
    }

}

AfterAll {
    Get-Module TenantPulseArmAdapterTest -ErrorAction SilentlyContinue | Remove-Module -Force
}

Describe 'ARM stays outside the Graph catalog' {
    It 'does not declare an ARM dataset, authority, or diagnostic-settings Graph type in DatasetMap.psd1' {
        $mapPath = Join-Path $script:repoRoot 'source/Data/DatasetMap.psd1'
        $map = Import-PowerShellDataFile -Path $mapPath
        $map.Keys | Should -Not -Contain 'intuneDiagnosticSettings'
        $map.Keys | Should -Not -Contain 'diagnosticSettings'
        foreach ($name in $map.Keys) {
            $entry = $map[$name]
            $entry.Contains('Authority') | Should -BeFalse -Because "dataset '$name' must remain a Graph map entry, not an ARM authority record"
            $entry.Type | Should -Not -Match 'Arm|AzureResourceManager|DiagnosticSetting'
            $entry.Type | Should -Not -Match 'management\.azure\.com'
        }
    }

    It 'does not ship a TP.INT.0010 check descriptor' {
        $check = Join-Path $script:repoRoot 'source/Data/Checks/TP.INT.0010.psd1'
        Test-Path -LiteralPath $check | Should -BeFalse
    }

    It 'keeps the ARM provider under source/Private/Providers/Arm rather than Graph operations' {
        Test-Path -LiteralPath $script:armDir -PathType Container | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:repoRoot 'source/Data/Operations') | Should -BeFalse
        (Get-ChildItem -LiteralPath $script:armDir -Filter '*.ps1').Count | Should -BeGreaterThan 0
    }
}

Describe 'ARM authority and audience' {
    It 'binds Global ARM traffic to management.azure.com and the ARM audience' {
        $profile = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmCloudProfile -Cloud 'Global'
        }
        $profile.Cloud | Should -Be 'Global'
        $profile.Authority | Should -Be 'management.azure.com'
        $profile.Audience | Should -Be 'https://management.azure.com/.default'
        $profile.BaseUri.AbsoluteUri | Should -Be 'https://management.azure.com/'
        $profile.PSObject.Properties.Name | Should -Not -Contain 'Type'
        $profile.PSObject.Properties.Name | Should -Not -Contain 'Operation'
    }

    It 'binds USGov and China to their ARM authorities, not Graph' {
        $profiles = InModuleScope TenantPulseArmAdapterTest {
            @(
                Get-PulseArmCloudProfile -Cloud 'USGov'
                Get-PulseArmCloudProfile -Cloud 'China'
            )
        }
        $profiles[0].Authority | Should -Be 'management.usgovcloudapi.net'
        $profiles[0].Audience | Should -Be 'https://management.usgovcloudapi.net/.default'
        $profiles[1].Authority | Should -Be 'management.chinacloudapi.cn'
        $profiles[1].Audience | Should -Be 'https://management.chinacloudapi.cn/.default'
        $profiles.Authority | Should -Not -Match 'graph\.microsoft'
    }

    It 'accepts the exact HTTPS ARM authority on port 443' {
        InModuleScope TenantPulseArmAdapterTest -ArgumentList ('https://management.azure.com' + $script:IntuneResourceId) {
            param($Uri)
            Test-PulseArmAuthority -Uri $Uri -Cloud 'Global'
        } | Should -BeTrue
    }

    It 'rejects a Graph authority before any ARM credential attach' {
        {
            InModuleScope TenantPulseArmAdapterTest {
                Test-PulseArmAuthority -Uri 'https://graph.microsoft.com/v1.0/deviceManagement' -Cloud 'Global'
            }
        } | Should -Throw -ExpectedMessage '*graph.microsoft.com*'
    }

    It 'rejects a non-HTTPS ARM URI' {
        {
            InModuleScope TenantPulseArmAdapterTest -ArgumentList ('http://management.azure.com' + $script:IntuneResourceId) {
                param($Uri)
                Test-PulseArmAuthority -Uri $Uri -Cloud 'Global'
            }
        } | Should -Throw -ExpectedMessage '*non-HTTPS*'
    }

    It 'rejects a non-443 port even on the ARM host' {
        {
            InModuleScope TenantPulseArmAdapterTest -ArgumentList ('https://management.azure.com:8443' + $script:IntuneResourceId) {
                param($Uri)
                Test-PulseArmAuthority -Uri $Uri -Cloud 'Global'
            }
        } | Should -Throw -ExpectedMessage '*8443*'
    }

    It 'rejects a sovereign ARM host that does not match the bound cloud' {
        {
            InModuleScope TenantPulseArmAdapterTest -ArgumentList ('https://management.usgovcloudapi.net' + $script:IntuneResourceId) {
                param($Uri)
                Test-PulseArmAuthority -Uri $Uri -Cloud 'Global'
            }
        } | Should -Throw -ExpectedMessage '*management.usgovcloudapi.net*'
    }

    It 'rejects a relative nextLink' {
        {
            InModuleScope TenantPulseArmAdapterTest -ArgumentList $script:IntuneResourceId {
                param($Uri)
                Test-PulseArmAuthority -Uri $Uri -Cloud 'Global'
            }
        } | Should -Throw -ExpectedMessage '*relative*'
    }
}

Describe 'ARM resource ID validation' {
    It 'accepts the tenant-level Intune resource ID' {
        $parsed = InModuleScope TenantPulseArmAdapterTest -ArgumentList $script:IntuneResourceId {
            param($ResourceId)
            Test-PulseArmResourceId -ResourceId $ResourceId
        }
        $parsed.ResourceId | Should -Be $script:IntuneResourceId
        $parsed.IsTenantLevel | Should -BeTrue
        $parsed.ProviderNamespace | Should -Be $script:IntuneNs
        $parsed.SubscriptionId | Should -BeNullOrEmpty
    }

    It 'accepts a subscription-scoped resource ID that matches the bound subscription' {
        $parsed = InModuleScope TenantPulseArmAdapterTest -ArgumentList $script:BoundSubscriptionId {
            param($SubscriptionId)
            Test-PulseArmResourceId -ResourceId "/subscriptions/$SubscriptionId/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1" `
                -BoundSubscriptionId $SubscriptionId
        }
        $parsed.IsTenantLevel | Should -BeFalse
        $parsed.SubscriptionId | Should -Be $script:BoundSubscriptionId
        $parsed.ResourceGroup | Should -Be 'rg1'
    }

    It 'rejects a resource ID that targets a different subscription than the bound one' {
        {
            InModuleScope TenantPulseArmAdapterTest -ArgumentList $script:BoundSubscriptionId, $script:OtherSubscriptionId {
                param($Bound, $Other)
                Test-PulseArmResourceId -ResourceId "/subscriptions/$Other/resourceGroups/rg1" -BoundSubscriptionId $Bound
            }
        } | Should -Throw -ExpectedMessage '*subscription*'
    }

    It 'rejects a resource ID that embeds a different tenant than the bound one' {
        {
            InModuleScope TenantPulseArmAdapterTest -ArgumentList $script:BoundTenantId, $script:OtherTenantId, $script:IntuneNs {
                param($Bound, $Other, $IntuneNs)
                Test-PulseArmResourceId -ResourceId "/tenants/$Other/providers/$IntuneNs" -BoundTenantId $Bound
            }
        } | Should -Throw -ExpectedMessage '*tenant*'
    }

    It 'rejects Graph-shaped, relative, traversal, and query resource IDs' {
        $ns = $script:IntuneNs
        $bad = @(
            "providers/$ns"
            '/v1.0/deviceManagement/diagnosticSettings'
            "$($script:IntuneResourceId)/../subscriptions/$($script:BoundSubscriptionId)"
            "$($script:IntuneResourceId)?api-version=2021-05-01-preview"
            "//providers/$ns"
            "https://management.azure.com$($script:IntuneResourceId)"
            '/subscriptions/not-a-guid'
            ''
        )
        foreach ($id in $bad) {
            {
                InModuleScope TenantPulseArmAdapterTest -ArgumentList $id {
                    param($ResourceId)
                    Test-PulseArmResourceId -ResourceId $ResourceId
                }
            } | Should -Throw
        }
    }
}

Describe 'ARM API version and Azure RBAC' {
    It 'accepts a dated ARM API version and rejects Graph versions' {
        InModuleScope TenantPulseArmAdapterTest {
            Test-PulseArmApiVersion -ApiVersion '2021-05-01-preview'
        } | Should -BeTrue
        InModuleScope TenantPulseArmAdapterTest {
            Test-PulseArmApiVersion -ApiVersion '2017-05-01'
        } | Should -BeTrue
        {
            InModuleScope TenantPulseArmAdapterTest { Test-PulseArmApiVersion -ApiVersion 'v1.0' }
        } | Should -Throw -ExpectedMessage '*API version*'
        {
            InModuleScope TenantPulseArmAdapterTest { Test-PulseArmApiVersion -ApiVersion 'beta' }
        } | Should -Throw -ExpectedMessage '*API version*'
    }

    It 'declares Azure RBAC for diagnostic settings, not a Graph permission' {
        $rbac = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmRbacRequirement -Operation 'diagnosticSettings'
        }
        $rbac | Should -Be @('Microsoft.Insights/diagnosticSettings/read')
        $rbac | Should -Not -Match 'Directory\.Read|DeviceManagement|Policy\.Read'
    }

    It 'records diagnostic-settings API version as unproven until a live contract exists' {
        $contract = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmDiagnosticSettingsContract
        }
        $contract.Provider | Should -Be 'ARM'
        $contract.Disposition | Should -Be 'DeferredUntilLiveContract'
        $contract.ApiVersion | Should -BeNullOrEmpty
        $contract.ApiVersionStatus | Should -Be 'Unproven'
        $contract.PSObject.Properties.Name | Should -Not -Contain 'Type'
        $contract.PSObject.Properties.Name | Should -Not -Contain 'Operation'
    }
}

Describe 'ARM retry and throttle decisions' {
    It 'treats 2xx as success and never replays, even with Retry-After' {
        $d = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmRetryDecision -Method 'GET' -StatusCode 200 -AttemptCertainty 'Succeeded' `
                -ForceRefreshUsed $false -CanRefresh $true
        }
        $d.ShouldRetry | Should -BeFalse
        $d.Outcome | Should -Be 'Succeeded'
        $d.Certainty | Should -Be 'Known'
    }

    It 'retries a clean 429 under the ARM GET Safe policy' {
        $d = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmRetryDecision -Method 'GET' -StatusCode 429 -AttemptCertainty 'Rejected' `
                -ForceRefreshUsed $false -CanRefresh $true
        }
        $d.ShouldRetry | Should -BeTrue
        $d.Outcome | Should -Be $null
    }

    It 'never retries 403 permission denial' {
        $d = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmRetryDecision -Method 'GET' -StatusCode 403 -AttemptCertainty 'Rejected' `
                -ForceRefreshUsed $false -CanRefresh $true
        }
        $d.ShouldRetry | Should -BeFalse
        $d.Outcome | Should -Be 'Failed'
        $d.Certainty | Should -Be 'Known'
        $d.FailureClass | Should -Be 'PermissionDenied'
    }

    It 'forces exactly one ARM token refresh on 401' {
        $first = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmRetryDecision -Method 'GET' -StatusCode 401 -AttemptCertainty 'Rejected' `
                -ForceRefreshUsed $false -CanRefresh $true
        }
        $first.ShouldRetry | Should -BeTrue
        $first.ForceRefresh | Should -BeTrue

        $second = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmRetryDecision -Method 'GET' -StatusCode 401 -AttemptCertainty 'Rejected' `
                -ForceRefreshUsed $true -CanRefresh $true
        }
        $second.ShouldRetry | Should -BeFalse
        $second.FailureClass | Should -Be 'AuthenticationFailed'
    }

    It 'retries an ambiguous GET 503 and refuses to replay an ambiguous POST' {
        $get = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmRetryDecision -Method 'GET' -StatusCode 503 -AttemptCertainty 'Ambiguous' `
                -ForceRefreshUsed $false -CanRefresh $true
        }
        $get.ShouldRetry | Should -BeTrue

        $post = InModuleScope TenantPulseArmAdapterTest {
            Get-PulseArmRetryDecision -Method 'POST' -StatusCode 503 -AttemptCertainty 'Ambiguous' `
                -ForceRefreshUsed $false -CanRefresh $true
        }
        $post.ShouldRetry | Should -BeFalse
        $post.Outcome | Should -Be 'Failed'
        $post.Certainty | Should -Be 'Indeterminate'
        $post.FailureClass | Should -Be 'Indeterminate'
    }
}

Describe 'ARM request, result, and provenance adapter' {
    It 'builds a GET ARM request with no Graph operation metadata' {
        $request = InModuleScope TenantPulseArmAdapterTest -ArgumentList $script:IntuneResourceId, $script:FixtureApiVersion {
            param($ResourceId, $ApiVersion)
            New-PulseArmRequest -ResourceId $ResourceId -ApiVersion $ApiVersion -Cloud 'Global'
        }
        $request.Provider | Should -Be 'ARM'
        $request.Method | Should -Be 'GET'
        $request.ReplayPolicy | Should -Be 'Safe'
        $request.ThrottleClass | Should -Be 'Read'
        $request.ApiVersion | Should -Be $script:FixtureApiVersion
        $request.Uri.Host | Should -Be 'management.azure.com'
        $request.Uri.AbsoluteUri | Should -Match 'api-version=2021-05-01-preview'
        $request.Uri.AbsolutePath | Should -Be ($script:IntuneResourceId + '/providers/microsoft.insights/diagnosticSettings')
        $request.Audience | Should -Be 'https://management.azure.com/.default'
        $request.RbacActions | Should -Be @('Microsoft.Insights/diagnosticSettings/read')
        $request.PSObject.Properties.Name | Should -Not -Contain 'Type'
        $request.PSObject.Properties.Name | Should -Not -Contain 'Operation'
        $request.PSObject.Properties.Name | Should -Not -Contain 'Token'
        $request.PSObject.Properties.Name | Should -Not -Contain 'Bearer'
    }

    It 'keeps ARM snapshot provenance distinguishable from GraphKit provenance' {
        $arm = InModuleScope TenantPulseArmAdapterTest -ArgumentList $script:IntuneResourceId, $script:FixtureApiVersion, $script:BoundTenantId {
            param($ResourceId, $ApiVersion, $TenantId)
            New-PulseArmProvenance -ResourceId $ResourceId -ApiVersion $ApiVersion -Cloud 'Global' -BoundTenantId $TenantId
        }
        $graph = InModuleScope TenantPulseArmAdapterTest {
            New-PulseCollectionOutcome -Dataset 'managedDevices' -Status 'Collected' -Rows @() -Gaps @() `
                -ReasonCode 'collected' -Provider 'GraphKit' -ApiVersion 'v1.0' -Operations @('List')
        }

        $arm.Provider | Should -Be 'ARM'
        $arm.Authority | Should -Be 'management.azure.com'
        $arm.Audience | Should -Be 'https://management.azure.com/.default'
        $arm.ResourceId | Should -Be $script:IntuneResourceId
        $arm.RbacActions | Should -Be @('Microsoft.Insights/diagnosticSettings/read')
        $arm.PSObject.Properties.Name | Should -Not -Contain 'Type'
        $arm.PSObject.Properties.Name | Should -Not -Contain 'Operation'
        $arm.PSObject.Properties.Name | Should -Not -Contain '_GraphPath'
        $arm.PSObject.Properties.Name | Should -Not -Contain '_Tenant'
        $arm.PSObject.Properties.Name | Should -Not -Contain '_RetrievedUtc'
        $arm.PSObject.Properties.Name | Should -Not -Contain '_ApiVersion'

        $graph.Provider | Should -Be 'GraphKit'
        $graph.ApiVersion | Should -Be 'v1.0'
        $graph.Operations | Should -Be @('List')
        $graph.PSObject.Properties.Name | Should -Not -Contain 'Audience'
        $graph.PSObject.Properties.Name | Should -Not -Contain 'ResourceId'
        $graph.PSObject.Properties.Name | Should -Not -Contain 'RbacActions'
    }

    It 'returns an explicit deferred disposition and never sends when no ARM transport is injected' {
        Reset-ArmProviderTestState
        $outcome = InModuleScope TenantPulseArmAdapterTest -ArgumentList $script:IntuneResourceId {
            param($ResourceId)
            Invoke-PulseArmProvider -Dataset 'intuneDiagnosticSettings' -ResourceId $ResourceId
        }
        $outcome.Status | Should -Be 'Skipped'
        $outcome.FailureClass | Should -Be 'DependencyUnavailable'
        $outcome.ReasonCode | Should -Be 'arm-live-contract-deferred'
        $outcome.Provider | Should -Be 'ARM'
        $outcome.Detail.Disposition | Should -Be 'DeferredUntilLiveContract'
        $outcome.Detail.LiveAccess | Should -Be 'NotAttempted'
        $outcome.Detail.ApiVersionStatus | Should -Be 'Unproven'
        $script:ArmSendUris.Count | Should -Be 0
    }
}

Describe 'Invoke-PulseArmProvider deterministic transport' {
    It 'aggregates ARM pages through nextLink and records ARM provenance on Collected' {
        Reset-ArmProviderTestState
        $next = 'https://management.azure.com' + $script:IntuneResourceId + '/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview&skipToken=page-2'
        $script:ArmResponseQueue.Enqueue((New-ArmTransportResult -Body @{
                    value    = @(@{ id = ($script:IntuneResourceId + '/diagnosticSettings/to-logs'); name = 'to-logs' })
                    nextLink = $next
                }))
        $script:ArmResponseQueue.Enqueue((New-ArmTransportResult -Body @{
                    value = @(@{ id = ($script:IntuneResourceId + '/diagnosticSettings/to-storage'); name = 'to-storage' })
                }))

        $outcome = InModuleScope TenantPulseArmAdapterTest -ArgumentList (Get-ArmTestInjections), $script:FixtureApiVersion, $script:BoundTenantId, $script:IntuneResourceId {
            param($Injections, $ApiVersion, $TenantId, $ResourceId)
            Invoke-PulseArmProvider -Dataset 'intuneDiagnosticSettings' -ResourceId $ResourceId `
                -ApiVersion $ApiVersion -BoundTenantId $TenantId -Injections $Injections
        }

        $outcome.Status | Should -Be 'Collected'
        $outcome.ReasonCode | Should -Be 'collected'
        $outcome.Provider | Should -Be 'ARM'
        $outcome.ApiVersion | Should -Be $script:FixtureApiVersion
        @($outcome.Rows).Count | Should -Be 2
        $outcome.Rows.Name | Should -Be @('to-logs', 'to-storage')
        $outcome.Detail.Provenance.Provider | Should -Be 'ARM'
        $outcome.Detail.Provenance.Authority | Should -Be 'management.azure.com'
        $outcome.PSObject.Properties.Name | Should -Not -Contain 'Type'
        $script:ArmSendUris.Count | Should -Be 2
        $script:ArmSendUris[1] | Should -Be $next
    }

    It 'refuses a Graph nextLink before the second page is sent' {
        Reset-ArmProviderTestState
        $script:ArmResponseQueue.Enqueue((New-ArmTransportResult -Body @{
                    value    = @(@{ name = 'page-1' })
                    nextLink = 'https://graph.microsoft.com/v1.0/deviceManagement'
                }))

        $outcome = InModuleScope TenantPulseArmAdapterTest -ArgumentList (Get-ArmTestInjections), $script:FixtureApiVersion, $script:IntuneResourceId {
            param($Injections, $ApiVersion, $ResourceId)
            Invoke-PulseArmProvider -Dataset 'intuneDiagnosticSettings' -ResourceId $ResourceId `
                -ApiVersion $ApiVersion -Injections $Injections
        }

        $outcome.Status | Should -Be 'Partial'
        $outcome.FailureClass | Should -BeNullOrEmpty
        $outcome.Gaps[0].FailureClass | Should -Be 'InvalidProviderData'
        $outcome.Gaps[0].ReasonCode | Should -Be 'untrusted-arm-authority'
        @($outcome.Rows).Count | Should -Be 1
        $script:ArmSendUris.Count | Should -Be 1
    }

    It 'retries throttling with Retry-After and then succeeds' {
        Reset-ArmProviderTestState
        $script:ArmResponseQueue.Enqueue((New-ArmTransportResult -StatusCode 429 -Headers @{ 'Retry-After' = '2' } -Body @{ error = @{ code = 'TooManyRequests' } }))
        $script:ArmResponseQueue.Enqueue((New-ArmTransportResult -Body @{ value = @(@{ name = 'after-throttle' }) }))

        $outcome = InModuleScope TenantPulseArmAdapterTest -ArgumentList (Get-ArmTestInjections), $script:FixtureApiVersion, $script:IntuneResourceId {
            param($Injections, $ApiVersion, $ResourceId)
            Invoke-PulseArmProvider -Dataset 'intuneDiagnosticSettings' -ResourceId $ResourceId `
                -ApiVersion $ApiVersion -Injections $Injections
        }

        $outcome.Status | Should -Be 'Collected'
        $outcome.Rows[0].Name | Should -Be 'after-throttle'
        $script:ArmSendUris.Count | Should -Be 2
        $script:DelaySeconds[0] | Should -Be 2
    }

    It 'maps deadline expiry without sending after the clock is exhausted' {
        Reset-ArmProviderTestState
        $script:UtcNowCalls = 0
        $injections = @{
            Send   = $script:FakeSend
            UtcNow = {
                $script:UtcNowCalls++
                if ($script:UtcNowCalls -le 1) {
                    [datetime]::SpecifyKind([datetime]'2026-09-02T00:00:00', 'Utc')
                }
                else {
                    [datetime]::SpecifyKind([datetime]'2026-09-02T00:00:02', 'Utc')
                }
            }
            Delay  = { param([double] $Seconds) $script:DelaySeconds.Add($Seconds) }
            Jitter = { 0.0 }
        }
        $outcome = InModuleScope TenantPulseArmAdapterTest -ArgumentList $injections, $script:FixtureApiVersion, $script:IntuneResourceId {
            param($Injections, $ApiVersion, $ResourceId)
            Invoke-PulseArmProvider -Dataset 'intuneDiagnosticSettings' -ResourceId $ResourceId `
                -ApiVersion $ApiVersion -Injections $Injections -DeadlineSeconds 1
        }
        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be 'DeadlineExpired'
        $outcome.ReasonCode | Should -Be 'deadline-expired'
        $script:ArmSendUris.Count | Should -Be 0
    }

    It 'maps cancellation without sending' {
        Reset-ArmProviderTestState
        $cts = [System.Threading.CancellationTokenSource]::new()
        $cts.Cancel()
        $injections = Get-ArmTestInjections
        $outcome = InModuleScope TenantPulseArmAdapterTest -ArgumentList $injections, $script:FixtureApiVersion, $cts.Token, $script:IntuneResourceId {
            param($Injections, $ApiVersion, $Token, $ResourceId)
            Invoke-PulseArmProvider -Dataset 'intuneDiagnosticSettings' -ResourceId $ResourceId `
                -ApiVersion $ApiVersion -Injections $Injections -CancellationToken $Token
        }
        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be 'Cancelled'
        $outcome.ReasonCode | Should -Be 'cancelled'
        $script:ArmSendUris.Count | Should -Be 0
    }

    It 'maps 403 to Failed PermissionDenied with Azure RBAC, not a Graph permission' {
        Reset-ArmProviderTestState
        $script:ArmResponseQueue.Enqueue((New-ArmTransportResult -StatusCode 403 -Body @{ error = @{ code = 'AuthorizationFailed' } }))
        $outcome = InModuleScope TenantPulseArmAdapterTest -ArgumentList (Get-ArmTestInjections), $script:FixtureApiVersion, $script:IntuneResourceId {
            param($Injections, $ApiVersion, $ResourceId)
            Invoke-PulseArmProvider -Dataset 'intuneDiagnosticSettings' -ResourceId $ResourceId `
                -ApiVersion $ApiVersion -Injections $Injections
        }
        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be 'PermissionDenied'
        $outcome.ReasonCode | Should -Be 'permission-denied'
        $outcome.Detail.RbacActions | Should -Be @('Microsoft.Insights/diagnosticSettings/read')
        $outcome.Detail.Contains('permissions') | Should -BeFalse
        @($outcome.Rows).Count | Should -Be 0
    }

    It 'maps a malformed ARM body to Failed InvalidProviderData' {
        Reset-ArmProviderTestState
        $script:ArmResponseQueue.Enqueue((New-ArmTransportResult -Body 'not-an-arm-page'))
        $outcome = InModuleScope TenantPulseArmAdapterTest -ArgumentList (Get-ArmTestInjections), $script:FixtureApiVersion, $script:IntuneResourceId {
            param($Injections, $ApiVersion, $ResourceId)
            Invoke-PulseArmProvider -Dataset 'intuneDiagnosticSettings' -ResourceId $ResourceId `
                -ApiVersion $ApiVersion -Injections $Injections
        }
        $outcome.Status | Should -Be 'Failed'
        $outcome.FailureClass | Should -Be 'InvalidProviderData'
        $outcome.ReasonCode | Should -Be 'invalid-provider-data'
        @($outcome.Rows).Count | Should -Be 0
    }

    It 'records truncation as Partial rather than a successful complete collection' {
        Reset-ArmProviderTestState
        $script:ArmResponseQueue.Enqueue((New-ArmTransportResult -Body @{
                    value    = @(@{ name = 'page-1' })
                    nextLink = ('https://management.azure.com' + $script:IntuneResourceId + '/providers/microsoft.insights/diagnosticSettings?skipToken=2')
                }))
        $outcome = InModuleScope TenantPulseArmAdapterTest -ArgumentList (Get-ArmTestInjections), $script:FixtureApiVersion, $script:IntuneResourceId {
            param($Injections, $ApiVersion, $ResourceId)
            Invoke-PulseArmProvider -Dataset 'intuneDiagnosticSettings' -ResourceId $ResourceId `
                -ApiVersion $ApiVersion -Injections $Injections -MaxPages 1
        }
        $outcome.Status | Should -Be 'Partial'
        $outcome.ReasonCode | Should -Be 'partial'
        $outcome.Gaps[0].FailureClass | Should -Be 'ProviderFailed'
        $outcome.Gaps[0].ReasonCode | Should -Be 'arm-page-cap'
        @($outcome.Rows).Count | Should -Be 1
    }
}
