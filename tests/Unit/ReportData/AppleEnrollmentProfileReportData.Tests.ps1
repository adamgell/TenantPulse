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

    Mock Get-GraphOperation -ModuleName TenantPulse {
        [pscustomobject]@{
            Type = $Type; Operation = $Operation; ApiVersion = 'beta'; Stability = 'BetaOnly'
            PagingStrategy = 'NextLink'; ThrottleClass = 'Read'; ReplayPolicy = 'Safe'
            RequiredPermissions = @([pscustomobject]@{ Type = 'Application'; Value = 'DeviceManagementServiceConfig.Read.All' })
        }
    }

    function script:New-AppleReportStore {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Tokens,
            [ValidateSet('Collected', 'Partial')] [string] $Status = 'Collected'
        )

        InModuleScope TenantPulse -ArgumentList $Root, $Tokens, $Status {
            param($storeRoot, $sourceTokens, $sourceStatus)
            $store = New-PulseSnapshotStore -Path $storeRoot -Tenant 'tp-fixture'
            $sourceGaps = if ($sourceStatus -eq 'Partial') {
                @([pscustomobject]@{
                        Scope = 'depOnboardingSettings'; FailureClass = 'Indeterminate'
                        ReasonCode = 'page-cap-reached'; Detail = @{}
                        Operation = 'List'; ApiVersion = 'beta'
                    })
            } else { @() }
            Write-PulseDataset -Store $store -Name depOnboardingSettings -Data @($sourceTokens) `
                -ApiVersion beta -Status $sourceStatus -Provider GraphKit -Operations @('List') `
                -ReasonCode $(if ($sourceStatus -eq 'Partial') { 'page-cap-reached' } else { 'collected' }) `
                -Gaps $sourceGaps
            return $store
        }
    }

    function script:New-AppleAuthorizationDecision {
        param([ValidateSet('Granted', 'Denied', 'Unknown')] [string] $Decision = 'Granted')
        $reasonCode = if ($Decision -eq 'Granted') { 'granted' } elseif ($Decision -eq 'Denied') { 'missing-grant' } else { 'descriptor-unresolved' }
        [pscustomobject]@{
            Decision = $Decision
            ReasonCode = $reasonCode
            Decisions = [ordered]@{
                'AppleEnrollmentProfile/ListByToken' = [pscustomobject]@{
                    Type = 'AppleEnrollmentProfile'; Operation = 'ListByToken'; ApiVersion = 'beta'
                    Decision = $Decision; ReasonCode = $reasonCode
                }
            }
        }
    }
}

Describe 'TenantPulse Apple enrollment profile report-data contract' {
    BeforeEach {
        $script:roots = @()
        $script:context = [pscustomobject]@{
            ProfileId = 'fixture'
            TenantId = '11111111-1111-1111-1111-111111111111'
            ClientId = '22222222-2222-2222-2222-222222222222'
        }
        $script:authorization = New-AppleAuthorizationDecision
        $script:abortState = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
    }

    AfterEach {
        foreach ($root in $script:roots) {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'declares the exact beta child collection required by the IHA successor' {
        $operations = InModuleScope TenantPulse { @(Get-PulseAppleEnrollmentProfileReportOperations) }
        $operations.Count | Should -Be 1
        $operations[0].Type | Should -Be 'AppleEnrollmentProfile'
        $operations[0].Operation | Should -Be 'ListByToken'
        $operations[0].ApiVersion | Should -Be 'beta'
        $operations[0].PagingStrategy | Should -Be 'NextLink'
    }

    It 'collects each token by service id and preserves the complete profile evidence without fuzzy group claims' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots += $root
        $tokens = @(
            [pscustomobject]@{ id = 'token-b'; tokenName = 'Bravo'; futureTokenField = 'token-proof-b' }
            [pscustomobject]@{ id = 'token-a'; tokenName = 'Alpha'; futureTokenField = 'token-proof-a' }
        )
        $store = New-AppleReportStore -Root $root -Tokens $tokens

        Mock Invoke-PulseReportGraphOperation -ModuleName TenantPulse {
            $tokenId = [string] $Parameters.depOnboardingSettingId
            [pscustomobject]@{
                Status = 'Collected'; FailureClass = $null; ReasonCode = 'collected'
                Rows = @([pscustomobject]@{
                        id = "profile-$tokenId"; displayName = "Profile $tokenId"
                        '@odata.type' = '#microsoft.graph.depIOSEnrollmentProfile'
                        description = 'Automated enrollment'; enrollmentType = 'userAffinity'
                        defaultIosUserEnrollmentType = 'device'; requiresUserAuthentication = $true
                        requireCompanyPortalOnSetupAssistantEnrolledDevices = $true
                        isDefault = $true; isMandatory = $false; locationDisabled = $false
                        supportPhoneNumber = '555-0100'; supportEmailAddress = 'support@example.test'
                        iTunesPairingMode = 'disallow'; managementCertificates = @([pscustomobject]@{ expirationDateTime = '2027-01-01T00:00:00Z' })
                        restoreBlocked = $true; iOSUserEnrollmentTypesAllowed = @('device', 'user')
                        createdDateTime = '2026-01-01T00:00:00Z'; lastModifiedDateTime = '2026-02-01T00:00:00Z'
                        roleScopeTagIds = @('0'); futureProfileField = 'preserved'
                    })
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $store, $script:context, $script:authorization, $script:abortState {
            param($snapshotStore, $ctx, $auth, $abort)
            Invoke-PulseAppleEnrollmentProfileReportCollection -Store $snapshotStore -Context $ctx `
                -AuthorizationDecision $auth -NetworkAbortState $abort -ProfileId fixture -Pseudonym tp-fixture
        }

        $result.Status | Should -Be 'Expanded'
        $result.RowCount | Should -Be 2
        $rows = InModuleScope TenantPulse -ArgumentList $store {
            param($snapshotStore)
            @(Get-PulseExpansionRows -Store $snapshotStore -Name 'apple-enrollment-profiles')
        }
        @($rows.tokenId) | Should -Be @('token-a', 'token-b')
        $rows[0].profileType | Should -Be 'depIOSEnrollmentProfile'
        $rows[0].platform | Should -Be 'iOS'
        $rows[0].requireCompanyPortalOnSetupAssistant | Should -BeTrue
        $rows[0].managementCertificateCount | Should -Be 1
        ([datetime] $rows[0].managementCertificates[0].expirationDateTime).ToUniversalTime().ToString('o') |
            Should -Be '2027-01-01T00:00:00.0000000Z'
        $rows[0].sourceColumns.futureProfileField | Should -Be 'preserved'
        $rows[0].tokenSourceColumns.futureTokenField | Should -Be 'token-proof-a'
        $rows[0].groupAssociationState | Should -Be 'NotEvaluated'
        @($rows[0].PSObject.Properties.Name) | Should -Not -Contain 'matchingGroups'
        @($rows[0].PSObject.Properties.Name) | Should -Not -Contain 'totalMatches'
        Should-Invoke Invoke-PulseReportGraphOperation -ModuleName TenantPulse -Times 2 -Exactly
        Should-Invoke Invoke-PulseReportGraphOperation -ModuleName TenantPulse -ParameterFilter {
            $Parameters.depOnboardingSettingId -eq 'token-a'
        } -Times 1 -Exactly
    }

    It 'keeps valid sibling rows while recording partial, malformed-token, and unnamed-profile gaps' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots += $root
        $tokens = @(
            [pscustomobject]@{ tokenName = 'Missing id' }
            [pscustomobject]@{ id = 'token-failed'; tokenName = 'Failed' }
            [pscustomobject]@{ id = 'token-partial'; tokenName = 'Partial' }
        )
        $store = New-AppleReportStore -Root $root -Tokens $tokens -Status Partial

        Mock Invoke-PulseReportGraphOperation -ModuleName TenantPulse {
            if ($Parameters.depOnboardingSettingId -eq 'token-failed') {
                return [pscustomobject]@{ Status = 'Failed'; FailureClass = 'ProviderFailed'; ReasonCode = 'provider-failed'; Rows = @() }
            }
            [pscustomobject]@{
                Status = 'Partial'; FailureClass = $null; ReasonCode = 'page-cap-reached'
                Rows = @(
                    [pscustomobject]@{ id = 'profile-valid'; displayName = 'Valid'; platform = 'macOS' }
                    [pscustomobject]@{ id = 'profile-unnamed' }
                    [pscustomobject]@{ displayName = 'Missing profile id' }
                )
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $store, $script:context, $script:authorization, $script:abortState {
            param($snapshotStore, $ctx, $auth, $abort)
            Invoke-PulseAppleEnrollmentProfileReportCollection -Store $snapshotStore -Context $ctx `
                -AuthorizationDecision $auth -NetworkAbortState $abort -ProfileId fixture -Pseudonym tp-fixture
        }

        $result.Status | Should -Be 'Partial'
        $result.RowCount | Should -Be 2
        @($result.Gaps.reason) | Should -Contain 'category:source-dataset-partial;operation:AppleEnrollmentProfile.ListByToken'
        @($result.Gaps.reason) | Should -Contain 'category:provider-failed;operation:AppleEnrollmentProfile.ListByToken'
        @($result.Gaps.reason) | Should -Contain 'category:profile-name-missing;operation:AppleEnrollmentProfile.ListByToken'
        Should-Invoke Invoke-PulseReportGraphOperation -ModuleName TenantPulse -Times 2 -Exactly
    }

    It 'fails closed before any child request when the descriptor or permission decision is unavailable' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots += $root
        $store = New-AppleReportStore -Root $root -Tokens @([pscustomobject]@{ id = 'token-1' })
        Mock Invoke-PulseReportGraphOperation -ModuleName TenantPulse { throw 'must not send' }
        Mock Get-GraphOperation -ModuleName TenantPulse { throw 'descriptor unavailable' }

        $result = InModuleScope TenantPulse -ArgumentList $store, $script:context, $script:authorization, $script:abortState {
            param($snapshotStore, $ctx, $auth, $abort)
            Invoke-PulseAppleEnrollmentProfileReportCollection -Store $snapshotStore -Context $ctx `
                -AuthorizationDecision $auth -NetworkAbortState $abort -ProfileId fixture -Pseudonym tp-fixture
        }
        $result.Status | Should -Be 'NotExpanded'
        Should-Invoke Invoke-PulseReportGraphOperation -ModuleName TenantPulse -Times 0 -Exactly
    }

    It 'aborts later token requests after an authentication failure and preserves the failure as gaps' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots += $root
        $store = New-AppleReportStore -Root $root -Tokens @(
            [pscustomobject]@{ id = 'token-a' }
            [pscustomobject]@{ id = 'token-b' }
        )
        Mock Invoke-PulseReportGraphOperation -ModuleName TenantPulse {
            [pscustomobject]@{ Status = 'Failed'; FailureClass = 'AuthenticationFailed'; ReasonCode = 'authentication-failed'; Rows = @() }
        }

        $result = InModuleScope TenantPulse -ArgumentList $store, $script:context, $script:authorization, $script:abortState {
            param($snapshotStore, $ctx, $auth, $abort)
            Invoke-PulseAppleEnrollmentProfileReportCollection -Store $snapshotStore -Context $ctx `
                -AuthorizationDecision $auth -NetworkAbortState $abort -ProfileId fixture -Pseudonym tp-fixture
        }
        $result.Status | Should -Be 'NotExpanded'
        $script:abortState.AuthenticationAborted | Should -BeTrue
        @($result.Gaps.policyId) | Should -Be @('token-a', 'token-b')
        Should-Invoke Invoke-PulseReportGraphOperation -ModuleName TenantPulse -Times 1 -Exactly
    }

    It 'publishes deterministic bytes and recursively scrubs the tenant id from profile and token evidence' {
        $rootA = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $rootB = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:roots += $rootA
        $script:roots += $rootB
        $tenantId = $script:context.TenantId
        $tokens = @(
            [pscustomobject]@{ id = 'token-b'; nested = [pscustomobject]@{ tenant = $tenantId } }
            [pscustomobject]@{ id = 'token-a' }
        )
        $storeA = New-AppleReportStore -Root $rootA -Tokens $tokens
        $storeB = New-AppleReportStore -Root $rootB -Tokens @($tokens[1], $tokens[0])
        Mock Invoke-PulseReportGraphOperation -ModuleName TenantPulse {
            [pscustomobject]@{
                Status = 'Collected'; FailureClass = $null; ReasonCode = 'collected'
                Rows = @([pscustomobject]@{
                        id = "profile-$($Parameters.depOnboardingSettingId)"
                        displayName = 'Profile'; nested = [pscustomobject]@{ tenant = $tenantId }
                    })
            }
        }

        foreach ($store in @($storeA, $storeB)) {
            InModuleScope TenantPulse -ArgumentList $store, $script:context, $script:authorization, $script:abortState {
                param($snapshotStore, $ctx, $auth, $abort)
                Invoke-PulseAppleEnrollmentProfileReportCollection -Store $snapshotStore -Context $ctx `
                    -AuthorizationDecision $auth -NetworkAbortState $abort -ProfileId fixture -Pseudonym tp-redacted | Out-Null
            }
        }
        $manifestA = Get-Content -LiteralPath $storeA.ManifestPath -Raw | ConvertFrom-Json
        $manifestB = Get-Content -LiteralPath $storeB.ManifestPath -Raw | ConvertFrom-Json
        $manifestA.expansions.'apple-enrollment-profiles'.sha256 | Should -Be $manifestB.expansions.'apple-enrollment-profiles'.sha256
        $artifactText = Get-Content -LiteralPath (Join-Path $storeA.Root $manifestA.expansions.'apple-enrollment-profiles'.path) -Raw
        $artifactText | Should -Not -Match ([regex]::Escape($tenantId))
        $artifactText | Should -Match 'tp-redacted'
    }
}
