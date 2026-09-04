BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $script:graphEnvelopeHelperPath = Join-Path $script:repoRoot 'tests/Helpers/New-PulseTestGraphEnvelope.ps1'
    . $script:graphEnvelopeHelperPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
    InModuleScope TenantPulse -ArgumentList $script:graphEnvelopeHelperPath {
        param($helperPath)
        . $helperPath
    }
}

Describe 'Invoke-PulseAdministrativeTemplateExpansion' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($path)
            New-PulseSnapshotStore -Path $path -Tenant 'tp-test'
        }
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:storeRoot) {
            Remove-Item -LiteralPath $script:storeRoot -Recurse -Force
        }
    }

    It 'returns honest NotExpanded DependencyUnavailable when expansion is not requested' {
        InModuleScope TenantPulse {
            function Get-GraphObject { param() }
        }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must not be called.' }

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Invoke-PulseAdministrativeTemplateExpansion -Store $store -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -ProfileId 'fixture' -Pseudonym 'tp-test' -TenantId 'tenant'
        }

        $result.Status | Should -Be 'NotExpanded'
        $result.FailureClass | Should -Be 'DependencyUnavailable'
        $result.ExpandedCount + $result.PartialCount + $result.NotExpandedCount | Should -Be $result.PolicyCount
        Should-NotInvoke Get-GraphObject -ModuleName TenantPulse

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.administrativeTemplates.status | Should -Be 'NotExpanded'
        $manifest.expansions.administrativeTemplates.reason | Should -Match 'dependency-unavailable'
    }

    It 'honors an existing shared authentication abort before descriptor resolution or any Graph request' {
        Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {
            throw 'a pre-aborted expansion must not resolve descriptors'
        }
        Mock Get-GraphObject -ModuleName TenantPulse {
            throw 'a pre-aborted expansion must not send'
        }
        $abortState = [pscustomobject]@{
            AuthenticationAborted = $true
            Reason                = 'authentication-failed: collection aborted'
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $abortState {
            param($store, $abortState)
            Invoke-PulseAdministrativeTemplateExpansion -Store $store `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Requested -ProfileId 'fixture' -Pseudonym 'tp-test' -TenantId 'tenant' `
                -NetworkAbortState $abortState
        }

        $result.Status | Should -Be 'NotExpanded'
        $result.FailureClass | Should -Be 'AuthenticationFailed'
        $result.PolicyCount | Should -Be 0
        $result.RowCount | Should -Be 0
        @($result.Operations).Count | Should -Be 0
        Should-NotInvoke Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse
        Should-NotInvoke Get-GraphObject -ModuleName TenantPulse

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.expansions.administrativeTemplates.status | Should -Be 'NotExpanded'
        $manifest.expansions.administrativeTemplates.reason | Should -Match 'authentication-failed'
    }

    It 'walks GraphKit GroupPolicyConfiguration, DefinitionValue, and PresentationValue ListBeta primitives' {
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $script:AdminTemplateCalls = [System.Collections.Generic.List[object]]::new()
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse {
                param($Type, $Operation, $ApiVersion)
                $script:AdminTemplateCalls.Add([pscustomobject]@{ Kind = 'Descriptor'; Type = $Type; Operation = $Operation; ApiVersion = $ApiVersion })
            }
            Mock Get-GraphObject -ModuleName TenantPulse {
                param($Context, $Type, $Operation, $Parameters)
                $script:AdminTemplateCalls.Add([pscustomobject]@{
                    Kind      = 'Graph'
                    Type      = $Type
                    Operation = $Operation
                    Id        = if ($null -ne $Parameters) { [string] $Parameters.id } else { $null }
                    DefId     = if ($null -ne $Parameters) { [string] $Parameters.definitionValueId } else { $null }
                })
                if ($Type -eq 'GroupPolicyConfiguration') {
                    return New-PulseTestGraphEnvelope -Data @([pscustomobject]@{ id = 'gp-1'; displayName = 'Admin Template One' })
                }
                if ($Type -eq 'GroupPolicyDefinitionValue') {
                    return New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                        id = 'dv-1'
                        enabled = $true
                        definition = [pscustomobject]@{ id = 'def-1'; displayName = 'Allow telemetry'; categoryPath = 'Windows' }
                    })
                }
                if ($Type -eq 'GroupPolicyPresentationValue') {
                    return New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                        id = 'pv-1'
                        value = '2'
                        '@odata.type' = '#microsoft.graph.groupPolicyPresentationValueDecimal'
                        presentation = [pscustomobject]@{ id = 'pres-1'; label = 'Telemetry level' }
                    })
                }
                throw "Unexpected Graph call '$Type/$Operation'."
            }

            $expansion = Invoke-PulseAdministrativeTemplateExpansion -Store $store -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Requested -ProfileId 'fixture' -Pseudonym 'tp-test' -TenantId 'tenant'
            [pscustomobject]@{ Result = $expansion; Calls = @($script:AdminTemplateCalls) }
        }

        $result.Result.Status | Should -Be 'Expanded'
        $result.Result.PolicyCount | Should -Be 1
        $result.Result.ExpandedCount | Should -Be 1
        $result.Result.PartialCount | Should -Be 0
        $result.Result.NotExpandedCount | Should -Be 0
        ($result.Result.ExpandedCount + $result.Result.PartialCount + $result.Result.NotExpandedCount) | Should -Be $result.Result.PolicyCount
        $result.Result.RowCount | Should -BeGreaterThan 0
        @($result.Calls | Where-Object Kind -eq 'Descriptor' | ForEach-Object { "$($_.Type)/$($_.Operation)/$($_.ApiVersion)" }) | Should -Be @(
            'GroupPolicyConfiguration/ListBeta/beta'
            'GroupPolicyDefinitionValue/ListBeta/beta'
            'GroupPolicyPresentationValue/ListBeta/beta'
        )
        @($result.Calls | Where-Object Kind -eq 'Graph' | ForEach-Object Type) | Should -Be @(
            'GroupPolicyConfiguration'
            'GroupPolicyDefinitionValue'
            'GroupPolicyPresentationValue'
        )
    }

    It 'classifies every enumerated administrative template as Expanded, Partial, or NotExpanded with preserved child gaps' {
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse { }
            Mock Get-GraphObject -ModuleName TenantPulse {
                param($Context, $Type, $Operation, $Parameters)
                if ($Type -eq 'GroupPolicyConfiguration') {
                    return New-PulseTestGraphEnvelope -Data @(
                        [pscustomobject]@{ id = 'gp-ok'; displayName = 'OK' }
                        [pscustomobject]@{ id = 'gp-partial'; displayName = 'Partial' }
                        [pscustomobject]@{ id = 'gp-fail'; displayName = 'Fail' }
                    )
                }
                if ($Type -eq 'GroupPolicyDefinitionValue') {
                    $id = [string] $Parameters.id
                    if ($id -eq 'gp-fail') {
                        throw [System.InvalidOperationException]::new('definition values failed')
                    }
                    return New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                        id = "dv-$id"
                        enabled = $true
                        definition = [pscustomobject]@{ id = "def-$id"; displayName = 'Setting'; categoryPath = 'Windows' }
                    })
                }
                if ($Type -eq 'GroupPolicyPresentationValue') {
                    $id = [string] $Parameters.id
                    if ($id -eq 'gp-partial') {
                        throw [System.InvalidOperationException]::new('presentation values failed')
                    }
                    return New-PulseTestGraphEnvelope -Data @([pscustomobject]@{
                        id = 'pv-ok'
                        value = '1'
                        presentation = [pscustomobject]@{ id = 'pres-ok'; label = 'Value' }
                    })
                }
                throw "Unexpected Graph call '$Type/$Operation'."
            }

            Invoke-PulseAdministrativeTemplateExpansion -Store $store -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Requested -ProfileId 'fixture' -Pseudonym 'tp-test' -TenantId 'tenant'
        }

        $result.Status | Should -Be 'Partial'
        $result.PolicyCount | Should -Be 3
        $result.ExpandedCount | Should -Be 1
        $result.PartialCount | Should -Be 1
        $result.NotExpandedCount | Should -Be 1
        ($result.ExpandedCount + $result.PartialCount + $result.NotExpandedCount) | Should -Be $result.PolicyCount
        $result.Gaps.Count | Should -BeGreaterThan 0
        @($result.Gaps | ForEach-Object { $_.reason }) | Should -Match 'GroupPolicy'
    }

    It 'marks a presentation value with no stable id as Partial instead of fabricating a random evidence identity' {
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse { }
            Mock Get-GraphObject -ModuleName TenantPulse {
                param($Context, $Type, $Operation, $Parameters)
                if ($Type -eq 'GroupPolicyConfiguration') {
                    return New-PulseTestGraphEnvelope -Data @(
                        [pscustomobject]@{ id = 'gp-missing-presentation-id'; displayName = 'Missing presentation identity' }
                    )
                }
                if ($Type -eq 'GroupPolicyDefinitionValue') {
                    return New-PulseTestGraphEnvelope -Data @(
                        [pscustomobject]@{
                            id = 'dv-stable'
                            enabled = $true
                            definition = [pscustomobject]@{ id = 'def-stable'; displayName = 'Stable setting'; categoryPath = 'Windows' }
                        }
                    )
                }
                if ($Type -eq 'GroupPolicyPresentationValue') {
                    return New-PulseTestGraphEnvelope -Data @(
                        [pscustomobject]@{
                            value = '2'
                            presentation = [pscustomobject]@{ id = 'presentation-definition'; label = 'Level' }
                        }
                    )
                }
                throw "Unexpected Graph call '$Type/$Operation'."
            }

            Invoke-PulseAdministrativeTemplateExpansion -Store $store `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Requested -ProfileId 'fixture' -Pseudonym 'tp-test' -TenantId 'tenant'
        }

        $result.Status | Should -Be 'Partial'
        $result.PolicyCount | Should -Be 1
        $result.ExpandedCount | Should -Be 0
        $result.PartialCount | Should -Be 1
        $result.NotExpandedCount | Should -Be 0
        $result.RowCount | Should -Be 1
        @($result.Gaps).Count | Should -Be 1
        $result.Gaps[0].policyId | Should -Be 'gp-missing-presentation-id'
        $result.Gaps[0].reason | Should -Match 'category:EmptyPresentationValueId;operation:GroupPolicyPresentationValue.ListBeta'

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $artifactPath = Join-Path $script:store.Root $manifest.expansions.administrativeTemplates.path
        $rows = @(Get-Content -LiteralPath $artifactPath |
                ForEach-Object { $_ | ConvertFrom-Json })
        @($rows.instanceId) | Should -Be @('dv-stable')
    }

    It 'fails closed when the configuration list is returned as rows without a GraphKit envelope' {
        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Mock Assert-PulseReadOnlyDescriptor -ModuleName TenantPulse { }
            Mock Get-GraphObject -ModuleName TenantPulse {
                return [pscustomobject]@{ id = 'gp-rows-only'; displayName = 'Unsafe rows-only result' }
            }

            Invoke-PulseAdministrativeTemplateExpansion -Store $store `
                -Context ([pscustomobject]@{ ProfileId = 'fixture'; TenantId = 'tenant' }) `
                -Requested -ProfileId 'fixture' -Pseudonym 'tp-test' -TenantId 'tenant'
        }

        $result.Status | Should -Be 'NotExpanded'
        $result.PolicyCount | Should -Be 0
        $result.RowCount | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:store.ExpandedPath 'administrativeTemplates.jsonl') | Should -BeFalse
    }
}
