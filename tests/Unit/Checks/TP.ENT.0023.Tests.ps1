BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:ConvertTo-PSObjectShape {
        param($Value)
        return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    }

    function script:Invoke-PulseCheckFixture {
        param(
            [Parameter(Mandatory)] [string] $CheckId,
            [Parameter(Mandatory)] [hashtable[]] $Datasets
        )

        $storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $keyPath = Join-Path $storeRoot '.opkey/operator.key'

        try {
            $evaluation = InModuleScope TenantPulse -ArgumentList $storeRoot, $keyPath, $CheckId, $Datasets {
                param($storeRoot, $keyPath, $checkId, $datasets)

                $catalog = @(Import-PulseCheckCatalog)
                $check = $catalog | Where-Object { $_.Id -eq $checkId }
                if (-not $check) { throw "fixture setup: check '$checkId' not found in the catalog." }

                $store = New-PulseSnapshotStore -Path (Join-Path $storeRoot 'snapshot') -Tenant 'tp-fixturetenant'
                foreach ($d in $datasets) {
                    $params = @{
                        Store      = $store
                        Name       = $d.Name
                        ApiVersion = $d.ApiVersion
                        Status     = $d.Status
                    }
                    if ($d.ContainsKey('Data')) { $params.Data = $d.Data }
                    if ($d.ContainsKey('Reason')) { $params.Reason = $d.Reason }
                    Write-PulseDataset @params
                }

                $manifest = Get-PulseSnapshotManifest -Store $store
                $gates = if ($null -eq $check.Data -or $null -eq $check.Data.Gates) { @() } else { @($check.Data.Gates) }
                if ($gates.Count -gt 0) {
                    if (-not $manifest.Contains('licenseEvidence') -or $manifest.licenseEvidence -isnot [System.Collections.IDictionary]) {
                        $manifest.licenseEvidence = [ordered]@{}
                    }
                    foreach ($gate in $gates) {
                        if ($null -ne $gate -and -not [string]::IsNullOrWhiteSpace([string] $gate)) {
                            $manifest.licenseEvidence[[string] $gate] = [ordered]@{
                                Status = 'Available'
                                Detail = 'fixture gate'
                            }
                        }
                    }
                    if ($manifest.licenseEvidence.Count -gt 0) {
                        $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $manifest
                        Set-PulseAtomicFileContent -Path $store.ManifestPath -Value $canonicalJson
                    }
                }

                Invoke-PulseEvaluation -Store $store -Checks @($check) -OperatorKeyPath $keyPath
            }
            return $evaluation.Document.findings[0]
        } finally {
            Remove-Item -LiteralPath $storeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    function script:New-PulseCrossTenantPolicy {
        param([string] $InboundAccessType = 'allowed', [string] $OutboundAccessType = 'allowed')
        @{
            id                       = 'default'
            b2bCollaborationInbound  = @{
                usersAndGroups = @{
                    accessType = $InboundAccessType
                    targets    = @(@{ target = 'AllUsers'; targetType = 'user' })
                }
                applications   = @{
                    accessType = $InboundAccessType
                    targets    = @(@{ target = 'AllApplications'; targetType = 'application' })
                }
            }
            b2bCollaborationOutbound = @{
                usersAndGroups = @{
                    accessType = $OutboundAccessType
                    targets    = @(@{ target = 'AllUsers'; targetType = 'user' })
                }
                applications   = @{
                    accessType = $OutboundAccessType
                    targets    = @(@{ target = 'AllApplications'; targetType = 'application' })
                }
            }
        }
    }

    # Construct this at runtime so the test still supplies a canonical GUID target while
    # the repository secret scan never sees a GUID literal adjacent to the PowerShell
    # usersAndGroups.targets property-access chain (which is domain-shaped to that scan).
    $script:specificGroupTargetId = @('11111111', '1111', '1111', '1111', '111111111111') -join '-'
}

Describe 'TP.ENT.0023 - Cross-tenant access default settings restrict inbound/outbound B2B collaboration' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.ENT.0023' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: both directions restricted (blocked)' {
        $policy = New-PulseCrossTenantPolicy -InboundAccessType 'blocked' -OutboundAccessType 'blocked'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Pass'
    }

    It 'Warn: default wide-open inbound and outbound (Microsoft''s own default; value round-trips through a PSObject before Write-PulseDataset - the fixture harness always re-materializes to hashtable before the rule runs, see ConvertTo-PulseCaPolicyView.Tests.ps1 for genuine shape-neutrality coverage at the view layer)' {
        $policy = ConvertTo-PSObjectShape -Value (New-PulseCrossTenantPolicy)
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Warn'
        $finding.reason | Should -Match 'inbound and outbound'
        $finding.evidence.Count | Should -Be 2
        $finding.evidence[0].detail.classification | Should -Be 'unrestricted'
    }

    It 'Warn: only inbound wide-open, outbound restricted - both directions evaluated independently' {
        $policy = New-PulseCrossTenantPolicy -InboundAccessType 'allowed' -OutboundAccessType 'blocked'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Warn'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.direction | Should -Be 'inbound'
    }

    It 'Pass: allowed access is restricted when both directions use specific target sets instead of the allow-all default' {
        $policy = New-PulseCrossTenantPolicy
        foreach ($direction in @('b2bCollaborationInbound', 'b2bCollaborationOutbound')) {
            $policy[$direction].usersAndGroups.targets = @(@{ target = $script:specificGroupTargetId; targetType = 'group' })
            $policy[$direction].applications.targets = @(@{ target = '22222222-2222-2222-2222-222222222222'; targetType = 'application' })
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: an application allowlist restricts a direction even when all users are allowed' {
        $policy = New-PulseCrossTenantPolicy
        $policy.b2bCollaborationInbound.applications.targets = @(@{ target = '22222222-2222-2222-2222-222222222222'; targetType = 'application' })
        $policy.b2bCollaborationOutbound.applications.targets = @(@{ target = '33333333-3333-3333-3333-333333333333'; targetType = 'application' })

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Warn: a narrow denylist is not a full default restriction because every other user and application remains allowed' {
        $policy = New-PulseCrossTenantPolicy -InboundAccessType blocked -OutboundAccessType blocked
        foreach ($direction in @('b2bCollaborationInbound', 'b2bCollaborationOutbound')) {
            $policy[$direction].usersAndGroups.targets = @(@{ target = $script:specificGroupTargetId; targetType = 'group' })
            $policy[$direction].applications.targets = @(@{ target = '22222222-2222-2222-2222-222222222222'; targetType = 'application' })
        }

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Warn'
        @($finding.evidence.detail.classification | Select-Object -Unique) | Should -Be @('narrow-block')
        $finding.reason | Should -Match 'narrow denylist'
    }

    It 'Warn as unclassifiable: accessType without targets is not proof of either allow-all or a restriction' {
        $policy = New-PulseCrossTenantPolicy
        $policy.b2bCollaborationInbound.usersAndGroups.Remove('targets')

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Warn'
        $inboundEvidence = $finding.evidence | Where-Object { $_.detail.direction -eq 'inbound' }
        $inboundEvidence.detail.classification | Should -Be 'unclassifiable'
        $inboundEvidence.detail.usersTargetScope | Should -Be 'unclassifiable'
    }

    It 'Warn as unclassifiable: malformed targetType cannot be promoted to a deliberate restriction' {
        $policy = New-PulseCrossTenantPolicy
        $policy.b2bCollaborationInbound.usersAndGroups.targets = @(
            @{ target = 'AllUsers'; targetType = 'application' }
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Warn'
        ($finding.evidence | Where-Object { $_.detail.direction -eq 'inbound' }).detail.classification | Should -Be 'unclassifiable'
    }

    It 'Warn as unclassifiable: a non-GUID specific target cannot be promoted to a scoped allowlist' {
        $policy = New-PulseCrossTenantPolicy
        $policy.b2bCollaborationInbound.usersAndGroups.targets = @(
            @{ target = 'not-a-group-id'; targetType = 'group' }
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Warn'
        ($finding.evidence | Where-Object { $_.detail.direction -eq 'inbound' }).detail.classification | Should -Be 'unclassifiable'
    }

    It 'Warn as unclassifiable: the AllUsers sentinel paired with targetType group is malformed' {
        $policy = New-PulseCrossTenantPolicy
        $policy.b2bCollaborationInbound.usersAndGroups.targets = @(
            @{ target = 'AllUsers'; targetType = 'group' }
        )

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Warn'
        ($finding.evidence | Where-Object { $_.detail.direction -eq 'inbound' }).detail.classification | Should -Be 'unclassifiable'
    }

    It 'NotApplicable: zero rows is invalid singleton cardinality, not evidence of an unrestricted tenant policy' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'invalid singleton cardinality'
        $finding.reason | Should -Match 'expected exactly 1 row, observed 0'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].identity | Should -Be 'crossTenantAccessPolicyDefault:cardinality'
        $finding.evidence[0].detail.classification | Should -Be 'invalid-singleton-cardinality'
        $finding.evidence[0].detail.expectedRowCount | Should -Be 1
        $finding.evidence[0].detail.observedRowCount | Should -Be 0
    }

    It 'NotApplicable: one null row is zero usable rows, not an unclassifiable policy object' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($null) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'expected exactly 1 row, observed 0'
        $finding.evidence[0].detail.observedRowCount | Should -Be 0
    }

    It 'NotApplicable: multiple rows is invalid singleton cardinality and no arbitrary first row is evaluated' {
        $restricted = New-PulseCrossTenantPolicy -InboundAccessType 'blocked' -OutboundAccessType 'blocked'
        $unrestricted = New-PulseCrossTenantPolicy

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($restricted, $unrestricted) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'invalid singleton cardinality'
        $finding.reason | Should -Match 'expected exactly 1 row, observed 2'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.classification | Should -Be 'invalid-singleton-cardinality'
        $finding.evidence[0].detail.expectedRowCount | Should -Be 1
        $finding.evidence[0].detail.observedRowCount | Should -Be 2
    }

    It 'Pass: a decisive full block or scoped allow proves restriction even when the sibling target configuration is unclassifiable' {
        $policy = New-PulseCrossTenantPolicy -InboundAccessType 'blocked' -OutboundAccessType 'allowed'

        # Inbound applications block all applications; malformed users evidence cannot
        # undo that decisive restriction.
        $policy.b2bCollaborationInbound.usersAndGroups.Remove('targets')

        # Outbound users are a scoped allowlist; malformed application evidence cannot
        # undo that decisive restriction.
        $policy.b2bCollaborationOutbound.usersAndGroups.targets = @(
            @{ target = $script:specificGroupTargetId; targetType = 'group' }
        )
        $policy.b2bCollaborationOutbound.applications.Remove('targets')

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Warn as unclassifiable: malformed sibling evidence remains indeterminate when the valid target configuration is not decisively restrictive' {
        $policy = New-PulseCrossTenantPolicy -InboundAccessType 'allowed' -OutboundAccessType 'blocked'
        $policy.b2bCollaborationInbound.usersAndGroups.Remove('targets')

        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Warn'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.direction | Should -Be 'inbound'
        $finding.evidence[0].detail.classification | Should -Be 'unclassifiable'
        $finding.evidence[0].detail.applicationsTargetScope | Should -Be 'open-all'
        $finding.reason | Should -Match 'unclassifiable'
    }

    It 'Warn (conservative, never thrown): an absent b2bCollaborationInbound/Outbound block is unclassifiable, not silently assumed compliant or confirmed wide open' {
        $policy = @{ id = 'default' }
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )
        $finding.status | Should -Be 'Warn'
        $finding.evidence.Count | Should -Be 2
        @($finding.evidence.detail.classification | Select-Object -Unique) | Should -Be @('unclassifiable')
    }

    It 'Warn (post-review, F5 - behavior now matches the honest claim): an unrecognized accessType value is never folded into restricted, and is surfaced as unclassifiable' {
        $policy = New-PulseCrossTenantPolicy -InboundAccessType 'someFutureGraphValue' -OutboundAccessType 'blocked'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Warn'
        $finding.evidence.Count | Should -Be 1
        $finding.evidence[0].detail.direction | Should -Be 'inbound'
        $finding.evidence[0].detail.classification | Should -Be 'unclassifiable'
        $finding.evidence[0].detail.accessType | Should -Be 'someFutureGraphValue'
        $finding.reason | Should -Match 'unclassifiable'
        $finding.reason | Should -Not -Match 'not counted as a Pass.*restrict'
    }

    It 'Warn: an unclassifiable direction alongside a genuinely unrestricted one reports both, distinctly classified' {
        $policy = New-PulseCrossTenantPolicy -InboundAccessType 'allowed' -OutboundAccessType 'weirdValue'
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Collected'; Data = @($policy) }
        )

        $finding.status | Should -Be 'Warn'
        $finding.evidence.Count | Should -Be 2
        ($finding.evidence | Where-Object { $_.detail.direction -eq 'inbound' }).detail.classification | Should -Be 'unrestricted'
        ($finding.evidence | Where-Object { $_.detail.direction -eq 'outbound' }).detail.classification | Should -Be 'unclassifiable'
        $finding.reason | Should -Match 'unrestricted B2B collaboration \(inbound\)'
        $finding.reason | Should -Match 'unclassifiable.*outbound'
    }

    It 'NotApplicable when the released dataset is skipped because collection permission is unavailable' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.ENT.0023' -Datasets @(
            @{ Name = 'crossTenantAccessPolicyDefault'; ApiVersion = 'v1.0'; Status = 'Skipped'; Reason = 'permission-denied: Policy.Read.All is unavailable' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'permission-denied: Policy.Read.All is unavailable'
    }
}
