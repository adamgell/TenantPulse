BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

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

    function script:New-PulseBrandingAssignment {
        param(
            [string] $Id = 'branding-assignment-1',
            [string] $TargetType = 'user',
            [string] $EntraObjectId = 'branding-group-1'
        )

        [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.intuneBrandingProfileAssignment'
            id            = $Id
            target        = [pscustomobject]@{
                '@odata.type' = 'microsoft.graph.scopeTagGroupAssignmentTarget'
                targetType    = $TargetType
                entraObjectId = $EntraObjectId
            }
        }
    }
}

Describe 'TP.INT.0011 - Default branding profile customized' {
    It 'catalog: loads and validates cleanly via Import-PulseCheckCatalog (self-check)' {
        $catalog = InModuleScope TenantPulse { @(Import-PulseCheckCatalog) }
        ($catalog | Where-Object { $_.Id -eq 'TP.INT.0011' }) | Should -Not -BeNullOrEmpty
    }

    It 'Pass: default profile has a non-empty displayName' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isDefaultProfile = $true; displayName = 'Contoso'; privacyUrl = $null }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: default profile has only privacyUrl set' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isDefaultProfile = $true; displayName = ''; privacyUrl = 'https://contoso.com/privacy' }) }
        )

        $finding.status | Should -Be 'Pass'
    }

    It 'Pass: default profile is blank but an additional custom profile is assigned' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'default'; isDefaultProfile = $true; displayName = ''; privacyUrl = '' }
                [pscustomobject]@{ id = 'custom-1'; isDefaultProfile = $false; displayName = 'Sales team'; privacyUrl = ''; assignments = @(
                    (New-PulseBrandingAssignment -EntraObjectId 'sales-group')
                ) }
            ) }
        )

        $finding.status | Should -Be 'Pass'
        $finding.reason | Should -Match 'at least one custom'
    }

    It 'Fail: exactly one blank default profile' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isDefaultProfile = $true; displayName = ''; privacyUrl = '' }) }
        )

        $finding.status | Should -Be 'Fail'
        $finding.reason | Should -Match 'unmodified'
    }

    It 'Error: intuneBrandingProfiles returning zero rows never reads as Pass or Fail' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @() }
        )

        $finding.status | Should -Be 'Error'
    }

    It 'Error: the default profile row has no displayName property at all (absent, not decidable)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isDefaultProfile = $true; privacyUrl = '' }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'displayName'
    }

    It 'Error: the default profile row has no privacyUrl property at all (absent, not decidable)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isDefaultProfile = $true; displayName = '' }) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'privacyUrl'
    }

    It 'Fail still holds: present-but-$null on both fields is decidable and correctly Fails (not an Error)' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @([pscustomobject]@{ id = 'default'; isDefaultProfile = $true; displayName = $null; privacyUrl = $null }) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'Error: no row identifies the required default profile' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'p1'; displayName = ''; privacyUrl = '' }
                [pscustomobject]@{ id = 'p2'; displayName = ''; privacyUrl = '' }
            ) }
        )

        $finding.status | Should -Be 'Error'
        $finding.reason | Should -Match 'default branding profile'
    }

    It 'NotApplicable: a blank default plus a custom profile without assignment evidence is not treated as in use' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'default'; isDefaultProfile = $true; displayName = ''; privacyUrl = '' }
                [pscustomobject]@{ id = 'custom-1'; isDefaultProfile = $false; displayName = 'Sales team'; privacyUrl = '' }
            ) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'assignment evidence'
    }

    It 'Fail: a blank default plus only explicitly unassigned custom profiles is not customized for any population' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'default'; isDefaultProfile = $true; displayName = ''; privacyUrl = '' }
                [pscustomobject]@{ id = 'custom-1'; isDefaultProfile = $false; displayName = 'Sales team'; privacyUrl = ''; assignments = @() }
            ) }
        )

        $finding.status | Should -Be 'Fail'
    }

    It 'NotApplicable: a custom profile with an unsupported scope-tag target remains indeterminate' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Collected'; Data = @(
                [pscustomobject]@{ id = 'default'; isDefaultProfile = $true; displayName = ''; privacyUrl = '' }
                [pscustomobject]@{ id = 'custom-1'; isDefaultProfile = $false; displayName = 'Sales team'; privacyUrl = ''; assignments = @(
                    (New-PulseBrandingAssignment -TargetType 'unknownFutureValue')
                ) }
            ) }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Match 'assignment evidence'
    }

    It 'gate-degraded: NotApplicable when the dataset is Pending on a live tenant' {
        $finding = Invoke-PulseCheckFixture -CheckId 'TP.INT.0011' -Datasets @(
            @{ Name = 'intuneBrandingProfiles'; ApiVersion = 'beta'; Status = 'Skipped'; Reason = 'descriptor-pending: awaiting GraphKit release' }
        )

        $finding.status | Should -Be 'NotApplicable'
        $finding.reason | Should -Be 'descriptor-pending: awaiting GraphKit release'
    }
}
