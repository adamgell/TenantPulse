<#
    Snapshot-only audit report projections for the IHA successor.

    These functions never call Graph. They read hash-verified TenantPulse datasets and
    publish deterministic schema-v1 JSONL artifacts for the five active IHA report families
    that were not covered by the application and managed-device producers. Every row keeps
    sourceColumns so a later Office renderer can evolve without recollecting the tenant.

    Presentation-only legacy behavior is deliberately excluded: no current-clock status,
    fuzzy matching, comma-joined cells, colors, branding, approval, or severity is computed.
    Missing/partial sources and malformed rows remain explicit gaps.
#>

function Get-PulseAuditReportDatasetState {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Store,
        [Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)] [string] $Name
    )

    if (-not $Manifest.Contains('datasets') -or -not $Manifest.datasets.Contains($Name)) {
        return [pscustomobject]@{ Name = $Name; Available = $false; Status = 'Missing'; Rows = @(); ReasonCode = 'dataset-missing' }
    }

    $entry = $Manifest.datasets[$Name]
    if ($entry.status -notin @('Collected', 'Partial')) {
        $reasonCode = if ([string]::IsNullOrWhiteSpace([string] $entry.reasonCode)) { 'dataset-unavailable' } else { [string] $entry.reasonCode }
        return [pscustomobject]@{ Name = $Name; Available = $false; Status = [string] $entry.status; Rows = @(); ReasonCode = $reasonCode }
    }

    try {
        $rows = Read-PulseDataset -Store $Store -Name $Name -ManifestSnapshot $Manifest
        return [pscustomobject]@{ Name = $Name; Available = $true; Status = [string] $entry.status; Rows = @($rows); ReasonCode = [string] $entry.reasonCode }
    } catch {
        return [pscustomobject]@{ Name = $Name; Available = $false; Status = 'Invalid'; Rows = @(); ReasonCode = 'dataset-integrity-failed' }
    }
}

function New-PulseAuditReportGap {
    param(
        [Parameter(Mandatory)] [string] $Scope,
        [Parameter(Mandatory)] [string] $Reason
    )

    return [pscustomobject][ordered]@{ policyId = $Scope; reason = $Reason }
}

function Publish-PulseAuditReportRows {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Store,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rows,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Gaps,
        [Parameter(Mandatory)] [int] $SourceCount,
        [Parameter(Mandatory)] [string[]] $SortProperties,
        [string] $ProfileId = '',
        [string] $Pseudonym = 'tp-unknown',
        [AllowNull()] [string] $TenantId
    )

    $safeRows = Protect-PulseGraphRowTenantId -Data @($Rows) -TenantId $TenantId -Pseudonym $Pseudonym
    $reason = if (@($Gaps).Count -gt 0) { [string] $Gaps[0].reason } else { $null }
    return Publish-PulseExpansionRows -Store $Store -Name $Name -Rows @($safeRows) -Gaps @($Gaps) `
        -PolicyCount $SourceCount -SortProperties $SortProperties -UnresolvedNameCount 0 `
        -RedactedSecretCount 0 -Reason $reason -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
}

function Set-PulseAuditReportUnavailable {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Store,
        [Parameter(Mandatory)] [string] $Artifact,
        [Parameter(Mandatory)] [string] $Dataset,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [string] $ProfileId = '',
        [string] $Pseudonym = 'tp-unknown',
        [AllowNull()] [string] $TenantId
    )

    $reason = Protect-PulseReason -Message "report-source-unavailable: $Dataset/$ReasonCode" `
        -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
    Set-PulseExpansionEntry -Store $Store -Name $Artifact -Status NotExpanded -Reason $reason
    return [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
}

function Get-PulseCompliancePlatform {
    param([AllowNull()] $Policy)
    $type = ConvertTo-PulseTargetType -Value (Get-PulseReportValue -InputObject $Policy -Name @('@odata.type'))
    switch -Regex ($type) {
        '^windows' { return 'Windows' }
        '^android' { return 'Android' }
        '^ios' { return 'iOS' }
        '^macOS' { return 'macOS' }
        '^linux' { return 'Linux' }
        default { return $type }
    }
}

function Get-PulseAuditReportRecordId {
    param(
        [Parameter(Mandatory)] [string] $Dataset,
        [Parameter(Mandatory)] $InputObject
    )

    $serviceId = [string] (Get-PulseReportValue -InputObject $InputObject -Name @('id'))
    if (-not [string]::IsNullOrWhiteSpace($serviceId)) { return $serviceId }

    # Some connector/token shapes have no Graph id. An input-order index would make the
    # content hash change when the same page arrives in a different order, so use a
    # deterministic source-row fingerprint as the local record identity instead.
    $canonical = ConvertTo-PulseCanonicalJsonLine -InputObject (ConvertTo-PulseReportSourceMap -InputObject $InputObject)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $hex = ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    return "$Dataset-$hex"
}

function Invoke-PulseComplianceReportCollection {
    param([pscustomobject] $Store, [string] $ProfileId = '', [string] $Pseudonym = 'tp-unknown', [AllowNull()] [string] $TenantId)
    $artifact = 'compliance-policy-assignments'
    $manifest = Get-PulseSnapshotManifest -Store $Store
    $source = Get-PulseAuditReportDatasetState -Store $Store -Manifest $manifest -Name 'deviceCompliancePolicies'
    if (-not $source.Available) {
        return Set-PulseAuditReportUnavailable -Store $Store -Artifact $artifact -Dataset $source.Name -ReasonCode $source.ReasonCode -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($policy in @($source.Rows)) {
        $index++
        $policyId = [string] (Get-PulseReportValue -InputObject $policy -Name @('id'))
        if ([string]::IsNullOrWhiteSpace($policyId)) {
            $gaps.Add((New-PulseAuditReportGap -Scope "compliance-policy-$index" -Reason 'category:invalid-provider-data;dataset:deviceCompliancePolicies;detail:identity-missing'))
            continue
        }
        $assignments = @(Get-PulseReportValue -InputObject $policy -Name @('assignments'))
        $rows.Add([pscustomobject][ordered]@{
                schemaVersion      = '1'
                policyId           = $policyId
                policyName         = Get-PulseReportValue -InputObject $policy -Name @('displayName')
                policyType         = ConvertTo-PulseTargetType -Value (Get-PulseReportValue -InputObject $policy -Name @('@odata.type'))
                platform           = Get-PulseCompliancePlatform -Policy $policy
                assignmentCount    = $assignments.Count
                assignments        = @($assignments | ForEach-Object { ConvertTo-PulseReportSourceMap -InputObject $_ })
                passcodeRequired   = Get-PulseReportValue -InputObject $policy -Name @('passwordRequired', 'passcodeRequired')
                minimumPasscodeLength = Get-PulseReportValue -InputObject $policy -Name @('passwordMinimumLength', 'passcodeMinimumLength')
                encryptionRequired = Get-PulseReportValue -InputObject $policy -Name @('storageRequireEncryption', 'deviceThreatProtectionEnabled', 'encryptionRequired')
                sourceColumns      = ConvertTo-PulseReportSourceMap -InputObject $policy
            })
    }
    if ($source.Status -eq 'Partial') { $gaps.Add((New-PulseAuditReportGap -Scope $source.Name -Reason 'category:source-dataset-partial;dataset:deviceCompliancePolicies')) }
    return Publish-PulseAuditReportRows -Store $Store -Name $artifact -Rows $rows.ToArray() -Gaps $gaps.ToArray() `
        -SourceCount @($source.Rows).Count -SortProperties @('policyId', 'policyName') -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
}

function Invoke-PulseConditionalAccessReportCollection {
    param([pscustomobject] $Store, [string] $ProfileId = '', [string] $Pseudonym = 'tp-unknown', [AllowNull()] [string] $TenantId)
    $artifact = 'conditional-access-policies'
    $manifest = Get-PulseSnapshotManifest -Store $Store
    $source = Get-PulseAuditReportDatasetState -Store $Store -Manifest $manifest -Name 'conditionalAccessPolicies'
    if (-not $source.Available) {
        return Set-PulseAuditReportUnavailable -Store $Store -Artifact $artifact -Dataset $source.Name -ReasonCode $source.ReasonCode -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($policy in @($source.Rows)) {
        $index++
        try { $view = @(ConvertTo-PulseCaPolicyView -Policies $policy)[0] } catch {
            $gaps.Add((New-PulseAuditReportGap -Scope "conditional-access-policy-$index" -Reason 'category:invalid-provider-data;dataset:conditionalAccessPolicies;detail:normalization-failed'))
            continue
        }
        if ($null -eq $view -or [string]::IsNullOrWhiteSpace([string] $view.id)) {
            $gaps.Add((New-PulseAuditReportGap -Scope "conditional-access-policy-$index" -Reason 'category:invalid-provider-data;dataset:conditionalAccessPolicies;detail:identity-missing'))
            continue
        }
        $rows.Add([pscustomobject][ordered]@{
                schemaVersion       = '1'
                policyId            = $view.id
                policyName          = $view.displayName
                state               = $view.state
                accessType          = if (@($view.grants.builtInControls) -contains 'block') { 'Block' } elseif ($view.grants.present) { 'Grant' } else { 'None' }
                usersIncluded       = @($view.conditions.users.includeUsers)
                usersExcluded       = @($view.conditions.users.excludeUsers)
                groupsIncluded      = @($view.conditions.users.includeGroups)
                groupsExcluded      = @($view.conditions.users.excludeGroups)
                applicationsIncluded = @($view.conditions.apps.includeApplications)
                applicationsExcluded = @($view.conditions.apps.excludeApplications)
                clientAppTypes      = @($view.conditions.clientAppTypes)
                platforms           = $view.conditions.platforms
                locations           = $view.conditions.locations
                grantControls       = $view.grants
                sessionControls     = $view.session
                createdDateTime     = Get-PulseReportValue -InputObject $policy -Name @('createdDateTime')
                modifiedDateTime    = Get-PulseReportValue -InputObject $policy -Name @('modifiedDateTime')
                sourceColumns       = ConvertTo-PulseReportSourceMap -InputObject $policy
            })
    }
    if ($source.Status -eq 'Partial') { $gaps.Add((New-PulseAuditReportGap -Scope $source.Name -Reason 'category:source-dataset-partial;dataset:conditionalAccessPolicies')) }
    return Publish-PulseAuditReportRows -Store $Store -Name $artifact -Rows $rows.ToArray() -Gaps $gaps.ToArray() `
        -SourceCount @($source.Rows).Count -SortProperties @('policyId', 'policyName') -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
}

function Invoke-PulseGroupReportCollection {
    param([pscustomobject] $Store, [string] $ProfileId = '', [string] $Pseudonym = 'tp-unknown', [AllowNull()] [string] $TenantId)
    $artifact = 'groups-inventory'
    $manifest = Get-PulseSnapshotManifest -Store $Store
    $source = Get-PulseAuditReportDatasetState -Store $Store -Manifest $manifest -Name 'groups'
    if (-not $source.Available) {
        return Set-PulseAuditReportUnavailable -Store $Store -Artifact $artifact -Dataset $source.Name -ReasonCode $source.ReasonCode -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($group in @($source.Rows)) {
        $index++
        $groupId = [string] (Get-PulseReportValue -InputObject $group -Name @('id'))
        if ([string]::IsNullOrWhiteSpace($groupId)) {
            $gaps.Add((New-PulseAuditReportGap -Scope "group-$index" -Reason 'category:invalid-provider-data;dataset:groups;detail:identity-missing'))
            continue
        }
        $rows.Add([pscustomobject][ordered]@{
                schemaVersion = '1'; groupId = $groupId
                displayName = Get-PulseReportValue -InputObject $group -Name @('displayName')
                description = Get-PulseReportValue -InputObject $group -Name @('description')
                groupTypes = @(Get-PulseReportValue -InputObject $group -Name @('groupTypes'))
                mail = Get-PulseReportValue -InputObject $group -Name @('mail')
                mailEnabled = Get-PulseReportValue -InputObject $group -Name @('mailEnabled')
                mailNickname = Get-PulseReportValue -InputObject $group -Name @('mailNickname')
                securityEnabled = Get-PulseReportValue -InputObject $group -Name @('securityEnabled')
                visibility = Get-PulseReportValue -InputObject $group -Name @('visibility')
                membershipRule = Get-PulseReportValue -InputObject $group -Name @('membershipRule')
                membershipRuleProcessingState = Get-PulseReportValue -InputObject $group -Name @('membershipRuleProcessingState')
                createdDateTime = Get-PulseReportValue -InputObject $group -Name @('createdDateTime')
                renewedDateTime = Get-PulseReportValue -InputObject $group -Name @('renewedDateTime')
                expirationDateTime = Get-PulseReportValue -InputObject $group -Name @('expirationDateTime')
                sourceColumns = ConvertTo-PulseReportSourceMap -InputObject $group
            })
    }
    if ($source.Status -eq 'Partial') { $gaps.Add((New-PulseAuditReportGap -Scope $source.Name -Reason 'category:source-dataset-partial;dataset:groups')) }
    return Publish-PulseAuditReportRows -Store $Store -Name $artifact -Rows $rows.ToArray() -Gaps $gaps.ToArray() `
        -SourceCount @($source.Rows).Count -SortProperties @('groupId', 'displayName') -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
}

function Invoke-PulseConnectorReportCollection {
    param([pscustomobject] $Store, [string] $ProfileId = '', [string] $Pseudonym = 'tp-unknown', [AllowNull()] [string] $TenantId)
    $artifact = 'connectors-and-tokens'
    $manifest = Get-PulseSnapshotManifest -Store $Store
    $specs = @(
        [pscustomobject]@{ Dataset = 'ndesConnectors'; Type = 'CertificateConnector' }
        [pscustomobject]@{ Dataset = 'domainConnectors'; Type = 'DomainConnector' }
        [pscustomobject]@{ Dataset = 'depOnboardingSettings'; Type = 'AppleEnrollmentToken' }
        [pscustomobject]@{ Dataset = 'vppTokens'; Type = 'AppleVppToken' }
    )
    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $availableSources = 0
    $sourceRows = 0
    foreach ($spec in $specs) {
        $source = Get-PulseAuditReportDatasetState -Store $Store -Manifest $manifest -Name $spec.Dataset
        if (-not $source.Available) {
            $gaps.Add((New-PulseAuditReportGap -Scope $spec.Dataset -Reason "category:source-dataset-unavailable;dataset:$($spec.Dataset);detail:$($source.ReasonCode)"))
            continue
        }
        $availableSources++
        $sourceRows += @($source.Rows).Count
        if ($source.Status -eq 'Partial') { $gaps.Add((New-PulseAuditReportGap -Scope $spec.Dataset -Reason "category:source-dataset-partial;dataset:$($spec.Dataset)")) }
        foreach ($item in @($source.Rows)) {
            $itemId = Get-PulseAuditReportRecordId -Dataset $spec.Dataset -InputObject $item
            $rows.Add([pscustomobject][ordered]@{
                    schemaVersion = '1'; sourceDataset = $spec.Dataset; recordType = $spec.Type; recordId = $itemId
                    name = Get-PulseReportValue -InputObject $item -Name @('displayName', 'tokenName', 'organizationName', 'machineName')
                    serviceState = Get-PulseReportValue -InputObject $item -Name @('state', 'status', 'lastSyncStatus')
                    version = Get-PulseReportValue -InputObject $item -Name @('version', 'connectorVersion')
                    installationDateTime = Get-PulseReportValue -InputObject $item -Name @('enrolledDateTime', 'createdDateTime', 'uploadDateTime')
                    lastCommunicationDateTime = Get-PulseReportValue -InputObject $item -Name @('lastHeartbeatDateTime', 'lastConnectionDateTime', 'lastSuccessfulSyncDateTime', 'lastModifiedDateTime', 'lastSyncDateTime')
                    expirationDateTime = Get-PulseReportValue -InputObject $item -Name @('tokenExpirationDateTime', 'expirationDateTime')
                    appleIdentifier = Get-PulseReportValue -InputObject $item -Name @('appleIdentifier', 'appleId')
                    machineName = Get-PulseReportValue -InputObject $item -Name @('machineName')
                    domainName = Get-PulseReportValue -InputObject $item -Name @('domainName')
                    sourceColumns = ConvertTo-PulseReportSourceMap -InputObject $item
                })
        }
    }
    if ($availableSources -eq 0) {
        return Set-PulseAuditReportUnavailable -Store $Store -Artifact $artifact -Dataset 'connector-sources' -ReasonCode 'all-sources-unavailable' -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
    }
    if ($sourceRows -eq 0 -and $gaps.Count -gt 0) { $sourceRows = 1 }
    return Publish-PulseAuditReportRows -Store $Store -Name $artifact -Rows $rows.ToArray() -Gaps $gaps.ToArray() `
        -SourceCount $sourceRows -SortProperties @('sourceDataset', 'recordId', 'name') -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
}

function Invoke-PulseDirectoryRoleReportCollection {
    param([pscustomobject] $Store, [string] $ProfileId = '', [string] $Pseudonym = 'tp-unknown', [AllowNull()] [string] $TenantId)
    $artifact = 'directory-role-summary'
    $manifest = Get-PulseSnapshotManifest -Store $Store
    $definitions = Get-PulseAuditReportDatasetState -Store $Store -Manifest $manifest -Name 'directoryRoleDefinitions'
    if (-not $definitions.Available) {
        return Set-PulseAuditReportUnavailable -Store $Store -Artifact $artifact -Dataset $definitions.Name -ReasonCode $definitions.ReasonCode -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
    }
    $assignments = Get-PulseAuditReportDatasetState -Store $Store -Manifest $manifest -Name 'directoryRoleAssignments'
    $active = Get-PulseAuditReportDatasetState -Store $Store -Manifest $manifest -Name 'roleAssignmentScheduleInstances'
    $eligible = Get-PulseAuditReportDatasetState -Store $Store -Manifest $manifest -Name 'roleEligibilityScheduleInstances'

    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    foreach ($source in @($definitions, $assignments, $active, $eligible)) {
        if (-not $source.Available) { $gaps.Add((New-PulseAuditReportGap -Scope $source.Name -Reason "category:source-dataset-unavailable;dataset:$($source.Name);detail:$($source.ReasonCode)")) }
        elseif ($source.Status -eq 'Partial') { $gaps.Add((New-PulseAuditReportGap -Scope $source.Name -Reason "category:source-dataset-partial;dataset:$($source.Name)")) }
    }
    $index = 0
    foreach ($definition in @($definitions.Rows)) {
        $index++
        $roleId = [string] (Get-PulseReportValue -InputObject $definition -Name @('id'))
        if ([string]::IsNullOrWhiteSpace($roleId)) {
            $gaps.Add((New-PulseAuditReportGap -Scope "directory-role-$index" -Reason 'category:invalid-provider-data;dataset:directoryRoleDefinitions;detail:identity-missing'))
            continue
        }
        $roleAssignments = @($assignments.Rows | Where-Object { [string](Get-PulseReportValue -InputObject $_ -Name @('roleDefinitionId')) -eq $roleId })
        $activeRows = @($active.Rows | Where-Object { [string](Get-PulseReportValue -InputObject $_ -Name @('roleDefinitionId')) -eq $roleId })
        $eligibleRows = @($eligible.Rows | Where-Object { [string](Get-PulseReportValue -InputObject $_ -Name @('roleDefinitionId')) -eq $roleId })
        $principalIds = @($roleAssignments | ForEach-Object { [string](Get-PulseReportValue -InputObject $_ -Name @('principalId')) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $rows.Add([pscustomobject][ordered]@{
                schemaVersion = '1'; roleDefinitionId = $roleId
                templateId = Get-PulseReportValue -InputObject $definition -Name @('templateId')
                roleName = Get-PulseReportValue -InputObject $definition -Name @('displayName')
                description = Get-PulseReportValue -InputObject $definition -Name @('description')
                isBuiltIn = Get-PulseReportValue -InputObject $definition -Name @('isBuiltIn')
                isPrivileged = Get-PulseReportValue -InputObject $definition -Name @('isPrivileged')
                permanentAssignmentCount = $roleAssignments.Count
                activeAssignmentCount = $activeRows.Count
                eligibleAssignmentCount = $eligibleRows.Count
                principalIds = $principalIds
                assignments = @($roleAssignments | ForEach-Object { ConvertTo-PulseReportSourceMap -InputObject $_ })
                activeScheduleInstances = @($activeRows | ForEach-Object { ConvertTo-PulseReportSourceMap -InputObject $_ })
                eligibleScheduleInstances = @($eligibleRows | ForEach-Object { ConvertTo-PulseReportSourceMap -InputObject $_ })
                sourceColumns = ConvertTo-PulseReportSourceMap -InputObject $definition
            })
    }
    return Publish-PulseAuditReportRows -Store $Store -Name $artifact -Rows $rows.ToArray() -Gaps $gaps.ToArray() `
        -SourceCount @($definitions.Rows).Count -SortProperties @('roleDefinitionId', 'roleName') -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
}

function Invoke-PulseAuditReportCollection {
    param([pscustomobject] $Store, [string] $ProfileId = '', [string] $Pseudonym = 'tp-unknown', [AllowNull()] [string] $TenantId)
    return [pscustomobject][ordered]@{
        CompliancePolicyAssignments = Invoke-PulseComplianceReportCollection @PSBoundParameters
        ConditionalAccessPolicies = Invoke-PulseConditionalAccessReportCollection @PSBoundParameters
        ConnectorsAndTokens = Invoke-PulseConnectorReportCollection @PSBoundParameters
        DirectoryRoles = Invoke-PulseDirectoryRoleReportCollection @PSBoundParameters
        Groups = Invoke-PulseGroupReportCollection @PSBoundParameters
    }
}
