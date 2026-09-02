<#
    Private: Administrative Template expansion over released GraphKit primitives.

    Walks GroupPolicyConfiguration.ListBeta, then per configuration
    GroupPolicyDefinitionValue.ListBeta, then per definition value
    GroupPolicyPresentationValue.ListBeta. Expansion is never default-on: callers pass
    -Requested (or selected checks that declare administrativeTemplates via
    Resolve-PulseRequestedExpansions). An explicit opt-out writes NotExpanded with
    DependencyUnavailable so artifact-backed checks degrade honestly.

    Every enumerated configuration ends Expanded, Partial, or NotExpanded and those
    counts always sum to PolicyCount. Child gaps name the GraphKit operation that failed.
#>

function Invoke-PulseAdministrativeTemplateExpansion {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $Context,

        [Parameter()]
        [switch] $Requested,

        [Parameter()]
        [AllowNull()]
        [object[]] $SelectedChecks,

        [Parameter()]
        [string] $Name = 'administrativeTemplates',

        [Parameter()]
        [string] $ProfileId = '',

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown',

        [Parameter()]
        [AllowNull()]
        [string] $TenantId,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $NetworkAbortState = $null
    )

    if ($null -eq $NetworkAbortState) {
        $NetworkAbortState = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
    }

    $selection = Resolve-PulseRequestedExpansions -SelectedChecks $SelectedChecks -ExpandSettings:$Requested
    $declared = @($selection.Requested) -contains $Name
    if (-not $Requested -and -not $declared) {
        $reason = Protect-PulseReason -Message 'expansion not requested: dependency-unavailable' `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $reason
        return [pscustomobject]@{
            Status           = 'NotExpanded'
            FailureClass     = 'DependencyUnavailable'
            PolicyCount      = 0
            ExpandedCount    = 0
            PartialCount     = 0
            NotExpandedCount = 0
            RowCount         = 0
            Gaps             = @()
            Operations       = @()
        }
    }

    $descriptorSpecs = @(
        @{ Type = 'GroupPolicyConfiguration'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'GroupPolicyDefinitionValue'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'GroupPolicyPresentationValue'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    )
    try {
        foreach ($spec in $descriptorSpecs) {
            Assert-PulseReadOnlyDescriptor -Type $spec.Type -Operation $spec.Operation -ApiVersion $spec.ApiVersion
        }
    } catch {
        if ($_.Exception.Message -match 'descriptor-version-drift') {
            $reason = Protect-PulseReason -Message $_.Exception.Message -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
            Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $reason
            return [pscustomobject]@{
                Status           = 'NotExpanded'
                FailureClass     = 'DependencyUnavailable'
                PolicyCount      = 0
                ExpandedCount    = 0
                PartialCount     = 0
                NotExpandedCount = 0
                RowCount         = 0
                Gaps             = @()
                Operations       = @()
            }
        }
        throw
    }

    function New-AdminTemplateGapReason {
        param([string] $Category, [string] $Operation, [System.Nullable[int]] $StatusCode = $null)
        $reason = "category:$Category;operation:$Operation"
        if ($null -ne $StatusCode) { $reason = "$reason;statusCode:$StatusCode" }
        return $reason
    }

    function New-AdminTemplateRow {
        param(
            [string] $PolicyId,
            [string] $PolicyName,
            [string] $SettingPath,
            [string] $SettingDefinitionId,
            [string] $SettingName,
            [bool] $NameResolved,
            [string] $InstanceId,
            $Value,
            $ValueLabel,
            [bool] $LabelResolved
        )
        return [pscustomobject]@{
            schemaVersion       = '1'
            policyId            = $PolicyId
            policyType          = 'administrativeTemplate'
            policyName          = $PolicyName
            templateFamily      = $null
            isBaseline          = $false
            settingPath         = $SettingPath
            settingDefinitionId = $SettingDefinitionId
            settingName         = $SettingName
            nameResolved        = $NameResolved
            instanceId          = $InstanceId
            value               = $Value
            valueLabel          = $ValueLabel
            labelResolved       = $LabelResolved
            redacted            = $false
            valueState          = $null
            applicability       = $null
            assignments         = @()
        }
    }

    $configurations = @()
    try {
        $configurations = @(Get-GraphObject -Context $Context -Type 'GroupPolicyConfiguration' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $failure = Resolve-PulseGraphFailure -ErrorRecord $_
        if ($failure.AbortCollection) {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = 'auth-failure: collection aborted'
        }
        $reason = Protect-PulseReason -Message (New-AdminTemplateGapReason -Category 'ConfigurationListFailed' -Operation 'GroupPolicyConfiguration.ListBeta' -StatusCode $failure.StatusCode) `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $reason
        return [pscustomobject]@{
            Status           = 'NotExpanded'
            FailureClass     = $failure.FailureClass
            PolicyCount      = 0
            ExpandedCount    = 0
            PartialCount     = 0
            NotExpandedCount = 0
            RowCount         = 0
            Gaps             = @()
            Operations       = @('GroupPolicyConfiguration.ListBeta')
        }
    }

    $allRows = [System.Collections.Generic.List[object]]::new()
    $gapEntries = [System.Collections.Generic.List[object]]::new()
    $expandedCount = 0
    $partialCount = 0
    $notExpandedCount = 0
    $operations = @(
        'GroupPolicyConfiguration.ListBeta'
        'GroupPolicyDefinitionValue.ListBeta'
        'GroupPolicyPresentationValue.ListBeta'
    )

    foreach ($configuration in $configurations) {
        $policyIdRaw = Get-PulseSettingsCatalogValueProperty -Node $configuration -PropertyName 'id'
        $policyId = if ($null -ne $policyIdRaw) { [string] $policyIdRaw } else { '' }
        if ([string]::IsNullOrWhiteSpace($policyId)) {
            $notExpandedCount++
            $gapEntries.Add([pscustomobject]@{ policyId = ''; reason = (New-AdminTemplateGapReason -Category 'EmptyPolicyId' -Operation 'GroupPolicyConfiguration.ListBeta') }) | Out-Null
            continue
        }

        $policyNameRaw = Get-PulseSettingsCatalogValueProperty -Node $configuration -PropertyName 'displayName'
        $policyName = if ($null -ne $policyNameRaw -and -not [string]::IsNullOrWhiteSpace([string] $policyNameRaw)) {
            [string] $policyNameRaw
        } else {
            $policyId
        }

        $definitionValues = @()
        try {
            $definitionValues = @(Get-GraphObject -Context $Context -Type 'GroupPolicyDefinitionValue' -Operation 'ListBeta' `
                    -Parameters @{ id = $policyId } -ErrorAction Stop)
        } catch {
            $failure = Resolve-PulseGraphFailure -ErrorRecord $_
            if ($failure.AbortCollection) {
                $NetworkAbortState.AuthenticationAborted = $true
                $NetworkAbortState.Reason = 'auth-failure: collection aborted'
            }
            $notExpandedCount++
            $reason = Protect-PulseReason -Message (New-AdminTemplateGapReason -Category 'DefinitionValueFetchFailed' -Operation 'GroupPolicyDefinitionValue.ListBeta' -StatusCode $failure.StatusCode) `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
            $gapEntries.Add([pscustomobject]@{ policyId = $policyId; reason = $reason }) | Out-Null
            if ($NetworkAbortState.AuthenticationAborted) { break }
            continue
        }

        $policyRows = [System.Collections.Generic.List[object]]::new()
        $policyPartial = $false
        foreach ($definitionValue in $definitionValues) {
            $definitionValueIdRaw = Get-PulseSettingsCatalogValueProperty -Node $definitionValue -PropertyName 'id'
            $definitionValueId = if ($null -ne $definitionValueIdRaw) { [string] $definitionValueIdRaw } else { '' }
            if ([string]::IsNullOrWhiteSpace($definitionValueId)) {
                $policyPartial = $true
                $gapEntries.Add([pscustomobject]@{
                        policyId = $policyId
                        reason   = (New-AdminTemplateGapReason -Category 'EmptyDefinitionValueId' -Operation 'GroupPolicyDefinitionValue.ListBeta')
                    }) | Out-Null
                continue
            }

            $definition = Get-PulseSettingsCatalogValueProperty -Node $definitionValue -PropertyName 'definition'
            $definitionIdRaw = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'id'
            $definitionId = if ($null -ne $definitionIdRaw) { [string] $definitionIdRaw } else { $definitionValueId }
            $definitionNameRaw = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'displayName'
            $definitionName = if ($null -ne $definitionNameRaw) { [string] $definitionNameRaw } else { $null }
            $categoryPathRaw = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'categoryPath'
            $settingPath = if (-not [string]::IsNullOrWhiteSpace([string] $categoryPathRaw) -and -not [string]::IsNullOrWhiteSpace($definitionName)) {
                "$categoryPathRaw/$definitionName"
            } elseif (-not [string]::IsNullOrWhiteSpace($definitionName)) {
                $definitionName
            } else {
                $definitionId
            }

            $enabled = Get-PulseSettingsCatalogValueProperty -Node $definitionValue -PropertyName 'enabled'
            if ($null -ne $enabled -and $enabled -isnot [bool]) {
                $policyPartial = $true
                $gapEntries.Add([pscustomobject]@{
                        policyId = $policyId
                        reason   = (New-AdminTemplateGapReason -Category 'UnknownEnabledValue' -Operation 'GroupPolicyDefinitionValue.ListBeta')
                    }) | Out-Null
            } else {
                $policyRows.Add((New-AdminTemplateRow -PolicyId $policyId -PolicyName $policyName `
                            -SettingPath $settingPath -SettingDefinitionId $definitionId `
                            -SettingName $definitionName -NameResolved (-not [string]::IsNullOrWhiteSpace($definitionName)) `
                            -InstanceId $definitionValueId -Value $enabled -ValueLabel $null -LabelResolved $false)) | Out-Null
            }

            try {
                $presentationValues = @(Get-GraphObject -Context $Context -Type 'GroupPolicyPresentationValue' -Operation 'ListBeta' `
                        -Parameters @{ id = $policyId; definitionValueId = $definitionValueId } -ErrorAction Stop)
            } catch {
                $failure = Resolve-PulseGraphFailure -ErrorRecord $_
                if ($failure.AbortCollection) {
                    $NetworkAbortState.AuthenticationAborted = $true
                    $NetworkAbortState.Reason = 'auth-failure: collection aborted'
                }
                $policyPartial = $true
                $reason = Protect-PulseReason -Message (New-AdminTemplateGapReason -Category 'PresentationValueFetchFailed' -Operation 'GroupPolicyPresentationValue.ListBeta' -StatusCode $failure.StatusCode) `
                    -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                $gapEntries.Add([pscustomobject]@{ policyId = $policyId; reason = $reason }) | Out-Null
                if ($NetworkAbortState.AuthenticationAborted) { break }
                continue
            }

            foreach ($presentationValue in $presentationValues) {
                $presentationIdRaw = Get-PulseSettingsCatalogValueProperty -Node $presentationValue -PropertyName 'id'
                $presentationId = if ($null -ne $presentationIdRaw) { [string] $presentationIdRaw } else { [guid]::NewGuid().ToString('N') }
                $presentation = Get-PulseSettingsCatalogValueProperty -Node $presentationValue -PropertyName 'presentation'
                $labelRaw = Get-PulseSettingsCatalogValueProperty -Node $presentation -PropertyName 'label'
                $label = if ($null -ne $labelRaw) { [string] $labelRaw } else { $null }
                $value = Get-PulseSettingsCatalogValueProperty -Node $presentationValue -PropertyName 'value'
                $policyRows.Add((New-AdminTemplateRow -PolicyId $policyId -PolicyName $policyName `
                            -SettingPath $(if ($label) { "$settingPath/$label" } else { $settingPath }) `
                            -SettingDefinitionId $definitionId -SettingName $label `
                            -NameResolved (-not [string]::IsNullOrWhiteSpace($label)) `
                            -InstanceId $presentationId -Value $value -ValueLabel $label `
                            -LabelResolved (-not [string]::IsNullOrWhiteSpace($label)))) | Out-Null
            }
            if ($NetworkAbortState.AuthenticationAborted) { break }
        }

        if ($NetworkAbortState.AuthenticationAborted -and $policyPartial -and $policyRows.Count -eq 0) {
            $notExpandedCount++
        } elseif ($policyPartial) {
            $partialCount++
            foreach ($row in $policyRows) { $allRows.Add($row) | Out-Null }
        } else {
            $expandedCount++
            foreach ($row in $policyRows) { $allRows.Add($row) | Out-Null }
        }
        if ($NetworkAbortState.AuthenticationAborted) { break }
    }

    $policyCount = $expandedCount + $partialCount + $notExpandedCount
    $sortedGaps = $gapEntries.ToArray()
    if ($sortedGaps.Count -gt 1) {
        $gapComparison = [System.Comparison[object]] {
            param($a, $b)
            $c = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
            if ($c -ne 0) { return $c }
            return [string]::CompareOrdinal([string] $a.reason, [string] $b.reason)
        }
        [System.Array]::Sort($sortedGaps, $gapComparison)
    }

    $redactedRows = Protect-PulseGraphRowTenantId -Data $allRows.ToArray() -TenantId $TenantId -Pseudonym $Pseudonym
    $published = Publish-PulseExpansionRows -Store $Store -Name $Name -Rows $redactedRows -Gaps $sortedGaps `
        -PolicyCount $policyCount -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId

    return [pscustomobject]@{
        Status           = $published.Status
        FailureClass     = $null
        PolicyCount      = $policyCount
        ExpandedCount    = $expandedCount
        PartialCount     = $partialCount
        NotExpandedCount = $notExpandedCount
        RowCount         = $published.RowCount
        Gaps             = $published.Gaps
        Operations       = $operations
    }
}
