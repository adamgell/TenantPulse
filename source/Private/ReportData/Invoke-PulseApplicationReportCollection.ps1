<#
    Private application-report collection contract.

    This is deliberately report data, not a pass/fail check and not an Office renderer.
    It replaces the first two IHA report inputs with neutral, versioned JSONL artifacts:
    application assignments and the Intune app-install summary report. Both live in the
    snapshot's existing expansions namespace so they inherit hash verification, atomic
    manifest publication, and explicit Expanded/Partial/NotExpanded outcomes. The rows
    retain Graph object ids and customer-facing names because they are audit evidence;
    the snapshot remains local-only material and no CDW/customer branding is introduced.

    Every Graph call uses GraphKit's OperationResult envelope. Complete, partial, invalid,
    denied, and authentication-aborted states remain distinct. The report endpoint is a
    safe read even though Graph exposes it as POST; GraphKit's descriptor is the authority
    for that semantic and Assert-PulseReadOnlyDescriptor enforces it here.
#>

$script:PulseApplicationReportOperations = @(
    [pscustomobject]@{ Type = 'AppInstallSummaryReport'; Operation = 'Get'; ApiVersion = 'beta' }
    [pscustomobject]@{ Type = 'Group'; Operation = 'Get'; ApiVersion = 'v1.0' }
    [pscustomobject]@{ Type = 'GroupMember'; Operation = 'List'; ApiVersion = 'v1.0' }
    [pscustomobject]@{ Type = 'MobileApp'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    [pscustomobject]@{ Type = 'MobileAppAssignment'; Operation = 'List'; ApiVersion = 'v1.0' }
)

function Get-PulseApplicationReportOperations {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return @($script:PulseApplicationReportOperations | ForEach-Object {
            [pscustomobject]@{ Type = $_.Type; Operation = $_.Operation; ApiVersion = $_.ApiVersion }
        })
}

function Get-PulseReportProperty {
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string[]] $Name
    )

    if ($null -eq $InputObject) { return [pscustomobject]@{ Success = $false; Value = $null } }
    foreach ($candidate in $Name) {
        try {
            if ($InputObject -is [System.Collections.IDictionary]) {
                foreach ($key in @($InputObject.Keys)) {
                    if ([string]::Equals([string] $key, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
                        return [pscustomobject]@{ Success = $true; Value = $InputObject[$key] }
                    }
                }
            } else {
                $property = $InputObject.PSObject.Properties[$candidate]
                if ($null -ne $property) {
                    return [pscustomobject]@{ Success = $true; Value = $property.Value }
                }
            }
        } catch {
            continue
        }
    }
    return [pscustomobject]@{ Success = $false; Value = $null }
}

function Get-PulseReportValue {
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string[]] $Name
    )

    $property = Get-PulseReportProperty -InputObject $InputObject -Name $Name
    if (-not $property.Success) { return $null }
    return $property.Value
}

function ConvertTo-PulseReportSourceMap {
    param([AllowNull()] $InputObject)

    $result = [ordered]@{}
    if ($null -eq $InputObject) { return $result }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $names = [string[]] @($InputObject.Keys | ForEach-Object { [string] $_ })
        [Array]::Sort($names, [System.StringComparer]::Ordinal)
        foreach ($name in $names) { $result[$name] = Get-PulseReportValue -InputObject $InputObject -Name @($name) }
        return $result
    }

    $names = [string[]] @($InputObject.PSObject.Properties.Name)
    [Array]::Sort($names, [System.StringComparer]::Ordinal)
    foreach ($name in $names) { $result[$name] = $InputObject.PSObject.Properties[$name].Value }
    return $result
}

function ConvertTo-PulseTargetType {
    param([AllowNull()] $Value)

    $text = [string] $Value
    if ($text.StartsWith('#microsoft.graph.', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $text.Substring('#microsoft.graph.'.Length)
    }
    return $text
}

function New-PulseApplicationAssignmentRow {
    param(
        [Parameter(Mandatory)] $Application,
        [AllowNull()] $Assignment,
        [Parameter(Mandatory)] [int] $AssignmentCount,
        [Parameter(Mandatory)] [string] $AssignmentResolutionState,
        [AllowNull()] $GroupResolution
    )

    $target = Get-PulseReportValue -InputObject $Assignment -Name @('target')
    $targetType = ConvertTo-PulseTargetType -Value (Get-PulseReportValue -InputObject $target -Name @('@odata.type'))
    $groupId = [string] (Get-PulseReportValue -InputObject $target -Name @('groupId'))
    if ([string]::IsNullOrWhiteSpace($groupId)) { $groupId = $null }
    $isExclusion = [string]::Equals($targetType, 'exclusionGroupAssignmentTarget', [System.StringComparison]::OrdinalIgnoreCase)

    $groupName = $null
    $groupDescription = $null
    $groupMemberCount = $null
    $groupResolutionState = 'NotApplicable'
    $memberResolutionState = 'NotApplicable'
    if ($null -ne $GroupResolution) {
        $groupName = $GroupResolution.Name
        $groupDescription = $GroupResolution.Description
        $groupMemberCount = $GroupResolution.MemberCount
        $groupResolutionState = $GroupResolution.GroupState
        $memberResolutionState = $GroupResolution.MemberState
    }

    $targetDisplayName = switch ($targetType) {
        'groupAssignmentTarget' { if ($groupName) { $groupName } else { 'Unresolved Group' }; break }
        'exclusionGroupAssignmentTarget' { if ($groupName) { "Exclude: $groupName" } else { 'Exclude: Unresolved Group' }; break }
        'allDevicesAssignmentTarget' { 'All Devices'; break }
        'allLicensedUsersAssignmentTarget' { 'All Licensed Users'; break }
        'deviceAndAppManagementAssignmentTarget' { 'Device Filter'; break }
        '' { $null; break }
        default { 'Unknown Target Type' }
    }

    $appOdataType = [string] (Get-PulseReportValue -InputObject $Application -Name @('@odata.type'))
    $appType = ConvertTo-PulseTargetType -Value $appOdataType
    $settingsProperty = Get-PulseReportProperty -InputObject $Assignment -Name @('settings')
    $settingsValue = $null
    if ($settingsProperty.Success) { $settingsValue = $settingsProperty.Value }

    return [pscustomobject][ordered]@{
        schemaVersion             = '1'
        appId                     = Get-PulseReportValue -InputObject $Application -Name @('id')
        appName                   = Get-PulseReportValue -InputObject $Application -Name @('displayName')
        publisher                 = Get-PulseReportValue -InputObject $Application -Name @('publisher')
        appType                   = $appType
        isFeatured                = Get-PulseReportValue -InputObject $Application -Name @('isFeatured')
        isBuiltIn                 = Get-PulseReportValue -InputObject $Application -Name @('isBuiltIn')
        isBuiltInDerived          = $false
        createdDateTime           = Get-PulseReportValue -InputObject $Application -Name @('createdDateTime')
        lastModifiedDateTime      = Get-PulseReportValue -InputObject $Application -Name @('lastModifiedDateTime')
        assignmentCount           = $AssignmentCount
        assignmentId              = Get-PulseReportValue -InputObject $Assignment -Name @('id')
        intent                    = Get-PulseReportValue -InputObject $Assignment -Name @('intent')
        targetType                = if ([string]::IsNullOrWhiteSpace($targetType)) { $null } else { $targetType }
        targetDisplayName         = $targetDisplayName
        groupId                   = $groupId
        groupName                 = $groupName
        groupDescription          = $groupDescription
        groupMemberCount          = $groupMemberCount
        isExclusion               = $isExclusion
        filterId                  = Get-PulseReportValue -InputObject $target -Name @('deviceAndAppManagementAssignmentFilterId', 'filterId')
        filterType                = Get-PulseReportValue -InputObject $target -Name @('deviceAndAppManagementAssignmentFilterType', 'filterType')
        settings                  = $settingsValue
        assignmentResolutionState = $AssignmentResolutionState
        groupResolutionState      = $groupResolutionState
        memberResolutionState     = $memberResolutionState
    }
}

function ConvertTo-PulseInstallColumnKey {
    param([string] $Name)
    return (($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant())
}

function ConvertTo-PulseAppInstallErrorRow {
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $SourceColumns)

    $lookup = @{}
    foreach ($name in @($SourceColumns.Keys)) {
        $lookup[(ConvertTo-PulseInstallColumnKey -Name ([string] $name))] = $SourceColumns[$name]
    }
    function Get-InstallValue {
        param([string[]] $Aliases)
        foreach ($alias in $Aliases) {
            $key = ConvertTo-PulseInstallColumnKey -Name $alias
            if ($lookup.ContainsKey($key)) { return $lookup[$key] }
        }
        return $null
    }

    return [pscustomobject][ordered]@{
        schemaVersion    = '1'
        appName          = Get-InstallValue @('appName', 'appDisplayName', 'applicationName')
        appVersion       = Get-InstallValue @('appVersion', 'applicationVersion', 'version')
        platform         = Get-InstallValue @('platform', 'devicePlatform')
        installStatus    = Get-InstallValue @('installStatus', 'status')
        errorCode        = Get-InstallValue @('errorCode', 'hexErrorCode')
        errorMessage     = Get-InstallValue @('errorMessage', 'errorDescription')
        deviceCount      = Get-InstallValue @('deviceCount', 'failedDeviceCount')
        userCount        = Get-InstallValue @('userCount', 'failedUserCount')
        lastUpdated      = Get-InstallValue @('lastUpdated', 'lastUpdatedDateTime', 'lastModifiedDateTime')
        appId            = Get-InstallValue @('appId', 'applicationId', 'mobileAppId')
        publisher        = Get-InstallValue @('publisher')
        installationType = Get-InstallValue @('installationType', 'installType')
        sourceColumns    = $SourceColumns
    }
}

function ConvertTo-PulseAppInstallErrorRows {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $PayloadRows
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $sourceIndex = 0
    foreach ($payload in @($PayloadRows)) {
        $sourceIndex++
        if ($null -eq $payload) {
            $gaps.Add([pscustomobject]@{ policyId = "report-$sourceIndex"; reason = 'category:invalid-provider-data;operation:AppInstallSummaryReport.Get' }) | Out-Null
            continue
        }

        $schemaProperty = Get-PulseReportProperty -InputObject $payload -Name @('schema', 'Schema')
        $valuesProperty = Get-PulseReportProperty -InputObject $payload -Name @('values', 'Values')
        $schema = $schemaProperty.Value
        $values = $valuesProperty.Value
        if ($schemaProperty.Success -or $valuesProperty.Success) {
            $columnNames = [System.Collections.Generic.List[string]]::new()
            foreach ($column in @($schema)) {
                $columnName = if ($column -is [string]) { [string] $column } else { [string] (Get-PulseReportValue -InputObject $column -Name @('column', 'name', 'property')) }
                if ([string]::IsNullOrWhiteSpace($columnName)) {
                    $columnNames.Clear()
                    break
                }
                $columnNames.Add($columnName)
            }

            if ($columnNames.Count -eq 0 -or -not $valuesProperty.Success -or $null -eq $values) {
                $gaps.Add([pscustomobject]@{ policyId = "report-$sourceIndex"; reason = 'category:invalid-provider-data;operation:AppInstallSummaryReport.Get' }) | Out-Null
                continue
            }

            $valueRows = @($values)
            if ($columnNames.Count -gt 1 -and $valueRows.Count -eq $columnNames.Count -and
                @($valueRows | Where-Object { $_ -is [System.Collections.IEnumerable] -and $_ -isnot [string] }).Count -eq 0) {
                $valueRows = , [object[]] $valueRows
            }

            $valueIndex = 0
            foreach ($valueRow in $valueRows) {
                $valueIndex++
                $cells = @($valueRow)
                if ($cells.Count -ne $columnNames.Count) {
                    $gaps.Add([pscustomobject]@{ policyId = "report-$sourceIndex-row-$valueIndex"; reason = 'category:invalid-provider-data;operation:AppInstallSummaryReport.Get' }) | Out-Null
                    continue
                }

                $record = [ordered]@{}
                for ($i = 0; $i -lt $columnNames.Count; $i++) { $record[$columnNames[$i]] = $cells[$i] }
                $rows.Add((ConvertTo-PulseAppInstallErrorRow -SourceColumns $record)) | Out-Null
            }
            continue
        }

        $sourceMap = ConvertTo-PulseReportSourceMap -InputObject $payload
        $recognizedKeys = @($sourceMap.Keys | Where-Object {
                (ConvertTo-PulseInstallColumnKey -Name ([string] $_)) -in @(
                    'appname', 'appdisplayname', 'applicationname', 'appid', 'applicationid',
                    'mobileappid', 'errorcode', 'hexerrorcode', 'devicecount', 'faileddevicecount',
                    'usercount', 'failedusercount', 'installstatus', 'status'
                )
            })
        if ($recognizedKeys.Count -eq 0) {
            $gaps.Add([pscustomobject]@{ policyId = "report-$sourceIndex"; reason = 'category:invalid-provider-data;operation:AppInstallSummaryReport.Get' }) | Out-Null
            continue
        }
        $rows.Add((ConvertTo-PulseAppInstallErrorRow -SourceColumns $sourceMap)) | Out-Null
    }

    return [pscustomobject]@{ Rows = $rows.ToArray(); Gaps = $gaps.ToArray() }
}

function Publish-PulseReportDataRows {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Store,
        [Parameter(Mandatory)] [ValidateSet('application-assignments', 'app-install-errors')] [string] $Name,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rows,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Gaps,
        [Parameter(Mandatory)] [ValidateRange(0, [int]::MaxValue)] [int] $SourceCount,
        [Parameter()] [string] $ProfileId = '',
        [Parameter()] [string] $Pseudonym = 'tp-unknown',
        [Parameter()] [AllowNull()] [string] $TenantId
    )

    $sortProperties = if ($Name -eq 'application-assignments') {
        @('appId', 'assignmentId', 'targetType', 'groupId')
    } else {
        @('appName', 'appId', 'errorCode', 'installStatus', 'platform')
    }
    $sortedGaps = @($Gaps)
    if ($sortedGaps.Count -gt 1) {
        $gapComparison = [System.Comparison[object]] {
            param($a, $b)
            $c = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
            if ($c -ne 0) { return $c }
            return [string]::CompareOrdinal([string] $a.reason, [string] $b.reason)
        }
        [Array]::Sort($sortedGaps, $gapComparison)
    }
    $unresolved = if ($Name -eq 'application-assignments') {
        @($Rows | Where-Object { $_.groupResolutionState -eq 'Failed' -or $_.assignmentResolutionState -in @('Failed', 'Malformed', 'Partial') }).Count
    } else { 0 }

    $notExpandedReason = if ($sortedGaps.Count -gt 0) { [string] $sortedGaps[0].reason } else { $null }
    return Publish-PulseExpansionRows -Store $Store -Name $Name -Rows $Rows -Gaps $sortedGaps `
        -PolicyCount $SourceCount -SortProperties $sortProperties -UnresolvedNameCount $unresolved `
        -RedactedSecretCount 0 -Reason $notExpandedReason -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
}

function Invoke-PulseReportGraphOperation {
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] $Spec,
        [Parameter(Mandatory)] [string] $Dataset,
        [Parameter()] [hashtable] $Parameters
    )

    try {
        $invokeParams = @{
            Context        = $Context
            Type           = $Spec.Type
            Operation      = $Spec.Operation
            PassThruResult = $true
            ErrorAction    = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Parameters')) { $invokeParams.Parameters = $Parameters }
        $raw = @(Get-GraphObject @invokeParams)
        $envelope = Convert-PulseGraphObjectResult -Result $raw
        return ConvertTo-PulseDatasetOutcomeFromGraphEnvelope -Envelope $envelope -Dataset $Dataset `
            -ApiVersion $Spec.ApiVersion -Provider 'GraphKit' -Operations @($Spec.Operation)
    } catch {
        $failure = Resolve-PulseGraphFailure -ErrorRecord $_
        return New-PulseCollectionOutcome -Dataset $Dataset -Status Failed -Rows @() -Gaps @() `
            -FailureClass $failure.FailureClass -ReasonCode $failure.ReasonCode `
            -Detail @{ statusCode = $failure.StatusCode } -Provider 'GraphKit' `
            -ApiVersion $Spec.ApiVersion -Operations @($Spec.Operation)
    }
}

function Get-PulseReportAuthorization {
    param(
        [AllowNull()] $AuthorizationDecision,
        [Parameter(Mandatory)] [object[]] $Operations
    )

    $firstUnknown = $null
    foreach ($operation in $Operations) {
        $decision = Get-PulseOperationAuthorization -AuthorizationDecision $AuthorizationDecision `
            -Type $operation.Type -Operation $operation.Operation
        if ($decision.Decision -eq 'Denied') { return $decision }
        if ($decision.Decision -ne 'Granted' -and $null -eq $firstUnknown) { $firstUnknown = $decision }
    }
    if ($null -ne $firstUnknown) { return $firstUnknown }
    return [pscustomobject]@{ Decision = 'Granted'; ReasonCode = 'granted' }
}

function New-PulseReportGap {
    param([string] $Scope, [string] $ReasonCode, [string] $Operation)
    return [pscustomobject]@{
        policyId = $Scope
        reason   = "category:$ReasonCode;operation:$Operation"
    }
}

function Invoke-PulseApplicationReportCollection {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Store,
        [Parameter(Mandatory)] [pscustomobject] $Context,
        [Parameter(Mandatory)] $AuthorizationDecision,
        [Parameter(Mandatory)] [pscustomobject] $NetworkAbortState,
        [Parameter(Mandatory)] [string] $ProfileId,
        [Parameter(Mandatory)] [string] $Pseudonym
    )

    $tenantId = if ($Context.PSObject.Properties['TenantId']) { [string] $Context.TenantId } else { $null }
    $operationByKey = @{}
    foreach ($operation in @(Get-PulseApplicationReportOperations)) {
        $operationByKey[('{0}/{1}' -f $operation.Type, $operation.Operation)] = $operation
    }
    $assignmentOperations = @(
        $operationByKey['MobileApp/ListBeta']
        $operationByKey['MobileAppAssignment/List']
        $operationByKey['Group/Get']
        $operationByKey['GroupMember/List']
    )
    $installOperations = @($operationByKey['AppInstallSummaryReport/Get'])

    $results = [ordered]@{ ApplicationAssignments = $null; AppInstallErrors = $null }
    foreach ($operation in @(Get-PulseApplicationReportOperations)) {
        Assert-PulseReadOnlyDescriptor -Type $operation.Type -Operation $operation.Operation -ApiVersion $operation.ApiVersion
    }

    $assignmentAuthorization = Get-PulseReportAuthorization -AuthorizationDecision $AuthorizationDecision -Operations $assignmentOperations
    if ($NetworkAbortState.AuthenticationAborted -or $assignmentAuthorization.Decision -ne 'Granted') {
        $reasonCode = if ($NetworkAbortState.AuthenticationAborted) { 'authentication-failed' } else { [string] $assignmentAuthorization.ReasonCode }
        $reason = Protect-PulseReason -Message "permission-preflight: $reasonCode" -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        Set-PulseExpansionEntry -Store $Store -Name 'application-assignments' -Status NotExpanded -Reason $reason
        $results.ApplicationAssignments = [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
    } else {
        $applicationSpec = $operationByKey['MobileApp/ListBeta']
        $applicationsOutcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $applicationSpec -Dataset 'application-assignments'
        if ($applicationsOutcome.FailureClass -eq 'AuthenticationFailed') {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = Protect-PulseReason -Message 'authentication-failed: report collection aborted' -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        }

        if ($applicationsOutcome.Status -eq 'Failed') {
            $reason = Protect-PulseReason -Message "application-list: $($applicationsOutcome.ReasonCode)" -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
            Set-PulseExpansionEntry -Store $Store -Name 'application-assignments' -Status NotExpanded -Reason $reason
            $results.ApplicationAssignments = [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
        } else {
            $apps = @($applicationsOutcome.Rows)
            $rows = [System.Collections.Generic.List[object]]::new()
            $gaps = [System.Collections.Generic.List[object]]::new()
            if ($applicationsOutcome.Status -eq 'Partial') {
                $gaps.Add((New-PulseReportGap -Scope 'application-list' -ReasonCode $applicationsOutcome.ReasonCode -Operation 'MobileApp.ListBeta')) | Out-Null
            }
            $groupCache = @{}

            foreach ($app in $apps) {
                $appId = [string] (Get-PulseReportValue -InputObject $app -Name @('id'))
                if ([string]::IsNullOrWhiteSpace($appId)) {
                    $rows.Add((New-PulseApplicationAssignmentRow -Application $app -Assignment $null -AssignmentCount 0 -AssignmentResolutionState 'Malformed')) | Out-Null
                    $gaps.Add((New-PulseReportGap -Scope 'application-without-id' -ReasonCode 'invalid-provider-data' -Operation 'MobileApp.ListBeta')) | Out-Null
                    continue
                }
                if ($NetworkAbortState.AuthenticationAborted) {
                    $rows.Add((New-PulseApplicationAssignmentRow -Application $app -Assignment $null -AssignmentCount 0 -AssignmentResolutionState 'Failed')) | Out-Null
                    $gaps.Add((New-PulseReportGap -Scope $appId -ReasonCode 'authentication-failed' -Operation 'MobileAppAssignment.List')) | Out-Null
                    continue
                }

                $assignmentOutcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $operationByKey['MobileAppAssignment/List'] `
                    -Dataset 'application-assignments' -Parameters @{ id = $appId }
                if ($assignmentOutcome.FailureClass -eq 'AuthenticationFailed') {
                    $NetworkAbortState.AuthenticationAborted = $true
                    $NetworkAbortState.Reason = Protect-PulseReason -Message 'authentication-failed: report collection aborted' -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
                }
                $assignments = @($assignmentOutcome.Rows)
                if ($assignmentOutcome.Status -eq 'Failed') {
                    $rows.Add((New-PulseApplicationAssignmentRow -Application $app -Assignment $null -AssignmentCount 0 -AssignmentResolutionState 'Failed')) | Out-Null
                    $gaps.Add((New-PulseReportGap -Scope $appId -ReasonCode $assignmentOutcome.ReasonCode -Operation 'MobileAppAssignment.List')) | Out-Null
                    continue
                }
                if ($assignments.Count -eq 0) {
                    $rows.Add((New-PulseApplicationAssignmentRow -Application $app -Assignment $null -AssignmentCount 0 -AssignmentResolutionState 'NoAssignments')) | Out-Null
                    if ($assignmentOutcome.Status -eq 'Partial') {
                        $gaps.Add((New-PulseReportGap -Scope $appId -ReasonCode $assignmentOutcome.ReasonCode -Operation 'MobileAppAssignment.List')) | Out-Null
                    }
                    continue
                }
                if ($assignmentOutcome.Status -eq 'Partial') {
                    $gaps.Add((New-PulseReportGap -Scope $appId -ReasonCode $assignmentOutcome.ReasonCode -Operation 'MobileAppAssignment.List')) | Out-Null
                }

                foreach ($assignment in $assignments) {
                    $target = Get-PulseReportValue -InputObject $assignment -Name @('target')
                    $targetType = ConvertTo-PulseTargetType -Value (Get-PulseReportValue -InputObject $target -Name @('@odata.type'))
                    $groupResolution = $null
                    $assignmentState = if ($assignmentOutcome.Status -eq 'Partial') { 'Partial' } else { 'Resolved' }
                    if ([string]::IsNullOrWhiteSpace($targetType)) {
                        $assignmentState = 'Malformed'
                        $gaps.Add((New-PulseReportGap -Scope $appId -ReasonCode 'invalid-provider-data' -Operation 'MobileAppAssignment.List')) | Out-Null
                    } elseif ($targetType -notin @('groupAssignmentTarget', 'exclusionGroupAssignmentTarget', 'allDevicesAssignmentTarget', 'allLicensedUsersAssignmentTarget', 'deviceAndAppManagementAssignmentTarget')) {
                        $assignmentState = 'Partial'
                        $gaps.Add((New-PulseReportGap -Scope $appId -ReasonCode 'unsupported-target-type' -Operation 'MobileAppAssignment.List')) | Out-Null
                    }

                    if ($targetType -in @('groupAssignmentTarget', 'exclusionGroupAssignmentTarget')) {
                        $groupId = [string] (Get-PulseReportValue -InputObject $target -Name @('groupId'))
                        if ([string]::IsNullOrWhiteSpace($groupId)) {
                            $assignmentState = 'Malformed'
                            $groupResolution = [pscustomobject]@{ Name = $null; Description = $null; MemberCount = $null; GroupState = 'Failed'; MemberState = 'NotEvaluated' }
                            $gaps.Add((New-PulseReportGap -Scope $appId -ReasonCode 'group-id-missing' -Operation 'MobileAppAssignment.List')) | Out-Null
                        } elseif ($groupCache.ContainsKey($groupId)) {
                            $groupResolution = $groupCache[$groupId]
                        } else {
                            $groupState = 'Failed'
                            $memberState = 'NotEvaluated'
                            $groupName = $null
                            $groupDescription = $null
                            $memberCount = $null

                            $groupOutcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $operationByKey['Group/Get'] `
                                -Dataset 'application-assignments' -Parameters @{ id = $groupId }
                            if ($groupOutcome.FailureClass -eq 'AuthenticationFailed') {
                                $NetworkAbortState.AuthenticationAborted = $true
                                $NetworkAbortState.Reason = Protect-PulseReason -Message 'authentication-failed: report collection aborted' -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
                            }
                            if ($groupOutcome.Status -in @('Collected', 'Partial') -and @($groupOutcome.Rows).Count -eq 1) {
                                $group = @($groupOutcome.Rows)[0]
                                $groupName = Get-PulseReportValue -InputObject $group -Name @('displayName')
                                $groupDescription = Get-PulseReportValue -InputObject $group -Name @('description')
                                $groupState = if ($groupOutcome.Status -eq 'Partial') { 'Partial' } else { 'Resolved' }
                            } else {
                                $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode $(if ($groupOutcome.Status -eq 'Failed') { $groupOutcome.ReasonCode } else { 'invalid-provider-data' }) -Operation 'Group.Get')) | Out-Null
                            }

                            if (-not $NetworkAbortState.AuthenticationAborted) {
                                $memberOutcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $operationByKey['GroupMember/List'] `
                                    -Dataset 'application-assignments' -Parameters @{ id = $groupId }
                                if ($memberOutcome.FailureClass -eq 'AuthenticationFailed') {
                                    $NetworkAbortState.AuthenticationAborted = $true
                                    $NetworkAbortState.Reason = Protect-PulseReason -Message 'authentication-failed: report collection aborted' -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
                                }
                                if ($memberOutcome.Status -in @('Collected', 'Partial')) {
                                    $memberCount = @($memberOutcome.Rows).Count
                                    $memberState = if ($memberOutcome.Status -eq 'Partial') { 'Partial' } else { 'Complete' }
                                    if ($memberOutcome.Status -eq 'Partial') {
                                        $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode $memberOutcome.ReasonCode -Operation 'GroupMember.List')) | Out-Null
                                    }
                                } else {
                                    $memberState = 'Failed'
                                    $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode $memberOutcome.ReasonCode -Operation 'GroupMember.List')) | Out-Null
                                }
                            }
                            $groupResolution = [pscustomobject]@{
                                Name = $groupName; Description = $groupDescription; MemberCount = $memberCount
                                GroupState = $groupState; MemberState = $memberState
                            }
                            $groupCache[$groupId] = $groupResolution
                        }
                    }
                    $rows.Add((New-PulseApplicationAssignmentRow -Application $app -Assignment $assignment `
                                -AssignmentCount $assignments.Count -AssignmentResolutionState $assignmentState `
                                -GroupResolution $groupResolution)) | Out-Null
                }
            }

            $results.ApplicationAssignments = Publish-PulseReportDataRows -Store $Store -Name 'application-assignments' `
                -Rows $rows.ToArray() -Gaps $gaps.ToArray() -SourceCount $apps.Count `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        }
    }

    $installAuthorization = Get-PulseReportAuthorization -AuthorizationDecision $AuthorizationDecision -Operations $installOperations
    if ($NetworkAbortState.AuthenticationAborted -or $installAuthorization.Decision -ne 'Granted') {
        $reasonCode = if ($NetworkAbortState.AuthenticationAborted) { 'authentication-failed' } else { [string] $installAuthorization.ReasonCode }
        $reason = Protect-PulseReason -Message "permission-preflight: $reasonCode" -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        Set-PulseExpansionEntry -Store $Store -Name 'app-install-errors' -Status NotExpanded -Reason $reason
        $results.AppInstallErrors = [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
    } else {
        $installOutcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $operationByKey['AppInstallSummaryReport/Get'] `
            -Dataset 'app-install-errors' -Parameters @{ Body = @{ filter = '' } }
        if ($installOutcome.FailureClass -eq 'AuthenticationFailed') {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = Protect-PulseReason -Message 'authentication-failed: report collection aborted' -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        }
        if ($installOutcome.Status -eq 'Failed') {
            $reason = Protect-PulseReason -Message "app-install-report: $($installOutcome.ReasonCode)" -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
            Set-PulseExpansionEntry -Store $Store -Name 'app-install-errors' -Status NotExpanded -Reason $reason
            $results.AppInstallErrors = [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
        } else {
            $converted = ConvertTo-PulseAppInstallErrorRows -PayloadRows @($installOutcome.Rows)
            $installGaps = [System.Collections.Generic.List[object]]::new()
            foreach ($gap in @($converted.Gaps)) { $installGaps.Add($gap) | Out-Null }
            if ($installOutcome.Status -eq 'Partial') {
                $installGaps.Add((New-PulseReportGap -Scope 'install-report' -ReasonCode $installOutcome.ReasonCode -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            }
            $results.AppInstallErrors = Publish-PulseReportDataRows -Store $Store -Name 'app-install-errors' `
                -Rows @($converted.Rows) -Gaps $installGaps.ToArray() -SourceCount @($installOutcome.Rows).Count `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        }
    }

    return [pscustomobject] $results
}
