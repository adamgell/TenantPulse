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
    [pscustomobject]@{ Type = 'AppInstallSummaryReport'; Operation = 'Get'; ApiVersion = 'beta'; PagingStrategy = 'None' }
    [pscustomobject]@{ Type = 'Group'; Operation = 'Get'; ApiVersion = 'v1.0'; PagingStrategy = 'None' }
    [pscustomobject]@{ Type = 'GroupMember'; Operation = 'List'; ApiVersion = 'v1.0'; PagingStrategy = 'NextLink' }
    [pscustomobject]@{ Type = 'MobileApp'; Operation = 'ListBeta'; ApiVersion = 'beta'; PagingStrategy = 'NextLink' }
    [pscustomobject]@{ Type = 'MobileAppAssignment'; Operation = 'List'; ApiVersion = 'v1.0'; PagingStrategy = 'NextLink' }
)

function Get-PulseApplicationReportOperations {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return @($script:PulseApplicationReportOperations | ForEach-Object {
            [pscustomobject]@{
                Type = $_.Type; Operation = $_.Operation; ApiVersion = $_.ApiVersion
                PagingStrategy = $_.PagingStrategy
            }
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
        foreach ($name in $names) {
            if ([string]::Equals($name, 'SessionId', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            $result[$name] = Get-PulseReportValue -InputObject $InputObject -Name @($name)
        }
        return $result
    }

    $names = [string[]] @($InputObject.PSObject.Properties.Name)
    [Array]::Sort($names, [System.StringComparer]::Ordinal)
    foreach ($name in $names) {
        if ([string]::Equals($name, 'SessionId', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $result[$name] = $InputObject.PSObject.Properties[$name].Value
    }
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
        appName          = Get-InstallValue @('appName', 'appDisplayName', 'applicationName', 'displayName')
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

function Test-PulseAppInstallSourceMap {
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $SourceColumns)

    $identityKeys = @(
        'appname', 'appdisplayname', 'applicationname', 'displayname',
        'appid', 'applicationid', 'mobileappid'
    )
    $signalKeys = @(
        'errorcode', 'hexerrorcode', 'installstatus', 'status',
        'devicecount', 'faileddevicecount', 'usercount', 'failedusercount',
        'pendinginstalldevicecount', 'installeddevicecount', 'notinstalleddevicecount',
        'pendinginstallusercount', 'installedusercount', 'notinstalledusercount'
    )

    $hasIdentity = $false
    $hasSignal = $false
    $normalizedKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($name in @($SourceColumns.Keys)) {
        $normalizedKey = ConvertTo-PulseInstallColumnKey -Name ([string] $name)
        # Direct named records do not pass through the matrix-schema duplicate check.
        # Two distinct source keys such as ApplicationId/application-id normalize to the
        # same lookup key and would otherwise overwrite one another based on enumeration
        # order. Refuse the whole record rather than choosing an arbitrary identity/value.
        if ([string]::IsNullOrWhiteSpace($normalizedKey) -or -not $normalizedKeys.Add($normalizedKey)) {
            return $false
        }
    }

    foreach ($name in @($SourceColumns.Keys)) {
        $normalizedKey = ConvertTo-PulseInstallColumnKey -Name ([string] $name)
        $value = $SourceColumns[$name]
        $hasValue = $null -ne $value -and
            ($value -isnot [string] -or -not [string]::IsNullOrWhiteSpace([string] $value))
        if (-not $hasValue) { continue }

        if ($normalizedKey -in $identityKeys) { $hasIdentity = $true }
        if ($normalizedKey -in $signalKeys) { $hasSignal = $true }
        if ($hasIdentity -and $hasSignal) { return $true }
    }
    return $hasIdentity -and $hasSignal
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
            $normalizedColumnNames = @{}
            foreach ($column in @($schema)) {
                $columnName = if ($column -is [string]) { [string] $column } else { [string] (Get-PulseReportValue -InputObject $column -Name @('column', 'name', 'property')) }
                $normalizedColumnName = ConvertTo-PulseInstallColumnKey -Name $columnName
                if ([string]::IsNullOrWhiteSpace($columnName) -or [string]::IsNullOrWhiteSpace($normalizedColumnName) -or
                    $normalizedColumnNames.ContainsKey($normalizedColumnName)) {
                    $columnNames.Clear()
                    break
                }
                $columnNames.Add($columnName)
                $normalizedColumnNames[$normalizedColumnName] = $true
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
                for ($i = 0; $i -lt $columnNames.Count; $i++) {
                    # SessionId is paging metadata even when a provider exposes it as a
                    # matrix column. Keep the cell aligned with the schema, but never copy
                    # the opaque session witness into normalized rows or persisted artifacts.
                    if ([string]::Equals($columnNames[$i], 'SessionId', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                    $record[$columnNames[$i]] = $cells[$i]
                }
                if (-not (Test-PulseAppInstallSourceMap -SourceColumns $record)) {
                    $gaps.Add([pscustomobject]@{ policyId = "report-$sourceIndex-row-$valueIndex"; reason = 'category:invalid-provider-data;operation:AppInstallSummaryReport.Get' }) | Out-Null
                    continue
                }
                $rows.Add((ConvertTo-PulseAppInstallErrorRow -SourceColumns $record)) | Out-Null
            }
            continue
        }

        $sourceMap = ConvertTo-PulseReportSourceMap -InputObject $payload
        if (-not (Test-PulseAppInstallSourceMap -SourceColumns $sourceMap)) {
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
    # Report rows can contain tenant identifiers in arbitrary forward-compatible fields
    # (notably settings and sourceColumns). Apply the same fail-closed recursive scrub used
    # by ordinary datasets and the other expansion producers before any bytes are staged.
    # Protect-PulseGraphRowTenantId deliberately returns its cloned [object[]] as one
    # pipeline object so empty arrays survive PowerShell's output enumeration. Assign it
    # directly; wrapping the call in @() would create a nested one-row array.
    $safeRows = Protect-PulseGraphRowTenantId -Data $Rows -TenantId $TenantId -Pseudonym $Pseudonym
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
        @($safeRows | Where-Object { $_.groupResolutionState -in @('Failed', 'Partial', 'NotEvaluated') -or $_.assignmentResolutionState -in @('Failed', 'Malformed', 'Partial') }).Count
    } else { 0 }

    $notExpandedReason = if ($sortedGaps.Count -gt 0) { [string] $sortedGaps[0].reason } else { $null }
    return Publish-PulseExpansionRows -Store $Store -Name $Name -Rows $safeRows -Gaps $sortedGaps `
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
        $envelope = Convert-PulseGraphObjectResult -Result $raw -PagingStrategy $Spec.PagingStrategy
        return ConvertTo-PulseDatasetOutcomeFromGraphEnvelope -Envelope $envelope -Dataset $Dataset `
            -ApiVersion $Spec.ApiVersion -Provider 'GraphKit' -Operations @($Spec.Operation) `
            -PagingStrategy $Spec.PagingStrategy
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

function Set-PulseReportAuthenticationAbort {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Store,
        [Parameter(Mandatory)] [pscustomobject] $NetworkAbortState,
        [Parameter(Mandatory)] [string] $ProfileId,
        [Parameter(Mandatory)] [string] $Pseudonym,
        [AllowNull()] [string] $TenantId
    )

    if ($NetworkAbortState.AuthenticationAborted) { return }

    $reason = Protect-PulseReason -Message 'authentication-failed: report collection aborted' `
        -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
    $NetworkAbortState.AuthenticationAborted = $true
    $NetworkAbortState.Reason = $reason
    Set-PulseManifestEntry -Store $Store -CollectionFailure $reason
}

function Get-PulseReportMatrixRowCount {
    param(
        [AllowNull()] $Schema,
        [AllowNull()] $Values
    )

    if ($null -eq $Values) { return 0 }
    $columnCount = @($Schema).Count
    $valueRows = @($Values)
    if ($columnCount -gt 1 -and $valueRows.Count -eq $columnCount -and
        @($valueRows | Where-Object { $_ -is [System.Collections.IEnumerable] -and $_ -isnot [string] }).Count -eq 0) {
        return 1
    }
    return $valueRows.Count
}

function Get-PulseReportMatrixPageIdentity {
    param(
        [AllowNull()] $Schema,
        [AllowNull()] $Values
    )

    $columnNames = @($Schema | ForEach-Object {
            if ($_ -is [string]) { [string] $_ }
            else { [string] (Get-PulseReportValue -InputObject $_ -Name @('column', 'name', 'property')) }
        })
    $applicationIdIndexes = @(
        for ($i = 0; $i -lt $columnNames.Count; $i++) {
            if ((ConvertTo-PulseInstallColumnKey -Name $columnNames[$i]) -in @('appid', 'applicationid', 'mobileappid')) {
                $i
            }
        }
    )
    if ($applicationIdIndexes.Count -ne 1) {
        return [pscustomobject]@{ Verifiable = $false; Duplicate = $false; Keys = @() }
    }

    $valueRows = @($Values)
    if ($columnNames.Count -gt 1 -and $valueRows.Count -eq $columnNames.Count -and
        @($valueRows | Where-Object { $_ -is [System.Collections.IEnumerable] -and $_ -isnot [string] }).Count -eq 0) {
        $valueRows = , [object[]] $valueRows
    }

    $keys = [System.Collections.Generic.List[string]]::new()
    $pageKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($valueRow in $valueRows) {
        $cells = @($valueRow)
        if ($cells.Count -ne $columnNames.Count) {
            return [pscustomobject]@{ Verifiable = $false; Duplicate = $false; Keys = @() }
        }
        $key = [string] $cells[[int] $applicationIdIndexes[0]]
        if ([string]::IsNullOrWhiteSpace($key)) {
            return [pscustomobject]@{ Verifiable = $false; Duplicate = $false; Keys = @() }
        }
        $key = $key.Trim()
        if (-not $pageKeys.Add($key)) {
            return [pscustomobject]@{ Verifiable = $false; Duplicate = $true; Keys = @() }
        }
        $keys.Add($key) | Out-Null
    }
    return [pscustomobject]@{ Verifiable = $true; Duplicate = $false; Keys = $keys.ToArray() }
}

function Invoke-PulseAppInstallReportPages {
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] $Spec,
        [ValidateRange(1, 1000)] [int] $PageSize = 200,
        [ValidateRange(1, 10000)] [int] $MaxPages = 200
    )

    $payloadRows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $pageFingerprints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $seenApplicationIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $expectedTotal = $null
    $expectedSessionId = $null
    $collectedRowCount = 0
    $skip = 0
    $pageCount = 0
    $failureClass = $null
    $reasonCode = $null

    while ($pageCount -lt $MaxPages) {
        $pageCount++
        $requestBody = [ordered]@{
            filter = ''
            # The Graph report action accepts orderBy. ApplicationId is the
            # summary row's stable identity, so pin it to reduce page drift; the
            # cross-page identity check below still fails closed if the live
            # dataset changes or the service ignores the requested order.
            orderBy = @('ApplicationId asc')
            select = @()
            skip = $skip
            top = $PageSize
        }
        if ($pageCount -gt 1 -and $null -ne $expectedSessionId) {
            # SessionId is an opaque service-issued snapshot witness. Never
            # manufacture, normalize, persist, or log it; return it only to the
            # report endpoint on continuation requests.
            $requestBody['sessionId'] = $expectedSessionId
        }
        $outcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $Spec -Dataset 'app-install-errors' `
            -Parameters @{ Body = $requestBody }

        if ($outcome.FailureClass) { $failureClass = $outcome.FailureClass }
        if ($outcome.Status -eq 'Failed') {
            $reasonCode = [string] $outcome.ReasonCode
            if ($payloadRows.Count -eq 0) {
                return [pscustomobject]@{
                    Status = 'Failed'; PayloadRows = @(); Gaps = @(); FailureClass = $failureClass
                    ReasonCode = $reasonCode; ExpectedTotal = $expectedTotal; CollectedRowCount = 0
                }
            }
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode $reasonCode -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }

        if ($outcome.Status -eq 'Partial') {
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode $outcome.ReasonCode -Operation 'AppInstallSummaryReport.Get')) | Out-Null
        }

        $responseRows = @($outcome.Rows)
        if ($responseRows.Count -eq 0) {
            if ($payloadRows.Count -eq 0) {
                return [pscustomobject]@{
                    Status = 'Failed'; PayloadRows = @(); Gaps = @(); FailureClass = 'ProviderFailed'
                    ReasonCode = 'invalid-provider-data'; ExpectedTotal = $null; CollectedRowCount = 0
                }
            }
            if ($null -ne $expectedTotal -and $collectedRowCount -lt [int64] $expectedTotal) {
                $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'total-row-count-mismatch' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            }
            break
        }

        # Matrix report responses carry Schema/Values and use request-body paging. A complete
        # GraphKit envelope can also contain direct named records; that legacy-compatible shape
        # is already the complete row set and must not be rejected merely for containing more
        # than one object or for lacking a matrix Values wrapper.
        $matrixShaped = $false
        foreach ($responseRow in $responseRows) {
            $rowSchema = Get-PulseReportProperty -InputObject $responseRow -Name @('schema', 'Schema')
            $rowValues = Get-PulseReportProperty -InputObject $responseRow -Name @('values', 'Values')
            if ($rowSchema.Success -or $rowValues.Success) {
                $matrixShaped = $true
                break
            }
        }
        if (-not $matrixShaped) {
            if ($pageCount -gt 1) {
                # Direct named records are accepted only as a complete first response.
                # Switching away from the matrix shape during continuation bypasses the
                # session and total witnesses, so discard that response and retain only
                # the already verified matrix pages.
                $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'invalid-provider-data' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
                break
            }
            foreach ($responseRow in $responseRows) { $payloadRows.Add($responseRow) | Out-Null }
            $collectedRowCount += $responseRows.Count
            break
        }
        if ($responseRows.Count -ne 1) {
            # One report action response must contain exactly one matrix body. With multiple
            # objects, no individual SessionId, total, or matrix cardinality can witness the
            # response as a coherent page, so none of its rows are safe to retain.
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'invalid-provider-data' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }

        $payload = $responseRows[0]
        $sessionProperty = Get-PulseReportProperty -InputObject $payload -Name @('sessionId', 'SessionId')
        $sessionId = if ($sessionProperty.Success -and $sessionProperty.Value -is [string] -and
            -not [string]::IsNullOrWhiteSpace([string] $sessionProperty.Value)) {
            [string] $sessionProperty.Value
        } else {
            $null
        }
        if ($pageCount -gt 1) {
            if ($null -eq $sessionId) {
                # A continuation page without the service's snapshot witness may
                # belong to a shifted dataset. Discard it rather than claiming a
                # complete report from unprovably related pages.
                $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'paging-session-missing' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
                break
            }
            if (-not [string]::Equals($expectedSessionId, $sessionId, [System.StringComparison]::Ordinal)) {
                $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'paging-session-mismatch' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
                break
            }
        } elseif ($null -ne $sessionId) {
            $expectedSessionId = $sessionId
        }

        $pageFingerprint = ConvertTo-PulseCanonicalJsonLine -InputObject $payload
        if (-not $pageFingerprints.Add($pageFingerprint)) {
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'repeated-page' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }
        $schemaProperty = Get-PulseReportProperty -InputObject $payload -Name @('schema', 'Schema')
        $valuesProperty = Get-PulseReportProperty -InputObject $payload -Name @('values', 'Values')
        $totalProperty = Get-PulseReportProperty -InputObject $payload -Name @('totalRowCount', 'TotalRowCount')
        if (-not $valuesProperty.Success -or $null -eq $valuesProperty.Value) {
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'invalid-provider-data' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }

        $batchCount = Get-PulseReportMatrixRowCount -Schema $schemaProperty.Value -Values $valuesProperty.Value
        $pageIdentity = Get-PulseReportMatrixPageIdentity -Schema $schemaProperty.Value -Values $valuesProperty.Value
        if ($pageIdentity.Duplicate) {
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'overlapping-page' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }
        $overlap = $false
        if ($pageIdentity.Verifiable) {
            foreach ($applicationId in @($pageIdentity.Keys)) {
                if ($seenApplicationIds.Contains([string] $applicationId)) {
                    $overlap = $true
                    break
                }
            }
        }
        if ($overlap) {
            # Do not publish the overlapping page: keeping only prior confirmed pages
            # avoids duplicating one application while another application is omitted.
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'overlapping-page' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }

        $parsedTotal = 0L
        $totalIsValid = $totalProperty.Success -and $null -ne $totalProperty.Value -and
            [int64]::TryParse([string] $totalProperty.Value, [Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture, [ref] $parsedTotal) -and $parsedTotal -ge 0
        if (-not $totalIsValid) {
            # The page itself is usable even though its total cannot drive another safe
            # request. Preserve its rows, then stop Partial with the bounded total gap.
            $payloadRows.Add($payload) | Out-Null
            $collectedRowCount += $batchCount
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'total-row-count-missing' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }
        $totalChanged = $false
        if ($null -eq $expectedTotal) {
            $expectedTotal = $parsedTotal
        } elseif ([int64] $expectedTotal -ne $parsedTotal) {
            $totalChanged = $true
        }

        $prospectiveRowCount = $collectedRowCount + $batchCount
        $payloadRows.Add($payload) | Out-Null
        $collectedRowCount = $prospectiveRowCount
        if ($pageIdentity.Verifiable) {
            foreach ($applicationId in @($pageIdentity.Keys)) {
                $seenApplicationIds.Add([string] $applicationId) | Out-Null
            }
        }

        if ($totalChanged -or $prospectiveRowCount -gt [int64] $expectedTotal -or
            ($batchCount -eq 0 -and $prospectiveRowCount -ne [int64] $expectedTotal)) {
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'total-row-count-mismatch' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }
        if ($collectedRowCount -eq [int64] $expectedTotal) { break }
        if (-not $pageIdentity.Verifiable) {
            # A single complete page needs no cross-page witness. Continuing skip/top
            # paging without a unique application identity could count reordered or
            # overlapping data as complete, so retain this page as Partial and stop.
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'stable-row-identity-missing' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }
        if ($null -eq $expectedSessionId) {
            # A complete single page does not need a session witness. Once the
            # declared total requires a continuation, however, proceeding without
            # one could silently combine different report snapshots.
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'paging-session-missing' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }
        if ($pageCount -ge $MaxPages) {
            $gaps.Add((New-PulseReportGap -Scope "install-report-skip-$skip" -ReasonCode 'page-cap' -Operation 'AppInstallSummaryReport.Get')) | Out-Null
            break
        }

        # Intune may return a short non-terminal page. Advance by what the service
        # actually returned; adding PageSize would skip rows between pages.
        $skip += $batchCount
    }

    $status = if ($gaps.Count -eq 0) {
        'Collected'
    } elseif ($payloadRows.Count -gt 0) {
        'Partial'
    } else {
        'Failed'
    }
    $resolvedFailureClass = if ($status -eq 'Failed' -and [string]::IsNullOrWhiteSpace([string] $failureClass)) {
        'InvalidProviderData'
    } else {
        $failureClass
    }

    return [pscustomobject]@{
        Status = $status
        PayloadRows = $payloadRows.ToArray()
        Gaps = $gaps.ToArray()
        FailureClass = $resolvedFailureClass
        ReasonCode = $(if ($gaps.Count -gt 0) {
                $reason = [string] $gaps[0].reason
                if ($reason -match '^category:([^;]+)') { $Matches[1] } else { 'partial' }
            } else { $null })
        ExpectedTotal = $expectedTotal
        CollectedRowCount = $collectedRowCount
    }
}

function Publish-PulseReportArtifactFailure {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Store,
        [Parameter(Mandatory)] [ValidateSet('application-assignments', 'app-install-errors')] [string] $Name,
        [Parameter(Mandatory)] [string] $ProfileId,
        [Parameter(Mandatory)] [string] $Pseudonym,
        [AllowNull()] [string] $TenantId
    )

    # Never persist the exception: a serializer/redaction/provider object can place tenant
    # content in its message. The fixed code is enough to distinguish this local artifact
    # failure from Graph collection and permission outcomes.
    $reason = Protect-PulseReason -Message 'artifact-publication-failed' -ProfileId $ProfileId `
        -Pseudonym $Pseudonym -TenantId $TenantId
    Set-PulseExpansionEntry -Store $Store -Name $Name -Status Failed -Reason $reason
    return [pscustomobject]@{ Status = 'Failed'; RowCount = 0; Gaps = @() }
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
    foreach ($operation in @($operationByKey.Values)) {
        $descriptor = Assert-PulseReadOnlyDescriptor -Type $operation.Type -Operation $operation.Operation `
            -ApiVersion $operation.ApiVersion -PassThru
        if ($null -ne $descriptor) {
            $resolvedPagingStrategy = [string] $descriptor.PagingStrategy
            if ($resolvedPagingStrategy -notin @('None', 'NextLink') -or
                $resolvedPagingStrategy -ne $operation.PagingStrategy) {
                throw "Invoke-PulseApplicationReportCollection: descriptor-paging-drift for '$($operation.Type)/$($operation.Operation)'."
            }
            $operation.PagingStrategy = $resolvedPagingStrategy
        }
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
            Set-PulseReportAuthenticationAbort -Store $Store -NetworkAbortState $NetworkAbortState `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
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
                    Set-PulseReportAuthenticationAbort -Store $Store -NetworkAbortState $NetworkAbortState `
                        -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
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

                    $assignmentId = [string] (Get-PulseReportValue -InputObject $assignment -Name @('id'))
                    if ([string]::IsNullOrWhiteSpace($assignmentId)) {
                        $assignmentState = 'Malformed'
                        $gaps.Add((New-PulseReportGap -Scope $appId -ReasonCode 'invalid-provider-data' -Operation 'MobileAppAssignment.List')) | Out-Null
                    }
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
                        } elseif ($NetworkAbortState.AuthenticationAborted) {
                            # The assignment list for this app is already known. A child
                            # authentication failure must suppress only the not-yet-started
                            # group lookup; relabeling the fetched assignment itself Failed
                            # would discard independently established assignment truth.
                            $groupResolution = [pscustomobject]@{
                                Name = $null; Description = $null; MemberCount = $null
                                GroupState = 'NotEvaluated'; MemberState = 'NotEvaluated'
                            }
                            $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode 'authentication-failed' -Operation 'Group.Get')) | Out-Null
                        } else {
                            $groupState = 'Failed'
                            $memberState = 'NotEvaluated'
                            $groupName = $null
                            $groupDescription = $null
                            $memberCount = $null

                            $groupOutcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $operationByKey['Group/Get'] `
                                -Dataset 'application-assignments' -Parameters @{ id = $groupId }
                            if ($groupOutcome.FailureClass -eq 'AuthenticationFailed') {
                                Set-PulseReportAuthenticationAbort -Store $Store -NetworkAbortState $NetworkAbortState `
                                    -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
                            }
                            if ($groupOutcome.Status -in @('Collected', 'Partial') -and @($groupOutcome.Rows).Count -eq 1) {
                                $group = @($groupOutcome.Rows)[0]
                                $returnedGroupId = [string] (Get-PulseReportValue -InputObject $group -Name @('id'))
                                if (-not [string]::Equals($returnedGroupId, $groupId, [System.StringComparison]::OrdinalIgnoreCase)) {
                                    $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode 'invalid-provider-data' -Operation 'Group.Get')) | Out-Null
                                } else {
                                    $groupName = Get-PulseReportValue -InputObject $group -Name @('displayName')
                                    $groupDescription = Get-PulseReportValue -InputObject $group -Name @('description')
                                    $groupState = if ($groupOutcome.Status -eq 'Partial') { 'Partial' } else { 'Resolved' }
                                }
                                if ([string]::Equals($returnedGroupId, $groupId, [System.StringComparison]::OrdinalIgnoreCase) -and
                                    [string]::IsNullOrWhiteSpace([string] $groupName)) {
                                    $groupState = 'Partial'
                                    $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode 'invalid-provider-data' -Operation 'Group.Get')) | Out-Null
                                } elseif ([string]::Equals($returnedGroupId, $groupId, [System.StringComparison]::OrdinalIgnoreCase) -and
                                    $groupOutcome.Status -eq 'Partial') {
                                    $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode $groupOutcome.ReasonCode -Operation 'Group.Get')) | Out-Null
                                }
                            } else {
                                $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode $(if ($groupOutcome.Status -eq 'Failed') { $groupOutcome.ReasonCode } else { 'invalid-provider-data' }) -Operation 'Group.Get')) | Out-Null
                            }

                            if (-not $NetworkAbortState.AuthenticationAborted) {
                                $memberOutcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $operationByKey['GroupMember/List'] `
                                    -Dataset 'application-assignments' -Parameters @{ id = $groupId }
                                if ($memberOutcome.FailureClass -eq 'AuthenticationFailed') {
                                    Set-PulseReportAuthenticationAbort -Store $Store -NetworkAbortState $NetworkAbortState `
                                        -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
                                }
                                if ($memberOutcome.Status -in @('Collected', 'Partial')) {
                                    $validMemberCount = 0
                                    $malformedMemberCount = 0
                                    foreach ($member in @($memberOutcome.Rows)) {
                                        $memberId = [string] (Get-PulseReportValue -InputObject $member -Name @('id'))
                                        if ([string]::IsNullOrWhiteSpace($memberId)) {
                                            $malformedMemberCount++
                                        } else {
                                            $validMemberCount++
                                        }
                                    }
                                    $memberCount = $validMemberCount
                                    $memberState = if ($memberOutcome.Status -eq 'Partial' -or $malformedMemberCount -gt 0) { 'Partial' } else { 'Complete' }
                                    if ($memberOutcome.Status -eq 'Partial') {
                                        $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode $memberOutcome.ReasonCode -Operation 'GroupMember.List')) | Out-Null
                                    }
                                    if ($malformedMemberCount -gt 0) {
                                        $gaps.Add((New-PulseReportGap -Scope $groupId -ReasonCode 'invalid-provider-data' -Operation 'GroupMember.List')) | Out-Null
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

            try {
                $results.ApplicationAssignments = Publish-PulseReportDataRows -Store $Store -Name 'application-assignments' `
                    -Rows $rows.ToArray() -Gaps $gaps.ToArray() -SourceCount $apps.Count `
                    -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
            } catch {
                $results.ApplicationAssignments = Publish-PulseReportArtifactFailure -Store $Store -Name 'application-assignments' `
                    -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
            }
        }
    }

    $installAuthorization = Get-PulseReportAuthorization -AuthorizationDecision $AuthorizationDecision -Operations $installOperations
    if ($NetworkAbortState.AuthenticationAborted -or $installAuthorization.Decision -ne 'Granted') {
        $reasonCode = if ($NetworkAbortState.AuthenticationAborted) { 'authentication-failed' } else { [string] $installAuthorization.ReasonCode }
        $reason = Protect-PulseReason -Message "permission-preflight: $reasonCode" -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        Set-PulseExpansionEntry -Store $Store -Name 'app-install-errors' -Status NotExpanded -Reason $reason
        $results.AppInstallErrors = [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
    } else {
        try {
            $installOutcome = Invoke-PulseAppInstallReportPages -Context $Context -Spec $operationByKey['AppInstallSummaryReport/Get']
            if ($installOutcome.FailureClass -eq 'AuthenticationFailed') {
                Set-PulseReportAuthenticationAbort -Store $Store -NetworkAbortState $NetworkAbortState `
                    -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
            }
            if ($installOutcome.Status -eq 'Failed') {
                $reason = Protect-PulseReason -Message "app-install-report: $($installOutcome.ReasonCode)" -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
                Set-PulseExpansionEntry -Store $Store -Name 'app-install-errors' -Status NotExpanded -Reason $reason
                $results.AppInstallErrors = [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
            } else {
                $converted = ConvertTo-PulseAppInstallErrorRows -PayloadRows @($installOutcome.PayloadRows)
                $installGaps = [System.Collections.Generic.List[object]]::new()
                foreach ($gap in @($converted.Gaps)) { $installGaps.Add($gap) | Out-Null }
                foreach ($gap in @($installOutcome.Gaps)) { $installGaps.Add($gap) | Out-Null }
                $results.AppInstallErrors = Publish-PulseReportDataRows -Store $Store -Name 'app-install-errors' `
                    -Rows @($converted.Rows) -Gaps $installGaps.ToArray() -SourceCount @($installOutcome.PayloadRows).Count `
                    -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
            }
        } catch {
            $results.AppInstallErrors = Publish-PulseReportArtifactFailure -Store $Store -Name 'app-install-errors' `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        }
    }

    return [pscustomobject] $results
}
