<#
    Private managed-device report-data projection.

    IHA defines six active reports over the same managedDevices collection: device OS
    compliance, devices without BitLocker, hardware inventory, noncompliant devices,
    stale Windows devices, and a file named TPM status that does not actually collect a
    TPM property. TenantPulse does not duplicate those presentation filters or pretend
    that encryption/compliance fields prove TPM state. Instead, -ReportData Devices
    guarantees the ordinary managedDevices dataset is collected once and publishes one
    neutral schema-v1 managed-device-inventory artifact from it. For Windows rows, the
    public collection path also uses GraphKit's beta singleton read because Microsoft
    documents that real hardwareInformation values require a device-id GET with that field
    selected; collection-shaped defaults are not treated as authoritative hardware detail.
    Singleton enrichment is bounded to 1,000 unique Windows device ids per run. The ids are
    selected in ordinal order, and any remainder stays in the artifact with
    detailResolutionState=NotEvaluated plus one explicit detail-cap-reached gap.

    The projection retains every source property in sourceColumns and promotes the stable
    fields required by the six IHA definitions. It makes no health/severity judgment. The
    external Office delivery layer may derive customer worksheets from this artifact using
    the migration rules in docs/contracts/device-report-data-v1.md.

    A Partial managedDevices dataset remains a Partial artifact with an explicit source
    gap. Failed, skipped, missing, corrupt, or wholly unusable source data becomes
    NotExpanded/Failed; it is never laundered into an authoritative empty report.
#>

$script:PulseManagedDeviceReportOperations = @(
    [pscustomobject]@{ Type = 'ManagedDevice'; Operation = 'GetBeta'; ApiVersion = 'beta'; PagingStrategy = 'None' }
)

function Get-PulseManagedDeviceReportOperations {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return @($script:PulseManagedDeviceReportOperations | ForEach-Object {
            [pscustomobject]@{
                Type = $_.Type; Operation = $_.Operation; ApiVersion = $_.ApiVersion
                PagingStrategy = $_.PagingStrategy
            }
        })
}

function Merge-PulseManagedDeviceReportSource {
    param(
        [Parameter(Mandatory)] $BaseDevice,
        [AllowNull()] $DetailDevice
    )

    $merged = [ordered]@{}
    foreach ($entry in @(
            (ConvertTo-PulseReportSourceMap -InputObject $BaseDevice),
            (ConvertTo-PulseReportSourceMap -InputObject $DetailDevice)
        )) {
        foreach ($key in @($entry.Keys)) { $merged[$key] = $entry[$key] }
    }
    return [pscustomobject] $merged
}

function New-PulseManagedDeviceReportRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        $Device,

        [AllowNull()]
        $BaseDevice,

        [AllowNull()]
        $DetailDevice,

        [ValidateSet('Resolved', 'Partial', 'Failed', 'NotEvaluated', 'NotApplicable', 'NotRequested')]
        [string] $DetailResolutionState = 'NotRequested'
    )

    $sourceColumns = ConvertTo-PulseReportSourceMap -InputObject $Device
    $resolvedBaseDevice = if ($null -ne $BaseDevice) { $BaseDevice } else { $Device }
    $hardwareInformation = Get-PulseReportValue -InputObject $Device -Name @('hardwareInformation')
    $healthAttestation = Get-PulseReportValue -InputObject $Device -Name @('deviceHealthAttestationState')
    $tpmVersion = Get-PulseReportValue -InputObject $hardwareInformation -Name @('tpmVersion')
    if ([string]::IsNullOrWhiteSpace([string] $tpmVersion)) {
        $tpmVersion = Get-PulseReportValue -InputObject $healthAttestation -Name @('tpmVersion')
    }

    return [pscustomobject][ordered]@{
        schemaVersion             = '1'
        deviceId                  = Get-PulseReportValue -InputObject $Device -Name @('id', 'managedDeviceId')
        azureAdDeviceId           = Get-PulseReportValue -InputObject $Device -Name @('azureADDeviceId', 'azureAdDeviceId')
        deviceName                = Get-PulseReportValue -InputObject $Device -Name @('deviceName', 'managedDeviceName')
        userPrincipalName         = Get-PulseReportValue -InputObject $Device -Name @('userPrincipalName')
        userId                    = Get-PulseReportValue -InputObject $Device -Name @('userId')
        operatingSystem           = Get-PulseReportValue -InputObject $Device -Name @('operatingSystem')
        osVersion                 = Get-PulseReportValue -InputObject $Device -Name @('osVersion')
        manufacturer              = Get-PulseReportValue -InputObject $Device -Name @('manufacturer')
        model                     = Get-PulseReportValue -InputObject $Device -Name @('model')
        serialNumber              = Get-PulseReportValue -InputObject $Device -Name @('serialNumber')
        physicalMemoryInBytes     = Get-PulseReportValue -InputObject $Device -Name @('physicalMemoryInBytes')
        isEncrypted               = Get-PulseReportValue -InputObject $Device -Name @('isEncrypted')
        complianceState           = Get-PulseReportValue -InputObject $Device -Name @('complianceState')
        lastSyncDateTime          = Get-PulseReportValue -InputObject $Device -Name @('lastSyncDateTime')
        enrolledDateTime          = Get-PulseReportValue -InputObject $Device -Name @('enrolledDateTime')
        managementAgent           = Get-PulseReportValue -InputObject $Device -Name @('managementAgent')
        managedDeviceOwnerType    = Get-PulseReportValue -InputObject $Device -Name @('managedDeviceOwnerType')
        deviceCategoryDisplayName = Get-PulseReportValue -InputObject $Device -Name @('deviceCategoryDisplayName')
        processorArchitecture     = Get-PulseReportValue -InputObject $Device -Name @('processorArchitecture')
        skuFamily                 = Get-PulseReportValue -InputObject $Device -Name @('skuFamily')
        skuNumber                 = Get-PulseReportValue -InputObject $Device -Name @('skuNumber')
        ethernetMacAddress        = Get-PulseReportValue -InputObject $Device -Name @('ethernetMacAddress')
        bootstrapTokenEscrowed    = Get-PulseReportValue -InputObject $Device -Name @('bootstrapTokenEscrowed')
        hardwareInformation      = if ($null -ne $hardwareInformation) { ConvertTo-PulseReportSourceMap -InputObject $hardwareInformation } else { $null }
        deviceHealthAttestationState = if ($null -ne $healthAttestation) { ConvertTo-PulseReportSourceMap -InputObject $healthAttestation } else { $null }
        tpmVersion                = $tpmVersion
        detailResolutionState     = $DetailResolutionState
        baseSourceColumns         = ConvertTo-PulseReportSourceMap -InputObject $resolvedBaseDevice
        detailSourceColumns       = if ($null -ne $DetailDevice) { ConvertTo-PulseReportSourceMap -InputObject $DetailDevice } else { $null }
        sourceColumns             = $sourceColumns
    }
}

function ConvertTo-PulseManagedDeviceReportRows {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Devices,

        [hashtable] $DetailByDeviceId = @{}
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $index = 0

    foreach ($device in @($Devices)) {
        $index++
        if ($null -eq $device) {
            $gaps.Add([pscustomobject]@{
                    policyId = "managed-device-$index"
                    reason   = 'category:invalid-provider-data;dataset:managedDevices;detail:null-row'
                }) | Out-Null
            continue
        }

        $deviceId = [string] (Get-PulseReportValue -InputObject $device -Name @('id', 'managedDeviceId'))
        $detailRecord = if (-not [string]::IsNullOrWhiteSpace($deviceId) -and $DetailByDeviceId.ContainsKey($deviceId)) {
            $DetailByDeviceId[$deviceId]
        } else { $null }
        $detailDevice = if ($null -ne $detailRecord) { $detailRecord.Device } else { $null }
        $detailState = if ($null -ne $detailRecord) { [string] $detailRecord.State } else { 'NotRequested' }
        $mergedDevice = if ($null -ne $detailDevice) {
            Merge-PulseManagedDeviceReportSource -BaseDevice $device -DetailDevice $detailDevice
        } else { $device }
        $row = New-PulseManagedDeviceReportRow -Device $mergedDevice -BaseDevice $device `
            -DetailDevice $detailDevice -DetailResolutionState $detailState
        $hasStableId = -not [string]::IsNullOrWhiteSpace([string] $row.deviceId) -or
            -not [string]::IsNullOrWhiteSpace([string] $row.azureAdDeviceId)
        $hasName = -not [string]::IsNullOrWhiteSpace([string] $row.deviceName)
        if (-not $hasStableId -and -not $hasName) {
            $gaps.Add([pscustomobject]@{
                    policyId = "managed-device-$index"
                    reason   = 'category:invalid-provider-data;dataset:managedDevices;detail:identity-missing'
                }) | Out-Null
            continue
        }

        $rows.Add($row) | Out-Null
    }

    return [pscustomobject]@{
        Rows = $rows.ToArray()
        Gaps = $gaps.ToArray()
    }
}

function Invoke-PulseDeviceReportCollection {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter()]
        [string] $ProfileId = '',

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown',

        [Parameter()]
        [AllowNull()]
        [string] $TenantId,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $Context,

        [Parameter()]
        [AllowNull()]
        $AuthorizationDecision,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $NetworkAbortState,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int] $MaxDetailReads = 1000
    )

    $artifactName = 'managed-device-inventory'
    $manifest = Get-PulseSnapshotManifest -Store $Store
    if (-not $manifest.Contains('datasets') -or -not $manifest.datasets.Contains('managedDevices')) {
        $reason = Protect-PulseReason -Message 'report-source-unavailable: managedDevices missing from manifest' `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $artifactName -Status NotExpanded -Reason $reason
        return [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
    }

    $sourceEntry = $manifest.datasets.managedDevices
    if ($sourceEntry.status -notin @('Collected', 'Partial')) {
        $reasonCode = if ([string]::IsNullOrWhiteSpace([string] $sourceEntry.reasonCode)) {
            'source-dataset-unavailable'
        } else {
            [string] $sourceEntry.reasonCode
        }
        $reason = Protect-PulseReason -Message "report-source-unavailable: managedDevices/$reasonCode" `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $artifactName -Status NotExpanded -Reason $reason
        return [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
    }

    try {
        # Read-PulseDataset returns its [object[]] as one pipeline object so an empty
        # dataset survives PowerShell enumeration. Assign directly; wrapping the call in
        # @() would turn that array into one nested pseudo-row.
        $devices = Read-PulseDataset -Store $Store -Name 'managedDevices' -ManifestSnapshot $manifest
        $gaps = [System.Collections.Generic.List[object]]::new()
        $detailByDeviceId = @{}

        if ($null -ne $Context) {
            $spec = @(Get-PulseManagedDeviceReportOperations)[0]
            $detailBlockReason = $null
            try {
                $descriptor = Assert-PulseReadOnlyDescriptor -Type $spec.Type -Operation $spec.Operation `
                    -ApiVersion $spec.ApiVersion -PassThru
                if ($null -eq $descriptor -or [string] $descriptor.PagingStrategy -ne $spec.PagingStrategy) {
                    $detailBlockReason = 'descriptor-paging-drift'
                }
            } catch {
                $detailBlockReason = 'descriptor-unavailable'
            }

            if ($null -eq $detailBlockReason) {
                $authorization = Get-PulseReportAuthorization -AuthorizationDecision $AuthorizationDecision -Operations @($spec)
                if ($authorization.Decision -ne 'Granted') {
                    $detailBlockReason = [string] $authorization.ReasonCode
                }
            }
            if ($null -eq $NetworkAbortState) {
                $NetworkAbortState = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
            }
            if ($NetworkAbortState.AuthenticationAborted) { $detailBlockReason = 'authentication-failed' }

            $windowsDevices = @($devices | Where-Object {
                    [string]::Equals([string] (Get-PulseReportValue -InputObject $_ -Name @('operatingSystem')), 'Windows', [System.StringComparison]::OrdinalIgnoreCase)
                })
            $seenWindowsDeviceIds = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            $validWindowsDeviceIds = [System.Collections.Generic.List[string]]::new()
            foreach ($device in $windowsDevices) {
                $id = [string] (Get-PulseReportValue -InputObject $device -Name @('id', 'managedDeviceId'))
                if ([string]::IsNullOrWhiteSpace($id)) {
                    $gaps.Add((New-PulseReportGap -Scope 'managed-device-detail-without-id' -ReasonCode 'invalid-provider-data' -Operation 'ManagedDevice.GetBeta')) | Out-Null
                    continue
                }
                if ($seenWindowsDeviceIds.Add($id)) {
                    $validWindowsDeviceIds.Add($id) | Out-Null
                }
            }
            [string[]] $orderedWindowsDeviceIds = $validWindowsDeviceIds.ToArray()
            [System.Array]::Sort($orderedWindowsDeviceIds, [System.StringComparer]::OrdinalIgnoreCase)

            if ($null -ne $detailBlockReason -and $orderedWindowsDeviceIds.Count -gt 0) {
                $gaps.Add((New-PulseReportGap -Scope 'managed-device-detail' -ReasonCode $detailBlockReason -Operation 'ManagedDevice.GetBeta')) | Out-Null
                foreach ($id in $orderedWindowsDeviceIds) {
                    $detailByDeviceId[$id] = [pscustomobject]@{ State = 'NotEvaluated'; Device = $null }
                }
            } else {
                $detailReadCount = 0
                $detailCapRecorded = $false
                foreach ($id in $orderedWindowsDeviceIds) {
                    if ($NetworkAbortState.AuthenticationAborted) {
                        $detailByDeviceId[$id] = [pscustomobject]@{ State = 'NotEvaluated'; Device = $null }
                        $gaps.Add((New-PulseReportGap -Scope $id -ReasonCode 'authentication-failed' -Operation 'ManagedDevice.GetBeta')) | Out-Null
                        continue
                    }
                    if ($detailReadCount -ge $MaxDetailReads) {
                        $detailByDeviceId[$id] = [pscustomobject]@{ State = 'NotEvaluated'; Device = $null }
                        if (-not $detailCapRecorded) {
                            $gaps.Add((New-PulseReportGap -Scope 'managed-device-detail' -ReasonCode 'detail-cap-reached' -Operation 'ManagedDevice.GetBeta')) | Out-Null
                            $detailCapRecorded = $true
                        }
                        continue
                    }

                    $detailReadCount++
                    $outcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $spec `
                        -Dataset 'managed-device-inventory' -Parameters @{ id = $id }
                    if ($outcome.FailureClass -eq 'AuthenticationFailed') {
                        Set-PulseReportAuthenticationAbort -Store $Store -NetworkAbortState $NetworkAbortState `
                            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                    }
                    $detailRows = @($outcome.Rows)
                    $returnedId = if ($detailRows.Count -eq 1) {
                        [string] (Get-PulseReportValue -InputObject $detailRows[0] -Name @('id', 'managedDeviceId'))
                    } else { $null }
                    if ($outcome.Status -in @('Collected', 'Partial') -and $detailRows.Count -eq 1 -and
                        [string]::Equals($returnedId, $id, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $detailState = if ($outcome.Status -eq 'Partial') { 'Partial' } else { 'Resolved' }
                        $detailByDeviceId[$id] = [pscustomobject]@{ State = $detailState; Device = $detailRows[0] }
                        if ($outcome.Status -eq 'Partial') {
                            $gaps.Add((New-PulseReportGap -Scope $id -ReasonCode $outcome.ReasonCode -Operation 'ManagedDevice.GetBeta')) | Out-Null
                        }
                    } else {
                        $detailByDeviceId[$id] = [pscustomobject]@{ State = 'Failed'; Device = $null }
                        $failureReason = if ($outcome.Status -eq 'Failed') { [string] $outcome.ReasonCode } else { 'invalid-provider-data' }
                        $gaps.Add((New-PulseReportGap -Scope $id -ReasonCode $failureReason -Operation 'ManagedDevice.GetBeta')) | Out-Null
                    }
                }
            }

            foreach ($device in @($devices | Where-Object {
                        -not [string]::Equals([string] (Get-PulseReportValue -InputObject $_ -Name @('operatingSystem')), 'Windows', [System.StringComparison]::OrdinalIgnoreCase)
                    })) {
                $id = [string] (Get-PulseReportValue -InputObject $device -Name @('id', 'managedDeviceId'))
                if (-not [string]::IsNullOrWhiteSpace($id)) {
                    $detailByDeviceId[$id] = [pscustomobject]@{ State = 'NotApplicable'; Device = $null }
                }
            }
        }

        $converted = ConvertTo-PulseManagedDeviceReportRows -Devices $devices -DetailByDeviceId $detailByDeviceId
        foreach ($gap in @($converted.Gaps)) { $gaps.Add($gap) | Out-Null }

        if ($sourceEntry.status -eq 'Partial') {
            $gaps.Add([pscustomobject]@{
                    policyId = 'managedDevices'
                    reason   = 'category:source-dataset-partial;dataset:managedDevices'
                }) | Out-Null
        }

        $safeRows = Protect-PulseGraphRowTenantId -Data @($converted.Rows) -TenantId $TenantId -Pseudonym $Pseudonym
        $sourceCount = @($devices).Count
        if ($sourceEntry.status -eq 'Partial' -and $sourceCount -eq 0) { $sourceCount = 1 }

        $reason = if ($gaps.Count -gt 0) { [string] $gaps[0].reason } else { $null }
        return Publish-PulseExpansionRows -Store $Store -Name $artifactName -Rows @($safeRows) `
            -Gaps $gaps.ToArray() -PolicyCount $sourceCount `
            -SortProperties @('deviceId', 'azureAdDeviceId', 'deviceName', 'serialNumber') `
            -UnresolvedNameCount 0 -RedactedSecretCount 0 -Reason $reason `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
    } catch {
        $reason = Protect-PulseReason -Message 'report-source-invalid: managedDevices could not be verified or projected' `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $artifactName -Status Failed -Reason $reason
        return [pscustomobject]@{ Status = 'Failed'; RowCount = 0; Gaps = @() }
    }
}
