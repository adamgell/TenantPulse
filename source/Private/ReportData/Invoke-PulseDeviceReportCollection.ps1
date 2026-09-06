<#
    Private managed-device report-data projection.

    IHA defines six active reports over the same managedDevices collection: device OS
    compliance, devices without BitLocker, hardware inventory, noncompliant devices,
    stale Windows devices, and a file named TPM status that does not actually collect a
    TPM property. TenantPulse does not duplicate those presentation filters or pretend
    that encryption/compliance fields prove TPM state. Instead, -ReportData Devices
    guarantees the ordinary managedDevices dataset is collected once and publishes one
    neutral schema-v1 managed-device-inventory artifact from it.

    The projection retains every source property in sourceColumns and promotes the stable
    fields required by the six IHA definitions. It makes no health/severity judgment. The
    external Office delivery layer may derive customer worksheets from this artifact using
    the migration rules in docs/contracts/device-report-data-v1.md.

    A Partial managedDevices dataset remains a Partial artifact with an explicit source
    gap. Failed, skipped, missing, corrupt, or wholly unusable source data becomes
    NotExpanded/Failed; it is never laundered into an authoritative empty report.
#>

function New-PulseManagedDeviceReportRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        $Device
    )

    $sourceColumns = ConvertTo-PulseReportSourceMap -InputObject $Device

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
        [object[]] $Devices
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

        $row = New-PulseManagedDeviceReportRow -Device $device
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
        [string] $TenantId
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
        $converted = ConvertTo-PulseManagedDeviceReportRows -Devices $devices
        $gaps = [System.Collections.Generic.List[object]]::new()
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
