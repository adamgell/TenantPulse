<#
    Private: TP.INT.0027 rule function - no orphaned Windows Autopilot device identities
    (Task 3.3, research-matrix - no Maester origin, practitioner judgment).

    REDESIGNED FROM THE ORIGINAL RESEARCH ENTRY, FOR THE BETTER (documented deviation): the
    research entry describes this as a composite check needing BOTH
    windowsAutopilotDeviceIdentities AND windowsAutopilotDeploymentProfiles cross-
    referenced. Live-verifying the beta windowsAutopilotDeviceIdentity resource shape
    (https://learn.microsoft.com/en-us/graph/api/resources/intune-enrollment-windowsautopilotdeviceidentity?view=graph-rest-beta,
    fetched for this check) found the device identity itself already carries its own
    `deploymentProfileAssignmentStatus` property directly - possible values `unknown`,
    `assignedInSync`, `assignedOutOfSync`, `assignedUnkownSyncState` [sic, Microsoft's own
    spelling], `notAssigned`, `pending`, `failed`. "Orphaned" (never targeted by ANY
    deployment profile) is therefore fully decidable from the SAME single dataset
    TP.INT.0027 already needs anyway, with no cross-reference to
    windowsAutopilotDeploymentProfiles (TP.INT.0026's own Pending dataset) required. This
    check is LIVE, not Pending, as a direct result - a strictly better outcome than the
    two-dataset composite plan, and one the composite plan would have blocked on
    TP.INT.0026's own Pending status per Invoke-PulseEvaluation's "every declared dataset
    must be Collected" contract.

    LIVE DATASET: `windowsAutopilotDeviceIdentities` maps to GraphKit 0.1.1's released
    `AutopilotDevice`/`List` (beta) descriptor, PathTemplate
    `/deviceManagement/windowsAutopilotDeviceIdentities` - confirmed via a live
    Get-GraphOperation -List enumeration, NOT Pending.

    "notAssigned" IS THE ORPHAN SIGNAL, NOT "failed"/"pending": `notAssigned` means the
    identity has never been targeted by any deployment profile at all - the exact
    "registered but never targeted" gap this check exists to catch. `pending` and `failed`
    describe an identity that HAS been targeted but whose assignment sync hasn't completed
    or errored - a different, narrower problem this check deliberately does not conflate
    with "orphaned" (a targeted-but-failing profile assignment is arguably a Pending/Failed
    telemetry concern for a future check, not evidence the device was never targeted).

    FIELD-ABSENCE LENS: deploymentProfileAssignmentStatus absent on an existing identity
    row is undecidable - throws.

    RULE: zero identities registered = NotApplicable (skip - no Autopilot devices
    registered at all). Otherwise Fail if any identity's deploymentProfileAssignmentStatus
    is `notAssigned`, listing every such identity in evidence; Pass otherwise.
#>

function Test-PulseNoOrphanedAutopilotIdentities {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $identities = @($Datasets.windowsAutopilotDeviceIdentities)
    if ($identities.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Windows Autopilot device identities are registered for this tenant - there is nothing for this check to evaluate.'
    }

    $orphaned = [System.Collections.Generic.List[object]]::new()
    $allRows = [System.Collections.Generic.List[object]]::new()
    foreach ($identity in $identities) {
        if (-not (Test-PulseRowPropertyPresent -Row $identity -PropertyName 'deploymentProfileAssignmentStatus') -or $null -eq $identity.deploymentProfileAssignmentStatus) {
            throw 'Test-PulseNoOrphanedAutopilotIdentities: a windowsAutopilotDeviceIdentities row is missing deploymentProfileAssignmentStatus.'
        }

        $status = [string] $identity.deploymentProfileAssignmentStatus
        $rowIdentity = if (Test-PulseRowPropertyPresent -Row $identity -PropertyName 'id') { [string] $identity.id } else { [string] $identity.serialNumber }
        $row = @{
            Identity = $rowIdentity
            Detail   = @{ serialNumber = $identity.serialNumber; model = $identity.model; deploymentProfileAssignmentStatus = $status }
            SortKey  = $rowIdentity
        }
        $allRows.Add($row)
        if ($status -eq 'notAssigned') {
            $orphaned.Add($row)
        }
    }

    if ($orphaned.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason "All $($identities.Count) registered Windows Autopilot device identity(ies) are covered by at least one deployment profile assignment." -Evidence $allRows.ToArray()
    }

    $reason = "$($orphaned.Count) of $($identities.Count) registered Windows Autopilot device identity(ies) have never been targeted by any deployment profile (deploymentProfileAssignmentStatus 'notAssigned') - these devices will fail zero-touch provisioning and require manual intervention when unboxed."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $orphaned.ToArray()
}
