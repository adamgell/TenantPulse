<#
    Private: resolve one declared capability gate without guessing from absent evidence.

    Gate status is intentionally separate from provider collection outcomes:
      - Available   => the check may consume its declared datasets.
      - Unavailable => a proven license/feature absence; map to Skipped/LicenseRequired.
      - Unknown     => evidence was not sufficient to decide; map to Skipped/GateUnknown.

    The normal evaluator path only has a snapshot manifest, so it may use explicit gate or
    license evidence recorded in that manifest. A caller can inject a provider for live or
    test-owned evidence via -Provider; this function never treats a missing dataset as proof
    that a license is absent. In particular, a PermissionDenied subscribedSkus outcome is
    preserved as permission evidence and does not become LicenseRequired.
#>

function Get-PulseGateProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Node,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains($Name)) { return $Node[$Name] }
        return $null
    }
    $property = $Node.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Test-PulseGateDecisionTuple {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [string] $Status,

        [AllowNull()]
        [string] $FailureClass
    )

    $hasFailureClass = -not [string]::IsNullOrWhiteSpace($FailureClass)
    switch ($Status) {
        'Available' { return -not $hasFailureClass }
        'Unavailable' { return -not $hasFailureClass -or $FailureClass -eq 'LicenseRequired' }
        'Unknown' { return -not $hasFailureClass -or $FailureClass -in @('GateUnknown', 'PermissionDenied') }
        default { return $false }
    }
}

function New-PulseGateStatusRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Gate,

        [Parameter(Mandatory)]
        [string] $Status,

        [AllowNull()]
        [string] $Detail,

        [AllowNull()]
        [string] $FailureClass = $null
    )

    if ($Status -notin @('Available', 'Unavailable', 'Unknown')) {
        $Status = 'Unknown'
    }

    if ([string]::IsNullOrEmpty($FailureClass)) {
        $FailureClass = if ($Status -eq 'Unavailable') { 'LicenseRequired' } else { 'GateUnknown' }
        if ($Status -eq 'Available') { $FailureClass = $null }
    }

    $outcome = $null
    if ($Status -ne 'Available') {
        $outcome = New-PulseCollectionOutcome -Dataset $Gate -Status 'Skipped' `
            -FailureClass $FailureClass -ReasonCode ("gate-" + $Status.ToLowerInvariant()) `
            -Detail @{ status = $Status; detail = $Detail } -Provider 'TenantPulse'
    }

    return [pscustomobject][ordered]@{
        Status       = $Status
        Detail       = $Detail
        FailureClass = $FailureClass
        Outcome      = $outcome
    }
}

function Resolve-PulseGateEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Gate,

        [Parameter(Mandatory)]
        $Manifest
    )

    # Explicit evidence is the only manifest-level status source. Both names are accepted
    # so a future collector can call the namespace `gates` while a focused provider can use
    # the more descriptive `licenseEvidence` name.
    foreach ($containerName in @('licenseEvidence', 'gates')) {
        $container = Get-PulseGateProperty -Node $Manifest -Name $containerName
        $entry = Get-PulseGateProperty -Node $container -Name $Gate
        if ($null -ne $entry) {
            $status = [string] (Get-PulseGateProperty -Node $entry -Name 'Status')
            if ([string]::IsNullOrEmpty($status)) {
                $available = Get-PulseGateProperty -Node $entry -Name 'Available'
                if ($available -is [bool]) {
                    $status = if ($available) { 'Available' } else { 'Unavailable' }
                }
            }
            $detail = [string] (Get-PulseGateProperty -Node $entry -Name 'Detail')
            $failureClass = [string] (Get-PulseGateProperty -Node $entry -Name 'FailureClass')
            return [pscustomobject]@{ Status = $status; Detail = $detail; FailureClass = $failureClass }
        }
    }

    # A subscribedSkus row is usable only when its collection outcome is explicit. A
    # missing entry, failed read, or complete entry with no summarized gate evidence is
    # Unknown, never Unavailable. Partial evidence may retain an independently proven
    # Available decision, but it can never prove Unavailable. PermissionDenied is retained.
    $datasets = Get-PulseGateProperty -Node $Manifest -Name 'datasets'
    $licenseEntry = Get-PulseGateProperty -Node $datasets -Name 'subscribedSkus'
    if ($null -ne $licenseEntry) {
        $entryStatus = [string] (Get-PulseGateProperty -Node $licenseEntry -Name 'status')
        $entryFailure = [string] (Get-PulseGateProperty -Node $licenseEntry -Name 'failureClass')
        $entryReason = [string] (Get-PulseGateProperty -Node $licenseEntry -Name 'reason')
        if ($entryFailure -eq 'PermissionDenied') {
            return [pscustomobject]@{ Status = 'Unknown'; Detail = $entryReason; FailureClass = 'PermissionDenied' }
        }
        if ($entryStatus -notin @('Collected', 'Partial')) {
            return [pscustomobject]@{ Status = 'Unknown'; Detail = $entryReason; FailureClass = 'GateUnknown' }
        }
        if ($entryStatus -eq 'Collected' -and $entryFailure -eq 'LicenseRequired') {
            return [pscustomobject]@{ Status = 'Unavailable'; Detail = $entryReason; FailureClass = 'LicenseRequired' }
        }

        $detailNode = Get-PulseGateProperty -Node $licenseEntry -Name 'detail'
        # Current snapshots persist one independent decision per supported gate beneath
        # subscribedSkus.detail.Gates. Keep the older flat detail.Status shape below as a
        # compatibility fallback for already-captured fixtures/snapshots.
        $gateContainer = Get-PulseGateProperty -Node $detailNode -Name 'Gates'
        $gateDecision = Get-PulseGateProperty -Node $gateContainer -Name $Gate
        if ($entryStatus -eq 'Partial') {
            $partialStatus = [string] (Get-PulseGateProperty -Node $gateDecision -Name 'Status')
            $partialFailureClass = [string] (Get-PulseGateProperty -Node $gateDecision -Name 'FailureClass')
            if ($partialStatus -eq 'Available') {
                return [pscustomobject]@{
                    Status       = 'Available'
                    Detail       = 'A qualifying provisioned service plan was found in collected license evidence.'
                    FailureClass = $partialFailureClass
                }
            }
            return [pscustomobject]@{
                Status       = 'Unknown'
                Detail       = 'Collected license evidence was incomplete or malformed; absence was not proven.'
                FailureClass = 'GateUnknown'
            }
        }
        if ($null -ne $gateDecision) {
            return [pscustomobject]@{
                Status       = [string] (Get-PulseGateProperty -Node $gateDecision -Name 'Status')
                Detail       = [string] (Get-PulseGateProperty -Node $gateDecision -Name 'Detail')
                FailureClass = [string] (Get-PulseGateProperty -Node $gateDecision -Name 'FailureClass')
            }
        }

        $status = [string] (Get-PulseGateProperty -Node $detailNode -Name 'Status')
        if ([string]::IsNullOrEmpty($status)) {
            $available = Get-PulseGateProperty -Node $detailNode -Name 'Available'
            if ($available -is [bool]) {
                $status = if ($available) { 'Available' } else { 'Unavailable' }
            }
        }
        if ($status -in @('Available', 'Unavailable', 'Unknown')) {
            return [pscustomobject]@{
                Status = $status
                Detail = [string] (Get-PulseGateProperty -Node $detailNode -Name 'Detail')
                FailureClass = $null
            }
        }
        return [pscustomobject]@{ Status = 'Unknown'; Detail = 'Collected license evidence did not include a gate decision.'; FailureClass = $null }
    }

    return [pscustomobject]@{ Status = 'Unknown'; Detail = $null; FailureClass = $null }
}

function Get-PulseGateStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Gate,

        [Parameter()]
        [hashtable] $Manifest = @{},

        [Parameter()]
        [Alias('GateProvider')]
        [AllowNull()]
        $Provider = $null
    )

    $evidence = $null
    if ($null -ne $Provider) {
        try {
            if ($Provider -is [scriptblock]) {
                $evidence = @(& $Provider -Gate $Gate -Manifest $Manifest)[-1]
            } elseif ($Provider -is [System.Collections.IDictionary]) {
                $evidence = $Provider[$Gate]
            } elseif ($Provider -is [string]) {
                $evidence = [pscustomobject]@{ Status = [string] $Provider; Detail = $null }
            } else {
                throw "provider must be a ScriptBlock, IDictionary, or status string, got '$($Provider.GetType().FullName)'"
            }
        } catch {
            return New-PulseGateStatusRecord -Gate $Gate -Status 'Unknown' -Detail "Gate provider failed: $($_.Exception.Message)"
        }
    } else {
        $evidence = Resolve-PulseGateEvidence -Gate $Gate -Manifest $Manifest
    }

    $status = [string] (Get-PulseGateProperty -Node $evidence -Name 'Status')
    $detail = [string] (Get-PulseGateProperty -Node $evidence -Name 'Detail')
    $failureClass = [string] (Get-PulseGateProperty -Node $evidence -Name 'FailureClass')
    if ([string]::IsNullOrWhiteSpace($failureClass)) {
        $failureClass = $null
    }
    if ($status -notin @('Available', 'Unavailable', 'Unknown')) {
        $status = 'Unknown'
        if ([string]::IsNullOrEmpty($detail)) { $detail = 'Gate evidence did not provide a recognized status.' }
    }

    # A provider may explicitly report a permission denial. Preserve that class and keep
    # the gate from being mistaken for a proven license absence.
    if ($failureClass -eq 'PermissionDenied') {
        $status = 'Unknown'
    }

    if (-not (Test-PulseGateDecisionTuple -Status $status -FailureClass $failureClass)) {
        $status = 'Unknown'
        $failureClass = 'GateUnknown'
        if ([string]::IsNullOrEmpty($detail)) {
            $detail = 'Gate evidence contained a contradictory status and failure class.'
        }
    }

    return New-PulseGateStatusRecord -Gate $Gate -Status $status -Detail $detail -FailureClass $failureClass
}
