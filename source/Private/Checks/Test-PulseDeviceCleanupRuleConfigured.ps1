<#
    Private: TP.INT.0007 rule function - Intune managed-device clean-up rule configured
    (Task 3.2, Maester port MT.1053 - Test-MtManagedDeviceCleanupSettings, MIT).

    The supported service contract is the per-platform RULES collection,
    `deviceManagement/managedDeviceCleanupRules` (plural). Each row is a distinct rule
    carrying id, displayName, deviceCleanupRulePlatformType, and
    deviceInactivityBeforeRetirementInDays. A successful empty collection authoritatively
    means no rule is configured. GraphKit 0.3.0's
    ManagedDeviceCleanupRule.ListBeta descriptor implements that collection as a direct
    Read/Safe primitive consumed by TenantPulse's DatasetMap.

    CORRECTED CLAIM (live-verified against
    https://learn.microsoft.com/en-us/intune/governance/configure-cleanup-rules, fetched
    for this check - an earlier research-entry draft said cleanup rules "delete
    managed-device records"; the live doc says otherwise): device clean-up rules only
    HIDE stale device records from the admin center/reports - "Don't trigger any actions
    on the device (no wipe or retire)", and a hidden device reappears automatically if it
    checks back in before its device certificate expires. This check's Consulting text
    reflects that corrected behavior throughout, never "deletes".

    RULE: Pass when at least one collected rule carries a positive day count; Fail for an
    authoritative empty collection or when every well-formed row carries 0. The Graph
    resource documents this field as Int32. Missing, null, string, fractional, negative,
    or out-of-Int32-range values are malformed service data and throw so the evaluator
    emits Error. A malformed sibling can never be ignored merely because another row is
    valid. Evidence is one row per rule and is deterministically ordered by platform then
    rule id by the evaluator's normal (SortKey, Identity) ordering contract.
#>

function Test-PulseDeviceCleanupRuleConfigured {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    function Get-PulseCleanupRuleProperty {
        param($Row, [string] $Name, [ref] $Found)

        $Found.Value = $false
        if ($Row -is [System.Collections.IDictionary]) {
            if ($Row.Contains($Name)) {
                $Found.Value = $true
                return $Row[$Name]
            }
            return $null
        }

        if ($Row -is [pscustomobject]) {
            $property = $Row.PSObject.Properties[$Name]
            if ($null -ne $property) {
                $Found.Value = $true
                return $property.Value
            }
        }

        return $null
    }

    $rows = @($Datasets.managedDeviceCleanupRules)
    if ($rows.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No Intune device clean-up rule is configured: the managed-device cleanup rules collection is authoritatively empty.' -Evidence @()
    }

    $evidence = [System.Collections.Generic.List[object]]::new()
    $configuredCount = 0
    foreach ($row in $rows) {
        if ($null -eq $row -or ($row -isnot [System.Collections.IDictionary] -and $row -isnot [pscustomobject])) {
            throw 'Test-PulseDeviceCleanupRuleConfigured: the managed-device cleanup rules collection contains a malformed row.'
        }

        $found = $false
        $rawDays = Get-PulseCleanupRuleProperty -Row $row -Name 'deviceInactivityBeforeRetirementInDays' -Found ([ref] $found)
        $integralTypes = @([byte], [sbyte], [int16], [uint16], [int32], [uint32], [int64], [uint64])
        $isIntegral = $false
        foreach ($type in $integralTypes) {
            if ($type.IsInstanceOfType($rawDays)) {
                $isIntegral = $true
                break
            }
        }
        if (-not $found -or $null -eq $rawDays -or -not $isIntegral -or $rawDays -lt 0 -or $rawDays -gt [int]::MaxValue) {
            throw 'Test-PulseDeviceCleanupRuleConfigured: deviceInactivityBeforeRetirementInDays is malformed; expected a non-negative Int32 value.'
        }
        $days = [int] $rawDays

        $idFound = $false
        $id = Get-PulseCleanupRuleProperty -Row $row -Name 'id' -Found ([ref] $idFound)
        if (-not $idFound -or [string]::IsNullOrWhiteSpace([string] $id)) {
            throw 'Test-PulseDeviceCleanupRuleConfigured: a managed-device cleanup rule is missing its required id.'
        }
        $displayNameFound = $false
        $displayName = Get-PulseCleanupRuleProperty -Row $row -Name 'displayName' -Found ([ref] $displayNameFound)
        $platformFound = $false
        $platform = Get-PulseCleanupRuleProperty -Row $row -Name 'deviceCleanupRulePlatformType' -Found ([ref] $platformFound)

        if ($days -gt 0) { $configuredCount++ }
        $evidence.Add(@{
            Identity = [string] $id
            SortKey  = if ($platformFound -and $null -ne $platform) { [string] $platform } else { [string] $id }
            Detail   = [ordered]@{
                deviceCleanupRulePlatformType            = if ($platformFound) { $platform } else { $null }
                deviceInactivityBeforeRetirementInDays   = $days
                displayName                              = if ($displayNameFound) { $displayName } else { $null }
            }
        })
    }

    if ($configuredCount -eq 0) {
        $reason = "No Intune device clean-up rule is configured: all $($rows.Count) collected rule row(s) have deviceInactivityBeforeRetirementInDays set to 0."
        return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence.ToArray()
    }

    $reason = if ($configuredCount -eq 1) {
        "1 Intune device clean-up rule is configured with a positive inactivity threshold ($($rows.Count) collected rule row(s) evaluated)."
    } else {
        "$configuredCount Intune device clean-up rules are configured with positive inactivity thresholds ($($rows.Count) collected rule rows evaluated)."
    }
    return New-PulseFinding -Status Pass -Reason $reason -Evidence $evidence.ToArray()
}
