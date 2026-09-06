<#
    Private: TP.INT.0004 rule function - at least 2 Windows Update rings exist with
    deadlines configured.

    Windows Update ring profiles are deviceConfigurations rows whose '@odata.type' is
    '#microsoft.graph.windowsUpdateForBusinessConfiguration' (v1.0). A "deadline" is
    considered configured when EITHER deadlineForFeatureUpdatesInDays or
    deadlineForQualityUpdatesInDays carries a value greater than zero - Microsoft's own
    default for both is null/unset (deadlines opt-in, not opt-out), so a non-null, positive
    value is a genuine authoring signal, not noise.

    The title's own number is the assertion: at least 2 rings (Microsoft's staged-rollout
    guidance - pilot then broad, minimum) must EACH have a deadline configured, not merely
    that 2 rings exist somewhere and 1 of them has a deadline.

    Assignment evidence is joined during collection. Only include-targeted rings count;
    authoritative empty and exclusion-only assignments do not. When fewer than two known
    assigned rings satisfy the deadline bar, a partial root list produces NotApplicable;
    bounded unresolved assignment/type evidence does so only when the known plus distinct
    possible candidates could still reach two. A scoped assignment gap on a known non-ring
    configuration is irrelevant and must not suppress a provable Fail. Deadline values must
    be finite whole-number scalars; PowerShell-coercible strings, booleans, and arrays are
    malformed evidence rather than configured deadlines.
#>

function Test-PulseUpdateRingDeadlines {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter(Mandatory)]
        [hashtable] $DatasetOutcomes
    )

    $outcomeState = Resolve-PulseDatasetOutcomeState -DatasetOutcomes $DatasetOutcomes `
        -DatasetName 'deviceConfigurations' -Caller $MyInvocation.MyCommand.Name

    $moduleBase = if ($MyInvocation.MyCommand.Module) { $MyInvocation.MyCommand.Module.ModuleBase } else { $PSScriptRoot }
    $typedPolicyMaps = Import-PowerShellDataFile -LiteralPath (Join-Path $moduleBase 'Data/TypedPolicyMaps.psd1') -ErrorAction Stop
    $knownConfigurationTypes = $typedPolicyMaps.deviceConfiguration

    $isPositiveDeadline = {
        param($value, [string] $propertyName)

        if ($null -eq $value) {
            return $false
        }

        $isNativeNumericScalar =
            $value -is [sbyte] -or $value -is [byte] -or
            $value -is [int16] -or $value -is [uint16] -or
            $value -is [int32] -or $value -is [uint32] -or
            $value -is [int64] -or $value -is [uint64] -or
            $value -is [single] -or $value -is [double] -or
            $value -is [decimal]
        if (-not $isNativeNumericScalar) {
            throw "Update ring property '$propertyName' must be a native numeric scalar or null."
        }

        $numericValue = [double] $value
        if ([double]::IsNaN($numericValue) -or [double]::IsInfinity($numericValue) -or
            $numericValue -ne [math]::Truncate($numericValue)) {
            throw "Update ring property '$propertyName' must be a finite whole number or null."
        }

        return $value -gt 0
    }

    $hasDeadline = {
        param($ring)
        $feature = Get-PulseSettingsCatalogValueProperty -Node $ring -PropertyName 'deadlineForFeatureUpdatesInDays'
        $quality = Get-PulseSettingsCatalogValueProperty -Node $ring -PropertyName 'deadlineForQualityUpdatesInDays'
        $featureIsPositive = & $isPositiveDeadline $feature 'deadlineForFeatureUpdatesInDays'
        $qualityIsPositive = & $isPositiveDeadline $quality 'deadlineForQualityUpdatesInDays'
        return $featureIsPositive -or $qualityIsPositive
    }

    $configurations = @($Datasets.deviceConfigurations)
    $allUpdateRings = [System.Collections.Generic.List[object]]::new()
    $configurationRowsById = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $duplicateConfigurationIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ringRelevantConfigurationIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $potentialQualifyingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $configurationOrdinal = 0
    foreach ($configuration in $configurations) {
        $configurationId = [string] (Get-PulseSettingsCatalogValueProperty -Node $configuration -PropertyName 'id')
        $configurationKey = if ([string]::IsNullOrWhiteSpace($configurationId)) {
            "row:$configurationOrdinal"
        } else {
            "id:$configurationId"
        }
        $configurationOrdinal++

        if (-not [string]::IsNullOrWhiteSpace($configurationId)) {
            if ($configurationRowsById.ContainsKey($configurationId)) {
                [void] $duplicateConfigurationIds.Add($configurationId)
            } else {
                $configurationRowsById.Add($configurationId, $configuration)
            }
        }

        $odataType = [string] (Get-PulseSettingsCatalogValueProperty -Node $configuration -PropertyName '@odata.type')
        if ([string]::IsNullOrWhiteSpace($odataType) -or -not $knownConfigurationTypes.ContainsKey($odataType)) {
            $intent = ConvertTo-PulseAssignmentIntent -Assignments (Get-PulseSettingsCatalogValueProperty -Node $configuration -PropertyName 'assignments')
            if (($intent.IsAssigned -or -not $intent.Complete) -and (& $hasDeadline $configuration)) {
                [void] $potentialQualifyingKeys.Add($configurationKey)
                if (-not [string]::IsNullOrWhiteSpace($configurationId)) {
                    [void] $ringRelevantConfigurationIds.Add($configurationId)
                }
            }
            continue
        }
        if ([string]::Equals($odataType, '#microsoft.graph.windowsUpdateForBusinessConfiguration', [System.StringComparison]::OrdinalIgnoreCase)) {
            $allUpdateRings.Add([pscustomobject]@{ Row = $configuration; Key = $configurationKey })
            $intent = ConvertTo-PulseAssignmentIntent -Assignments (Get-PulseSettingsCatalogValueProperty -Node $configuration -PropertyName 'assignments')
            if (($intent.IsAssigned -or -not $intent.Complete) -and (& $hasDeadline $configuration) -and
                -not [string]::IsNullOrWhiteSpace($configurationId)) {
                [void] $ringRelevantConfigurationIds.Add($configurationId)
            }
        }
    }

    $hasRingRelevantDuplicate = $false
    foreach ($duplicateConfigurationId in $duplicateConfigurationIds) {
        if ($ringRelevantConfigurationIds.Contains($duplicateConfigurationId)) {
            $hasRingRelevantDuplicate = $true
            break
        }
    }
    if ($hasRingRelevantDuplicate) {
        throw 'Duplicate configuration ids were returned in deviceConfigurations; update-ring deadlines cannot be evaluated from conflicting rows.'
    }

    $updateRings = [System.Collections.Generic.List[object]]::new()
    $assignedRingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $knownQualifyingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($ringEntry in $allUpdateRings) {
        $ring = $ringEntry.Row
        $ringKey = [string] $ringEntry.Key
        $intent = ConvertTo-PulseAssignmentIntent -Assignments (Get-PulseSettingsCatalogValueProperty -Node $ring -PropertyName 'assignments')
        if ($intent.IsAssigned) {
            if ($assignedRingKeys.Add($ringKey)) {
                $updateRings.Add($ring) | Out-Null
            }
            if (& $hasDeadline $ring) {
                [void] $knownQualifyingKeys.Add($ringKey)
            }
        } elseif (-not $intent.Complete -and (& $hasDeadline $ring)) {
            [void] $potentialQualifyingKeys.Add($ringKey)
        }
    }

    $hasBroadPartialUncertainty = $false
    if ($outcomeState.IsPartial) {
        foreach ($gap in @($DatasetOutcomes['deviceConfigurations']['Gaps'])) {
            $scope = [string] (Get-PulseSettingsCatalogValueProperty -Node $gap -PropertyName 'Scope')
            if ($scope -match '^policy:(.+)/assignments$') {
                $gapConfigurationId = [string] $Matches[1]
            } else {
                $hasBroadPartialUncertainty = $true
                continue
            }

            if (-not $configurationRowsById.ContainsKey($gapConfigurationId) -or
                ($duplicateConfigurationIds.Contains($gapConfigurationId) -and $ringRelevantConfigurationIds.Contains($gapConfigurationId))) {
                $hasBroadPartialUncertainty = $true
                continue
            }

            $gapConfigurationType = [string] (Get-PulseSettingsCatalogValueProperty -Node $configurationRowsById[$gapConfigurationId] -PropertyName '@odata.type')
            if ([string]::IsNullOrWhiteSpace($gapConfigurationType) -or -not $knownConfigurationTypes.ContainsKey($gapConfigurationType)) {
                if (& $hasDeadline $configurationRowsById[$gapConfigurationId]) {
                    [void] $potentialQualifyingKeys.Add("id:$gapConfigurationId")
                }
            } elseif ([string]::Equals($gapConfigurationType, '#microsoft.graph.windowsUpdateForBusinessConfiguration', [System.StringComparison]::OrdinalIgnoreCase) -and
                (& $hasDeadline $configurationRowsById[$gapConfigurationId])) {
                [void] $potentialQualifyingKeys.Add("id:$gapConfigurationId")
            }
        }
    }

    foreach ($knownQualifyingKey in $knownQualifyingKeys) {
        [void] $potentialQualifyingKeys.Remove($knownQualifyingKey)
    }

    $ringsWithDeadlines = @($updateRings | Where-Object { & $hasDeadline $_ })

    if ($ringsWithDeadlines.Count -ge 2) {
        $evidence = @($ringsWithDeadlines | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName } } })
        return New-PulseFinding -Status Pass -Reason "$($ringsWithDeadlines.Count) Windows Update rings have deadlines configured." -Evidence $evidence
    }

    if ($hasBroadPartialUncertainty -or
        ($ringsWithDeadlines.Count + $potentialQualifyingKeys.Count) -ge 2) {
        return New-PulseFinding -Status NotApplicable -Reason "Only $($ringsWithDeadlines.Count) known assigned Windows Update ring(s) have deadlines, with $($potentialQualifyingKeys.Count) additional possible qualifying ring(s); configuration type evidence, partial root evidence, or relevant assignment evidence is unresolved, so fewer than 2 cannot be proven."
    }

    $ringsWithoutDeadlines = @($updateRings | Where-Object { -not (& $hasDeadline $_) })
    $evidence = @($ringsWithoutDeadlines | ForEach-Object { @{ Identity = [string] $_.id; Detail = @{ displayName = $_.displayName; hasDeadline = $false } } })

    return New-PulseFinding -Status Fail -Reason "Only $($ringsWithDeadlines.Count) of $($updateRings.Count) Windows Update ring(s) have deadlines configured; Microsoft's staged-rollout guidance recommends at least 2 rings (pilot + broad), each with a deadline, so updates cannot be deferred indefinitely." -Evidence $evidence
}
