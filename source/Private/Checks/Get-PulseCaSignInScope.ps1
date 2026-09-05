<#
    Classifies the non-user, non-resource conditions that determine a Conditional Access
    policy's effective sign-in scope. Known narrowing never establishes universal coverage;
    missing or malformed required evidence remains incomplete.
#>
function Get-PulseCaSignInScope {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $PolicyView,

        [Parameter(Mandatory)]
        [ValidateSet('Mfa', 'Legacy')]
        [string] $Mode
    )

    $narrowReasons = [System.Collections.Generic.List[string]]::new()
    $incompleteReasons = [System.Collections.Generic.List[string]]::new()
    $coversExchangeActiveSync = $false
    $coversOther = $false
    $couldCoverExchangeActiveSync = $false
    $couldCoverOther = $false

    if ($null -eq $PolicyView) {
        $incompleteReasons.Add('missing-policy-view')
    }
    $conditions = if ($null -ne $PolicyView) {
        Get-PulseSettingsCatalogValueProperty -Node $PolicyView -PropertyName 'conditions'
    } else { $null }
    if ($null -eq $conditions -or -not [bool] (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'present')) {
        $incompleteReasons.Add('missing-conditions')
    }
    if ($null -ne $conditions -and [bool] (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'timesPresent')) {
        $narrowReasons.Add('time-condition-scope')
    }
    $unknownConditionPropertyCount = if ($null -ne $conditions) {
        [int] (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'unknownConditionPropertyCount')
    } else { 0 }
    if ($unknownConditionPropertyCount -gt 0) {
        $incompleteReasons.Add('unrecognized-condition-property')
    }

    [string[]] $clientAppTypes = @()
    if ($null -ne $conditions) {
        $rawClientAppTypes = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'clientAppTypes'
        if ($null -ne $rawClientAppTypes -and @($rawClientAppTypes).Count -gt 0) {
            $clientAppTypes = [string[]] @($rawClientAppTypes)
        }
    }
    $clientAppTypesPresent = $null -ne $conditions -and [bool] (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'clientAppTypesPresent')
    if (-not $clientAppTypesPresent -or $clientAppTypes.Count -eq 0) {
        $incompleteReasons.Add('missing-client-app-types')
        if ($Mode -eq 'Legacy') {
            $couldCoverExchangeActiveSync = $true
            $couldCoverOther = $true
        }
    } else {
        if (@($clientAppTypes | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            $incompleteReasons.Add('blank-client-app-type')
        }
        $normalizedTypes = @($clientAppTypes |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim().ToLowerInvariant() })
        if ($normalizedTypes.Count -eq 0) {
            if ($Mode -eq 'Legacy') {
                $couldCoverExchangeActiveSync = $true
                $couldCoverOther = $true
            }
        } else {
            $recognizedTypes = @('all', 'browser', 'mobileappsanddesktopclients', 'exchangeactivesync', 'eassupported', 'other')
            $recognizedDeclaredTypes = @($normalizedTypes | Where-Object { $_ -in $recognizedTypes })
            if (@($normalizedTypes | Where-Object { $_ -notin $recognizedTypes }).Count -gt 0) {
                $incompleteReasons.Add('unrecognized-client-app-type')
            }
            if ($normalizedTypes -contains 'all' -and $normalizedTypes.Count -ne 1) {
                $incompleteReasons.Add('contradictory-all-client-app-types')
            }

            # Preserve the lower bound established by every recognized enum member even
            # when a sibling is unknown. A future enum value is a distinct category; it
            # cannot silently alias Graph's existing `all`, `exchangeActiveSync`, or `other`
            # members and broaden those known buckets.
            if ($Mode -eq 'Mfa') {
                if ($recognizedDeclaredTypes -notcontains 'all') {
                    $narrowReasons.Add('client-app-types-not-all')
                }
            } else {
                if ($recognizedDeclaredTypes -contains 'all') {
                    $coversExchangeActiveSync = $true
                    $coversOther = $true
                } else {
                    $coversExchangeActiveSync = $recognizedDeclaredTypes -contains 'exchangeactivesync'
                    $coversOther = $recognizedDeclaredTypes -contains 'other'
                    if (-not $coversExchangeActiveSync -and -not $coversOther) {
                        $narrowReasons.Add('no-legacy-client-app-type')
                    }
                }
                $couldCoverExchangeActiveSync = $coversExchangeActiveSync
                $couldCoverOther = $coversOther
            }
        }
    }

    foreach ($dimension in @(
        @{ Name = 'platform'; NodeName = 'platforms'; IncludeName = 'includePlatforms'; ExcludeName = 'excludePlatforms'; All = 'all' }
        @{ Name = 'location'; NodeName = 'locations'; IncludeName = 'includeLocations'; ExcludeName = 'excludeLocations'; All = 'all' }
    )) {
        if ($null -eq $conditions) { continue }

        $node = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName $dimension.NodeName
        if ($null -eq $node -or -not [bool] (Get-PulseSettingsCatalogValueProperty -Node $node -PropertyName 'present')) { continue }
        [string[]] $included = @()
        [string[]] $excluded = @()
        $rawIncluded = Get-PulseSettingsCatalogValueProperty -Node $node -PropertyName $dimension.IncludeName
        $rawExcluded = Get-PulseSettingsCatalogValueProperty -Node $node -PropertyName $dimension.ExcludeName
        if ($null -ne $rawIncluded -and @($rawIncluded).Count -gt 0) { $included = [string[]] @($rawIncluded) }
        if ($null -ne $rawExcluded -and @($rawExcluded).Count -gt 0) { $excluded = [string[]] @($rawExcluded) }
        [string[]] $validIncluded = @($included | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        [string[]] $validExcluded = @($excluded | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($included.Count -eq 0) {
            if ($validExcluded.Count -gt 0) {
                # A known exclusion proves this condition cannot be universal even when
                # its required include selector is missing and the full shape is invalid.
                $narrowReasons.Add("narrow-$($dimension.Name)-scope")
            }
            $incompleteReasons.Add("invalid-$($dimension.Name)-scope")
            continue
        }

        if ($validIncluded.Count -ne $included.Count -or $validExcluded.Count -ne $excluded.Count) {
            $incompleteReasons.Add("invalid-$($dimension.Name)-scope")
        }

        $allCount = @($validIncluded | Where-Object { [string]::Equals($_, $dimension.All, [System.StringComparison]::OrdinalIgnoreCase) }).Count
        if ($allCount -gt 0 -and $validIncluded.Count -ne 1) {
            $incompleteReasons.Add("contradictory-all-$($dimension.Name)-scope")
        }
        if (($allCount -eq 0 -and $validIncluded.Count -gt 0) -or $validExcluded.Count -gt 0) {
            $narrowReasons.Add("narrow-$($dimension.Name)-scope")
        }
    }

    foreach ($risk in @(
        @{ Name = 'sign-in-risk'; Values = 'signInRisk'; Present = 'signInRiskPresent' }
        @{ Name = 'user-risk'; Values = 'userRisk'; Present = 'userRiskPresent' }
        @{ Name = 'service-principal-risk'; Values = 'servicePrincipalRisk'; Present = 'servicePrincipalRiskPresent' }
        @{ Name = 'insider-risk'; Values = 'insiderRisk'; Present = 'insiderRiskPresent' }
    )) {
        if ($null -eq $conditions -or -not [bool] (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName $risk.Present)) { continue }
        [string[]] $values = @()
        $rawValues = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName $risk.Values
        if ($null -ne $rawValues -and @($rawValues).Count -gt 0) { $values = [string[]] @($rawValues) }
        # Graph may serialize an unconfigured optional risk collection as an explicit
        # empty array. That is a complete "no risk filter" value, not missing evidence.
        if ($values.Count -eq 0) { continue }
        [string[]] $validValues = @($values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($validValues.Count -ne $values.Count) {
            $incompleteReasons.Add("invalid-$($risk.Name)-scope")
        }
        if ($validValues.Count -gt 0) {
            $narrowReasons.Add("narrow-$($risk.Name)-scope")
        }
    }

    if ($null -ne $conditions -and [bool] (Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'agentIdRiskPresent')) {
        [string[]] $agentIdRiskLevels = @()
        $rawAgentIdRiskLevels = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'agentIdRisk'
        if ($null -ne $rawAgentIdRiskLevels -and @($rawAgentIdRiskLevels).Count -gt 0) {
            $agentIdRiskLevels = [string[]] @($rawAgentIdRiskLevels)
        }
        if ($agentIdRiskLevels.Count -gt 0) {
            $normalizedAgentRisk = @($agentIdRiskLevels | ForEach-Object {
                if ($null -eq $_) { '' } else { ([string] $_).Trim().ToLowerInvariant() }
            })
            $recognizedAgentRisk = @($normalizedAgentRisk | Where-Object { $_ -in @('low', 'medium', 'high', 'unknownfuturevalue') })
            if ($recognizedAgentRisk.Count -ne $normalizedAgentRisk.Count) {
                $incompleteReasons.Add('invalid-agent-id-risk-scope')
            }
            if (@($normalizedAgentRisk | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
                # Even an unknown nonblank enum member proves that a risk condition is
                # configured. Unknown validity cannot broaden that known scope to all.
                $narrowReasons.Add('narrow-agent-id-risk-scope')
            }
        }
    }

    if ($null -ne $conditions) {
        $clientApplications = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'clientApplications'
        if ($null -ne $clientApplications -and [bool] (Get-PulseSettingsCatalogValueProperty -Node $clientApplications -PropertyName 'present')) {
            $workloadScope = Get-PulseCaWorkloadIdentityScope -ClientApplications $clientApplications
            $hasDeclaredWorkloadSelector = $false
            foreach ($selectorName in @(
                'includeServicePrincipals', 'excludeServicePrincipals',
                'includeAgentIdServicePrincipals', 'excludeAgentIdServicePrincipals'
            )) {
                $selectorValues = Get-PulseSettingsCatalogValueProperty -Node $clientApplications -PropertyName $selectorName
                if (@($selectorValues | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) }).Count -gt 0) {
                    $hasDeclaredWorkloadSelector = $true
                }
            }
            if ($null -ne (Get-PulseSettingsCatalogValueProperty -Node $clientApplications -PropertyName 'servicePrincipalFilter') -or
                $null -ne (Get-PulseSettingsCatalogValueProperty -Node $clientApplications -PropertyName 'agentIdServicePrincipalFilter')) {
                $hasDeclaredWorkloadSelector = $true
            }
            if ($workloadScope.HasValidInclude -or $hasDeclaredWorkloadSelector) {
                # Selector validity controls completeness, but any observed workload-
                # identity selector still proves this is not an all-user sign-in scope.
                $narrowReasons.Add('workload-identity-client-application-scope')
            }
            if ($workloadScope.State -ne 'Valid') {
                $incompleteReasons.Add('invalid-client-application-scope')
            }
        }

        $devices = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'devices'
        if ($null -ne $devices -and [bool] (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'present')) {
            $filterPresent = [bool] (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'filterPresent')
            $filterMode = [string] (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'filterMode')
            $filterRule = [string] (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'filterRule')
            $filterValid = $filterPresent -and $filterMode -in @('include', 'exclude') -and
                -not [string]::IsNullOrWhiteSpace($filterRule)
            $currentSelectorPresent = [bool] (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'includeDevicesPresent') -or
                [bool] (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'excludeDevicesPresent')
            $deprecatedSelectorPresent = [bool] (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'includeDeviceStatesPresent') -or
                [bool] (Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName 'excludeDeviceStatesPresent')

            if ($filterValid) {
                $narrowReasons.Add('device-filter')
            }
            foreach ($selector in @(
                @{ Present = $currentSelectorPresent; Include = 'includeDevices'; Exclude = 'excludeDevices' }
                @{ Present = $deprecatedSelectorPresent; Include = 'includeDeviceStates'; Exclude = 'excludeDeviceStates' }
            )) {
                if (-not $selector.Present) { continue }
                $knownIncluded = @((Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName $selector.Include) |
                    ForEach-Object { if ($null -eq $_) { '' } else { ([string] $_).Trim().ToLowerInvariant() } } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                $knownExcluded = @((Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName $selector.Exclude) |
                    ForEach-Object { if ($null -eq $_) { '' } else { ([string] $_).Trim().ToLowerInvariant() } } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                $includesAll = @($knownIncluded | Where-Object { $_ -eq 'all' }).Count -gt 0
                if ($knownExcluded.Count -gt 0 -and -not $narrowReasons.Contains('device-selector-exclusion')) {
                    # Any observed exclusion prevents universal scope even when the
                    # required include selector is missing or another value is unknown.
                    $narrowReasons.Add('device-selector-exclusion')
                }
                if ($knownIncluded.Count -gt 0 -and -not $includesAll -and
                    -not $narrowReasons.Contains('device-selector-scope')) {
                    $narrowReasons.Add('device-selector-scope')
                }
            }

            if (($filterPresent -and ($currentSelectorPresent -or $deprecatedSelectorPresent)) -or
                ($currentSelectorPresent -and $deprecatedSelectorPresent)) {
                $incompleteReasons.Add('conflicting-device-scope')
            } elseif ($filterPresent) {
                if (-not $filterValid) {
                    $incompleteReasons.Add('invalid-device-filter')
                }
            } elseif ($currentSelectorPresent -or $deprecatedSelectorPresent) {
                $includeName = if ($currentSelectorPresent) { 'includeDevices' } else { 'includeDeviceStates' }
                $excludeName = if ($currentSelectorPresent) { 'excludeDevices' } else { 'excludeDeviceStates' }
                [string[]] $includedDevices = @((Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName $includeName))
                [string[]] $excludedDevices = @((Get-PulseSettingsCatalogValueProperty -Node $devices -PropertyName $excludeName))
                $normalizedIncludedDevices = @($includedDevices | ForEach-Object { if ($null -eq $_) { '' } else { $_.Trim().ToLowerInvariant() } })
                $normalizedExcludedDevices = @($excludedDevices | ForEach-Object { if ($null -eq $_) { '' } else { $_.Trim().ToLowerInvariant() } })
                if ($normalizedIncludedDevices.Count -ne 1 -or $normalizedIncludedDevices[0] -ne 'all' -or
                    @($normalizedExcludedDevices | Where-Object { $_ -notin @('compliant', 'domainjoined') }).Count -gt 0) {
                    $incompleteReasons.Add('invalid-device-selector-scope')
                } elseif ($normalizedExcludedDevices.Count -gt 0 -and -not $narrowReasons.Contains('device-selector-exclusion')) {
                    $narrowReasons.Add('device-selector-exclusion')
                }
            } else {
                $incompleteReasons.Add('invalid-device-scope')
            }
        }

        $deviceStates = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'deviceStates'
        if ($null -ne $deviceStates -and [bool] (Get-PulseSettingsCatalogValueProperty -Node $deviceStates -PropertyName 'present')) {
            [string[]] $includedStates = @((Get-PulseSettingsCatalogValueProperty -Node $deviceStates -PropertyName 'includeStates'))
            [string[]] $excludedStates = @((Get-PulseSettingsCatalogValueProperty -Node $deviceStates -PropertyName 'excludeStates'))
            $includeStatesPresent = [bool] (Get-PulseSettingsCatalogValueProperty -Node $deviceStates -PropertyName 'includeStatesPresent')
            $normalizedIncludedStates = @($includedStates | ForEach-Object { if ($null -eq $_) { '' } else { $_.Trim().ToLowerInvariant() } })
            $normalizedExcludedStates = @($excludedStates | ForEach-Object { if ($null -eq $_) { '' } else { $_.Trim().ToLowerInvariant() } })
            $knownIncludedStates = @($normalizedIncludedStates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $knownExcludedStates = @($normalizedExcludedStates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $includesAllStates = @($knownIncludedStates | Where-Object { $_ -eq 'all' }).Count -gt 0
            if ($knownExcludedStates.Count -gt 0) {
                $narrowReasons.Add('device-state-exclusion')
            }
            if ($knownIncludedStates.Count -gt 0 -and -not $includesAllStates) {
                $narrowReasons.Add('device-state-scope')
            }
            if (-not $includeStatesPresent -or $normalizedIncludedStates.Count -ne 1 -or $normalizedIncludedStates[0] -ne 'all' -or
                @($normalizedExcludedStates | Where-Object { $_ -notin @('compliant', 'domainjoined') }).Count -gt 0) {
                $incompleteReasons.Add('invalid-device-state-scope')
            }
        }

        $authenticationFlows = Get-PulseSettingsCatalogValueProperty -Node $conditions -PropertyName 'authenticationFlows'
        if ($null -ne $authenticationFlows -and [bool] (Get-PulseSettingsCatalogValueProperty -Node $authenticationFlows -PropertyName 'present')) {
            $transferMethods = [string] (Get-PulseSettingsCatalogValueProperty -Node $authenticationFlows -PropertyName 'transferMethods')
            if ([string]::IsNullOrWhiteSpace($transferMethods)) {
                $incompleteReasons.Add('invalid-authentication-flow-scope')
            } else {
                # conditionalAccessTransferMethods is an OData flags enum. Graph encodes
                # combined flags as one comma-separated string, not an array.
                [string[]] $methods = @($transferMethods -split ',' | ForEach-Object { $_.Trim() })
                $recognizedMethods = @('none', 'deviceCodeFlow', 'authenticationTransfer', 'unknownFutureValue')
                if (@($methods | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -notin $recognizedMethods }).Count -gt 0) {
                    $incompleteReasons.Add('invalid-authentication-flow-scope')
                }
                if (@($methods | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne 'none' }).Count -gt 0) {
                    # Every non-none flag scopes the policy to one or more transfer flows.
                    # Preserve that lower bound even when another flag is unrecognized.
                    $narrowReasons.Add('authentication-flow-scope')
                }
            }
        }
    }

    $state = if ($incompleteReasons.Count -gt 0) { 'Incomplete' }
    elseif ($narrowReasons.Count -gt 0) { 'Narrow' }
    else { 'Universal' }
    $reasons = if ($state -eq 'Narrow') { @($narrowReasons) } elseif ($state -eq 'Incomplete') { @($incompleteReasons) } else { @() }
    [pscustomobject][ordered]@{
        State                    = $state
        Complete                 = ($state -ne 'Incomplete')
        CouldBeUniversal         = ($narrowReasons.Count -eq 0)
        ReasonCode               = if (@($reasons).Count -gt 0) { @($reasons)[0] } else { $null }
        ReasonCodes              = [string[]] $reasons
        NarrowReasonCodes        = [string[]] @($narrowReasons)
        IncompleteReasonCodes    = [string[]] @($incompleteReasons)
        CoversExchangeActiveSync = $coversExchangeActiveSync
        CoversOther              = $coversOther
        CouldCoverExchangeActiveSync = $couldCoverExchangeActiveSync
        CouldCoverOther              = $couldCoverOther
    }
}
