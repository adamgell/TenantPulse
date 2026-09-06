<#
    TenantPulse-owned composite collection for TP.INT.0014 and TP.INT.0015.

    GraphKit supplies the released ConfigurationPolicy.ListBeta,
    ConfigurationPolicySetting.ListBeta, and ConfigurationPolicyAssignment.ListBeta
    primitives. This plan performs the template-family filter, sequential per-policy
    child reads, and compact row resolution. Missing or unrecognized template metadata,
    a child-read failure, an incomplete assignment classification, or an invalid child
    value remains scoped to its policy and cannot become an authoritative empty collection
    or a false check result.
#>

function ConvertTo-PulseEndpointSecurityAssignmentGapReasons {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $MalformedReasons = @(),

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $State
    )

    # ConvertTo-PulseAssignmentIntent may name an unfamiliar Graph target type in its
    # diagnostic suffix. Provider gaps are persisted evidence, so keep only a finite
    # vocabulary here and never copy raw target-derived values into Detail.
    $safeReasons = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($reason in @($MalformedReasons)) {
        $reasonText = [string] $reason
        $safeReason = switch -Regex ($reasonText) {
            '^null-assignment$'                       { 'null-assignment'; break }
            '^missing-target-type$'                   { 'missing-target-type'; break }
            '^missing-scope-tag-target-type$'         { 'missing-scope-tag-target-type'; break }
            '^unsupported-scope-tag-target-type(?::.*)?$' { 'unsupported-scope-tag-target-type'; break }
            '^missing-entra-object-id$'                { 'missing-entra-object-id'; break }
            '^missing-group-id$'                       { 'missing-group-id'; break }
            '^unknown-target-type(?::.*)?$'            { 'unknown-target-type'; break }
            default                                    { 'unrecognized-assignment-shape' }
        }
        [void] $safeReasons.Add($safeReason)
    }

    if ($safeReasons.Count -eq 0) {
        $fallback = if ([string]::Equals($State, 'Unknown', [System.StringComparison]::OrdinalIgnoreCase)) {
            'assignment-intent-unknown'
        } else {
            'assignment-target-malformed'
        }
        [void] $safeReasons.Add($fallback)
    }

    return @(ConvertTo-PulseOrdinalStringArray -Values $safeReasons)
}

function Invoke-PulseEndpointSecurityPolicyPlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Context,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Dataset,

        [Parameter(Mandatory)]
        [pscustomobject] $ManifestEntry,

        [Parameter(Mandatory)]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [string] $TenantPseudonym,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $NetworkAbortState = $null
    )

    if ($null -eq $NetworkAbortState) {
        $NetworkAbortState = [pscustomobject]@{ AuthenticationAborted = $false; Reason = $null }
    }

    # These parameters are part of the common provider-plan contract. The plan deliberately
    # passes the same immutable Context instance to every GraphKit call.
    $null = $ProfileId
    $null = $TenantPseudonym

    $descriptorSpecs = @(
        @{ Type = 'ConfigurationPolicy'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'ConfigurationPolicyAssignment'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    )
    foreach ($spec in $descriptorSpecs) {
        Assert-PulseReadOnlyDescriptor -Type $spec.Type -Operation $spec.Operation -ApiVersion $spec.ApiVersion
    }

    $apiVersion = if ($ManifestEntry.PSObject.Properties['ApiVersion'] -and $ManifestEntry.ApiVersion) {
        [string] $ManifestEntry.ApiVersion
    } else {
        'beta'
    }
    $operations = @(
        'ConfigurationPolicy.ListBeta'
        'ConfigurationPolicySetting.ListBeta'
        'ConfigurationPolicyAssignment.ListBeta'
    )

    $isBitLocker = $Dataset -eq 'endpointSecurityDiskEncryptionPolicies'
    $isLaps = $Dataset -eq 'endpointSecurityLapsPolicies'
    if (-not $isBitLocker -and -not $isLaps) {
        throw "Invoke-PulseEndpointSecurityPolicyPlan: unsupported dataset '$Dataset'."
    }

    $policies = @()
    try {
        $policies = @(Invoke-PulseGraphRead -Context $Context -Type 'ConfigurationPolicy' -Operation 'ListBeta')

    } catch {
        $failure = Resolve-PulseGraphFailure -ErrorRecord $_
        if ($failure.AbortCollection) {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = 'authentication-failed: collection aborted'
        }
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass $failure.FailureClass -ReasonCode $failure.ReasonCode `
            -Detail @{ operation = 'ConfigurationPolicy.ListBeta' } -Provider 'GraphKit' -ApiVersion $apiVersion `
            -Operations $operations
    }

    $selectedPolicies = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $expandedCount = 0
    $partialCount = 0
    $notExpandedCount = 0
    $recognizedTemplateFamilies = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($knownFamily in @(
            'none'
            'endpointSecurityAntivirus'
            'endpointSecurityDiskEncryption'
            'endpointSecurityFirewall'
            'endpointSecurityEndpointDetectionAndResponse'
            'endpointSecurityAttackSurfaceReduction'
            'endpointSecurityAccountProtection'
            'endpointSecurityApplicationControl'
            'endpointSecurityEndpointPrivilegeManagement'
            'enrollmentConfiguration'
            'appQuietTime'
            'deviceConfigurationScripts'
            'deviceConfigurationPolicies'
            'windowsOsRecoveryPolicies'
            'companyPortal'
            'advancedThreatProtection'
            'baseline'
            'baselineDefenderForEndpoint'
            'baselineMicrosoftEdge'
            'baselineWindows365'
        )) {
        $recognizedTemplateFamilies.Add($knownFamily) | Out-Null
    }

    foreach ($policy in $policies) {
        if ($null -eq $policy) {
            $notExpandedCount++
            $gaps.Add((New-PulseCollectionGap -Scope 'policy:unknown' -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'missing-template-metadata' -Detail @{ missing = 'policy-or-templateReference' } `
                    -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta')) | Out-Null
            continue
        }
        $policyId = [string] (Get-PulseEndpointSecurityNodeProperty -Node $policy -PropertyName 'id')
        $scope = if ([string]::IsNullOrWhiteSpace($policyId)) { 'policy:unknown' } else { "policy:$policyId" }
        $templateReference = Get-PulseEndpointSecurityNodeProperty -Node $policy -PropertyName 'templateReference'
        $templateFamily = [string] (Get-PulseEndpointSecurityNodeProperty -Node $templateReference -PropertyName 'templateFamily')
        if ($null -eq $templateReference -or [string]::IsNullOrWhiteSpace($templateFamily)) {
            $notExpandedCount++
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'missing-template-metadata' -Detail @{ missing = 'templateReference.templateFamily' } `
                    -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta')) | Out-Null
            continue
        }
        if (-not $recognizedTemplateFamilies.Contains($templateFamily)) {
            $notExpandedCount++
            $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'unrecognized-template-metadata' -Detail @{ templateFamily = $templateFamily } `
                    -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta')) | Out-Null
            continue
        }
        if ($isBitLocker) {
            if (-not [string]::Equals($templateFamily, 'endpointSecurityDiskEncryption', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
        } else {
            $templateId = [string] (Get-PulseEndpointSecurityNodeProperty -Node $templateReference -PropertyName 'templateId')
            if (-not [string]::Equals($templateFamily, 'endpointSecurityAccountProtection', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            if ([string]::IsNullOrWhiteSpace($templateId)) {
                $notExpandedCount++
                $gaps.Add((New-PulseCollectionGap -Scope $scope -FailureClass 'InvalidProviderData' `
                        -ReasonCode 'missing-template-metadata' -Detail @{ missing = 'templateReference/templateId' } `
                        -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta')) | Out-Null
                continue
            }
            if (-not [string]::Equals($templateId, 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
        }

        if ([string]::IsNullOrWhiteSpace($policyId)) {
            $notExpandedCount++
            $gaps.Add((New-PulseCollectionGap -Scope 'policy:unknown' -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'missing-policy-id' -Detail @{ missing = 'id' } `
                    -Operation 'ConfigurationPolicy.ListBeta' -ApiVersion 'beta')) | Out-Null
            continue
        }
        $policyName = [string] (Get-PulseEndpointSecurityNodeProperty -Node $policy -PropertyName 'name')
        if ([string]::IsNullOrWhiteSpace($policyName)) { $policyName = $policyId }
        $selectedPolicies.Add([pscustomobject][ordered]@{
                PolicyId   = $policyId
                PolicyName = $policyName
                Policy     = $policy
            }) | Out-Null
    }

    $selected = @($selectedPolicies.ToArray())
    if ($selected.Count -gt 1) {
        $comparison = [System.Comparison[object]] {
            param($left, $right)
            $idComparison = [string]::CompareOrdinal([string] $left.PolicyId, [string] $right.PolicyId)
            if ($idComparison -ne 0) { return $idComparison }
            return [string]::CompareOrdinal([string] $left.PolicyName, [string] $right.PolicyName)
        }
        [System.Array]::Sort($selected, $comparison)
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    for ($selectedIndex = 0; $selectedIndex -lt $selected.Count; $selectedIndex++) {
        $selectedPolicy = $selected[$selectedIndex]
        $policyId = [string] $selectedPolicy.PolicyId
        $settings = @()
        try {
            $settings = @(Invoke-PulseGraphRead -Context $Context -Type 'ConfigurationPolicySetting' -Operation 'ListBeta' `
                    -Parameters @{ id = $policyId })

        } catch {
            $failure = Resolve-PulseGraphFailure -ErrorRecord $_
            $notExpandedCount++
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId" -FailureClass $failure.FailureClass `
                    -ReasonCode $failure.ReasonCode `
                    -Detail @{ policyId = $policyId } `
                    -Operation 'ConfigurationPolicySetting.ListBeta' -ApiVersion 'beta')) | Out-Null
            if ($failure.AbortCollection) {
                $NetworkAbortState.AuthenticationAborted = $true
                $NetworkAbortState.Reason = 'authentication-failed: collection aborted'
                for ($remainingIndex = $selectedIndex + 1; $remainingIndex -lt $selected.Count; $remainingIndex++) {
                    $remainingPolicyId = [string] $selected[$remainingIndex].PolicyId
                    $notExpandedCount++
                    $gaps.Add((New-PulseCollectionGap -Scope "policy:$remainingPolicyId" `
                            -FailureClass 'AuthenticationFailed' `
                            -ReasonCode 'not-attempted-after-authentication-failure' `
                            -Detail @{ policyId = $remainingPolicyId } `
                            -Operation 'ConfigurationPolicySetting.ListBeta' -ApiVersion 'beta')) | Out-Null
                }
                break
            }
            continue
        }
        $assignmentIntentResult = $null
        try {
            $assignmentRows = @(Invoke-PulseGraphRead -Context $Context -Type 'ConfigurationPolicyAssignment' -Operation 'ListBeta' `
                    -Parameters @{ id = $policyId })
            $assignmentIntentResult = ConvertTo-PulseAssignmentIntent -Assignments $assignmentRows
        } catch {
            $failure = Resolve-PulseGraphFailure -ErrorRecord $_
            $notExpandedCount++
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId" -FailureClass $failure.FailureClass `
                    -ReasonCode $failure.ReasonCode `
                    -Detail @{ policyId = $policyId } `
                    -Operation 'ConfigurationPolicyAssignment.ListBeta' -ApiVersion 'beta')) | Out-Null
            if ($failure.AbortCollection) {
                $NetworkAbortState.AuthenticationAborted = $true
                $NetworkAbortState.Reason = 'authentication-failed: collection aborted'
                for ($remainingIndex = $selectedIndex + 1; $remainingIndex -lt $selected.Count; $remainingIndex++) {
                    $remainingPolicyId = [string] $selected[$remainingIndex].PolicyId
                    $notExpandedCount++
                    $gaps.Add((New-PulseCollectionGap -Scope "policy:$remainingPolicyId" `
                            -FailureClass 'AuthenticationFailed' `
                            -ReasonCode 'not-attempted-after-authentication-failure' `
                            -Detail @{ policyId = $remainingPolicyId } `
                            -Operation 'ConfigurationPolicyAssignment.ListBeta' -ApiVersion 'beta')) | Out-Null
                }
                break
            }
            continue
        }

        $assignmentIntent = [string] $assignmentIntentResult.State
        if ($assignmentIntent -notin @('Empty', 'ExcludeOnly', 'Include', 'Malformed', 'Unknown')) {
            $assignmentIntent = 'Unknown'
        }
        $assignmentComplete = [bool] $assignmentIntentResult.Complete
        if ($assignmentIntent -in @('Malformed', 'Unknown')) {
            $assignmentComplete = $false
        } elseif (-not $assignmentComplete) {
            # An incomplete result can never leave a qualifying Include value on the row,
            # even if a future classifier accidentally returns an inconsistent record.
            $assignmentIntent = 'Unknown'
        }
        if (-not $assignmentComplete) {
            $safeMalformedReasons = @(ConvertTo-PulseEndpointSecurityAssignmentGapReasons `
                    -MalformedReasons @($assignmentIntentResult.MalformedReasons) -State $assignmentIntent)
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'assignment-intent-incomplete' `
                    -Detail @{
                        policyId         = $policyId
                        assignmentState  = $assignmentIntent
                        malformedReasons = $safeMalformedReasons
                    } `
                    -Operation 'ConfigurationPolicyAssignment.ListBeta' -ApiVersion 'beta')) | Out-Null
        }

        try {
            if ($isBitLocker) {
                $isFullDiskEncryption = Resolve-PulseBitLockerPolicyValue -Settings $settings
                $rows.Add([pscustomobject][ordered]@{
                        policyId             = $policyId
                        policyName           = [string] $selectedPolicy.PolicyName
                        isFullDiskEncryption = [bool] $isFullDiskEncryption
                        assignmentIntent     = $assignmentIntent
                    }) | Out-Null
            } else {
                $lapsValues = Resolve-PulseLapsPolicyValues -Settings $settings
                $rows.Add([pscustomobject][ordered]@{
                        policyId                = $policyId
                        policyName              = [string] $selectedPolicy.PolicyName
                        backsUpToEntra          = [bool] $lapsValues.backsUpToEntra
                        hasSufficientComplexity = [bool] $lapsValues.hasSufficientComplexity
                        hasSufficientLength     = [bool] $lapsValues.hasSufficientLength
                        hasPostAuthAction       = [bool] $lapsValues.hasPostAuthAction
                        assignmentIntent        = $assignmentIntent
                    }) | Out-Null
            }
            if ($assignmentComplete) {
                $expandedCount++
            } else {
                $partialCount++
            }
        } catch {
            $reasonCode = if ($_.Exception.Message -match '(?i)unknown') { 'unknown-setting' } else { 'missing-setting' }
            $partialCount++
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode $reasonCode -Detail @{ policyId = $policyId } `
                    -Operation 'ConfigurationPolicySetting.ListBeta' -ApiVersion 'beta')) | Out-Null
        }
    }

    $rowArray = $rows.ToArray()
    $gapArray = $gaps.ToArray()
    $enumeratedCount = $expandedCount + $partialCount + $notExpandedCount
    $terminalDetail = New-PulseCompositeTerminalDetail -EnumeratedCount $enumeratedCount -ExpandedCount $expandedCount `
        -PartialCount $partialCount -NotExpandedCount $notExpandedCount `
        -Extra @{ policyCount = $rowArray.Count; gapCount = $gapArray.Count }
    if ($gapArray.Count -eq 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Collected' -Rows $rowArray -Gaps @() `
            -ReasonCode 'collected' -Detail $terminalDetail -Provider 'GraphKit' `
            -ApiVersion $apiVersion -Operations $operations
    }
    if ($rowArray.Count -gt 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Partial' -Rows $rowArray -Gaps $gapArray `
            -ReasonCode 'partial' -Detail $terminalDetail `
            -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations
    }

    if ($NetworkAbortState.AuthenticationAborted) {
        $topFailureClass = 'AuthenticationFailed'
        $topReasonCode = 'authentication-failed'
    } else {
        $topFailureClass = [string] $gapArray[0].FailureClass
        $topReasonCode = [string] $gapArray[0].ReasonCode
        foreach ($gap in $gapArray) {
            if ([string] $gap.FailureClass -ne $topFailureClass -or
                [string] $gap.ReasonCode -ne $topReasonCode) {
                $topFailureClass = 'ProviderFailed'
                $topReasonCode = 'provider-failed'
                break
            }
        }
    }
    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gapArray `
        -FailureClass $topFailureClass -ReasonCode $topReasonCode -Detail $terminalDetail `
        -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations

}
