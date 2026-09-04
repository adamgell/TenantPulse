<#
    TenantPulse-owned composite collection for TP.INT.0014 and TP.INT.0015.

    GraphKit supplies only the released ConfigurationPolicy.ListBeta and
    ConfigurationPolicySetting.ListBeta primitives. This plan performs the template-family
    filter, sequential per-policy settings reads, and compact row resolution. A settings
    failure or invalid child value remains scoped to its policy and cannot become an
    authoritative empty collection or a false check result.
#>

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
    )

    $isBitLocker = $Dataset -eq 'endpointSecurityDiskEncryptionPolicies'
    $isLaps = $Dataset -eq 'endpointSecurityLapsPolicies'
    if (-not $isBitLocker -and -not $isLaps) {
        throw "Invoke-PulseEndpointSecurityPolicyPlan: unsupported dataset '$Dataset'."
    }

    $policies = @()
    try {
        $policies = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicy' -Operation 'ListBeta' -ErrorAction Stop)
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
    foreach ($policy in $policies) {
        if ($null -eq $policy) { continue }
        $templateReference = Get-PulseEndpointSecurityNodeProperty -Node $policy -PropertyName 'templateReference'
        $templateFamily = [string] (Get-PulseEndpointSecurityNodeProperty -Node $templateReference -PropertyName 'templateFamily')
        if ($isBitLocker) {
            if (-not [string]::Equals($templateFamily, 'endpointSecurityDiskEncryption', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
        } else {
            $templateId = [string] (Get-PulseEndpointSecurityNodeProperty -Node $templateReference -PropertyName 'templateId')
            if (-not [string]::Equals($templateFamily, 'endpointSecurityAccountProtection', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
            if (-not [string]::Equals($templateId, 'adc46e5a-f4aa-4ff6-aeff-4f27bc525796', [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
        }

        $policyId = [string] (Get-PulseEndpointSecurityNodeProperty -Node $policy -PropertyName 'id')
        if ([string]::IsNullOrWhiteSpace($policyId)) {
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
    foreach ($selectedPolicy in $selected) {
        $policyId = [string] $selectedPolicy.PolicyId
        $settings = @()
        try {
            $settings = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicySetting' -Operation 'ListBeta' `
                    -Parameters @{ id = $policyId } -ErrorAction Stop)
        } catch {
            $failure = Resolve-PulseGraphFailure -ErrorRecord $_
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId" -FailureClass $failure.FailureClass `
                    -ReasonCode $failure.ReasonCode `
                    -Detail @{ policyId = $policyId } `
                    -Operation 'ConfigurationPolicySetting.ListBeta' -ApiVersion 'beta')) | Out-Null
            if ($failure.AbortCollection) {
                $NetworkAbortState.AuthenticationAborted = $true
                $NetworkAbortState.Reason = 'authentication-failed: collection aborted'
                break
            }
            continue
        }

        try {
            if ($isBitLocker) {
                $isFullDiskEncryption = Resolve-PulseBitLockerPolicyValue -Settings $settings
                $rows.Add([pscustomobject][ordered]@{
                        policyId              = $policyId
                        policyName            = [string] $selectedPolicy.PolicyName
                        isFullDiskEncryption  = [bool] $isFullDiskEncryption
                    }) | Out-Null
            } else {
                $lapsValues = Resolve-PulseLapsPolicyValues -Settings $settings
                $rows.Add([pscustomobject][ordered]@{
                        policyId               = $policyId
                        policyName             = [string] $selectedPolicy.PolicyName
                        backsUpToEntra         = [bool] $lapsValues.backsUpToEntra
                        hasSufficientComplexity = [bool] $lapsValues.hasSufficientComplexity
                        hasSufficientLength    = [bool] $lapsValues.hasSufficientLength
                        hasPostAuthAction      = [bool] $lapsValues.hasPostAuthAction
                    }) | Out-Null
            }
        } catch {
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId" -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'missing-setting' -Detail @{ policyId = $policyId; message = $_.Exception.Message } `
                    -Operation 'ConfigurationPolicySetting.ListBeta' -ApiVersion 'beta')) | Out-Null
        }
    }

    $rowArray = $rows.ToArray()
    $gapArray = $gaps.ToArray()
    if ($gapArray.Count -eq 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Collected' -Rows $rowArray -Gaps @() `
            -ReasonCode 'collected' -Detail @{ policyCount = $rowArray.Count } -Provider 'GraphKit' `
            -ApiVersion $apiVersion -Operations $operations
    }
    if ($rowArray.Count -gt 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Partial' -Rows $rowArray -Gaps $gapArray `
            -ReasonCode 'partial' -Detail @{ policyCount = $rowArray.Count; gapCount = $gapArray.Count } `
            -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations
    }

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
    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gapArray `
        -FailureClass $topFailureClass -ReasonCode $topReasonCode -Detail @{ gapCount = $gapArray.Count } `
        -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations
}
