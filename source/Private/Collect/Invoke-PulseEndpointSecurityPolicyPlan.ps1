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
        [string] $TenantPseudonym
    )

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
    $operations = [System.Collections.Generic.List[string]]::new()
    $operations.Add('ListBeta') | Out-Null

    $isBitLocker = $Dataset -eq 'endpointSecurityDiskEncryptionPolicies'
    $isLaps = $Dataset -eq 'endpointSecurityLapsPolicies'
    if (-not $isBitLocker -and -not $isLaps) {
        throw "Invoke-PulseEndpointSecurityPolicyPlan: unsupported dataset '$Dataset'."
    }

    function Convert-EndpointFailureClass {
        param([System.Management.Automation.ErrorRecord] $ErrorRecord)
        $classified = Get-PulseFailureClass -ErrorRecord $ErrorRecord
        switch ($classified) {
            'PermissionDenied' { return 'PermissionDenied' }
            'AuthFailure' { return 'AuthenticationFailed' }
            default { return 'ProviderFailed' }
        }
    }

    function Get-EndpointFailureReasonCode {
        param([string] $FailureClass)
        switch ($FailureClass) {
            'PermissionDenied' { return 'permission-denied' }
            'AuthenticationFailed' { return 'authentication-failed' }
            default { return 'provider-failed' }
        }
    }

    $policies = @()
    try {
        $policies = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicy' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $failureClass = Convert-EndpointFailureClass -ErrorRecord $_
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass $failureClass -ReasonCode (Get-EndpointFailureReasonCode -FailureClass $failureClass) `
            -Detail @{ operation = 'ConfigurationPolicy.ListBeta' } -Provider 'GraphKit' -ApiVersion $apiVersion `
            -Operations $operations.ToArray()
    }

    $selectedPolicies = [System.Collections.Generic.List[object]]::new()
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
    $gaps = [System.Collections.Generic.List[object]]::new()
    foreach ($selectedPolicy in $selected) {
        $policyId = [string] $selectedPolicy.PolicyId
        $settings = @()
        $operations.Add('ListBeta') | Out-Null
        try {
            $settings = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicySetting' -Operation 'ListBeta' `
                    -Parameters @{ id = $policyId } -ErrorAction Stop)
        } catch {
            $failureClass = Convert-EndpointFailureClass -ErrorRecord $_
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId" -FailureClass $failureClass `
                    -ReasonCode (Get-EndpointFailureReasonCode -FailureClass $failureClass) `
                    -Detail @{ policyId = $policyId } -Operation 'ListBeta' -ApiVersion 'beta')) | Out-Null
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
                    -Operation 'ListBeta' -ApiVersion 'beta')) | Out-Null
        }
    }

    $rowArray = $rows.ToArray()
    $gapArray = $gaps.ToArray()
    if ($gapArray.Count -eq 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Collected' -Rows $rowArray -Gaps @() `
            -ReasonCode 'collected' -Detail @{ policyCount = $rowArray.Count } -Provider 'GraphKit' `
            -ApiVersion $apiVersion -Operations $operations.ToArray()
    }
    if ($rowArray.Count -gt 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Partial' -Rows $rowArray -Gaps $gapArray `
            -ReasonCode 'partial' -Detail @{ policyCount = $rowArray.Count; gapCount = $gapArray.Count } `
            -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations.ToArray()
    }

    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gapArray `
        -FailureClass 'ProviderFailed' -ReasonCode 'provider-failed' -Detail @{ gapCount = $gapArray.Count } `
        -Provider 'GraphKit' -ApiVersion $apiVersion -Operations $operations.ToArray()
}
