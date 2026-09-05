<#
    Private: collect an Intune policy root and its authoritative per-policy assignments.

    GraphKit deliberately exposes one operation at a time. TenantPulse owns this bounded,
    sequential join for deviceCompliancePolicies and deviceConfigurations: one root List,
    followed by one assignment List for each unambiguous parent id. The result always
    carries an `assignments` property. A complete zero-row child is `@()`; unavailable or
    incomplete child evidence is `$null` plus a policy-scoped gap. Consumers can therefore
    distinguish authoritative absence from missing evidence without another Graph call.

    Parent and assignment ordering is ordinal and deterministic. Missing or duplicate
    parent ids are never used in a request path. A shared authentication abort stops the
    fan-out immediately and marks every unattempted parent unknown.
#>

function Invoke-PulsePolicyAssignmentPlan {
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
    $null = $ManifestEntry
    $null = $ProfileId
    $null = $TenantPseudonym

    $spec = switch ($Dataset) {
        'deviceCompliancePolicies' {
            [pscustomobject]@{
                RootType       = 'DeviceCompliancePolicy'
                AssignmentType = 'DeviceCompliancePolicyAssignment'
            }
            break
        }
        'deviceConfigurations' {
            [pscustomobject]@{
                RootType       = 'DeviceConfiguration'
                AssignmentType = 'DeviceConfigurationAssignment'
            }
            break
        }
        default {
            throw "Invoke-PulsePolicyAssignmentPlan: unsupported dataset '$Dataset'."
        }
    }

    $apiVersion = 'v1.0'
    $rootOperation = "$($spec.RootType).List"
    $assignmentOperation = "$($spec.AssignmentType).List"
    $operations = @($rootOperation, $assignmentOperation)

    if ($NetworkAbortState.AuthenticationAborted) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass 'AuthenticationFailed' -ReasonCode 'authentication-failed' `
            -Detail @{ status = 'collection aborted' } -Provider 'TenantPulse' `
            -ApiVersion $apiVersion -Operations $operations
    }

    Assert-PulseReadOnlyDescriptor -Type $spec.RootType -Operation 'List' -ApiVersion $apiVersion
    Assert-PulseReadOnlyDescriptor -Type $spec.AssignmentType -Operation 'List' -ApiVersion $apiVersion

    function Copy-PolicyWithAssignments {
        param(
            [Parameter(Mandatory)] $Policy,
            [AllowNull()] $Assignments
        )

        $copy = [ordered]@{}
        if ($Policy -is [System.Collections.IDictionary]) {
            $keys = [string[]] @($Policy.Keys | ForEach-Object { [string] $_ })
            [System.Array]::Sort($keys, [System.StringComparer]::Ordinal)
            foreach ($key in $keys) {
                if ([string]::Equals($key, 'assignments', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                $copy[$key] = $Policy[$key]
            }
        } else {
            $properties = @($Policy.PSObject.Properties)
            foreach ($property in $properties) {
                if ([string]::Equals([string] $property.Name, 'assignments', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                $copy[[string] $property.Name] = $property.Value
            }
        }
        $copy['assignments'] = $Assignments
        return [pscustomobject] $copy
    }

    function Sort-PolicyAssignmentRows {
        param([AllowNull()] [object[]] $Rows)

        $result = [object[]] @($Rows | Where-Object { $null -ne $_ })
        if ($result.Count -gt 1) {
            $comparison = [System.Comparison[object]] {
                param($left, $right)
                $leftId = [string] (Get-PulseSettingsCatalogValueProperty -Node $left -PropertyName 'id')
                $rightId = [string] (Get-PulseSettingsCatalogValueProperty -Node $right -PropertyName 'id')
                $idComparison = [string]::CompareOrdinal($leftId, $rightId)
                if ($idComparison -ne 0) { return $idComparison }
                $leftJson = ConvertTo-PulseCanonicalJson -InputObject $left
                $rightJson = ConvertTo-PulseCanonicalJson -InputObject $right
                return [string]::CompareOrdinal($leftJson, $rightJson)
            }
            [System.Array]::Sort($result, $comparison)
        }
        return , [object[]] $result
    }

    $rootRaw = $null
    try {
        $rootRaw = @(Get-GraphObject -Context $Context -Type $spec.RootType -Operation 'List' `
                -PassThruResult -ErrorAction Stop)
    } catch {
        $failure = Resolve-PulseGraphFailure -ErrorRecord $_
        if ($failure.AbortCollection) {
            $NetworkAbortState.AuthenticationAborted = $true
            $NetworkAbortState.Reason = 'authentication-failed: collection aborted'
        }
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass $failure.FailureClass -ReasonCode $failure.ReasonCode `
            -Detail @{ operation = $rootOperation } -Provider 'TenantPulse' -ApiVersion $apiVersion `
            -Operations $operations
    }

    $rootEnvelope = Convert-PulseGraphObjectResult -Result $rootRaw
    $rootOutcome = ConvertTo-PulseDatasetOutcomeFromGraphEnvelope -Envelope $rootEnvelope `
        -Dataset $Dataset -ApiVersion $apiVersion -Provider 'TenantPulse' -Operations $operations
    if ($rootOutcome.Status -eq 'Failed') {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass $rootOutcome.FailureClass -ReasonCode $rootOutcome.ReasonCode `
            -Detail $rootOutcome.Detail -Provider 'TenantPulse' -ApiVersion $apiVersion -Operations $operations
    }

    $gaps = [System.Collections.Generic.List[object]]::new()
    if ($rootOutcome.Status -eq 'Partial') {
        $rootGap = @($rootOutcome.Gaps)[0]
        $gaps.Add((New-PulseCollectionGap -Scope "dataset:$Dataset/root" `
                -FailureClass ([string] $rootGap.FailureClass) -ReasonCode ([string] $rootGap.ReasonCode) `
                -Detail $rootGap.Detail -Operation $rootOperation -ApiVersion $apiVersion)) | Out-Null
    }

    $candidateRows = [System.Collections.Generic.List[object]]::new()
    $counts = @{}
    $index = 0
    foreach ($policy in @($rootOutcome.Rows)) {
        if ($null -eq $policy) { continue }
        $policyId = [string] (Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'id')
        if ([string]::IsNullOrWhiteSpace($policyId)) {
            $gaps.Add((New-PulseCollectionGap -Scope "dataset:$Dataset/parent:$index" `
                    -FailureClass 'InvalidProviderData' -ReasonCode 'missing-parent-id' `
                    -Detail @{ ordinal = $index } -Operation $rootOperation -ApiVersion $apiVersion)) | Out-Null
            $index++
            continue
        }
        $key = $policyId.ToLowerInvariant()
        if (-not $counts.ContainsKey($key)) { $counts[$key] = 0 }
        $counts[$key]++
        $candidateRows.Add([pscustomobject]@{ Id = $policyId; Policy = $policy }) | Out-Null
        $index++
    }

    $validRows = [System.Collections.Generic.List[object]]::new()
    $duplicateIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($candidate in $candidateRows) {
        if ($counts[$candidate.Id.ToLowerInvariant()] -gt 1) {
            if ($duplicateIds.Add($candidate.Id)) {
                $gaps.Add((New-PulseCollectionGap -Scope "policy:$($candidate.Id)" `
                        -FailureClass 'InvalidProviderData' -ReasonCode 'duplicate-parent-id' `
                        -Detail @{ id = $candidate.Id } -Operation $rootOperation -ApiVersion $apiVersion)) | Out-Null
            }
            continue
        }
        $validRows.Add($candidate) | Out-Null
    }

    $parents = [object[]] @($validRows)
    if ($parents.Count -gt 1) {
        $comparison = [System.Comparison[object]] {
            param($left, $right)
            [string]::CompareOrdinal([string] $left.Id, [string] $right.Id)
        }
        [System.Array]::Sort($parents, $comparison)
    }

    $joined = [System.Collections.Generic.List[object]]::new()
    for ($parentIndex = 0; $parentIndex -lt $parents.Count; $parentIndex++) {
        $parent = $parents[$parentIndex]
        $policyId = [string] $parent.Id

        if ($NetworkAbortState.AuthenticationAborted) {
            $joined.Add((Copy-PolicyWithAssignments -Policy $parent.Policy -Assignments $null)) | Out-Null
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId/assignments" `
                    -FailureClass 'AuthenticationFailed' -ReasonCode 'not-attempted-after-authentication-failure' `
                    -Detail @{ policyId = $policyId } -Operation $assignmentOperation -ApiVersion $apiVersion)) | Out-Null
            continue
        }

        try {
            $childRaw = @(Get-GraphObject -Context $Context -Type $spec.AssignmentType -Operation 'List' `
                    -Parameters @{ id = $policyId } -PassThruResult -ErrorAction Stop)
            $childEnvelope = Convert-PulseGraphObjectResult -Result $childRaw
            $childOutcome = ConvertTo-PulseDatasetOutcomeFromGraphEnvelope -Envelope $childEnvelope `
                -Dataset "$Dataset/$policyId/assignments" -ApiVersion $apiVersion `
                -Provider 'TenantPulse' -Operations @($assignmentOperation)

            if ($childOutcome.Status -eq 'Collected') {
                $assignments = Sort-PolicyAssignmentRows -Rows @($childOutcome.Rows)
                $joined.Add((Copy-PolicyWithAssignments -Policy $parent.Policy -Assignments $assignments)) | Out-Null
                continue
            }

            $joined.Add((Copy-PolicyWithAssignments -Policy $parent.Policy -Assignments $null)) | Out-Null
            $childFailureClass = if ($childOutcome.Status -eq 'Partial') {
                [string] @($childOutcome.Gaps)[0].FailureClass
            } else {
                [string] $childOutcome.FailureClass
            }
            $childReasonCode = if ($childOutcome.Status -eq 'Partial') {
                [string] @($childOutcome.Gaps)[0].ReasonCode
            } else {
                [string] $childOutcome.ReasonCode
            }
            $childDetail = if ($childOutcome.Status -eq 'Partial') {
                @($childOutcome.Gaps)[0].Detail
            } else {
                $childOutcome.Detail
            }
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId/assignments" `
                    -FailureClass $childFailureClass -ReasonCode $childReasonCode -Detail $childDetail `
                    -Operation $assignmentOperation -ApiVersion $apiVersion)) | Out-Null
        } catch {
            $failure = Resolve-PulseGraphFailure -ErrorRecord $_
            $joined.Add((Copy-PolicyWithAssignments -Policy $parent.Policy -Assignments $null)) | Out-Null
            $gaps.Add((New-PulseCollectionGap -Scope "policy:$policyId/assignments" `
                    -FailureClass $failure.FailureClass -ReasonCode $failure.ReasonCode `
                    -Detail @{ policyId = $policyId } -Operation $assignmentOperation -ApiVersion $apiVersion)) | Out-Null
            if ($failure.AbortCollection) {
                $NetworkAbortState.AuthenticationAborted = $true
                $NetworkAbortState.Reason = 'authentication-failed: collection aborted'
            }
        }
    }

    $detail = @{
        parentCount   = @($rootOutcome.Rows).Count
        collectedCount = $joined.Count
        gapCount      = $gaps.Count
    }
    if ($joined.Count -eq 0 -and $gaps.Count -gt 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps $gaps.ToArray() `
            -FailureClass 'InvalidProviderData' -ReasonCode 'no-authoritative-parent-rows' -Detail $detail `
            -Provider 'TenantPulse' -ApiVersion $apiVersion -Operations $operations
    }
    if ($gaps.Count -gt 0) {
        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Partial' -Rows $joined.ToArray() -Gaps $gaps.ToArray() `
            -ReasonCode 'partial-policy-assignments' -Detail $detail -Provider 'TenantPulse' `
            -ApiVersion $apiVersion -Operations $operations
    }
    return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Collected' -Rows $joined.ToArray() -Gaps @() `
        -ReasonCode 'collected' -Detail $detail -Provider 'TenantPulse' -ApiVersion $apiVersion `
        -Operations $operations
}
