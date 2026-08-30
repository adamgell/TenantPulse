<#
    Private: collect subscribed SKUs and persist deterministic license-gate decisions.

    A narrowed assessment still needs license evidence for every Data.Gates value it declares.
    This plan owns the one read of Graph's subscribedSkus collection and records independent
    Intune, EntraP1, and EntraP2 decisions in the dataset entry's structured Detail. Evaluation
    can therefore make the same decision later from the snapshot alone; it never performs a
    fresh Graph call and never guesses that missing evidence means unlicensed.

    The service-plan GUIDs are Microsoft's stable identifiers from the official product and
    service-plan reference. Intune Plan 2 is additive to Plan 1, so only the base Intune and
    Intune for Education service plans satisfy the Intune gate. Entra P2 satisfies P1-level
    capability as well as its own gate. An Enabled SKU, or a Warning SKU in Microsoft's
    renewal grace state, is affirmative when it carries a service plan whose
    provisioningStatus is Success. Malformed evidence is Partial and can never prove
    license absence.
#>

function Invoke-PulseSubscribedSkuLicensePlan {
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

    $null = $ProfileId
    $null = $TenantPseudonym

    Assert-PulseReadOnlyDescriptor -Type 'SubscribedSku' -Operation 'List' -ApiVersion 'beta'

    $apiVersion = if ($ManifestEntry.PSObject.Properties['ApiVersion'] -and $ManifestEntry.ApiVersion) {
        [string] $ManifestEntry.ApiVersion
    } else {
        'beta'
    }

    $rows = @()
    try {
        $rows = @(Get-GraphObject -Context $Context -Type 'SubscribedSku' -Operation 'List' -ErrorAction Stop)
    } catch {
        $classified = Get-PulseFailureClass -ErrorRecord $_
        $failureClass = switch ($classified) {
            'PermissionDenied' { 'PermissionDenied'; break }
            'AuthFailure' { 'AuthenticationFailed'; break }
            default { 'ProviderFailed' }
        }
        $reasonCode = switch ($failureClass) {
            'PermissionDenied' { 'permission-denied'; break }
            'AuthenticationFailed' { 'authentication-failed'; break }
            default { 'provider-failed' }
        }

        return New-PulseCollectionOutcome -Dataset $Dataset -Status 'Failed' -Rows @() -Gaps @() `
            -FailureClass $failureClass -ReasonCode $reasonCode -Detail @{ operation = 'SubscribedSku.List' } `
            -Provider 'GraphKit' -ApiVersion $apiVersion -Operations @('List')
    }

    function Get-LicenseNodeProperty {
        param($Node, [string] $Name)
        if ($null -eq $Node) {
            return [pscustomobject]@{ Found = $false; Value = $null }
        }
        if ($Node -is [System.Collections.IDictionary]) {
            if ($Node.Contains($Name)) {
                return [pscustomobject]@{ Found = $true; Value = $Node[$Name] }
            }
            return [pscustomobject]@{ Found = $false; Value = $null }
        }
        $property = $Node.PSObject.Properties[$Name]
        if ($null -ne $property) {
            return [pscustomobject]@{ Found = $true; Value = $property.Value }
        }
        return [pscustomobject]@{ Found = $false; Value = $null }
    }

    $knownCapabilityStatuses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($knownStatus in @('Enabled', 'Warning', 'Suspended', 'Deleted', 'LockedOut')) {
        $knownCapabilityStatuses.Add($knownStatus) | Out-Null
    }
    $knownProvisioningStatuses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($knownStatus in @('Success', 'Disabled', 'Error', 'PendingInput', 'PendingActivation', 'PendingProvisioning')) {
        $knownProvisioningStatuses.Add($knownStatus) | Out-Null
    }
    $successfulPlanIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $malformedCategories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($sku in $rows) {
        $capabilityStatus = (Get-LicenseNodeProperty -Node $sku -Name 'capabilityStatus').Value
        $validCapabilityStatus = $capabilityStatus -is [string] -and
            -not [string]::IsNullOrWhiteSpace([string] $capabilityStatus) -and
            $knownCapabilityStatuses.Contains([string] $capabilityStatus)
        if (-not $validCapabilityStatus) {
            $malformedCategories.Add('MalformedCapabilityStatus') | Out-Null
        }
        $skuAllowsProvisionedPlans = $validCapabilityStatus -and
            [string] $capabilityStatus -in @('Enabled', 'Warning')

        $servicePlans = (Get-LicenseNodeProperty -Node $sku -Name 'servicePlans').Value
        $validServicePlanCollection = $null -ne $servicePlans -and
            $servicePlans -is [System.Collections.IEnumerable] -and
            $servicePlans -isnot [string] -and
            $servicePlans -isnot [System.Collections.IDictionary]
        if (-not $validServicePlanCollection) {
            $malformedCategories.Add('MalformedServicePlans') | Out-Null
            continue
        }

        foreach ($plan in @($servicePlans)) {
            $status = (Get-LicenseNodeProperty -Node $plan -Name 'provisioningStatus').Value
            $validStatus = $status -is [string] -and
                -not [string]::IsNullOrWhiteSpace([string] $status) -and
                $knownProvisioningStatuses.Contains([string] $status)
            if (-not $validStatus) {
                $malformedCategories.Add('MalformedProvisioningStatus') | Out-Null
            }

            $planId = (Get-LicenseNodeProperty -Node $plan -Name 'servicePlanId').Value
            $parsedPlanId = [guid]::Empty
            $validPlanId = $planId -is [string] -and
                -not [string]::IsNullOrWhiteSpace([string] $planId) -and
                [guid]::TryParse([string] $planId, [ref] $parsedPlanId)
            if (-not $validPlanId) {
                $malformedCategories.Add('MalformedServicePlanId') | Out-Null
            }

            if (-not $skuAllowsProvisionedPlans -or -not $validStatus -or -not $validPlanId) { continue }
            if ([string]::Equals([string] $status, 'Success', [System.StringComparison]::OrdinalIgnoreCase)) {
                $successfulPlanIds.Add($parsedPlanId.ToString('D')) | Out-Null
            }
        }
    }

    $requirements = [ordered]@{
        Intune = @(
            'c1ec4a95-1f05-45b3-a911-aa3fa01094f5' # Microsoft Intune Plan 1
            'da24caf9-af8e-485c-b7c8-e73336da2693' # Microsoft Intune for Education
        )
        EntraP1 = @(
            '41781fb2-bc02-4b7c-bd55-b576c07bb09d' # Microsoft Entra ID P1
            'eec0eb4f-6444-4f95-aba0-50c24d67f998' # Microsoft Entra ID P2 includes P1 capability
        )
        EntraP2 = @(
            'eec0eb4f-6444-4f95-aba0-50c24d67f998' # Microsoft Entra ID P2
        )
    }

    $hasMalformedEvidence = $malformedCategories.Count -gt 0
    $gateEvidence = [ordered]@{}
    foreach ($gate in $requirements.Keys) {
        $available = $false
        foreach ($requiredPlanId in $requirements[$gate]) {
            if ($successfulPlanIds.Contains($requiredPlanId)) {
                $available = $true
                break
            }
        }

        $gateStatus = if ($available) {
            'Available'
        } elseif ($hasMalformedEvidence) {
            'Unknown'
        } else {
            'Unavailable'
        }
        $gateEvidence[$gate] = [ordered]@{
            Status       = $gateStatus
            Detail       = switch ($gateStatus) {
                'Available' { 'A qualifying provisioned service plan was found in collected license evidence.' }
                'Unknown' { 'Collected license evidence was incomplete or malformed; absence was not proven.' }
                default { 'No qualifying provisioned service plan was found in collected license evidence.' }
            }
            FailureClass = switch ($gateStatus) {
                'Available' { $null }
                'Unknown' { 'GateUnknown' }
                default { 'LicenseRequired' }
            }
        }
    }

    $gaps = [object[]]@()
    if ($hasMalformedEvidence) {
        $categories = [string[]]@($malformedCategories | Sort-Object)
        $gaps = @(
            New-PulseCollectionGap -Scope 'license-evidence' -FailureClass 'InvalidProviderData' `
                -ReasonCode 'invalid-provider-data' -Detail @{ Categories = $categories } `
                -Operation 'List' -ApiVersion $apiVersion
        )
    }

    $outcomeStatus = if ($hasMalformedEvidence) { 'Partial' } else { 'Collected' }
    $reasonCode = if ($hasMalformedEvidence) { 'partial' } else { 'collected' }
    return New-PulseCollectionOutcome -Dataset $Dataset -Status $outcomeStatus -Rows $rows -Gaps $gaps `
        -ReasonCode $reasonCode -Detail @{ Gates = $gateEvidence } -Provider 'GraphKit' `
        -ApiVersion $apiVersion -Operations @('List')
}
