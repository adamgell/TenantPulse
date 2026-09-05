<#
    Private: TP.INT.0002 rule function - a compliance policy exists for every enrolled
    device platform.

    Enrolled platforms are derived from managedDevices.operatingSystem (the actual,
    observed device population), not from an assumption of "every platform Intune
    supports" - a tenant that has only ever enrolled Windows devices is not faulted for
    lacking an iOS compliance policy nobody needs. Compliance policy PLATFORM is
    discriminated by the object's '@odata.type' (deviceCompliancePolicies uses GraphKit's
    beta ListBeta collection so platform-specific derived policy shapes are not omitted;
    each row's own '@odata.type' is Microsoft's own supported way
    to tell a windows10CompliancePolicy from an iosCompliancePolicy). Android is matched by
    substring because Intune ships more than one Android compliance policy type
    (androidWorkProfileCompliancePolicy, androidDeviceOwnerCompliancePolicy, and the legacy
    androidCompliancePolicy) and any one of them satisfies "Android has a compliance
    policy".

    PLATFORM ALLOWLIST (post-review, M1): only 4 platform categories are actually compared -
    windows, iOS/iPadOS, android, macOS - Intune's compliance-policy-bearing platforms. An
    enrolled operatingSystem value that does not map to one of these (Linux, ChromeOS, or
    anything unrecognized) is explicitly OUT OF SCOPE for this check: it is named in the
    Reason as out-of-scope context so an operator can see it was observed, but it NEVER
    contributes to a Fail - Intune does not offer a compliance policy type for those
    platforms at all, so faulting the tenant for lacking one would be asserting a
    requirement Microsoft itself does not support meeting.

    Assignment evidence is joined during collection. Include targets count as coverage;
    authoritative empty and exclusion-only targets do not. Missing/malformed assignment
    evidence, an incomplete root list, and an unclassified policy discriminator with
    potentially covering assignment intent remain NotApplicable unless known evidence
    already proves the universal Pass or a complete platform branch proves a Fail. A
    policy-scoped assignment gap only affects the platform represented by that policy; it
    must not hide a known offender on another platform.
#>

function Test-PulseCompliancePolicyPerPlatform {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter(Mandatory)]
        [hashtable] $DatasetOutcomes
    )

    $outcomeState = Resolve-PulseDatasetOutcomeState -DatasetOutcomes $DatasetOutcomes `
        -DatasetName 'deviceCompliancePolicies' -Caller $MyInvocation.MyCommand.Name

    $devices = @($Datasets.managedDevices)
    # Ordinal sort/dedup (post-review fix, matching every other "deterministic ordering
    # everywhere" rule in this codebase - see ConvertTo-PulseCanonicalJson and
    # Import-PulseCheckCatalog): Sort-Object -Unique uses PowerShell's default culture-aware,
    # case-INSENSITIVE comparison, which is non-deterministic across locales/hosts. A
    # HashSet with an ordinal comparer dedups, then [System.Array]::Sort with an ordinal
    # StringComparer sorts - never Sort-Object without an explicit ordinal comparer.
    $rawPlatforms = @($devices | ForEach-Object { [string] $_.operatingSystem } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $uniquePlatformSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($platform in $rawPlatforms) { [void] $uniquePlatformSet.Add($platform) }
    $enrolledPlatforms = [string[]] @($uniquePlatformSet)
    [System.Array]::Sort($enrolledPlatforms, [System.StringComparer]::Ordinal)

    if ($enrolledPlatforms.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason 'No managed devices are enrolled on any platform - there is nothing to require a compliance policy for yet.'
    }

    # Maps a normalized (lowercased) platform string to one of the 4 categories Intune
    # actually offers a compliance policy type for - $null means out of scope (see the
    # PLATFORM ALLOWLIST docstring section above).
    $categorize = {
        param($normalized)
        if ($normalized -like '*window*') { return 'windows' }
        if ($normalized -like '*ios*' -or $normalized -like '*ipados*' -or $normalized -like '*ipad*') { return 'ios' }
        if ($normalized -like '*android*') { return 'android' }
        if ($normalized -like '*macos*' -or $normalized -like '*mac os*') { return 'macos' }
        return $null
    }

    $categorizePolicyType = {
        param([AllowNull()] [string] $ODataType)

        if ([string]::IsNullOrWhiteSpace($ODataType)) { return $null }
        if ([string]::Equals($ODataType, '#microsoft.graph.windows10CompliancePolicy', [System.StringComparison]::OrdinalIgnoreCase)) { return 'windows' }
        if ([string]::Equals($ODataType, '#microsoft.graph.iosCompliancePolicy', [System.StringComparison]::OrdinalIgnoreCase)) { return 'ios' }
        if ([string]::Equals($ODataType, '#microsoft.graph.macOSCompliancePolicy', [System.StringComparison]::OrdinalIgnoreCase)) { return 'macos' }

        foreach ($androidType in @(
                '#microsoft.graph.androidCompliancePolicy'
                '#microsoft.graph.androidWorkProfileCompliancePolicy'
                '#microsoft.graph.androidDeviceOwnerCompliancePolicy'
                '#microsoft.graph.aospDeviceOwnerCompliancePolicy'
            )) {
            if ([string]::Equals($ODataType, $androidType, [System.StringComparison]::OrdinalIgnoreCase)) { return 'android' }
        }

        return $null
    }

    $policies = @($Datasets.deviceCompliancePolicies)
    $assignedPolicyCategories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $unresolvedPolicyCategories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $policyRowsById = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $duplicatePolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $hasUnclassifiedPotentialCoverage = $false
    foreach ($policy in $policies) {
        $policyId = [string] (Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'id')
        if (-not [string]::IsNullOrWhiteSpace($policyId)) {
            if ($policyRowsById.ContainsKey($policyId)) {
                [void] $duplicatePolicyIds.Add($policyId)
            } else {
                $policyRowsById.Add($policyId, $policy)
            }
        }

        $intent = ConvertTo-PulseAssignmentIntent -Assignments (Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName 'assignments')
        $odataType = [string] (Get-PulseSettingsCatalogValueProperty -Node $policy -PropertyName '@odata.type')
        $policyCategory = & $categorizePolicyType $odataType
        if ($null -eq $policyCategory) {
            if ($intent.IsAssigned -or -not $intent.Complete) {
                $hasUnclassifiedPotentialCoverage = $true
            }
            continue
        }

        if ($intent.IsAssigned) {
            [void] $assignedPolicyCategories.Add($policyCategory)
        } elseif (-not $intent.Complete) {
            [void] $unresolvedPolicyCategories.Add($policyCategory)
        }
    }

    $hasBroadPartialUncertainty = $false
    if ($outcomeState.IsPartial) {
        foreach ($gap in @($DatasetOutcomes['deviceCompliancePolicies']['Gaps'])) {
            $scope = [string] (Get-PulseSettingsCatalogValueProperty -Node $gap -PropertyName 'Scope')
            if ($scope -match '^policy:(.+)/assignments$') {
                $gapPolicyId = [string] $Matches[1]
            } else {
                $hasBroadPartialUncertainty = $true
                continue
            }

            if (-not $policyRowsById.ContainsKey($gapPolicyId) -or $duplicatePolicyIds.Contains($gapPolicyId)) {
                $hasBroadPartialUncertainty = $true
                continue
            }

            $gapPolicyType = [string] (Get-PulseSettingsCatalogValueProperty -Node $policyRowsById[$gapPolicyId] -PropertyName '@odata.type')
            $gapPolicyCategory = & $categorizePolicyType $gapPolicyType
            if ($null -eq $gapPolicyCategory) {
                $hasUnclassifiedPotentialCoverage = $true
            } else {
                [void] $unresolvedPolicyCategories.Add($gapPolicyCategory)
            }
        }
    }

    $inScopePlatforms = @()
    $outOfScopePlatforms = @()
    foreach ($platform in $enrolledPlatforms) {
        $category = & $categorize $platform.ToLowerInvariant()
        if ($null -eq $category) {
            $outOfScopePlatforms += $platform
        } else {
            $inScopePlatforms += [pscustomobject]@{ Platform = $platform; Category = $category }
        }
    }

    $outOfScopeNote = if ($outOfScopePlatforms.Count -gt 0) {
        " ($($outOfScopePlatforms.Count) out-of-scope platform(s) observed but not evaluated - Intune has no compliance policy type for them: $($outOfScopePlatforms -join ', '))."
    } else {
        '.'
    }

    $missingPlatforms = @()
    $unresolvedPlatforms = @()
    $definitelyMissingPlatforms = @()
    foreach ($entry in $inScopePlatforms) {
        $hasPolicy = switch ($entry.Category) {
            'windows' { $assignedPolicyCategories.Contains('windows') }
            'ios' { $assignedPolicyCategories.Contains('ios') }
            'android' { $assignedPolicyCategories.Contains('android') }
            'macos' { $assignedPolicyCategories.Contains('macos') }
        }

        if (-not $hasPolicy) {
            $missingPlatforms += $entry.Platform
            $hasUnresolvedPolicy = $unresolvedPolicyCategories.Contains([string] $entry.Category)
            if ($hasBroadPartialUncertainty -or $hasUnclassifiedPotentialCoverage -or $hasUnresolvedPolicy) {
                $unresolvedPlatforms += $entry.Platform
            } else {
                $definitelyMissingPlatforms += $entry.Platform
            }
        }
    }

    if ($missingPlatforms.Count -eq 0) {
        $coveredNote = if ($inScopePlatforms.Count -gt 0) { "Every enrolled in-scope platform ($(($inScopePlatforms | ForEach-Object Platform) -join ', ')) has at least one compliance policy" } else { 'No in-scope platform is enrolled' }
        return New-PulseFinding -Status Pass -Reason "$coveredNote$outOfScopeNote"
    }

    if ($definitelyMissingPlatforms.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason "Policy type evidence, partial root evidence, or assignment evidence is unresolved for $($unresolvedPlatforms.Count) enrolled platform(s): $($unresolvedPlatforms -join ', '); absence cannot be proven.$outOfScopeNote"
    }

    $evidence = @()
    foreach ($platform in $definitelyMissingPlatforms) {
        $count = @($devices | Where-Object { [string] $_.operatingSystem -eq $platform }).Count
        $evidence += @{ Identity = $platform; Detail = @{ enrolledDeviceCount = $count } }
    }

    return New-PulseFinding -Status Fail -Reason "$($definitelyMissingPlatforms.Count) of $($inScopePlatforms.Count) enrolled in-scope platform(s) have no authoritatively assigned compliance policy: $($definitelyMissingPlatforms -join ', ')$outOfScopeNote" -Evidence $evidence
}
