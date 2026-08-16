<#
    Private: TP.INT.0002 rule function - a compliance policy exists for every enrolled
    device platform.

    Enrolled platforms are derived from managedDevices.operatingSystem (the actual,
    observed device population), not from an assumption of "every platform Intune
    supports" - a tenant that has only ever enrolled Windows devices is not faulted for
    lacking an iOS compliance policy nobody needs. Compliance policy PLATFORM is
    discriminated by the object's '@odata.type' (deviceCompliancePolicies is a v1.0 List
    of a polymorphic type - each row's own '@odata.type' is Microsoft's own supported way
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

    HONEST LIMITATION: this checks policy EXISTENCE per platform, not that the policy is
    actually ASSIGNED to any device - deviceCompliancePolicies (v1.0 List, no $expand) does
    not carry assignment data in this dataset's shape. An unassigned compliance policy would
    still Pass this check. Assignment verification is future work (see TP.INT.0003 for the
    related "what happens with NO assigned policy" default-behavior check).
#>

function Test-PulseCompliancePolicyPerPlatform {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $devices = @($Datasets.managedDevices)
    $enrolledPlatforms = @($devices | ForEach-Object { [string] $_.operatingSystem } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

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

    $policies = @($Datasets.deviceCompliancePolicies)
    $policyTypes = @($policies | ForEach-Object { [string] $_.'@odata.type' })

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
    foreach ($entry in $inScopePlatforms) {
        $hasPolicy = switch ($entry.Category) {
            'windows' { $policyTypes -contains '#microsoft.graph.windows10CompliancePolicy' }
            'ios' { $policyTypes -contains '#microsoft.graph.iosCompliancePolicy' }
            'android' { @($policyTypes | Where-Object { $_ -match 'android' }).Count -gt 0 }
            'macos' { $policyTypes -contains '#microsoft.graph.macOSCompliancePolicy' }
        }

        if (-not $hasPolicy) {
            $missingPlatforms += $entry.Platform
        }
    }

    if ($missingPlatforms.Count -eq 0) {
        $coveredNote = if ($inScopePlatforms.Count -gt 0) { "Every enrolled in-scope platform ($(($inScopePlatforms | ForEach-Object Platform) -join ', ')) has at least one compliance policy" } else { 'No in-scope platform is enrolled' }
        return New-PulseFinding -Status Pass -Reason "$coveredNote$outOfScopeNote"
    }

    $evidence = @()
    foreach ($platform in $missingPlatforms) {
        $count = @($devices | Where-Object { [string] $_.operatingSystem -eq $platform }).Count
        $evidence += @{ Identity = $platform; Detail = @{ enrolledDeviceCount = $count } }
    }

    return New-PulseFinding -Status Fail -Reason "$($missingPlatforms.Count) of $($inScopePlatforms.Count) enrolled in-scope platform(s) have no compliance policy at all: $($missingPlatforms -join ', ')$outOfScopeNote" -Evidence $evidence
}
