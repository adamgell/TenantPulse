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

    $policies = @($Datasets.deviceCompliancePolicies)
    $policyTypes = @($policies | ForEach-Object { [string] $_.'@odata.type' })

    $missingPlatforms = @()
    foreach ($platform in $enrolledPlatforms) {
        $normalized = $platform.ToLowerInvariant()

        $hasPolicy = $false
        if ($normalized -like '*window*') {
            $hasPolicy = $policyTypes -contains '#microsoft.graph.windows10CompliancePolicy'
        } elseif ($normalized -like '*ios*') {
            $hasPolicy = $policyTypes -contains '#microsoft.graph.iosCompliancePolicy'
        } elseif ($normalized -like '*android*') {
            $hasPolicy = @($policyTypes | Where-Object { $_ -match 'android' }).Count -gt 0
        } elseif ($normalized -like '*macos*') {
            $hasPolicy = $policyTypes -contains '#microsoft.graph.macOSCompliancePolicy'
        }

        if (-not $hasPolicy) {
            $missingPlatforms += $platform
        }
    }

    if ($missingPlatforms.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason "Every enrolled platform ($($enrolledPlatforms -join ', ')) has at least one compliance policy."
    }

    $evidence = @()
    foreach ($platform in $missingPlatforms) {
        $count = @($devices | Where-Object { [string] $_.operatingSystem -eq $platform }).Count
        $evidence += @{ Identity = $platform; Detail = @{ enrolledDeviceCount = $count } }
    }

    return New-PulseFinding -Status Fail -Reason "$($missingPlatforms.Count) of $($enrolledPlatforms.Count) enrolled platform(s) have no compliance policy at all: $($missingPlatforms -join ', ')." -Evidence $evidence
}
