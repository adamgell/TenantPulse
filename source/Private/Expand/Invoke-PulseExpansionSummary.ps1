<#
    Private: one content-addressed expansion summary over the snapshot's expansion families.

    Records counts, statuses, gaps, evidence caps, and hashes. Expansion is never
    default-on: without -Requested the summary is NotExpanded / DependencyUnavailable.
#>

function Invoke-PulseExpansionSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter()]
        [switch] $Requested,

        [Parameter()]
        [AllowNull()]
        [object[]] $SelectedChecks,

        [Parameter()]
        [string] $Name = 'expansionSummary',

        [Parameter()]
        [string] $ProfileId = '',

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown',

        [Parameter()]
        [AllowNull()]
        [string] $TenantId
    )

    $selection = Resolve-PulseRequestedExpansions -SelectedChecks $SelectedChecks -ExpandSettings:$Requested
    $declared = @($selection.Requested) -contains $Name
    if (-not $Requested -and -not $declared) {
        $reason = Protect-PulseReason -Message 'expansion not requested: dependency-unavailable' `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $reason
        return [pscustomobject]@{
            Status       = 'NotExpanded'
            FailureClass = 'DependencyUnavailable'
            Counts       = $null
            Statuses     = $null
            Caps         = $null
            Hashes       = $null
            Gaps         = @()
        }
    }

    $manifest = Get-PulseSnapshotManifest -Store $Store
    $expansions = $null
    if ($null -ne $manifest -and $manifest.Contains('expansions') -and $manifest.expansions -is [System.Collections.IDictionary]) {
        $expansions = $manifest.expansions
    }

    $familyNames = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $expansions) {
        foreach ($familyName in @($expansions.Keys)) {
            if ([string]::Equals([string] $familyName, $Name, [System.StringComparison]::Ordinal)) { continue }
            $familyNames.Add([string] $familyName) | Out-Null
        }
    }
    if ($familyNames.Count -gt 1) {
        $sortedNames = [string[]] @($familyNames)
        [System.Array]::Sort($sortedNames, [System.StringComparer]::Ordinal)
        $familyNames = [System.Collections.Generic.List[string]]::new()
        foreach ($sortedName in $sortedNames) { $familyNames.Add($sortedName) | Out-Null }
    }

    if ($familyNames.Count -eq 0) {
        $reason = Protect-PulseReason -Message 'no expansion families available' `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $reason
        return [pscustomobject]@{
            Status       = 'NotExpanded'
            FailureClass = $null
            Counts       = @{ families = 0; expanded = 0; partial = 0; notExpanded = 0; failed = 0; policies = 0; rows = 0 }
            Statuses     = [ordered]@{}
            Caps         = @{ reasonCharacters = 500 }
            Hashes       = [ordered]@{}
            Gaps         = @()
        }
    }

    $statuses = [ordered]@{}
    $hashes = [ordered]@{}
    $summaryGaps = [System.Collections.Generic.List[object]]::new()
    $expanded = 0
    $partial = 0
    $notExpanded = 0
    $failed = 0
    $policies = 0
    $rows = 0

    foreach ($familyName in $familyNames) {
        $entry = $expansions[$familyName]
        $status = if ($null -ne $entry -and $null -ne $entry.status) { [string] $entry.status } else { 'NotExpanded' }
        $statuses[$familyName] = $status
        switch ($status) {
            'Expanded' { $expanded++ }
            'Partial' { $partial++ }
            'Failed' { $failed++ }
            default { $notExpanded++ }
        }
        if ($null -ne $entry) {
            if ($null -ne $entry.policyCount) { $policies += [int] $entry.policyCount }
            if ($null -ne $entry.rowCount) { $rows += [int] $entry.rowCount }
            if (-not [string]::IsNullOrWhiteSpace([string] $entry.sha256)) {
                $hashes[$familyName] = [string] $entry.sha256
            }
            $familyGapCount = 0
            foreach ($gap in @($entry.gaps)) {
                if ($null -eq $gap) { continue }
                $familyGapCount++
                $summaryGaps.Add([pscustomobject][ordered]@{
                        family   = $familyName
                        policyId = Protect-PulseReason -Message ([string] $gap.policyId) -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                        reason   = Protect-PulseReason -Message ([string] $gap.reason) -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                    }) | Out-Null
            }
            if ($familyGapCount -eq 0 -and $status -ne 'Expanded') {
                $familyReason = if ($null -ne $entry.reason -and -not [string]::IsNullOrWhiteSpace([string] $entry.reason)) {
                    Protect-PulseReason -Message ([string] $entry.reason) -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
                } else {
                    "family:$familyName status $status"
                }
                $summaryGaps.Add([pscustomobject][ordered]@{
                        family   = $familyName
                        policyId = ''
                        reason   = $familyReason
                    }) | Out-Null
            }
        }
    }

    $sortedGaps = $summaryGaps.ToArray()
    if ($sortedGaps.Count -gt 1) {
        $gapComparison = [System.Comparison[object]] {
            param($a, $b)
            $c = [string]::CompareOrdinal([string] $a.family, [string] $b.family)
            if ($c -ne 0) { return $c }
            $c = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
            if ($c -ne 0) { return $c }
            return [string]::CompareOrdinal([string] $a.reason, [string] $b.reason)
        }
        [System.Array]::Sort($sortedGaps, $gapComparison)
    }

    $counts = [ordered]@{
        families     = $familyNames.Count
        expanded     = $expanded
        partial      = $partial
        notExpanded  = $notExpanded
        failed       = $failed
        policies     = $policies
        rows         = $rows
    }
    $caps = [ordered]@{ reasonCharacters = 500 }

    $document = [ordered]@{
        schemaVersion = '1'
        counts        = $counts
        statuses      = $statuses
        gaps          = $sortedGaps
        caps          = $caps
        hashes        = $hashes
    }

    $tempFileName = "$Name.$([guid]::NewGuid().ToString('N')).tmp"
    $tempPath = Join-Path $Store.ExpandedPath $tempFileName
    $tempOwnershipTransferred = $false
    try {
        $documentText = ConvertTo-PulseCanonicalJson -InputObject ([pscustomobject] $document)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($documentText)
        [System.IO.File]::WriteAllBytes($tempPath, $bytes)

        $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

        $generationFileName = "$Name.$sha256.json"
        $generationPath = Join-Path $Store.ExpandedPath $generationFileName
        [System.IO.File]::Move($tempPath, $generationPath, $true)
        $tempOwnershipTransferred = $true

        $status = if ($partial -eq 0 -and $notExpanded -eq 0 -and $failed -eq 0) { 'Expanded' } else { 'Partial' }
        $setParams = @{
            Store         = $Store
            Name          = $Name
            Status        = $status
            Path          = "expanded/$generationFileName"
            Format        = 'json'
            SchemaVersion = '1'
            Sha256        = $sha256
            PolicyCount   = $familyNames.Count
            RowCount      = $rows
        }
        if ($sortedGaps.Count -gt 0) { $setParams.Gaps = $sortedGaps }

        Set-PulseExpansionEntry @setParams

        return [pscustomobject]@{
            Status       = $status
            FailureClass = $null
            Counts       = $counts
            Statuses     = $statuses
            Caps         = $caps
            Hashes       = $hashes
            Gaps         = $sortedGaps
        }
    } finally {
        if (-not $tempOwnershipTransferred -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
