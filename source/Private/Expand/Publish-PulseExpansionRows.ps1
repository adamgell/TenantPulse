<#
    Private: shared crash-consistent jsonl staging/hash/publish helper.

    Originally extracted out of Invoke-PulseSettingsCatalogExpansion.ps1's own inline
    staging block (T2.2) so Invoke-PulseTypedPolicyExpansion (T2.3) did not COPY that
    block's tricky crash-safety sequencing - see this file's own CRASH-CONSISTENT
    PUBLICATION notes below for the fault-injection history this sequencing defends
    against (old-manifest/new-bytes split-brain; orphaned .tmp files). T2.2's own inline
    copy was left as a separate implementation at the time, deliberately, since it already
    had an exhaustive, review-hardened test suite (SettingsCatalogExpansion.Tests.ps1)
    exercising every one of those fault windows and retrofitting it onto this helper was
    judged a separate, higher-risk refactor. That refactor has since landed (60c002f,
    post-T2.3-review): Invoke-PulseSettingsCatalogExpansion's tail now also calls THIS
    function for its own staging/hash/publish, so there is exactly ONE implementation of
    this logic left in the module - every producer (T2.2's settings-catalog expansion,
    T2.3's typed-policy expansion, and any future one) goes through this same function.
    SettingsCatalogExpansion.Tests.ps1's fault-injection coverage still applies unchanged,
    now exercising this shared code path instead of a duplicated inline one.

    Sorts -Rows deterministically on (policyId, settingPath, instanceId) via
    [string]::CompareOrdinal (never trusts caller ordering / worker completion order),
    serializes through ConvertTo-PulseCanonicalJsonLine, hashes incrementally, renames to an
    IMMUTABLE, content-addressed generation file BEFORE the manifest mutex is ever touched,
    then calls Set-PulseExpansionEntry with -Path already pointing at that durable file -
    the exact ordering T2.2's own docstring explains closes the split-brain window.

    -Gaps (already policyId/reason-shaped, already sorted by the caller - this function
    does not re-sort them, matching Set-PulseExpansionEntry's own "callers supply
    pre-validated data" convention) decide Expanded vs Partial. -PolicyCount ZERO with ANY
    gaps and ZERO rows is NotExpanded (all-attempted-policies-failed, matching T2.2's own
    "never a Partial with an empty artifact" rule) - a -PolicyCount of zero with zero gaps
    (nothing was ever attempted) still stages and publishes a valid, empty-but-hash-verified
    Expanded artifact, exactly like T2.2's own -Policies @() path.
#>

function Publish-PulseExpansionRows {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Rows,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Gaps,

        [Parameter(Mandatory)]
        [int] $PolicyCount,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Reason,

        [Parameter()]
        [string] $ProfileId = '',

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown',

        [Parameter()]
        [AllowNull()]
        [string] $TenantId
    )

    $sortedRows = @($Rows)
    $rowComparison = [System.Comparison[object]] {
        param($a, $b)
        $c = [string]::CompareOrdinal([string] $a.policyId, [string] $b.policyId)
        if ($c -ne 0) { return $c }
        $c = [string]::CompareOrdinal([string] $a.settingPath, [string] $b.settingPath)
        if ($c -ne 0) { return $c }
        return [string]::CompareOrdinal([string] $a.instanceId, [string] $b.instanceId)
    }
    [System.Array]::Sort($sortedRows, $rowComparison)

    $sortedGaps = @($Gaps)
    $unresolvedNameCount = @($sortedRows | Where-Object { -not $_.nameResolved }).Count
    $redactedSecretCount = @($sortedRows | Where-Object { $_.redacted }).Count

    if ($PolicyCount -gt 0 -and $sortedRows.Count -eq 0 -and $sortedGaps.Count -gt 0) {
        $notExpandedReason = Protect-PulseReason -Message "all $PolicyCount policy(ies) failed: $($sortedGaps.Count) gap(s), zero usable rows" `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
        Set-PulseExpansionEntry -Store $Store -Name $Name -Status 'NotExpanded' -Reason $notExpandedReason -Gaps $sortedGaps `
            -PolicyCount $PolicyCount -RowCount 0 -UnresolvedNameCount 0 -RedactedSecretCount 0
        return [pscustomobject]@{
            Status              = 'NotExpanded'
            PolicyCount         = $PolicyCount
            RowCount            = 0
            UnresolvedNameCount = 0
            RedactedSecretCount = 0
            Gaps                = $sortedGaps
        }
    }

    $tempFileName = "$Name.$([guid]::NewGuid().ToString('N')).tmp"
    $tempPath = Join-Path $Store.ExpandedPath $tempFileName
    $tempOwnershipTransferred = $false
    $incrementalHash = $null

    try {
        $incrementalHash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $fileStream = [System.IO.File]::Open($tempPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        try {
            foreach ($row in $sortedRows) {
                $line = ConvertTo-PulseCanonicalJsonLine -InputObject $row
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
                $fileStream.Write($bytes, 0, $bytes.Length)
                $incrementalHash.AppendData($bytes)
            }
            $fileStream.Flush()
        } finally {
            $fileStream.Dispose()
        }
        $hashBytes = $incrementalHash.GetHashAndReset()
        $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

        $generationFileName = "$Name.$sha256.jsonl"
        $generationPath = Join-Path $Store.ExpandedPath $generationFileName
        [System.IO.File]::Move($tempPath, $generationPath, $true)
        $tempOwnershipTransferred = $true

        $status = if ($sortedGaps.Count -eq 0) { 'Expanded' } else { 'Partial' }

        $setParams = @{
            Store               = $Store
            Name                = $Name
            Status              = $status
            Path                = "expanded/$generationFileName"
            SchemaVersion       = '1'
            Sha256              = $sha256
            PolicyCount         = $PolicyCount
            RowCount            = $sortedRows.Count
            UnresolvedNameCount = $unresolvedNameCount
            RedactedSecretCount = $redactedSecretCount
        }
        if (-not [string]::IsNullOrEmpty($Reason)) { $setParams.Reason = $Reason }
        if ($sortedGaps.Count -gt 0) { $setParams.Gaps = $sortedGaps }

        Set-PulseExpansionEntry @setParams

        return [pscustomobject]@{
            Status              = $status
            PolicyCount         = $PolicyCount
            RowCount            = $sortedRows.Count
            UnresolvedNameCount = $unresolvedNameCount
            RedactedSecretCount = $redactedSecretCount
            Gaps                = $sortedGaps
        }
    } finally {
        if ($null -ne $incrementalHash) { $incrementalHash.Dispose() }
        if (-not $tempOwnershipTransferred -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
