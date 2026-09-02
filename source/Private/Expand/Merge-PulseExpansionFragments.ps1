<#
    Private: merge identifiable expansion fragments into one published jsonl artifact.

    Missing fragments throw (no silent truncation). Combined rows are handed to
    Publish-PulseExpansionRows, which re-sorts on (policyId, settingPath, instanceId),
    so two different chunkings of the same rows produce byte-identical generation files.
#>

function Read-PulseExpansionFragmentRows {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Read-PulseExpansionFragmentRows: fragment file '$Path' is missing - refusing to merge a truncated fragment set."
    }

    $rawBytes = [System.IO.File]::ReadAllBytes($Path)
    $content = [System.Text.Encoding]::UTF8.GetString($rawBytes)
    $lines = $content -split "`n"
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $lines) {
        if ([string]::IsNullOrEmpty($line)) { continue }
        $rows.Add((ConvertFrom-Json -InputObject $line -Depth 64)) | Out-Null
    }
    return , [object[]] @($rows.ToArray())
}

function Merge-PulseExpansionFragments {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $FragmentIds,

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

    Assert-PulseDatasetName -Name $Name -Kind 'expansion name'

    $mergedRows = [System.Collections.Generic.List[object]]::new()
    $expectedCount = 0
    foreach ($fragmentId in @($FragmentIds)) {
        Assert-PulseDatasetName -Name $fragmentId -Kind 'expansion fragment id'
        $path = Get-PulseExpansionFragmentPath -Store $Store -Name $Name -FragmentId $fragmentId
        $fragmentRows = [System.Collections.Generic.List[object]]::new()
        foreach ($item in @(Read-PulseExpansionFragmentRows -Path $path)) {
            if ($item -is [System.Array]) {
                foreach ($inner in $item) { $fragmentRows.Add($inner) | Out-Null }
            } else {
                $fragmentRows.Add($item) | Out-Null
            }
        }
        $expectedCount += $fragmentRows.Count
        foreach ($row in $fragmentRows) {
            $mergedRows.Add($row) | Out-Null
        }
    }

    if ($mergedRows.Count -ne $expectedCount) {
        throw "Merge-PulseExpansionFragments: row count mismatch while merging '$Name' fragments - expected $expectedCount, got $($mergedRows.Count)."
    }

    $publishParams = @{
        Store       = $Store
        Name        = $Name
        Rows        = $mergedRows.ToArray()
        Gaps        = $Gaps
        PolicyCount = $PolicyCount
        ProfileId   = $ProfileId
        Pseudonym   = $Pseudonym
        TenantId    = $TenantId
    }
    if (-not [string]::IsNullOrEmpty($Reason)) {
        $publishParams.Reason = $Reason
    }
    return Publish-PulseExpansionRows @publishParams
}
