function Resolve-PulseDatasetOutcomeState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [System.Collections.IDictionary] $DatasetOutcomes,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DatasetName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Caller
    )

    $invalidMessage = "${Caller}: the dataset outcome projection is invalid."
    if ($null -eq $DatasetOutcomes) {
        throw $invalidMessage
    }

    if (-not $DatasetOutcomes.Contains($DatasetName)) {
        return [pscustomobject]@{
            IsPartial         = $false
            UnresolvedGapCount = 0
        }
    }

    $outcome = $DatasetOutcomes[$DatasetName]
    if ($null -eq $outcome -or $outcome -isnot [System.Collections.IDictionary]) {
        throw $invalidMessage
    }

    $outcomePropertyNames = @($outcome.Keys)
    if ($outcomePropertyNames -cnotcontains 'Status') {
        throw $invalidMessage
    }

    $outcomeStatus = $outcome['Status']
    if ($outcomeStatus -isnot [string] -or $outcomeStatus -cnotin @('Collected', 'Partial')) {
        throw $invalidMessage
    }

    $isPartial = $outcomeStatus -ceq 'Partial'
    $unresolvedGapCount = 0
    if ($isPartial) {
        if ($outcomePropertyNames -cnotcontains 'Gaps') {
            throw $invalidMessage
        }

        $gaps = $outcome['Gaps']
        if ($null -eq $gaps -or $gaps -isnot [array] -or @($gaps).Count -eq 0 -or @($gaps | Where-Object { $null -eq $_ }).Count -gt 0) {
            throw $invalidMessage
        }
        $unresolvedGapCount = @($gaps).Count
    }

    return [pscustomobject]@{
        IsPartial          = $isPartial
        UnresolvedGapCount = $unresolvedGapCount
    }
}
