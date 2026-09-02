<#
    Private: map one GraphKit.OperationResult envelope to a provider-neutral collection
    outcome.

    AC-26: Collected is allowed only when Outcome=Succeeded, Certainty=Known, Truncated is
    not true, and no cap/incompleteness signal is present. Succeeded with usable but
    incomplete rows becomes Partial plus one structured gap. Incomplete envelopes without
    safe rows become Failed/Indeterminate. Missing or malformed required envelopes become
    Failed/InvalidProviderData. This function is total: hostile getters degrade only to
    InvalidProviderData and never throw to a snapshot writer.
#>

function Test-PulseGraphResultEnvelope {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject -or $InputObject -is [string]) {
        return $false
    }

    try {
        if ($InputObject.PSObject.TypeNames -contains 'GraphKit.OperationResult') {
            return $true
        }
    } catch {
        return $false
    }

    return $false
}

function ConvertTo-PulseDatasetOutcomeFromGraphEnvelope {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        $Envelope,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Dataset,

        [Parameter(Mandatory)]
        [ValidateSet('v1.0', 'beta')]
        [string] $ApiVersion,

        [Parameter()]
        [AllowNull()]
        $Provider = 'GraphKit',

        [Parameter()]
        [AllowNull()]
        [object[]] $Operations = @()
    )

    function Get-SafeEnvelopeProperty {
        param(
            [AllowNull()] [object] $InputObject,
            [Parameter(Mandatory)] [string] $Name
        )

        try {
            if ($null -eq $InputObject) {
                return [pscustomobject]@{ Success = $false; Value = $null }
            }
            if ($InputObject -is [System.Collections.IDictionary]) {
                if (-not $InputObject.Contains($Name)) {
                    return [pscustomobject]@{ Success = $false; Value = $null }
                }
                return [pscustomobject]@{ Success = $true; Value = $InputObject[$Name] }
            }

            $property = $InputObject.PSObject.Properties[$Name]
            if ($null -eq $property) {
                return [pscustomobject]@{ Success = $false; Value = $null }
            }
            return [pscustomobject]@{ Success = $true; Value = $property.Value }
        } catch {
            return [pscustomobject]@{ Success = $false; Value = $null }
        }
    }

    function ConvertTo-SafeEnvelopeString {
        param([AllowNull()] [object] $Value)

        try {
            if ($null -eq $Value) { return $null }
            return [string] $Value
        } catch {
            return $null
        }
    }

    $operationsValue = [object[]]@()
    if ($null -ne $Operations) { $operationsValue = [object[]]@($Operations) }
    $providerValue = if ($null -eq $Provider -or [string]::IsNullOrWhiteSpace([string] $Provider)) { 'GraphKit' } else { [string] $Provider }
    $gapOperation = if ($operationsValue.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string] $operationsValue[0])) {
        [string] $operationsValue[0]
    } else {
        'List'
    }

    function New-InvalidEnvelopeOutcome {
        New-PulseCollectionOutcome -Dataset $Dataset -Status Failed -Rows @() -Gaps @() `
            -FailureClass InvalidProviderData -ReasonCode 'invalid-provider-data' -Detail @{} `
            -Provider $providerValue -ApiVersion $ApiVersion -Operations $operationsValue
    }

    try {
        if ($null -eq $Envelope -or $Envelope -is [string]) {
            return New-InvalidEnvelopeOutcome
        }

        $outcomeRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'Outcome'
        $certaintyRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'Certainty'
        $outcomeText = if ($outcomeRead.Success) { ConvertTo-SafeEnvelopeString -Value $outcomeRead.Value } else { $null }
        $certaintyText = if ($certaintyRead.Success) { ConvertTo-SafeEnvelopeString -Value $certaintyRead.Value } else { $null }

        if ([string]::IsNullOrWhiteSpace($outcomeText) -or [string]::IsNullOrWhiteSpace($certaintyText)) {
            return New-InvalidEnvelopeOutcome
        }

        $truncated = $false
        $truncatedRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'Truncated'
        if ($truncatedRead.Success -and $null -ne $truncatedRead.Value) {
            try {
                $truncated = [bool] $truncatedRead.Value
            } catch {
                return New-InvalidEnvelopeOutcome
            }
        }

        $pageCount = $null
        $pageCountRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'PageCount'
        if ($pageCountRead.Success -and $null -ne $pageCountRead.Value) {
            try {
                $pageCount = [int] $pageCountRead.Value
            } catch {
                $pageCount = $null
            }
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        $dataRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'Data'
        if ($dataRead.Success -and $null -ne $dataRead.Value) {
            foreach ($item in @($dataRead.Value)) {
                if ($null -ne $item) {
                    $rows.Add($item) | Out-Null
                }
            }
        }

        $detail = @{
            outcome   = $outcomeText
            certainty = $certaintyText
            truncated = $truncated
        }
        if ($null -ne $pageCount) {
            $detail.pageCount = $pageCount
        }

        $isSucceeded = [string]::Equals($outcomeText, 'Succeeded', [System.StringComparison]::OrdinalIgnoreCase)
        $isKnown = [string]::Equals($certaintyText, 'Known', [System.StringComparison]::OrdinalIgnoreCase)
        $isComplete = $isSucceeded -and $isKnown -and -not $truncated

        if ($isComplete) {
            return New-PulseCollectionOutcome -Dataset $Dataset -Status Collected -Rows $rows.ToArray() -Gaps @() `
                -ReasonCode 'collected' -Detail $detail -Provider $providerValue -ApiVersion $ApiVersion `
                -Operations $operationsValue
        }

        if (-not $isSucceeded) {
            return New-InvalidEnvelopeOutcome
        }

        $reasonCode = if ($truncated -and $null -ne $pageCount -and $pageCount -ge 2) {
            'page-cap'
        } elseif ($truncated) {
            'truncated'
        } else {
            'indeterminate'
        }

        if ($rows.Count -gt 0) {
            $gap = New-PulseCollectionGap -Scope 'graph-envelope' -FailureClass Indeterminate `
                -ReasonCode $reasonCode -Detail $detail -Operation $gapOperation -ApiVersion $ApiVersion
            return New-PulseCollectionOutcome -Dataset $Dataset -Status Partial -Rows $rows.ToArray() `
                -Gaps @($gap) -ReasonCode $reasonCode -Detail $detail -Provider $providerValue `
                -ApiVersion $ApiVersion -Operations $operationsValue
        }

        return New-PulseCollectionOutcome -Dataset $Dataset -Status Failed -Rows @() -Gaps @() `
            -FailureClass Indeterminate -ReasonCode $reasonCode -Detail $detail `
            -Provider $providerValue -ApiVersion $ApiVersion -Operations $operationsValue
    } catch {
        return New-InvalidEnvelopeOutcome
    }
}
