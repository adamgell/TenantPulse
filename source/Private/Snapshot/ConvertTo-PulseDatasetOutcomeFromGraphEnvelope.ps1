<#
    Private: validate and map exactly one genuine GraphKit.OperationResult envelope to a
    provider-neutral collection outcome. Genuine means the GraphKit.OperationResult type
    identity is present and non-null Data, Outcome, and Certainty members exist, Data has
    no null elements, and
    supported signal values; successful paged operations additionally require native-Boolean
    Truncated and positive PageCount members. GraphKit 0.3.0 non-paged operations and paged
    terminal failures omit both paging members, so the caller must identify PagingStrategy=None
    before only a successful member-free shape is accepted. A plain object carrying similarly
    named properties is not an envelope.

    AC-26: Collected is allowed only when Outcome=Succeeded, Certainty=Known, Truncated is
    not true, and no cap/incompleteness signal is present. Succeeded with usable but
    incomplete rows becomes Partial plus one structured gap. Incomplete envelopes without
    safe rows become Failed/Indeterminate. Null, rows-only, multiple, type-spoofed, or
    malformed input becomes Failed/InvalidProviderData; success is never synthesized from
    the absence of an envelope. This function is total: hostile getters degrade only to
    InvalidProviderData and never throw to a snapshot writer.
#>

function Test-PulseGraphResultEnvelope {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $InputObject,

        [Parameter()]
        [ValidateSet('None', 'NextLink')]
        [string] $PagingStrategy = 'NextLink'
    )

    try {
        if ($null -eq $InputObject -or $InputObject -is [string] -or
            $InputObject.PSObject.TypeNames -notcontains 'GraphKit.OperationResult') {
            return $false
        }

        $values = [ordered]@{}
        foreach ($name in @('Outcome', 'Certainty', 'Data')) {
            if ($InputObject -is [System.Collections.IDictionary]) {
                $matchingKey = @($InputObject.Keys | Where-Object {
                        [string]::Equals([string] $_, $name, [System.StringComparison]::OrdinalIgnoreCase)
                    })
                if ($matchingKey.Count -ne 1) { return $false }
                $values[$name] = $InputObject[$matchingKey[0]]
            }
            else {
                $property = $InputObject.PSObject.Properties[$name]
                if ($null -eq $property) { return $false }
                $values[$name] = $property.Value
            }
        }

        $truncatedFound = $false
        $pageCountFound = $false
        if ($InputObject -is [System.Collections.IDictionary]) {
            foreach ($key in @($InputObject.Keys)) {
                if ([string]::Equals([string] $key, 'Truncated', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $truncatedFound = $true
                    $values['Truncated'] = $InputObject[$key]
                }
                if ([string]::Equals([string] $key, 'PageCount', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $pageCountFound = $true
                    $values['PageCount'] = $InputObject[$key]
                }
            }
        } else {
            $truncatedProperty = $InputObject.PSObject.Properties['Truncated']
            $pageCountProperty = $InputObject.PSObject.Properties['PageCount']
            if ($null -ne $truncatedProperty) {
                $truncatedFound = $true
                $values['Truncated'] = $truncatedProperty.Value
            }
            if ($null -ne $pageCountProperty) {
                $pageCountFound = $true
                $values['PageCount'] = $pageCountProperty.Value
            }
        }

        if ($values['Outcome'] -isnot [string] -or
            $values['Outcome'] -notin @('Succeeded', 'Failed', 'Cancelled', 'DeadlineExpired')) {
            return $false
        }
        if ($values['Certainty'] -isnot [string] -or
            $values['Certainty'] -notin @('Known', 'Indeterminate')) {
            return $false
        }
        if ($truncatedFound -and $values['Truncated'] -isnot [bool]) { return $false }
        if ($pageCountFound -and
            ($values['PageCount'] -isnot [int] -or [int] $values['PageCount'] -lt 1)) {
            return $false
        }
        if ($PagingStrategy -eq 'NextLink') {
            # GraphKit's terminal paged failure envelope has no Truncated/PageCount:
            # those fields describe the completeness of a successful page traversal.
            # A successful NextLink result must always carry both proof signals; a
            # supported non-success result may omit them, but any supplied value was
            # still type/range checked above.
            if ($values['Outcome'] -eq 'Succeeded' -and
                (-not $truncatedFound -or -not $pageCountFound)) {
                return $false
            }
        } else {
            # GraphKit 0.3.0's non-paged result has neither member. Universal envelope
            # producers and older fixtures may still add harmless Truncated=$false or
            # PageCount metadata; the resolved None descriptor is the completeness proof.
            # Truncated=$true still contradicts that proof and therefore fails closed.
            if ($truncatedFound -and $values['Truncated']) { return $false }
        }
        if ($null -eq $values['Data']) { return $false }
        foreach ($item in @($values['Data'])) {
            if ($null -eq $item) { return $false }
        }

        return $true
    } catch {
        return $false
    }
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
        [ValidateSet('None', 'NextLink')]
        [string] $PagingStrategy = 'NextLink',

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
        if (-not (Test-PulseGraphResultEnvelope -InputObject $Envelope -PagingStrategy $PagingStrategy)) {
            return New-InvalidEnvelopeOutcome
        }

        $outcomeRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'Outcome'
        $certaintyRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'Certainty'
        $outcomeText = if ($outcomeRead.Success) { ConvertTo-SafeEnvelopeString -Value $outcomeRead.Value } else { $null }
        $certaintyText = if ($certaintyRead.Success) { ConvertTo-SafeEnvelopeString -Value $certaintyRead.Value } else { $null }

        $truncated = $false
        $truncatedRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'Truncated'
        if ($truncatedRead.Success) {
            if ($truncatedRead.Value -isnot [bool]) { return New-InvalidEnvelopeOutcome }
            $truncated = [bool] $truncatedRead.Value
        }

        $pageCount = $null
        $pageCountRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'PageCount'
        if ($PagingStrategy -eq 'NextLink' -and $pageCountRead.Success -and $null -ne $pageCountRead.Value) {
            try {
                $pageCount = [int] $pageCountRead.Value
                if ($PagingStrategy -eq 'NextLink' -and $pageCount -lt 1) { return New-InvalidEnvelopeOutcome }
            } catch {
                return New-InvalidEnvelopeOutcome
            }
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        $dataRead = Get-SafeEnvelopeProperty -InputObject $Envelope -Name 'Data'
        if (-not $dataRead.Success) { return New-InvalidEnvelopeOutcome }
        if ($null -ne $dataRead.Value) {
            foreach ($item in @($dataRead.Value)) {
                if ($null -eq $item) { return New-InvalidEnvelopeOutcome }
                $rows.Add($item) | Out-Null
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
            $failure = switch ($outcomeText) {
                'Failed' { @{ Class = 'ProviderFailed'; Code = 'provider-failed' }; break }
                'Cancelled' { @{ Class = 'Cancelled'; Code = 'cancelled' }; break }
                'DeadlineExpired' { @{ Class = 'DeadlineExpired'; Code = 'deadline-expired' }; break }
                default { $null }
            }
            if ($null -eq $failure) { return New-InvalidEnvelopeOutcome }
            return New-PulseCollectionOutcome -Dataset $Dataset -Status Failed -Rows @() -Gaps @() `
                -FailureClass $failure.Class -ReasonCode $failure.Code -Detail $detail `
                -Provider $providerValue -ApiVersion $ApiVersion -Operations $operationsValue
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
