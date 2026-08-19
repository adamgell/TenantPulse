<#
    Private: construct one provider-neutral dataset collection outcome.

    Status and FailureClass are deliberately separate dimensions. Collected is complete and
    therefore cannot carry failure metadata; Partial requires at least one structured gap;
    Failed and Skipped require a supported top-level failure class and cannot carry usable rows.
#>

function New-PulseCollectionOutcome {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Dataset,

        [Parameter(Mandatory)]
        [ValidateSet('Collected', 'Partial', 'Failed', 'Skipped')]
        [string] $Status,

        [Parameter()]
        [AllowNull()]
        [object[]] $Rows = @(),

        [Parameter()]
        [AllowNull()]
        [object[]] $Gaps = @(),

        [Parameter()]
        [AllowNull()]
        $FailureClass = $null,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ReasonCode,

        [Parameter()]
        [AllowNull()]
        [hashtable] $Detail = $null,

        [Parameter()]
        [AllowNull()]
        $Provider = $null,

        [Parameter()]
        [AllowNull()]
        $ApiVersion = $null,

        [Parameter()]
        [AllowNull()]
        [object[]] $Operations = @()
    )

    $supportedFailureClasses = @(
        'DescriptorPending'
        'PlatformUnavailable'
        'PermissionDenied'
        'LicenseRequired'
        'GateUnknown'
        'DependencyUnavailable'
        'AuthenticationFailed'
        'DeadlineExpired'
        'Cancelled'
        'InvalidProviderData'
        'ProviderFailed'
        'Indeterminate'
    )

    if ($null -ne $FailureClass) {
        $failureClassText = [string] $FailureClass
        if ([string]::IsNullOrWhiteSpace($failureClassText) -or $supportedFailureClasses -notcontains $failureClassText) {
            throw "New-PulseCollectionOutcome: unsupported FailureClass '$failureClassText'."
        }
        $FailureClass = $failureClassText
    }

    $rowsValue = if ($null -eq $Rows) { @() } else { @($Rows) }
    $gapsValue = if ($null -eq $Gaps) { @() } else { @($Gaps) }
    $operationsValue = if ($null -eq $Operations) { @() } else { @($Operations) }

    foreach ($gap in $gapsValue) {
        if ($null -eq $gap) {
            throw 'New-PulseCollectionOutcome: Gaps cannot contain null values.'
        }

        $gapPropertyNames = @($gap.PSObject.Properties.Name)
        foreach ($requiredGapProperty in @('Scope', 'FailureClass', 'ReasonCode', 'Detail', 'Operation', 'ApiVersion')) {
            if ($gapPropertyNames -notcontains $requiredGapProperty) {
                throw "New-PulseCollectionOutcome: each gap must contain '$requiredGapProperty'."
            }
        }

        if ($supportedFailureClasses -notcontains ([string] $gap.FailureClass)) {
            throw "New-PulseCollectionOutcome: gap FailureClass '$($gap.FailureClass)' is unsupported."
        }
    }

    switch ($Status) {
        'Collected' {
            if ($null -ne $FailureClass) {
                throw "New-PulseCollectionOutcome: Collected outcomes cannot carry a FailureClass."
            }
            if ($gapsValue.Count -gt 0) {
                throw "New-PulseCollectionOutcome: Collected outcomes cannot carry gaps."
            }
        }
        'Partial' {
            if ($gapsValue.Count -eq 0) {
                throw "New-PulseCollectionOutcome: Partial outcomes require at least one gap."
            }
            if ($null -ne $FailureClass) {
                throw "New-PulseCollectionOutcome: Partial outcomes carry failure classes on their gaps, not at the top level."
            }
        }
        'Failed' { }
        'Skipped' { }
    }

    if ($Status -in @('Failed', 'Skipped')) {
        if ($null -eq $FailureClass) {
            throw "New-PulseCollectionOutcome: $Status outcomes require a top-level FailureClass."
        }
        if ($rowsValue.Count -gt 0) {
            throw "New-PulseCollectionOutcome: $Status outcomes cannot carry usable Rows."
        }
    }

    return [pscustomobject][ordered]@{
        Dataset      = $Dataset
        Status       = $Status
        Rows         = $rowsValue
        Gaps         = $gapsValue
        FailureClass = $FailureClass
        ReasonCode   = $ReasonCode
        Detail       = $Detail
        Provider     = if ($null -eq $Provider) { $null } else { [string] $Provider }
        ApiVersion   = if ($null -eq $ApiVersion) { $null } else { [string] $ApiVersion }
        Operations   = $operationsValue
    }
}
