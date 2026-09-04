function script:New-PulseTestGraphEnvelope {
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Data = @(),

        [Parameter()]
        [ValidateSet('Succeeded', 'Failed', 'Cancelled', 'DeadlineExpired')]
        [string] $Outcome = 'Succeeded',

        [Parameter()]
        [ValidateSet('Known', 'Indeterminate')]
        [string] $Certainty = 'Known',

        [Parameter()]
        [bool] $Truncated = $false,

        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int] $PageCount = 1
    )

    [pscustomobject]@{
        PSTypeName = 'GraphKit.OperationResult'
        Outcome    = $Outcome
        Certainty  = $Certainty
        Truncated  = $Truncated
        Data       = @($Data)
        PageCount  = $PageCount
        Telemetry  = @()
        Provenance = @{}
    }
}
