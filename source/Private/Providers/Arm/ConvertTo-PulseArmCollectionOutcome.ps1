<#
    Private: map an ARM provider result onto the provider-neutral collection outcome.

    Status, FailureClass, and provenance stay structured. ARM never emits Graph
    Type/Operation metadata. Failed outcomes cannot carry rows.
#>

function ConvertTo-PulseArmCollectionOutcome {
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
        $ApiVersion = $null
    )

    $detailValue = @{}
    if ($null -ne $Detail) {
        foreach ($key in $Detail.Keys) {
            $detailValue[$key] = $Detail[$key]
        }
    }
    return New-PulseCollectionOutcome -Dataset $Dataset -Status $Status -Rows $Rows -Gaps $Gaps `
        -FailureClass $FailureClass -ReasonCode $ReasonCode -Detail $detailValue `
        -Provider 'ARM' -ApiVersion $ApiVersion -Operations @('GET')
}
