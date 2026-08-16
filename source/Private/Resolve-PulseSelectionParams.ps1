<#
    Private: the ONE place -AssessmentProfile is loaded and folded together with a
    caller's own CLI selection parameters into a ready-to-splat Select-PulseCheck
    parameter hashtable. Factored out (post-review) because Invoke-PulseAssessment and
    Get-PulseTenantSnapshot each carried a near-verbatim copy of this block - one bug fix
    or semantic change now lands in exactly one function instead of two that could drift
    apart.

    -BoundParameters must be the CALLER's own $PSBoundParameters (not this function's) -
    it is what determines whether a CLI selection parameter was explicitly bound (and
    therefore wins over the profile file), including the "bound to an empty array still
    wins" case, which a value-only check (e.g. `if ($IncludeCategory)`) cannot distinguish
    from "never bound at all".

    -AssessmentProfile's Include/Exclude arrays are folded into Select-PulseCheck's own
    -Include/-Exclude params (the profile vocabulary - a token matches either a category
    prefix or an exact check id, see Select-PulseCheck's own docstring), never into
    -IncludeCategory/-IncludeCheck - and only for whichever axis (include/exclude) has NO
    CLI parameter bound at all: binding EITHER -IncludeCategory or -IncludeCheck (even to
    an empty array) counts as "the include axis is spoken for on the CLI" and the
    profile's Include is not folded in at all; same rule for Exclude.

    BreakGlassAccounts/ServiceAccounts, if present in the profile file, are returned as
    -Context (for Invoke-PulseEvaluation's own -Context parameter - see that function's
    docstring for how a check rule receives it as $Context). ThresholdOverrides, if
    present, is read only to confirm the key exists in the file - RESERVED, its value is
    never inspected, never returned, and never wired into -Context or anywhere else; no
    schema/shape validation is performed on it (this function does not claim to validate
    the profile file's shape at all, only to read the four keys it actually consumes).

    Returns @{ SelectParams = <hashtable, ready to splat into Select-PulseCheck alongside
    -Checks>; Context = <hashtable, or $null if no -AssessmentProfile was supplied> }.
#>

function Resolve-PulseSelectionParams {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $BoundParameters,

        [Parameter()]
        [string[]] $IncludeCategory,

        [Parameter()]
        [string[]] $ExcludeCategory,

        [Parameter()]
        [string[]] $IncludeCheck,

        [Parameter()]
        [string[]] $ExcludeCheck,

        [Parameter()]
        [string] $AssessmentProfile
    )

    $profileInclude = $null
    $profileExclude = $null
    $context = $null

    if ($BoundParameters.ContainsKey('AssessmentProfile') -and -not [string]::IsNullOrWhiteSpace($AssessmentProfile)) {
        $profileData = Import-PowerShellDataFile -LiteralPath $AssessmentProfile -ErrorAction Stop

        if ($profileData.ContainsKey('Include')) { $profileInclude = @($profileData.Include) }
        if ($profileData.ContainsKey('Exclude')) { $profileExclude = @($profileData.Exclude) }

        $breakGlassAccounts = if ($profileData.ContainsKey('BreakGlassAccounts')) { @($profileData.BreakGlassAccounts) } else { @() }
        $serviceAccounts = if ($profileData.ContainsKey('ServiceAccounts')) { @($profileData.ServiceAccounts) } else { @() }
        $context = @{
            BreakGlassAccounts = $breakGlassAccounts
            ServiceAccounts    = $serviceAccounts
        }
    }

    # A CLI param on EITHER axis-specific parameter counts as "the same axis" as the
    # profile's single, axis-ambiguous Include/Exclude array - if the caller explicitly
    # bound -IncludeCategory or -IncludeCheck (even to an empty array), that wins outright
    # and the profile's Include is not folded in at all. Same rule for Exclude.
    $includeBoundOnCli = $BoundParameters.ContainsKey('IncludeCategory') -or $BoundParameters.ContainsKey('IncludeCheck')
    $excludeBoundOnCli = $BoundParameters.ContainsKey('ExcludeCategory') -or $BoundParameters.ContainsKey('ExcludeCheck')

    $selectParams = @{}
    if ($BoundParameters.ContainsKey('IncludeCategory')) { $selectParams.IncludeCategory = $IncludeCategory }
    if ($BoundParameters.ContainsKey('ExcludeCategory')) { $selectParams.ExcludeCategory = $ExcludeCategory }
    if ($BoundParameters.ContainsKey('IncludeCheck')) { $selectParams.IncludeCheck = $IncludeCheck }
    if ($BoundParameters.ContainsKey('ExcludeCheck')) { $selectParams.ExcludeCheck = $ExcludeCheck }
    if (-not $includeBoundOnCli -and $null -ne $profileInclude) { $selectParams.Include = $profileInclude }
    if (-not $excludeBoundOnCli -and $null -ne $profileExclude) { $selectParams.Exclude = $profileExclude }

    return @{
        SelectParams = $selectParams
        Context      = $context
    }
}
