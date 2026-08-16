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
    docstring for how a check rule receives it as $Context). FORMAT CONTRACT (post-review,
    M2): both arrays must be declared by ENTRA OBJECT ID (GUID). CONSUMPTION IS NARROWER
    THAN THE ARRAY NAMES SUGGEST (post-review docstring fix - an earlier draft of this note
    overclaimed "TP.ENT.0003/0004/0005, via Get-PulseCaExclusionContext" all consume this):
    verified against the actual rule functions, only TP.ENT.0003 (Test-PulseBreakGlassExcluded)
    declares a -Context parameter and actually reads it today. TP.ENT.0004
    (Test-PulseLegacyAuthBlocked) and TP.ENT.0005 (Test-PulseAdminMfaEnforced) declare no
    -Context parameter at all, so Invoke-PulseEvaluation's opt-in $Context wiring (see its
    own docstring) never threads BreakGlassAccounts/ServiceAccounts into either of them -
    wiring those two checks up to this same context is real, but not-yet-done future work
    (phase 4), not a currently-active behavior. This function does not itself validate the
    GUID format (it just reads the two keys through) - a non-GUID entry surfaces at
    evaluation time, in the ONE check that actually consumes it (TP.ENT.0003), as an
    unresolvable-format Warn, not silently as an unverified Fail.

    ThresholdOverrides, if present in the profile file, is ACCEPTED but entirely
    UNCONSUMED today (post-review docstring fix - an earlier draft of this note claimed
    this function "reads" it "only to confirm the key exists", which overclaimed even that
    much: the function body below never inspects the key's presence, value, or shape at
    all). A profile author may include a ThresholdOverrides key with no error, but its
    value is silently ignored end to end - never validated, never returned, never wired
    into -Context or anywhere else. This is honestly a no-op today, not a partially-wired
    reserved key; wiring it is future work.

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

        # Unknown-key warning (post-review fix, typo protection): a profile author who
        # misspells a key (e.g. 'BreakGlasAccounts') previously had it silently ignored -
        # indistinguishable from "I deliberately did not set this". Every top-level key
        # this function does not itself recognize is now named in a Write-Warning, so a
        # typo surfaces immediately instead of silently producing an under-configured
        # profile the operator believes is fully wired.
        $knownProfileKeys = [System.Collections.Generic.HashSet[string]]::new(
            [string[]] @('Include', 'Exclude', 'BreakGlassAccounts', 'ServiceAccounts', 'ThresholdOverrides'),
            [System.StringComparer]::Ordinal
        )
        foreach ($profileKey in $profileData.Keys) {
            if (-not $knownProfileKeys.Contains([string] $profileKey)) {
                Write-Warning "Resolve-PulseSelectionParams: -AssessmentProfile '$AssessmentProfile' has an unrecognized key '$profileKey' - it is not read or used by this module. Check for a typo (known keys: $(($knownProfileKeys | Sort-Object) -join ', '))."
            }
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
