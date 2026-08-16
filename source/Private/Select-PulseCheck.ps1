<#
    Private: the single check-selection filter shared by every public entry point that
    narrows a check catalog (Get-PulseTenantSnapshot's own selection params today,
    Invoke-PulseAssessment/Invoke-PulseCheck from Task 1.8 onward). One filter, not two -
    this function exists specifically so selection semantics can never diverge between the
    collector and the assessment pipeline.

    TWO SELECTION VOCABULARIES (deliberate, both AND together with everything else):
        - CLI vocabulary (-IncludeCategory/-ExcludeCategory/-IncludeCheck/-ExcludeCheck):
          axis-specific and unambiguous. -IncludeCategory/-ExcludeCategory match a check's
          Category by DOTTED-PREFIX (see Test-PulseCategoryPrefixMatch below): a token
          'Entra' matches 'Entra', 'Entra.ConditionalAccess', 'Entra.Identity', ... but
          never 'EntraFoo' - only a full path-segment prefix counts. -IncludeCheck/
          -ExcludeCheck match a check's Id by EXACT ordinal equality (check ids are not
          hierarchical - there is no prefix concept to apply).
        - Profile vocabulary (-Include/-Exclude): used only by an assessment-profile
          .psd1's Include/Exclude arrays (Task 1.8's Invoke-PulseAssessment), where a
          single token list cannot say up front whether an entry is a category prefix or a
          literal check id. A token in -Include/-Exclude matches a check if EITHER its
          Category dotted-prefix-matches the token OR its Id exactly equals the token -
          tried against both, so a profile author can freely mix 'Entra.ConditionalAccess'
          and 'TP.ENT.0007' in the same list.

    EVERY SUPPLIED FILTER NARROWS FURTHER (AND across axes, matching
    Get-PulseTenantSnapshot's original docstring promise): each bound parameter is applied
    as its own sequential Where-Object pass over whatever survived the previous pass, never
    combined with OR across axes. Exclude-vs-include precedence falls out of this
    ordering by construction: every Exclude pass runs strictly after every Include pass in
    this function's body, so a check that matches both an Include and an Exclude for the
    same or a different axis is always dropped - exclude always wins, at every axis,
    including across the CLI and profile vocabularies.

    ORDINAL MATCHING ONLY: this function never uses PowerShell's default -eq/-in/-contains
    (case-insensitive collation), matching every other "deterministic ordering/matching
    everywhere" rule in this codebase (see ConvertTo-PulseCanonicalJson, Import-
    PulseCheckCatalog). Every comparison goes through [string]::Equals(a, b,
    [System.StringComparison]::Ordinal) or a case-sensitive prefix check built the same way.

    ORDER-PRESERVING: the input array's relative order is never changed. Import-
    PulseCheckCatalog already returns Id-sorted output and callers rely on that invariant
    surviving selection - this function is a pure filter, never a sorter.

    An empty/unbound filter parameter on any axis means "do not filter on this axis"
    (matches everything) - identical to Get-PulseTenantSnapshot's pre-Task-1.8 behavior.
#>

function Test-PulseCategoryPrefixMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Category,

        [Parameter(Mandatory)]
        [string[]] $Tokens
    )

    foreach ($token in $Tokens) {
        if ([string]::Equals($Category, $token, [System.StringComparison]::Ordinal)) {
            return $true
        }
        if ($Category.StartsWith("$token.", [System.StringComparison]::Ordinal)) {
            return $true
        }
    }

    return $false
}

function Test-PulseIdExactMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Id,

        [Parameter(Mandatory)]
        [string[]] $Tokens
    )

    foreach ($token in $Tokens) {
        if ([string]::Equals($Id, $token, [System.StringComparison]::Ordinal)) {
            return $true
        }
    }

    return $false
}

function Test-PulseProfileTokenMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Check,

        [Parameter(Mandatory)]
        [string[]] $Tokens
    )

    if (Test-PulseCategoryPrefixMatch -Category ([string] $Check.Category) -Tokens $Tokens) {
        return $true
    }

    return Test-PulseIdExactMatch -Id ([string] $Check.Id) -Tokens $Tokens
}

function Select-PulseCheck {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Checks,

        [Parameter()]
        [string[]] $IncludeCategory,

        [Parameter()]
        [string[]] $ExcludeCategory,

        [Parameter()]
        [string[]] $IncludeCheck,

        [Parameter()]
        [string[]] $ExcludeCheck,

        [Parameter()]
        [string[]] $Include,

        [Parameter()]
        [string[]] $Exclude
    )

    $result = @($Checks)

    if ($IncludeCategory -and $IncludeCategory.Count -gt 0) {
        $result = @($result | Where-Object { Test-PulseCategoryPrefixMatch -Category ([string] $_.Category) -Tokens $IncludeCategory })
    }
    if ($ExcludeCategory -and $ExcludeCategory.Count -gt 0) {
        $result = @($result | Where-Object { -not (Test-PulseCategoryPrefixMatch -Category ([string] $_.Category) -Tokens $ExcludeCategory) })
    }
    if ($IncludeCheck -and $IncludeCheck.Count -gt 0) {
        $result = @($result | Where-Object { Test-PulseIdExactMatch -Id ([string] $_.Id) -Tokens $IncludeCheck })
    }
    if ($ExcludeCheck -and $ExcludeCheck.Count -gt 0) {
        $result = @($result | Where-Object { -not (Test-PulseIdExactMatch -Id ([string] $_.Id) -Tokens $ExcludeCheck) })
    }
    if ($Include -and $Include.Count -gt 0) {
        $result = @($result | Where-Object { Test-PulseProfileTokenMatch -Check $_ -Tokens $Include })
    }
    if ($Exclude -and $Exclude.Count -gt 0) {
        $result = @($result | Where-Object { -not (Test-PulseProfileTokenMatch -Check $_ -Tokens $Exclude) })
    }

    return $result
}
