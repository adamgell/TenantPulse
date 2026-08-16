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
    combined with OR across axes. ACTUAL PASS ORDER (verified against the code, post-review
    docstring fix - an earlier draft of this note claimed "every Exclude pass runs strictly
    after every Include pass", which does not match the function body below): the six
    passes run in the fixed order IncludeCategory, ExcludeCategory, IncludeCheck,
    ExcludeCheck, Include, Exclude - ExcludeCategory (pass 2) runs BEFORE IncludeCheck
    (pass 3), so Excludes are not literally grouped after every Include. Exclude-vs-include
    precedence still holds - a check dropped by any exclude pass can never be re-admitted by
    a later include pass, because every pass only ever narrows (Where-Object over whatever
    survived so far, never a re-union) - but that guarantee comes from every pass being a
    pure AND-narrowing step, not from Excludes being ordered strictly after Includes. The
    FINAL result is identical regardless of the passes' relative order (AND is
    commutative), so this ordering detail affects nothing observable - it just was not what
    the original docstring claimed.

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

    ELEMENT-LEVEL VALIDATION (post-review fix): every token array is checked for a
    null/empty/whitespace-only ELEMENT and throws naming the offending parameter if one is
    found - a blank element is never silently ignored or treated as "no filter". This
    closes a real bug: `if ($IncludeCategory -and $IncludeCategory.Count -gt 0)` looks like
    a safe not-empty check, but PowerShell collapses a SINGLE-element array used in a
    boolean context to that one element's own truthiness rather than the array's Count -
    `-IncludeCategory @('')` produced an `if (@('') -and ...)` that evaluated to $false
    (an empty string is falsy) even though the array's Count was 1, silently skipping the
    whole IncludeCategory filter and returning the full, unfiltered catalog. Every
    not-empty check in this file now tests `$null -ne $Array -and $Array.Count -gt 0`
    instead, which cannot collapse this way, and the new blank-element guard means an
    accidental `@('')` is a loud error instead of a silent "select everything".
#>

function Assert-PulseSelectionTokensNotBlank {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ParameterName,

        [Parameter()]
        [AllowNull()]
        [string[]] $Tokens
    )

    if ($null -eq $Tokens) {
        return
    }

    foreach ($token in $Tokens) {
        if ([string]::IsNullOrWhiteSpace($token)) {
            throw "Select-PulseCheck: -$ParameterName contains a null, empty or whitespace-only element - every selection token must be a real, non-blank value."
        }
    }
}

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

    Assert-PulseSelectionTokensNotBlank -ParameterName 'IncludeCategory' -Tokens $IncludeCategory
    Assert-PulseSelectionTokensNotBlank -ParameterName 'ExcludeCategory' -Tokens $ExcludeCategory
    Assert-PulseSelectionTokensNotBlank -ParameterName 'IncludeCheck' -Tokens $IncludeCheck
    Assert-PulseSelectionTokensNotBlank -ParameterName 'ExcludeCheck' -Tokens $ExcludeCheck
    Assert-PulseSelectionTokensNotBlank -ParameterName 'Include' -Tokens $Include
    Assert-PulseSelectionTokensNotBlank -ParameterName 'Exclude' -Tokens $Exclude

    $result = @($Checks)

    # Every not-empty check below tests `$null -ne $Array -and $Array.Count -gt 0` rather
    # than the more natural-looking `$Array -and $Array.Count -gt 0` - see this file's own
    # ELEMENT-LEVEL VALIDATION docstring note for why the latter is a real bug (a
    # single-element array collapses to its element's truthiness in a boolean context).
    if ($null -ne $IncludeCategory -and $IncludeCategory.Count -gt 0) {
        $result = @($result | Where-Object { Test-PulseCategoryPrefixMatch -Category ([string] $_.Category) -Tokens $IncludeCategory })
    }
    if ($null -ne $ExcludeCategory -and $ExcludeCategory.Count -gt 0) {
        $result = @($result | Where-Object { -not (Test-PulseCategoryPrefixMatch -Category ([string] $_.Category) -Tokens $ExcludeCategory) })
    }
    if ($null -ne $IncludeCheck -and $IncludeCheck.Count -gt 0) {
        $result = @($result | Where-Object { Test-PulseIdExactMatch -Id ([string] $_.Id) -Tokens $IncludeCheck })
    }
    if ($null -ne $ExcludeCheck -and $ExcludeCheck.Count -gt 0) {
        $result = @($result | Where-Object { -not (Test-PulseIdExactMatch -Id ([string] $_.Id) -Tokens $ExcludeCheck) })
    }
    if ($null -ne $Include -and $Include.Count -gt 0) {
        $result = @($result | Where-Object { Test-PulseProfileTokenMatch -Check $_ -Tokens $Include })
    }
    if ($null -ne $Exclude -and $Exclude.Count -gt 0) {
        $result = @($result | Where-Object { -not (Test-PulseProfileTokenMatch -Check $_ -Tokens $Exclude) })
    }

    return $result
}
