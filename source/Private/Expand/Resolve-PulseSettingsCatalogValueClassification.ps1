<#
    Private: the ONE shape-aware classifier for "is this Settings Catalog value node
    secret, and can I trust its shape at all" - used by BOTH the raw-payload redactor
    (Protect-PulseSettingsCatalogSecretPayload, in Invoke-PulseSettingsCatalogExpansion.ps1)
    and the row walker (ConvertTo-PulseSettingRows.ps1). Review finding (P0-2, omp
    reproduced a fail-open bypass): two independent reimplementations of "is this secret"
    is exactly how a bypass like this happens - one copy checked `@odata.type` on a
    [PSObject] only and silently returned "not secret" for a hashtable-shaped or
    discriminator-less value, so a value shaped like `@{ value = 'plaintext' }` (no
    `@odata.type` at all) sailed through as an ordinary value. There is now exactly one
    function that makes this call, called from both places, so a shape a future Graph
    response introduces can only need fixing in ONE place, not two that can silently drift.

    FAIL CLOSED (P0-2, unconditional): a value node is treated as secret whenever ANY of
    the following is true - never only when the discriminator explicitly says so:
      1. -DefinitionIsSecretCapable is $true (the SETTING DEFINITION this value belongs to
         is flagged secret-capable in the definitions corpus - Get-PulseSettingDefinitionIndex's
         own IsSecretCapable field).
      2. The value's own `@odata.type` discriminator IS the secret subtype
         (`...SecretSettingValue`, matched case-insensitively by suffix - this is the
         expected, structurally normal case; classified secret, no accompanying gap).
      3. The discriminator is MISSING entirely (no `@odata.type` property at all, on
         either a [PSObject] or an [IDictionary]/hashtable-shaped value - the exact
         no-discriminator bypass the review reproduced).
      4. The discriminator IS present but does not match any entry in the small
         known-safe whitelist below (an unrecognized/future value shape).
    Cases 3 and 4 are "unknown shape", not "known secret" - IsKnownSafeShape/IsSecretByType
    on the returned object distinguish them so a caller can additionally raise a GAP for
    an unknown shape (Partial semantics), while a real declared secret (case 1 or 2) is the
    expected, silent-redact case with no gap.

    KNOWN-SAFE WHITELIST (deliberately small and explicit, matching the two `@odata.type`
    shapes T2.0's own golden fixtures actually exercise - see docs/spike/2026-08-16-
    settings-catalog-spike.md): the two FULLY-QUALIFIED strings
    `#microsoft.graph.deviceManagementConfigurationStringSettingValue` and
    `#microsoft.graph.deviceManagementConfigurationIntegerSettingValue`. Anything else -
    including a value shape this task's fixtures never saw - is NOT assumed safe; it is
    classified secret (fail closed) so a future/unrecognized Settings Catalog value shape
    can never silently leak through as "not secret" just because nobody has written a rule
    for it yet.

    EXACT MATCH, NOT SUFFIX (re-review round 2 - reproduced bypass): the whitelist is
    compared as an EXACT, case-insensitive, FULLY-QUALIFIED string
    ([string]::Equals(..., OrdinalIgnoreCase)) - mirroring exactly the fix
    Test-PulseSettingsCatalogInstanceType already applies to the five known instance types
    (ConvertTo-PulseSettingRows.ps1's own P1-9 fix), for the identical reason. The pre-fix
    shape here matched by SUFFIX (`(?i)$([regex]::Escape($safeShape))$`), which the
    re-review reproduced as a real secret-leak bypass: a value whose `@odata.type` merely
    ENDS in `...IntegerSettingValue` - e.g. a hypothetical/unknown
    `#microsoft.graph.deviceManagementConfigurationFutureIntegerSettingValue` - matched the
    whitelist and shipped `redacted:false` with the plaintext value intact and ZERO gaps,
    the exact opposite of this function's own FAIL CLOSED contract above. Note this is
    asymmetric with the SECRET-type check just above (case 2): that one is INTENTIONALLY
    still a suffix match - over-matching a string as secret only ever REDACTS something
    that might not strictly have needed it (fails closed, safe direction); only the
    known-safe whitelist's suffix match was the actual vulnerability, because over-matching
    THERE means classifying something safe that is not.

    ValueState VALIDATION: only Graph's own three documented enum-ish values -
    'notEncrypted', 'encryptedValueToken', 'invalidValueState' - are ever returned in
    -ValueState; anything else observed on the raw value (including $null, an empty
    string, or a value this classifier has never seen) comes back as $null. This is a
    small but deliberate hardening: valueState itself carries no secret content, but an
    unvalidated pass-through would let an attacker-shaped payload smuggle an arbitrary
    string into a persisted artifact under a field name a reader trusts to be one of three
    known values.
#>

# EXACT, fully-qualified strings (re-review round 2 - see this file's own EXACT MATCH, NOT
# SUFFIX docstring section for the reproduced suffix-match secret-leak bypass this closes).
$script:PulseSettingsCatalogKnownSafeValueShapes = @(
    '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
    '#microsoft.graph.deviceManagementConfigurationIntegerSettingValue'
)
$script:PulseSettingsCatalogKnownValueStates = @('notEncrypted', 'encryptedValueToken', 'invalidValueState')

function Get-PulseSettingsCatalogValueProperty {
    <#
        Private helper: read one property off a node that may be a [PSObject]
        (pscustomobject) OR an [IDictionary] (hashtable/ordered dictionary) - the
        no-discriminator bypass the review reproduced specifically exploited a classifier
        that only ever checked the PSObject shape and silently treated a dictionary-shaped
        value as having no `@odata.type` property to find, which then fell through to
        "not secret" instead of "unknown shape, fail closed".

        SHAPE NEUTRALITY (Task 2.2 P0 re-review): this is now the ONE shared accessor for
        EVERY raw-Graph-shaped read anywhere in the Settings Catalog expansion surface -
        the walk (ConvertTo-PulseSettingRows), the definitions-corpus index
        (Get-PulseSettingDefinitionIndex), and per-policy metadata reads
        (Invoke-PulseSettingsCatalogPolicy) - not only value-node secret classification.
        GraphKit's REAL response shape (verified against the live pipeline: every raw
        payload flows through `ConvertFrom-Json -AsHashtable`, never pscustomobject) is an
        [System.Management.Automation.OrderedHashtable] tree - and PowerShell's own
        `.PSObject.Properties[name]` ALWAYS returns the fixed IDictionary ADAPTER member
        set (Count/Keys/Values/IsReadOnly/...) for a hashtable-shaped node, never its
        actual dictionary entries (see Protect-PulseGraphRowTenantId's own docstring for
        the earlier, independent discovery of this exact trap). A guard-then-access
        pattern built on `.PSObject.Properties[name]` therefore silently evaluates
        "property absent" for every single field on a hashtable-shaped node, regardless of
        what the node actually contains - this was reproduced end to end against all 15
        T2.0 golden fixtures re-materialized through `-AsHashtable`: every one walked to
        zero rows and zero gaps, a silent-nothing false-clean result on real, populated
        Settings Catalog data. Every property read this module needs off a raw node MUST
        go through this function (or `Test-PulseSettingsCatalogNode` below for a bare
        container check) - never `.PSObject.Properties[...]` or `-is [PSObject]` directly
        against a value that might have come from Graph.
    #>
    param($Node, [string] $PropertyName)

    if ($null -eq $Node) { return $null }

    # ARRAY-RETURN UNROLLING TRAP (found chasing a real "walks to zero rows on a real
    # AsHashtable-shaped array-of-one" regression): a bare `return $value` on an
    # array/collection value gets UNROLLED onto the pipeline by `return` - a one-element
    # array collapses to its bare item, and a multi-element array becomes multiple
    # separate return values a normal `$x = Get-Foo` assignment silently re-collects into
    # an array that no longer matches what was actually stored. Worse: if the unrolled
    # single item is itself a Hashtable, a caller's OWN defensive `@($x)` wrap does not
    # restore the original array - `@()` on a bare Hashtable enumerates its
    # DictionaryEntry pairs (Hashtable implements IEnumerable), producing a garbage
    # "elements" list keyed by property count, not an array containing the hashtable. This
    # is the exact same class of trap Write-PulseDataset's and Remove-PulseGraphRowProvenance's
    # own docstrings already document (`return , $Data`) - protecting an
    # array/collection-typed value with the unary comma operator before returning is
    # mandatory here for the identical reason.
    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains($PropertyName)) {
            $value = $Node[$PropertyName]
            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { return , $value }
            return $value
        }
        return $null
    }

    if ($Node -is [System.Management.Automation.PSObject]) {
        $property = $Node.PSObject.Properties[$PropertyName]
        if ($null -ne $property) {
            $value = $property.Value
            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { return , $value }
            return $value
        }
        return $null
    }

    return $null
}

function Test-PulseSettingsCatalogNode {
    <#
        Private helper: is -Node something this module's raw-payload readers can safely
        property-access at all (via Get-PulseSettingsCatalogValueProperty above) - a
        [PSObject]/pscustomobject OR an [IDictionary] (hashtable/ordered dictionary)?

        DELIBERATELY NOT `-is [System.Management.Automation.PSObject]` alone (the
        pre-fix shape-check pattern this replaces): that type check is unreliable across
        BOTH real shapes this module ever sees - reproduced, empirically, against real
        `ConvertFrom-Json -AsHashtable` output: the OUTERMOST object a cmdlet call returns
        evaluates `-is [PSObject]` TRUE (PowerShell's pipeline-boundary wrapping), but a
        NESTED hashtable reached by property access off that same object (e.g. one root
        entry's own `settingInstance`) evaluates `-is [PSObject]` FALSE - the identical
        runtime type, inconsistent result depending on nothing but how deep in the tree it
        was reached. Checking `-is [IDictionary]` as well as `-is [PSObject]` makes this
        check give the SAME answer regardless of that wrapping accident, for every node in
        the tree.
    #>
    param($Node)
    return ($Node -is [System.Management.Automation.PSObject]) -or ($Node -is [System.Collections.IDictionary])
}

function Resolve-PulseSettingsCatalogValueClassification {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $SettingValue,

        [Parameter()]
        [bool] $DefinitionIsSecretCapable = $false
    )

    $odataTypeRaw = Get-PulseSettingsCatalogValueProperty -Node $SettingValue -PropertyName '@odata.type'
    $odataType = if ($null -ne $odataTypeRaw) { [string] $odataTypeRaw } else { $null }
    $hasDiscriminator = -not [string]::IsNullOrEmpty($odataType)

    $isSecretByType = $hasDiscriminator -and ($odataType -match '(?i)SecretSettingValue$')

    $isKnownSafeShape = $false
    if ($hasDiscriminator) {
        foreach ($safeShape in $script:PulseSettingsCatalogKnownSafeValueShapes) {
            if ([string]::Equals($odataType, $safeShape, [System.StringComparison]::OrdinalIgnoreCase)) {
                $isKnownSafeShape = $true
                break
            }
        }
    }

    # FAIL CLOSED: secret whenever the definition says so, the type says so, OR the shape
    # cannot be confidently classified safe (missing/unrecognized discriminator).
    $isSecret = $DefinitionIsSecretCapable -or $isSecretByType -or (-not $isKnownSafeShape)

    $rawValueState = Get-PulseSettingsCatalogValueProperty -Node $SettingValue -PropertyName 'valueState'
    $valueState = $null
    if ($null -ne $rawValueState) {
        $candidateValueState = [string] $rawValueState
        if ($script:PulseSettingsCatalogKnownValueStates -contains $candidateValueState) {
            $valueState = $candidateValueState
        }
    }

    return [pscustomobject]@{
        IsSecret         = $isSecret
        IsSecretByType    = $isSecretByType
        IsKnownSafeShape = $isKnownSafeShape
        HasDiscriminator = $hasDiscriminator
        ODataType        = $odataType
        ValueState       = $valueState
    }
}
