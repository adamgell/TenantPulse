<#
    Private: Sensitive-aware redaction pass for RAW dataset writes of map-covered typed-
    policy datasets (`deviceCompliancePolicies`, `deviceConfigurations`) - the SECRET
    CONTRACT gap a review found (C1, task-2.3-report.md addendum): TypedPolicyMaps.psd1's
    own Sensitive classifications (e.g. windows10CustomConfiguration's omaSettings[].value
    - a WiFi pre-shared key/VPN secret/certificate push channel, see that file's own
    docstring) previously drove redaction ONLY in the setting-expansion walk
    (ConvertTo-PulseTypedPolicyRows.ps1) - the RAW dataset write Invoke-PulseCollection.ps1
    performs for every Collected dataset persisted every Graph row, Sensitive-flagged
    properties included, in cleartext, to datasets/deviceConfigurations.json - for the full
    lifetime of every snapshot, independent of whether -ExpandSettings was ever used at all.

    Called by Invoke-PulseCollection.ps1 immediately after Get-GraphObject returns and
    BEFORE Write-PulseDataset is ever invoked - redaction happens before the FIRST byte
    touches disk, matching every other secret-handling call site in this module (never
    "redact after the fact").

    DATASET SCOPE, HONEST BOUNDARY (documented per the review's explicit ask): this
    function redacts EXACTLY the two datasets TypedPolicyMaps.psd1 has a
    'deviceCompliancePolicies'->'compliance' / 'deviceConfigurations'->'deviceConfiguration'
    mapping for. Every OTHER dataset name is returned completely UNCHANGED - this function
    has no way to know whether some other dataset's rows carry a Sensitive-shaped property,
    because no map exists to tell it so. This is not a general-purpose raw-payload
    redactor (compare Protect-PulseSettingsCatalogSecretPayload, which classifies EVERY
    value node structurally via a shared discriminator-based classifier with no map
    dependency); it is scoped, by design, to exactly the two typed-policy families
    TypedPolicyMaps.psd1 actually describes. A dataset added to DatasetMap.psd1 in the
    future that also happens to carry Sensitive-shaped Graph properties gets NO protection
    from this function until (and unless) it is also added to TypedPolicyMaps.psd1's own
    dataset->policyType mapping below - this is the one honest gap in this fix, called out
    here rather than implied to be more general than it is.

    UNMAPPED @odata.type WITHIN A MAPPED DATASET: a row whose own `@odata.type` has no
    entry in the relevant TypedPolicyMaps.psd1 sub-map (the identical "collected, not
    setting-expanded" situation Invoke-PulseTypedPolicyExpansion.ps1 gaps) is passed
    through UNCHANGED here too, for the same reason - there is no known Sensitive
    classification for a shape this module has no property map for. This is consistent
    with (not a regression relative to) the expansion walk's own behavior: neither layer
    can redact what it has no classification for.

    SHAPE NEUTRALITY: every raw-row read goes through the shared
    Get-PulseSettingsCatalogValueProperty/Test-PulseSettingsCatalogNode accessors (works
    identically on a [PSObject] or an [IDictionary] - GraphKit's real production shape,
    see those functions' own docstrings), never `.PSObject.Properties[...]` directly.

    REDACTION SHAPE: a Sensitive-flagged property's value is replaced with
    `{ redacted: true }` (a small marker object, never `$null` alone and never the raw
    value in any form) - structurally distinguishable from an ordinary absent/null field on
    read-back, matching the {redacted:true} shape the row-schema secret contract already
    uses elsewhere in this module. Every OTHER property on the row - including every
    property this map does not even list - is copied through completely unchanged; this is
    a surgical, map-driven redaction, not a blanket "wipe everything" pass.

    RECURSIVE, UNBOUNDED DEPTH - SYMMETRIC WITH ConvertTo-PulseTypedPolicyRows.ps1
    (T3.4 whole-task dual review, fix round 1, MEDIUM finding - adversarial-proven live: a
    depth-3 Sensitive leaf reached raw disk cleartext through THIS pass, because it was
    still capped at one level of Nested while the row-emission walk had already grown
    genuine recursion in Part C. Inert with today's SHIPPED map - no real map entry
    actually nests 3 levels deep yet - but a structural hole, not merely a documentation
    gap, closed here rather than left latent for the next map entry that does nest that
    deep to reopen it for real.): `Protect-PulseTypedPolicyValueBySpec` (below) now walks a
    property's own `Nested` description exactly as deep as the map declares it, calling
    itself recursively for every Nested.Properties entry - the SAME "Sensitive always wins,
    at every depth, unconditionally; a Sensitive property's own Nested description, if
    present, is schema-legal documentation, never walked" rule
    ConvertTo-PulseTypedPolicyRows.ps1/TypedPolicyMaps.psd1 already state, now TRUE for
    BOTH layers, not just the row-emission one. `Protect-PulseTypedPolicyNestedElement`
    (the ORIGINAL one-level helper, -SensitiveNames-based) is kept UNCHANGED below - not
    because the main path still calls it, but because its own dedicated regression suite
    (ProtectTypedPolicySensitivePayload.Tests.ps1's "FAIL CLOSED" Describe block) calls it
    DIRECTLY by that exact signature; retired as the main path's engine, kept as its own
    tested, working primitive. `Protect-PulseTypedPolicyValueBySpec`/
    `Protect-PulseTypedPolicyNestedContainer` (new, below) are the real recursive engine
    `Protect-PulseTypedPolicyRow` now calls, mirroring the SAME fail-closed rule for an
    unrecognized/scalar container shape under a Nested property (redact wholesale, never
    pass through) at every recursion level, not just the first.
#>

# DATASET -> policyType MAP (see this file's own DATASET SCOPE docstring section for why
# this is a small, closed, honestly-documented list rather than "every DatasetMap.psd1
# entry").
$script:PulseTypedPolicyRedactionDatasetMap = @{
    'deviceCompliancePolicies' = 'compliance'
    'deviceConfigurations'     = 'deviceConfiguration'
}

function New-PulseRedactedMarker {
    return [pscustomobject]@{ redacted = $true }
}

function Protect-PulseTypedPolicyNestedElement {
    <#
        Private helper: clone one nested element (an omaSettings array entry, or a single
        installationSchedule-shaped object), redacting only the property names in
        -SensitiveNames. Shape-preserving for both [IDictionary] and [PSObject] inputs.

        FAIL CLOSED (task-2.3-review round 2, finding 1 - reproduced fail-open):
        -SensitiveNames is always non-empty at every call site (the caller,
        Protect-PulseTypedPolicyRow's own Protect-PulseTypedPolicyPropertyValue closure,
        only ever invokes this function when at least one Nested.Properties entry is
        flagged Sensitive - see that function's own $nestedSpecByName construction). An
        -Element that is NEITHER an [IDictionary] NOR a [PSObject] - a scalar sitting where
        an object was expected (a raw string/int/bool array element, or a bare scalar
        sitting in the single-object nested position), or any other shape this function
        cannot structurally redact INTO - is therefore redacted WHOLESALE rather than
        passed through unchanged. The pre-fix behavior returned an unrecognized-shape
        element completely UNREDACTED, a real fail-open: top-level Sensitive redaction
        (Protect-PulseTypedPolicyRow's own $sensitiveTopNames check) redacts
        UNCONDITIONALLY regardless of the property's own value shape, but this nested path
        only redacted when the CONTAINER shape matched what was expected - an asymmetry a
        value shaped unexpectedly (e.g. a raw string sitting where an omaSettings[] element
        is normally an object) walked straight through in cleartext. "Cannot confidently
        redact just the flagged sub-property" now means "redact the whole thing", never
        "pass it through" - the same fail-closed rule this module applies everywhere else a
        shape cannot be confidently classified (see
        Resolve-PulseSettingsCatalogValueClassification's own FAIL CLOSED docstring).
    #>
    param($Element, [string[]] $SensitiveNames)

    if ($Element -is [System.Collections.IDictionary]) {
        $clone = [ordered]@{}
        foreach ($key in @($Element.Keys)) {
            $clone[$key] = if ($SensitiveNames -contains $key) { New-PulseRedactedMarker } else { $Element[$key] }
        }
        return $clone
    }

    if ($Element -is [System.Management.Automation.PSObject]) {
        $clone = [pscustomobject]@{}
        foreach ($property in @($Element.PSObject.Properties)) {
            $value = if ($SensitiveNames -contains $property.Name) { New-PulseRedactedMarker } else { $property.Value }
            Add-Member -InputObject $clone -NotePropertyName $property.Name -NotePropertyValue $value
        }
        return $clone
    }

    # FAIL CLOSED: an unrecognized/scalar shape under a Sensitive-nested rule is redacted
    # wholesale, never passed through - see this function's own docstring.
    return New-PulseRedactedMarker
}

function Protect-PulseTypedPolicyNestedContainer {
    <#
        Private helper (Part C/T3.4 fix round, new): redact ONE container (an omaSettings
        array element, an installationSchedule-shaped object, or any deeper Nested
        container) according to -NestedProperties (the map's own PropertySpec objects for
        this container's own declared children - Name/Sensitive/optionally a further
        Nested), recursing into Protect-PulseTypedPolicyValueBySpec per named child. Mirrors
        Protect-PulseTypedPolicyNestedElement's own FAIL CLOSED rule for a container shape
        this function cannot decompose into (redact WHOLESALE, never pass through
        unredacted) - the same discipline, now available at every recursion depth, not just
        the first.
    #>
    param($Container, [object[]] $NestedProperties)

    if ($Container -is [System.Collections.IDictionary]) {
        $clone = [ordered]@{}
        foreach ($key in @($Container.Keys)) {
            $spec = $NestedProperties | Where-Object { [string] $_.Name -eq $key } | Select-Object -First 1
            $clone[$key] = if ($spec) { Protect-PulseTypedPolicyValueBySpec -Value $Container[$key] -PropertySpec $spec } else { $Container[$key] }
        }
        return $clone
    }

    if ($Container -is [System.Management.Automation.PSObject]) {
        $clone = [pscustomobject]@{}
        foreach ($property in @($Container.PSObject.Properties)) {
            $spec = $NestedProperties | Where-Object { [string] $_.Name -eq $property.Name } | Select-Object -First 1
            $value = if ($spec) { Protect-PulseTypedPolicyValueBySpec -Value $property.Value -PropertySpec $spec } else { $property.Value }
            Add-Member -InputObject $clone -NotePropertyName $property.Name -NotePropertyValue $value
        }
        return $clone
    }

    # FAIL CLOSED: an unrecognized/scalar shape sitting where a Nested container was
    # expected cannot be confidently decomposed into per-property redaction - redact
    # WHOLESALE rather than risk a Sensitive leaf somewhere inside surviving unredacted.
    # Same rule Protect-PulseTypedPolicyNestedElement already established one level deep;
    # here at any depth.
    return New-PulseRedactedMarker
}

function Protect-PulseTypedPolicyValueBySpec {
    <#
        Private helper (Part C/T3.4 fix round, new): the RECURSIVE engine -
        Protect-PulseTypedPolicyRow's own top-level walk and every Nested container level
        below it all call this SAME function. Redacts -Value according to -PropertySpec
        (one entry from a TypedPolicyMaps.psd1 Properties/Nested.Properties list):
          - Sensitive=$true -> redacted WHOLESALE, unconditionally, regardless of -Value's
            own shape and regardless of whether -PropertySpec ALSO carries a Nested key
            (never walked into if Sensitive - "Sensitive always wins, at every depth").
          - Sensitive=$false with a Nested key -> walked once per array element, or once
            directly for a single object, via Protect-PulseTypedPolicyNestedContainer -
            which calls back into THIS function for each of ITS OWN declared children,
            recursing to whatever depth the map actually declares.
          - Sensitive=$false, no Nested key -> returned completely UNCHANGED (nothing to
            redact into).
    #>
    param($Value, $PropertySpec)

    if ([bool] $PropertySpec.Sensitive) {
        return New-PulseRedactedMarker
    }

    $hasNested = $PropertySpec.Contains('Nested') -and $null -ne $PropertySpec.Nested
    if (-not $hasNested) {
        return $Value
    }

    if ($null -eq $Value) { return $Value }

    $nestedProperties = @($PropertySpec.Nested.Properties)

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string] -and -not (Test-PulseSettingsCatalogNode -Node $Value)) {
        $elements = @($Value)
        $clonedElements = [object[]]::new($elements.Count)
        for ($i = 0; $i -lt $elements.Count; $i++) {
            $clonedElements[$i] = Protect-PulseTypedPolicyNestedContainer -Container $elements[$i] -NestedProperties $nestedProperties
        }
        return , $clonedElements
    }

    # Single-object shape OR an unrecognized/scalar shape sitting where an object was
    # expected - Protect-PulseTypedPolicyNestedContainer itself fails closed on anything
    # that is not [IDictionary]/[PSObject] (mirrors Protect-PulseTypedPolicyNestedElement's
    # own FAIL-OPEN fix, task-2.3-review round 2 finding 1) - every non-null, non-array
    # value for a Nested property routes through it uniformly.
    return Protect-PulseTypedPolicyNestedContainer -Container $Value -NestedProperties $nestedProperties
}

function Protect-PulseTypedPolicyRow {
    <#
        Private helper: clone ONE raw policy row, redacting Sensitive and Nested
        properties (to whatever depth -TypeMap's own PropertySpecs declare - see
        Protect-PulseTypedPolicyValueBySpec's own docstring for the recursive engine) per
        -TypeMap (the relevant policyType sub-map from TypedPolicyMaps.psd1). An unmapped
        `@odata.type` (or a row with none at all) returns the ORIGINAL row object
        unchanged - see this file's own UNMAPPED @odata.type docstring section.
    #>
    param($Row, [System.Collections.IDictionary] $TypeMap)

    $odataTypeRaw = Get-PulseSettingsCatalogValueProperty -Node $Row -PropertyName '@odata.type'
    $odataType = if ($null -ne $odataTypeRaw) { [string] $odataTypeRaw } else { $null }

    if ([string]::IsNullOrEmpty($odataType) -or -not $TypeMap.Contains($odataType)) {
        return $Row
    }

    $typeEntry = $TypeMap[$odataType]
    $properties = @($typeEntry.Properties)

    $anyRedactionPossible = $false
    foreach ($propertySpec in $properties) {
        if ([bool] $propertySpec.Sensitive -or ($propertySpec.Contains('Nested') -and $null -ne $propertySpec.Nested)) {
            $anyRedactionPossible = $true
            break
        }
    }
    if (-not $anyRedactionPossible) {
        # Nothing this map flags Sensitive/Nested for this type at all - no clone needed,
        # return the original row (avoids an unnecessary allocation for the common case).
        return $Row
    }

    $specsByName = @{}
    foreach ($propertySpec in $properties) { $specsByName[[string] $propertySpec.Name] = $propertySpec }

    function Protect-PulseTypedPolicyPropertyValue {
        param([string] $Name, $Value)
        if ($specsByName.ContainsKey($Name)) {
            return Protect-PulseTypedPolicyValueBySpec -Value $Value -PropertySpec $specsByName[$Name]
        }
        return $Value
    }

    if ($Row -is [System.Collections.IDictionary]) {
        $clone = [ordered]@{}
        foreach ($key in @($Row.Keys)) {
            $clone[$key] = Protect-PulseTypedPolicyPropertyValue -Name $key -Value $Row[$key]
        }
        return $clone
    }

    if ($Row -is [System.Management.Automation.PSObject]) {
        $clone = [pscustomobject]@{}
        foreach ($property in @($Row.PSObject.Properties)) {
            $value = Protect-PulseTypedPolicyPropertyValue -Name $property.Name -Value $property.Value
            Add-Member -InputObject $clone -NotePropertyName $property.Name -NotePropertyValue $value
        }
        return $clone
    }

    # Neither shape - nothing structured to redact into; return unchanged (see this
    # module's other clone functions, e.g. Protect-PulseSettingsCatalogSecretPayload, for
    # the same "unrecognized container shape passes through" rule).
    return $Row
}

function Protect-PulseTypedPolicySensitivePayload {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Data,

        [Parameter(Mandatory)]
        [string] $DatasetName,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $TypedPolicyMaps
    )

    if (-not $script:PulseTypedPolicyRedactionDatasetMap.ContainsKey($DatasetName)) {
        # PASS-THROUGH: no known Sensitive classification exists for this dataset - see
        # this file's own DATASET SCOPE docstring section.
        return , @($Data)
    }

    $policyType = $script:PulseTypedPolicyRedactionDatasetMap[$DatasetName]
    if (-not $TypedPolicyMaps.Contains($policyType)) {
        return , @($Data)
    }
    $typeMap = $TypedPolicyMaps[$policyType]

    $rows = @($Data)
    $result = [object[]]::new($rows.Count)
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $result[$i] = Protect-PulseTypedPolicyRow -Row $rows[$i] -TypeMap $typeMap
    }
    return , $result
}
