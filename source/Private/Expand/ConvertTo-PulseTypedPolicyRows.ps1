<#
    Private: pure walk - turn ONE compliance/legacy-configuration policy row (already
    collected by the ordinary check-driven flow, from `deviceCompliancePolicies` or
    `deviceConfigurations`) into frozen row-schema-v1 rows, using the flat property map in
    TypedPolicyMaps.psd1 (Task 2.3) rather than a Settings Catalog definitionId walk (T2.2
    has no analogue here - these two families are polymorphic, hand-typed Graph resources,
    not a generic definition tree). No Graph, no disk I/O, no manifest writes - mirrors
    ConvertTo-PulseSettingRows's own "pure walk, caller owns every side effect" split.

    ROW SCHEMA V1 (FROZEN, same as every other T2.2-T2.5 producer):
        schemaVersion; policyId; policyType; policyName; templateFamily; isBaseline;
        settingPath; settingDefinitionId; settingName; nameResolved; instanceId; value;
        valueLabel; labelResolved; redacted; valueState; applicability; assignments.
    -PolicyType is always 'compliance' or 'deviceConfiguration' (T2.3's own two policyType
    values) - never the Settings Catalog's 'settingsCatalog'. templateFamily/applicability/
    valueLabel/valueState are always $null for a typed-policy row (no template concept, no
    Settings Catalog OptionLabels catalog, no Graph valueState discriminator exists for
    these two families) - isBaseline is always $false for the identical reason.
    -Assignments (already fetched and normalized by the driver, or $null) is stamped
    IDENTICALLY onto every row this walk emits for the policy - assignments are a
    per-POLICY fact, not a per-setting one, exactly like -PolicyName/-TemplateFamily above.

    SHAPE NEUTRALITY (T2.2's hard lesson, carried forward unconditionally): every raw-policy
    property read goes through the shared Get-PulseSettingsCatalogValueProperty accessor
    (works identically whether -Policy is a [PSObject] from `ConvertFrom-Json` or an
    [System.Collections.IDictionary] from `ConvertFrom-Json -AsHashtable` - GraphKit's real
    production shape) - never `.PSObject.Properties[...]`/`-is [PSObject]` directly.

    EXACT-MATCH DISPATCH (T2.2's hard lesson): -TypeMap is keyed by the policy's own
    `@odata.type`, looked up as an EXACT, case-insensitive, fully-qualified string via
    ordinary hashtable/dictionary key lookup (never suffix/contains) - see
    Invoke-PulseTypedPolicyExpansion's own docstring for how the key is resolved before
    this function is ever called. A policy whose `@odata.type` has no entry in -TypeMap
    (including a bare legacy row with NO `@odata.type` at all) is the caller's job to
    detect and gap BEFORE calling this function - see that file's own docstring; this
    function itself throws if handed a -TypeMap it cannot use (an authoring bug, not a
    per-policy runtime outcome).

    SECRET CONTRACT (P0, unconditional): a property whose map entry sets Sensitive=$true
    is redacted exactly like a Settings Catalog secret - redacted:true, value:$null, NEVER
    the raw value, regardless of the raw value's own shape (scalar, object, array, $null).
    This applies at BOTH levels this walk ever recurses to - a top-level Sensitive property,
    and a Nested.Properties entry marked Sensitive within an array/object container.

    NESTED (RECURSIVE, arbitrary depth - Part C/T3.4 extension; was "exactly ONE level" per
    TypedPolicyMaps.psd1's original docstring, closing the deferred-F3/T2.7-live-gate gap
    - see TypedPolicyMaps.psd1's own docstring for the full accounting): a property whose
    map entry carries `Nested` gets a CONTAINER row first (value:$null, mirroring T2.2's
    GroupSettingCollectionInstance container-row pattern), then one row per
    Nested.Properties entry - walked once directly if the raw property value is a single
    object, or once PER ELEMENT (ordinal-suffixed settingPath/instanceId) if the raw
    property value is an array. A raw value that is neither an object nor an array under a
    Nested property contributes the container row only (nothing to descend into) - not a
    gap; an absent/null/scalar value under a documented Nested property is a legitimate,
    unpopulated-shell shape (T2.0's own "8 admin-template configurations, ALL unpopulated
    shells" finding applies equally here).

    Each Nested.Properties entry is now itself walked through the EXACT SAME rule this
    docstring describes for a top-level property - which means a Nested.Properties entry
    MAY carry its own `Nested` key, recursing to a further container row + its own
    Nested.Properties walk, to whatever depth the map actually declares (no depth limit is
    enforced here; TypedPolicyMaps.psd1's own docstring is the map-authoring discipline that
    keeps this from growing unboundedly in practice). SENSITIVE ALWAYS WINS, AT EVERY DEPTH,
    UNCONDITIONALLY: a property spec with Sensitive=$true is redacted wholesale - one row,
    redacted:true, value:$null - the INSTANT it is reached, regardless of whether it ALSO
    carries a `Nested` key. A Sensitive property's own Nested description (if present) is
    therefore never walked into; it exists in the map purely as documentation of the real
    observed shape (see windows10CustomConfiguration's own `omaSettings.value` entry - a
    live-confirmed 2-level-deep shape, still unconditionally redacted at its own Sensitive
    leaf, never decomposed). This is the SAME "declared flag, never inferred, never bypassed
    by structure" discipline this whole map already applies at depth 1, just proven to hold
    at any depth now that depth is no longer capped at 1.

    INSTANCE IDS: '<PolicyId>/p:<settingPath>' - the 'p:' tag (property) keeps this
    namespace visually distinct from T2.2's own 'n:'/'s:'/'o:' tags, though collision safety
    does not depend on that (this function's rows are merged into an entirely separate
    jsonl artifact from the Settings Catalog one). settingPath is the property-name chain,
    '/'-joined, root->leaf (top property name, or 'topName/subName' for a Nested object
    property, or 'topName/<ordinal>/subName' for a Nested array element) - '/' and '~' in a
    property NAME are escaped with the same '~s'/'~t' scheme ConvertTo-PulseSettingRows
    uses (property names in this map are author-controlled ASCII identifiers today, so this
    is defense-in-depth, not a reproduced defect).
#>

function Protect-PulseTypedPolicyPathSegment {
    param([string] $Segment)
    if ($null -eq $Segment) { return '' }
    return $Segment.Replace('~', '~t').Replace('/', '~s')
}

function ConvertTo-PulseTypedPolicyRows {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $PolicyId,

        [Parameter(Mandatory)]
        [ValidateSet('compliance', 'deviceConfiguration')]
        [string] $PolicyType,

        [Parameter()]
        [AllowNull()]
        [string] $PolicyName,

        [Parameter(Mandatory)]
        $Policy,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $TypeEntry,

        [Parameter()]
        [AllowNull()]
        [object[]] $Assignments
    )

    $rows = [System.Collections.Generic.List[object]]::new()

    function New-PulseTypedPolicyRow {
        param([string] $SettingPath, [string] $SettingName, $Value, [bool] $Redacted)
        return [pscustomobject]@{
            schemaVersion       = '1'
            policyId            = $PolicyId
            policyType          = $PolicyType
            policyName          = $PolicyName
            templateFamily      = $null
            isBaseline           = $false
            settingPath         = $SettingPath
            settingDefinitionId = $SettingPath
            settingName         = $SettingName
            nameResolved        = $true
            instanceId          = "$PolicyId/p:$SettingPath"
            value               = if ($Redacted) { $null } else { $Value }
            valueLabel          = $null
            labelResolved       = $false
            redacted            = $Redacted
            valueState          = $null
            applicability       = $null
            assignments         = $Assignments
        }
    }

    # RECURSIVE PROPERTY WALK (Part C/T3.4 extension - see this file's own docstring's
    # NESTED section): the single rule "Sensitive redacts wholesale unconditionally;
    # otherwise a Nested spec gets a container row + a walk of its own Nested.Properties,
    # each walked through this SAME rule" now applies uniformly at the top level AND at
    # every Nested.Properties entry, to whatever depth the map declares - no separate
    # "top-level" vs "nested" code path any more (the two used to be near-duplicates of
    # each other; unifying them is what makes depth >1 possible without duplicating the
    # container/array/object dispatch logic at every level).
    function Invoke-PulseWalkTypedPolicyPropertySpec {
        param([string] $SettingPath, [string] $PropertyName, $RawValue, $PropertySpec)

        if ([bool] $PropertySpec.Sensitive) {
            # SENSITIVE ALWAYS WINS, AT EVERY DEPTH (see docstring) - redacted wholesale,
            # one row, regardless of the raw value's own shape and regardless of whether
            # this spec ALSO carries a `Nested` key (never walked into if Sensitive).
            $rows.Add((New-PulseTypedPolicyRow -SettingPath $SettingPath -SettingName $PropertyName `
                        -Value $RawValue -Redacted $true)) | Out-Null
            return
        }

        $hasNested = $PropertySpec.Contains('Nested') -and $null -ne $PropertySpec.Nested
        if (-not $hasNested) {
            $rows.Add((New-PulseTypedPolicyRow -SettingPath $SettingPath -SettingName $PropertyName `
                        -Value $RawValue -Redacted $false)) | Out-Null
            return
        }

        # CONTAINER ROW - value always $null, mirrors T2.2's collection-instance container
        # row pattern (see this file's own docstring).
        $rows.Add((New-PulseTypedPolicyRow -SettingPath $SettingPath -SettingName $PropertyName `
                    -Value $null -Redacted $false)) | Out-Null

        $nestedProperties = @($PropertySpec.Nested.Properties)
        if ($null -eq $RawValue) { return }

        if ($RawValue -is [System.Collections.IEnumerable] -and $RawValue -isnot [string] -and -not (Test-PulseSettingsCatalogNode -Node $RawValue)) {
            $elements = @($RawValue)
            for ($i = 0; $i -lt $elements.Count; $i++) {
                Invoke-PulseWalkNestedContainer -ParentSettingPath "$SettingPath/$i" -Container $elements[$i] -NestedProperties $nestedProperties
            }
        } elseif (Test-PulseSettingsCatalogNode -Node $RawValue) {
            Invoke-PulseWalkNestedContainer -ParentSettingPath $SettingPath -Container $RawValue -NestedProperties $nestedProperties
        }
        # else: a scalar under a documented Nested property - unpopulated-shell shape,
        # container row already emitted above, nothing more to walk (not a gap - see this
        # file's own docstring).
    }

    function Invoke-PulseWalkNestedContainer {
        param([string] $ParentSettingPath, $Container, [object[]] $NestedProperties)
        foreach ($nestedSpec in $NestedProperties) {
            $nestedName = [string] $nestedSpec.Name
            $nestedSegment = Protect-PulseTypedPolicyPathSegment -Segment $nestedName
            $nestedPath = "$ParentSettingPath/$nestedSegment"
            $nestedValue = Get-PulseSettingsCatalogValueProperty -Node $Container -PropertyName $nestedName
            Invoke-PulseWalkTypedPolicyPropertySpec -SettingPath $nestedPath -PropertyName $nestedName -RawValue $nestedValue -PropertySpec $nestedSpec
        }
    }

    $properties = @($TypeEntry.Properties)
    foreach ($propertySpec in $properties) {
        $propertyName = [string] $propertySpec.Name
        $propertySegment = Protect-PulseTypedPolicyPathSegment -Segment $propertyName
        $rawValue = Get-PulseSettingsCatalogValueProperty -Node $Policy -PropertyName $propertyName
        Invoke-PulseWalkTypedPolicyPropertySpec -SettingPath $propertySegment -PropertyName $propertyName -RawValue $rawValue -PropertySpec $propertySpec
    }

    return [pscustomobject]@{ Rows = $rows.ToArray() }
}
