<#
    Private: pure walk - turn one policy's raw ConfigurationPolicySetting.ListBeta payload
    into frozen row-schema-v1 rows. No Graph, no disk I/O, no manifest writes: this function
    only ever reads -SettingsPayload/-DefinitionIndex and returns
    { Rows = [rowSchemaV1...]; Gaps = [string...] } - Invoke-PulseSettingsCatalogExpansion
    (the fan-out driver) owns every side effect (fetching, writing fragments, classifying
    per-policy terminal state). THROWS on an internal instanceId collision (P1-7/P1-8
    review fix - see COLLISION REJECTION below) - the caller (Invoke-PulseSettingsCatalogPolicy)
    turns that into a whole-policy gap rather than trusting a row set this function itself
    could not keep internally consistent.

    ROW SCHEMA V1 (FROZEN - see the plan's Task 2.2 section, verbatim, every producer
    T2.2-T2.5 emits exactly these properties, null where inapplicable):
        schemaVersion; policyId; policyType; policyName; templateFamily; isBaseline;
        settingPath; settingDefinitionId; settingName; nameResolved; instanceId; value;
        valueLabel; labelResolved; redacted; valueState; applicability; assignments.

    ASSIGNMENTS-DEFERRED (G-gate sequencing amendment, 2026-08-16): every row this function
    emits carries assignments:null unconditionally - ConfigurationPolicyAssignment.ListBeta
    is unreleased GraphKit (see the plan's G-gate section).

    SHAPE NEUTRALITY (Task 2.2 P0 re-review - the headline defect): every raw-payload read
    in this file goes through the shared accessors in Resolve-PulseSettingsCatalogValueClassification.ps1
    - Get-PulseSettingsCatalogValueProperty (property read) and Test-PulseSettingsCatalogNode
    (container check) - never `.PSObject.Properties[...]`/`-is [PSObject]` directly. GraphKit's
    REAL response shape is an OrderedHashtable tree (`ConvertFrom-Json -AsHashtable`), not
    pscustomobject; this file previously walked to ZERO rows and ZERO gaps against every one
    of T2.0's 15 golden fixtures once re-materialized through that real shape - "Expanded,
    rowCount: 0" on populated policies, the silent-nothing failure the review reproduced.
    Both shapes are exercised in this module's own test suite; this function must keep
    behaving identically for either one.

    EXACT INSTANCE-TYPE MATCH (P1-9 review fix - reproduced bypass): the five known
    `@odata.type` values are matched as EXACT, case-insensitive, FULLY-QUALIFIED strings
    (`#microsoft.graph.deviceManagementConfiguration<Kind>SettingInstance`), never a
    trailing-suffix regex. A suffix match (the pre-fix shape) treats any string merely
    ENDING WITH e.g. 'SimpleSettingInstance' as a real SimpleSettingInstance - reproduced:
    a hypothetical future/unknown type
    '#microsoft.graph.deviceManagementConfigurationFutureSimpleSettingInstance' silently
    misclassified as the real, known kind instead of falling through to the unknown-type
    gap. Exact match closes this: only the five literal strings below are ever recognized.

    MALFORMED SHAPES GAP, NEVER SILENT SUCCESS (P1-9 review fix - reproduced holes):
      - a root `Settings[]` entry with no (or a null) `settingInstance` now raises a
        'malformed-root' gap instead of silently contributing zero rows and zero gaps;
      - a non-object element encountered where an instance is expected (a scalar inside a
        children/collection array) now raises a 'malformed-instance' gap instead of a
        silent early return;
      - a missing or non-object `simpleSettingValue`/`simpleSettingCollectionValue` element
        now routes through the shared value classifier (Resolve-PulseSettingsCatalogValueClassification)
        the same as any other value node - an invalid/absent container is an UNKNOWN SHAPE,
        which the classifier fails closed on (redacted:true) - never the pre-fix
        `value:null; redacted:false` (a redacted-LOOKING null that was not actually flagged
        redacted at all).
      - an unknown `@odata.type` gap now notes, best-effort, how many immediate child
        nodes under it (if structurally identifiable at all) were consequently never
        walked - "record dropped descendants in the gap reason" per the review.

    SECRET CONTRACT (P0-2, unconditional, SHARED classifier): every `simpleSettingValue`
    and every `simpleSettingCollectionValue` element is classified through
    Resolve-PulseSettingsCatalogValueClassification - the exact same function
    Protect-PulseSettingsCatalogSecretPayload (the raw-dataset redactor) uses - passing the
    setting definition's own IsSecretCapable flag (from -DefinitionIndex) alongside the
    instance's own value shape. A value classified secret for any reason OTHER than a
    clean, expected secret-typed match (i.e. an unrecognized/missing discriminator - see
    that function's own FAIL CLOSED docstring section) additionally raises an
    'unknown-value-shape' gap, so an unrecognized shape both redacts (safe) AND is visible
    as a Partial reason (not silently absorbed).

    SETTING PATH ('/'-joined definitionId chain root->leaf). ESCAPE THE ESCAPE (P1-8
    review fix - reproduced collision): a literal '~' in a real definitionId is now escaped
    to '~t' BEFORE '/' is escaped to '~s' - encoding the escape character itself first is
    what makes the whole mapping injective. Pre-fix (escaping only '/') the two distinct
    definitionId chains 'a/b' and 'a~sb' both produced the identical settingPath 'a~sb' -
    reproduced by the review. Post-fix: 'a/b' -> 'a~sb' (unchanged, no literal tildes to
    escape) and 'a~sb' -> 'a~tsb' (the literal tilde is escaped to '~t' first) - now
    distinct. Real Settings Catalog CSP definitionIds can and do contain '~' (per the
    review), so this is not a theoretical edge case.

    NAMESPACED, COLLISION-REJECTING INSTANCE IDS (P1-8 review fix). Three distinct id
    namespaces, tagged so a value from one namespace can never be confused with another:
      - native root id (the `Settings[]` entry's own `id` field, when present):
        'n:<nativeId>'.
      - a root with NO native id: falls through to the ordinary synthetic-child scheme
        below with $PolicyId as its parent - '<PolicyId>/s:<definitionId>#<ordinal>' - no
        separate root-only scheme; $PolicyId is never itself a valid non-root parent id,
        so this can never collide with a deeper synthetic id.
      - an ordinary synthetic child (a ChoiceSettingInstance's own recursed child, NOT a
        collection element): '<ParentInstanceId>/s:<definitionId>#<ordinal>' - ordinal
        counts occurrences of the SAME definitionId under the SAME parent, matching the
        frozen schema's own '#<ordinal>' comment.
      - a collection OCCURRENCE (one element of a GroupSettingCollectionValue/
        ChoiceSettingCollectionValue array - carries no definitionId of its own):
        '<ParentInstanceId>/o:<definitionId>#<elementOrdinal>' - the 'o:' tag keeps this
        namespace distinct from an ordinary 's:' child even when both would otherwise
        produce the same '<parent>/<definitionId>#<ordinal>' text.
    Every tag ('n:', 's:', 'o:') is inserted by THIS function, immediately after a '/' or
    at string start - never trusted from raw input - so a crafted native id value can
    influence what comes AFTER a tag but can never forge the tag itself.

    COLLISION REJECTION: every computed instanceId is checked against a per-call
    HashSet[string] (ordinal comparer) before being assigned to a row or used as a further
    parent id; a collision (which the namespacing/escaping above should make structurally
    unreachable in practice, but is checked anyway rather than assumed away) THROWS - see
    this file's own top-level docstring for why a collision aborts the whole policy's walk
    rather than silently overwriting or skipping one row.

    DEPTH BUDGET (64): checked before descending into any child/element; exceeding it is a
    Gap, not a throw - matches the "unknown @odata.type -> Partial gap, walk continues"
    resilience the driver depends on for every OTHER gap class; only an instanceId
    collision (a data-integrity anomaly, not a shape/depth issue) throws.
#>

# SHARED DEPTH BUDGET (Task 2.2 omp-Medium re-review fix): the WALKER's own unit of depth
# is "one settingInstance level" - Invoke-PulseWalkInstance increments -Depth by exactly 1
# per recursive child/element call, so -MaxDepth 64 here means "64 settingInstance levels
# deep, however many raw JSON wrapper objects/arrays sit between one instance and the
# next." Protect-PulseSettingsCatalogSecretPayload (the raw-payload redactor, in
# Invoke-PulseSettingsCatalogExpansion.ps1) walks the SAME payload but counts depth
# per RAW NODE (every dictionary/object AND every array is its own level) - a
# GroupSettingCollection/ChoiceSettingCollection occurrence costs 4 raw levels per walker
# level (collectionValue array -> element object -> children array -> next instance
# object), the worst case among the five instance kinds. A VALID chain that is exactly at
# the walker's own 64-level budget could therefore need up to 64*4=256 raw levels to
# redact - misclassified as a redaction failure (and, one layer up, a bare
# "fetch-failed" gap) if the redactor's own depth budget were left at a smaller,
# independently-chosen number. The redactor's own default (see that file) is derived from
# THIS constant, not chosen independently, so the two can never silently drift back out of
# alignment - see PulseSettingsCatalogValueRedactionMaxDepthMultiplier below.
$script:PulseSettingsCatalogWalkerMaxDepth = 64

# RAW-NODE DEPTH BUDGET, shared by every reader of the SAME raw payload that counts depth
# per raw JSON node (object AND array each cost one level) rather than per settingInstance
# level - Protect-PulseSettingsCatalogSecretPayload's own default -MaxDepth AND
# Write-PulseDataset's -Depth override for the raw configurationPolicySettings write (see
# Invoke-PulseSettingsCatalogPolicy.ps1). Both derive from THIS one constant so they can
# never independently drift back out of alignment with each other, or with the walker's
# own $script:PulseSettingsCatalogWalkerMaxDepth above. A worst-case
# GroupSettingCollection/ChoiceSettingCollection occurrence costs 4 raw levels per walker
# level; the fixed +16 headroom above that 4x multiplier is empirically tuned (reproduced
# regression: a chain exactly AT the walker's own budget still tripped a bare 4x-multiplier
# counter with no buffer - the per-call fixed overhead outside the repeating per-level
# pattern, e.g. each row's own wrapper object and its `settingInstance` property lookup, is
# real but does not scale with depth, so a multiplier alone is one off-by-a-few short at
# the exact boundary).
$script:PulseSettingsCatalogRawPayloadMaxDepth = ($script:PulseSettingsCatalogWalkerMaxDepth * 4) + 16

# The five - and only five - known Settings Catalog instance kinds, matched as EXACT,
# case-insensitive, fully-qualified strings (P1-9 - see this file's own docstring for why a
# suffix regex is the reproduced bypass this replaces).
$script:PulseSettingsCatalogKnownInstanceTypes = @(
    '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
    '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
    '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
    '#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance'
    '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
)

function Test-PulseSettingsCatalogInstanceType {
    param([string] $ODataType, [string] $KnownType)
    if ([string]::IsNullOrEmpty($ODataType)) { return $false }
    return [string]::Equals($ODataType, $KnownType, [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-PulseSettingRows {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $PolicyId,

        [Parameter()]
        [AllowNull()]
        [string] $PolicyType,

        [Parameter()]
        [AllowNull()]
        [string] $PolicyName,

        [Parameter()]
        [AllowNull()]
        [string] $TemplateFamily,

        [Parameter()]
        [bool] $IsBaseline = $false,

        [Parameter()]
        [AllowNull()]
        [object] $SettingsPayload,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary] $DefinitionIndex,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $MaxDepth = $script:PulseSettingsCatalogWalkerMaxDepth
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[string]]::new()
    $assignedInstanceIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    # SHAPE NEUTRALITY: coerce a raw node's property to [string], via the module-shared
    # Get-PulseSettingsCatalogValueProperty (handles both [PSObject] and [IDictionary] -
    # see this file's own top-level docstring). Absent/$null both come back $null.
    function Get-PulseSettingsCatalogStringProperty {
        param($Node, [string] $PropertyName)
        $raw = Get-PulseSettingsCatalogValueProperty -Node $Node -PropertyName $PropertyName
        if ($null -eq $raw) { return $null }
        return [string] $raw
    }

    function Protect-PulseSettingPathSegment {
        param([string] $Segment)
        if ($null -eq $Segment) { return '' }
        # ESCAPE THE ESCAPE (P1-8): '~' must be escaped BEFORE '/' - see this file's own
        # top-level docstring for the collision this ordering fixes.
        return $Segment.Replace('~', '~t').Replace('/', '~s')
    }

    function Register-PulseInstanceId {
        param([string] $InstanceId)
        if (-not $assignedInstanceIds.Add($InstanceId)) {
            throw "ConvertTo-PulseSettingRows: instanceId collision on '$InstanceId' for policy '$PolicyId' - refusing to continue this policy's walk with an ambiguous id space."
        }
    }

    function Resolve-PulseDefinitionEntry {
        param([string] $DefinitionId, [System.Collections.IDictionary] $Index)
        if ($null -eq $Index) { return $null }
        if (-not $Index.Contains($DefinitionId)) { return $null }
        return $Index[$DefinitionId]
    }

    function Resolve-PulseSettingName {
        param($Entry)
        if ($null -eq $Entry) { return [pscustomobject]@{ Name = $null; Resolved = $false } }
        $name = $null
        if ($Entry.Contains('DisplayName') -and -not [string]::IsNullOrEmpty([string] $Entry.DisplayName)) {
            $name = [string] $Entry.DisplayName
        } elseif ($Entry.Contains('Name') -and -not [string]::IsNullOrEmpty([string] $Entry.Name)) {
            $name = [string] $Entry.Name
        }
        return [pscustomobject]@{ Name = $name; Resolved = (-not [string]::IsNullOrEmpty($name)) }
    }

    function Resolve-PulseOptionLabel {
        param($Entry, [string] $Value)
        if ($null -eq $Entry -or $null -eq $Value) { return [pscustomobject]@{ Label = $null; Resolved = $false } }
        if (-not $Entry.Contains('OptionLabels') -or $null -eq $Entry.OptionLabels) {
            return [pscustomobject]@{ Label = $null; Resolved = $false }
        }
        $optionLabels = $Entry.OptionLabels
        if ($optionLabels -is [System.Collections.IDictionary] -and $optionLabels.Contains($Value)) {
            $label = $optionLabels[$Value]
            return [pscustomobject]@{ Label = $label; Resolved = (-not [string]::IsNullOrEmpty([string] $label)) }
        }
        return [pscustomobject]@{ Label = $null; Resolved = $false }
    }

    function New-PulseSettingRow {
        param(
            [string] $SettingPath, [string] $SettingDefinitionId, [string] $InstanceId,
            $Value, $ValueLabel, [bool] $LabelResolved, [bool] $Redacted, $ValueState
        )

        $entry = Resolve-PulseDefinitionEntry -DefinitionId $SettingDefinitionId -Index $DefinitionIndex
        $nameResult = Resolve-PulseSettingName -Entry $entry
        $applicability = if ($null -ne $entry -and $entry.Contains('Applicability')) { $entry.Applicability } else { $null }

        return [pscustomobject]@{
            schemaVersion       = '1'
            policyId            = $PolicyId
            policyType          = $PolicyType
            policyName          = $PolicyName
            templateFamily      = $TemplateFamily
            isBaseline          = $IsBaseline
            settingPath         = $SettingPath
            settingDefinitionId = $SettingDefinitionId
            settingName         = $nameResult.Name
            nameResolved        = $nameResult.Resolved
            instanceId          = $InstanceId
            value               = $Value
            valueLabel          = $ValueLabel
            labelResolved       = $LabelResolved
            redacted            = $Redacted
            valueState          = $ValueState
            applicability       = $applicability
            assignments         = $null
        }
    }

    function Resolve-PulseValueClassification {
        param($SettingValue, $DefinitionEntry)
        $isSecretCapable = $false
        if ($null -ne $DefinitionEntry -and $DefinitionEntry.Contains('IsSecretCapable')) {
            $isSecretCapable = [bool] $DefinitionEntry.IsSecretCapable
        }
        return Resolve-PulseSettingsCatalogValueClassification -SettingValue $SettingValue -DefinitionIsSecretCapable $isSecretCapable
    }

    # True only for a classification whose secrecy came from a shape this classifier could
    # not confidently call safe (missing/unrecognized discriminator) - a real declared
    # secret (IsSecretByType) is expected and does NOT get an accompanying gap.
    function Test-PulseUnknownValueShape {
        param($Classification)
        return ($Classification.IsSecret -and -not $Classification.IsSecretByType -and -not $Classification.IsKnownSafeShape)
    }

    function Get-PulseInstanceDescendantHint {
        # Best-effort, structural-only count of what an unknown-type node's children WOULD
        # have been, for the gap message (P1-9: "record dropped descendants in the gap
        # reason") - never inspects VALUES, only counts array lengths under the known
        # collection-value property names so this stays a safe, no-secret-risk hint.
        # SHAPE NEUTRAL: reads through the shared accessor, not `.PSObject.Properties[...]`.
        param($Instance)
        $count = 0
        foreach ($propName in @('groupSettingCollectionValue', 'choiceSettingCollectionValue', 'simpleSettingCollectionValue')) {
            $propValue = Get-PulseSettingsCatalogValueProperty -Node $Instance -PropertyName $propName
            if ($null -ne $propValue) { $count += @($propValue).Count }
        }
        $choiceValue = Get-PulseSettingsCatalogValueProperty -Node $Instance -PropertyName 'choiceSettingValue'
        if ($null -ne $choiceValue) {
            $children = Get-PulseSettingsCatalogValueProperty -Node $choiceValue -PropertyName 'children'
            if ($null -ne $children) { $count += @($children).Count }
        }
        return $count
    }

    function Invoke-PulseWalkInstance {
        param(
            $Instance, [string] $ParentSettingPath, [string] $ParentInstanceId,
            [string] $NativeInstanceId, [int] $Depth,
            [System.Collections.Generic.Dictionary[string, int]] $OrdinalCounters
        )

        if ($Depth -gt $MaxDepth) {
            $gaps.Add("depth-budget-exceeded: settings tree exceeds $MaxDepth levels under parent '$ParentInstanceId'") | Out-Null
            return
        }

        if (-not (Test-PulseSettingsCatalogNode -Node $Instance)) {
            $actualType = if ($null -eq $Instance) { 'null' } else { $Instance.GetType().Name }
            $gaps.Add("malformed-instance: expected an object under parent '$ParentInstanceId', got '$actualType'") | Out-Null
            return
        }

        $definitionId = Get-PulseSettingsCatalogStringProperty -Node $Instance -PropertyName 'settingDefinitionId'
        if ([string]::IsNullOrEmpty($definitionId)) {
            $gaps.Add("malformed-instance: missing settingDefinitionId under parent '$ParentInstanceId'") | Out-Null
            return
        }

        $escapedSegment = Protect-PulseSettingPathSegment -Segment $definitionId
        $settingPath = if ([string]::IsNullOrEmpty($ParentSettingPath)) { $escapedSegment } else { "$ParentSettingPath/$escapedSegment" }

        $instanceId = $NativeInstanceId
        if ([string]::IsNullOrEmpty($instanceId)) {
            $counterKey = "$ParentInstanceId|s|$definitionId"
            $ordinal = 0
            if ($OrdinalCounters.ContainsKey($counterKey)) {
                $ordinal = $OrdinalCounters[$counterKey]
            }
            $OrdinalCounters[$counterKey] = $ordinal + 1
            $instanceId = "$ParentInstanceId/s:$definitionId#$ordinal"
        }
        Register-PulseInstanceId -InstanceId $instanceId

        $odataType = Get-PulseSettingsCatalogStringProperty -Node $Instance -PropertyName '@odata.type'
        $entry = Resolve-PulseDefinitionEntry -DefinitionId $definitionId -Index $DefinitionIndex

        if (Test-PulseSettingsCatalogInstanceType -ODataType $odataType -KnownType '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance') {
            $choiceValue = Get-PulseSettingsCatalogValueProperty -Node $Instance -PropertyName 'choiceSettingValue'
            $rawValue = $null
            $children = @()
            if (Test-PulseSettingsCatalogNode -Node $choiceValue) {
                $rawValue = Get-PulseSettingsCatalogStringProperty -Node $choiceValue -PropertyName 'value'
                $childrenRaw = Get-PulseSettingsCatalogValueProperty -Node $choiceValue -PropertyName 'children'
                if ($null -ne $childrenRaw) { $children = @($childrenRaw) }
            }
            $labelResult = Resolve-PulseOptionLabel -Entry $entry -Value $rawValue
            $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                        -InstanceId $instanceId -Value $rawValue -ValueLabel $labelResult.Label `
                        -LabelResolved $labelResult.Resolved -Redacted $false -ValueState $null)) | Out-Null

            foreach ($child in $children) {
                Invoke-PulseWalkInstance -Instance $child -ParentSettingPath $settingPath -ParentInstanceId $instanceId `
                    -NativeInstanceId $null -Depth ($Depth + 1) -OrdinalCounters $OrdinalCounters
            }
            return
        }

        if (Test-PulseSettingsCatalogInstanceType -ODataType $odataType -KnownType '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance') {
            $simpleValue = Get-PulseSettingsCatalogValueProperty -Node $Instance -PropertyName 'simpleSettingValue'
            $classification = Resolve-PulseValueClassification -SettingValue $simpleValue -DefinitionEntry $entry

            if ($classification.IsSecret) {
                if (Test-PulseUnknownValueShape -Classification $classification) {
                    $gaps.Add("unknown-value-shape: settingPath '$settingPath' odataType '$($classification.ODataType)'") | Out-Null
                }
                $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                            -InstanceId $instanceId -Value $null -ValueLabel $null -LabelResolved $false `
                            -Redacted $true -ValueState $classification.ValueState)) | Out-Null
            } else {
                $rawValue = Get-PulseSettingsCatalogValueProperty -Node $simpleValue -PropertyName 'value'
                $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                            -InstanceId $instanceId -Value $rawValue -ValueLabel $null -LabelResolved $false `
                            -Redacted $false -ValueState $null)) | Out-Null
            }
            return
        }

        if (Test-PulseSettingsCatalogInstanceType -ODataType $odataType -KnownType '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance') {
            $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                        -InstanceId $instanceId -Value $null -ValueLabel $null -LabelResolved $false `
                        -Redacted $false -ValueState $null)) | Out-Null

            $elementsRaw = Get-PulseSettingsCatalogValueProperty -Node $Instance -PropertyName 'groupSettingCollectionValue'
            $elements = if ($null -ne $elementsRaw) { , @($elementsRaw) } else { , @() }

            for ($elementOrdinal = 0; $elementOrdinal -lt $elements.Count; $elementOrdinal++) {
                $element = $elements[$elementOrdinal]
                $occurrenceParentId = "$instanceId/o:$definitionId#$elementOrdinal"
                Register-PulseInstanceId -InstanceId $occurrenceParentId
                $childList = @()
                if (Test-PulseSettingsCatalogNode -Node $element) {
                    $childrenRaw = Get-PulseSettingsCatalogValueProperty -Node $element -PropertyName 'children'
                    if ($null -ne $childrenRaw) { $childList = @($childrenRaw) }
                }
                foreach ($child in $childList) {
                    Invoke-PulseWalkInstance -Instance $child -ParentSettingPath $settingPath -ParentInstanceId $occurrenceParentId `
                        -NativeInstanceId $null -Depth ($Depth + 1) -OrdinalCounters $OrdinalCounters
                }
            }
            return
        }

        if (Test-PulseSettingsCatalogInstanceType -ODataType $odataType -KnownType '#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance') {
            $elementsRaw = Get-PulseSettingsCatalogValueProperty -Node $Instance -PropertyName 'choiceSettingCollectionValue'
            $elements = if ($null -ne $elementsRaw) { , @($elementsRaw) } else { , @() }

            $values = [System.Collections.Generic.List[object]]::new()
            $labels = [System.Collections.Generic.List[object]]::new()
            $anyLabelResolved = $false
            for ($elementOrdinal = 0; $elementOrdinal -lt $elements.Count; $elementOrdinal++) {
                $element = $elements[$elementOrdinal]
                $elementValue = Get-PulseSettingsCatalogStringProperty -Node $element -PropertyName 'value'
                $values.Add($elementValue) | Out-Null
                $labelResult = Resolve-PulseOptionLabel -Entry $entry -Value $elementValue
                $labels.Add($labelResult.Label) | Out-Null
                if ($labelResult.Resolved) { $anyLabelResolved = $true }
            }

            $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                        -InstanceId $instanceId -Value $values.ToArray() -ValueLabel $labels.ToArray() `
                        -LabelResolved $anyLabelResolved -Redacted $false -ValueState $null)) | Out-Null

            for ($elementOrdinal = 0; $elementOrdinal -lt $elements.Count; $elementOrdinal++) {
                $element = $elements[$elementOrdinal]
                $occurrenceParentId = "$instanceId/o:$definitionId#$elementOrdinal"
                Register-PulseInstanceId -InstanceId $occurrenceParentId
                $childList = @()
                if (Test-PulseSettingsCatalogNode -Node $element) {
                    $childrenRaw = Get-PulseSettingsCatalogValueProperty -Node $element -PropertyName 'children'
                    if ($null -ne $childrenRaw) { $childList = @($childrenRaw) }
                }
                foreach ($child in $childList) {
                    Invoke-PulseWalkInstance -Instance $child -ParentSettingPath $settingPath -ParentInstanceId $occurrenceParentId `
                        -NativeInstanceId $null -Depth ($Depth + 1) -OrdinalCounters $OrdinalCounters
                }
            }
            return
        }

        if (Test-PulseSettingsCatalogInstanceType -ODataType $odataType -KnownType '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance') {
            $elementsRaw = Get-PulseSettingsCatalogValueProperty -Node $Instance -PropertyName 'simpleSettingCollectionValue'
            $elements = if ($null -ne $elementsRaw) { , @($elementsRaw) } else { , @() }

            $anySecret = $false
            $anyUnknownShape = $false
            $firstSecretValueState = $null
            $values = [System.Collections.Generic.List[object]]::new()
            foreach ($element in $elements) {
                $elementClassification = Resolve-PulseValueClassification -SettingValue $element -DefinitionEntry $entry
                if ($elementClassification.IsSecret) {
                    if (-not $anySecret) {
                        $anySecret = $true
                        $firstSecretValueState = $elementClassification.ValueState
                    }
                    if (Test-PulseUnknownValueShape -Classification $elementClassification) { $anyUnknownShape = $true }
                    continue
                }
                $elementValue = Get-PulseSettingsCatalogValueProperty -Node $element -PropertyName 'value'
                $values.Add($elementValue) | Out-Null
            }

            if ($anyUnknownShape) {
                $gaps.Add("unknown-value-shape: settingPath '$settingPath' (collection element)") | Out-Null
            }

            if ($anySecret) {
                $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                            -InstanceId $instanceId -Value $null -ValueLabel $null -LabelResolved $false `
                            -Redacted $true -ValueState $firstSecretValueState)) | Out-Null
            } else {
                $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                            -InstanceId $instanceId -Value $values.ToArray() -ValueLabel $null -LabelResolved $false `
                            -Redacted $false -ValueState $null)) | Out-Null
            }
            return
        }

        # Unknown @odata.type (P1-9): note a best-effort descendant-drop hint in the gap.
        $descendantHint = Get-PulseInstanceDescendantHint -Instance $Instance
        $descendantSuffix = if ($descendantHint -gt 0) { " ($descendantHint descendant node(s) not walked)" } else { '' }
        $gaps.Add("unknown-instance-type: '$odataType' at settingPath '$settingPath'$descendantSuffix") | Out-Null
    }

    $roots = @()
    if ($null -ne $SettingsPayload) {
        $roots = @($SettingsPayload)
    }

    $ordinalCounters = [System.Collections.Generic.Dictionary[string, int]]::new()

    foreach ($root in $roots) {
        if (-not (Test-PulseSettingsCatalogNode -Node $root)) {
            $actualType = if ($null -eq $root) { 'null' } else { $root.GetType().Name }
            $gaps.Add("malformed-root: expected an object, got '$actualType'") | Out-Null
            continue
        }

        $nativeIdRaw = Get-PulseSettingsCatalogStringProperty -Node $root -PropertyName 'id'
        $nativeId = if (-not [string]::IsNullOrEmpty($nativeIdRaw)) { $nativeIdRaw } else { $null }
        $settingInstance = Get-PulseSettingsCatalogValueProperty -Node $root -PropertyName 'settingInstance'

        if ($null -eq $settingInstance -or -not (Test-PulseSettingsCatalogNode -Node $settingInstance)) {
            $rootLabel = if ($nativeId) { "id '$nativeId'" } else { 'a root entry with no id' }
            $gaps.Add("malformed-root: missing settingInstance for $rootLabel") | Out-Null
            continue
        }

        # NAMESPACED ROOT SEED (P1-8): 'n:<nativeId>' when a native id is present. A root
        # with NO native id falls through to the ordinary synthetic-id machinery below
        # (ParentInstanceId = $PolicyId, the same 's:<definitionId>#<ordinal>' scheme every
        # other synthetic id uses) rather than a bespoke root-only scheme - simpler, and
        # already collision-safe: $PolicyId is never itself a valid non-root parent id, so
        # a root-level synthetic id can never be confused with a deeper one.
        $rootSeed = if ($nativeId) { "n:$nativeId" } else { $null }

        Invoke-PulseWalkInstance -Instance $settingInstance -ParentSettingPath '' -ParentInstanceId $PolicyId `
            -NativeInstanceId $rootSeed -Depth 1 -OrdinalCounters $ordinalCounters
    }

    return [pscustomobject]@{
        Rows = $rows.ToArray()
        Gaps = $gaps.ToArray()
    }
}
