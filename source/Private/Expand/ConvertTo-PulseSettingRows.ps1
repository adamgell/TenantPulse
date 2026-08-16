<#
    Private: pure walk - turn one policy's raw ConfigurationPolicySetting.ListBeta payload
    into frozen row-schema-v1 rows. No Graph, no disk I/O, no manifest writes: this function
    only ever reads -SettingsPayload/-DefinitionIndex and returns
    { Rows = [rowSchemaV1...]; Gaps = [string...] } - Invoke-PulseSettingsCatalogExpansion
    (the fan-out driver) owns every side effect (fetching, writing fragments, classifying
    per-policy terminal state).

    ROW SCHEMA V1 (FROZEN - see the plan's Task 2.2 section, verbatim, every producer
    T2.2-T2.5 emits exactly these properties, null where inapplicable):
        schemaVersion; policyId; policyType; policyName; templateFamily; isBaseline;
        settingPath; settingDefinitionId; settingName; nameResolved; instanceId; value;
        valueLabel; labelResolved; redacted; valueState; applicability; assignments.

    ASSIGNMENTS-DEFERRED (G-gate sequencing amendment, 2026-08-16): every row this function
    emits carries assignments:null unconditionally - ConfigurationPolicyAssignment.ListBeta
    is unreleased GraphKit (see the plan's G-gate section). This function has no
    -Assignments parameter at all yet, by design: Phase 2b's assignment sub-fetch slots in
    later as an additional per-policy input this function joins against instanceId/
    settingPath, without restructuring the walk itself.

    ONE ROW PER SETTING-INSTANCE TREE NODE. The `Settings` payload is either a single
    object or an array of { id; settingInstance } root entries (GraphKit's
    ConfigurationPolicySetting.ListBeta shape, matching every tests/Fixtures/SettingsCatalog
    fixture's own `Settings` member). Each root's own `id` is used as its row's -instanceId
    verbatim (native id). A settingInstance's `@odata.type` selects one of the five known
    instance kinds:
      - ChoiceSettingInstance: one row; value/valueLabel resolved from `choiceSettingValue`;
        recurses into `choiceSettingValue.children` (each child is itself a root-shaped
        instance, one row per child, nested under this row's settingPath/instanceId).
      - SimpleSettingInstance: one row; value read straight off `simpleSettingValue.value`
        UNLESS its own `@odata.type` matches the secret contract (see SECRET CONTRACT
        below), in which case value is null and redacted/valueState take over. No children.
      - GroupSettingCollectionInstance: NO independent value of its own (value stays null) -
        it is a pure container. Each element of `groupSettingCollectionValue` is walked as
        one "occurrence" (ordinal-suffixed synthetic parent id, since an occurrence carries
        no id/definitionId of its own) and its own `children` recursed under that.
      - ChoiceSettingCollectionInstance: one row; -value is the ARRAY of each element's
        `.value` (frozen schema's own "array for collections" comment); -valueLabel is the
        parallel array of resolved labels (or null entries where unresolved). Any element
        that itself carries `children` is ALSO recursed (ordinal-suffixed synthetic parent,
        same occurrence scheme as GroupSettingCollection) - a collection element is not
        assumed leaf-only.
      - SimpleSettingCollectionInstance: one row; -value is the array of each element's
        scalar `.value`. If ANY element is secret-typed, the WHOLE row redacts (value=null,
        redacted=true, valueState = the first secret element's valueState) - fail-closed,
        matching this codebase's "a value this code cannot prove is safe must not ship"
        convention (see Protect-PulseGraphRowTenantId's own FAIL CLOSED precedent).
      - Anything else (unknown @odata.type): the node itself is SKIPPED (no row emitted for
        it - there is no known instance shape to build one from) and a gap string is added
        to the returned Gaps array; the walk continues into sibling/already-emitted rows
        rather than aborting the whole policy.

    SETTING PATH ('/'-joined definitionId chain root->leaf; '/' in a definitionId escaped
    as '~s' - matches the frozen schema's own comment). Every settingDefinitionId a
    real Settings Catalog CSP path can legally contain is escaped BEFORE joining, not after,
    so a definitionId that itself happened to contain '/' can never be misparsed as an
    extra path segment by anything that later splits settingPath on '/'.

    SYNTHETIC INSTANCE IDS ('<parentInstanceId>/<definitionId>#<ordinal>' - matches the
    frozen schema's own comment). -ordinal counts occurrences of the SAME definitionId
    under the SAME parent instance id, starting at 0 - so two sibling children that happen
    to share a definitionId (legal - e.g. a repeated collection element) still get distinct
    ids, and re-running this walk against byte-identical input always assigns the same
    ordinals in the same order (determinism - no dictionary/hashtable iteration order is
    ever consulted for ordinal assignment, only the input array's own order).
    GroupSettingCollectionValue/ChoiceSettingCollectionValue ELEMENTS carry no definitionId
    of their own - each element's synthetic "occurrence" parent id is
    '<parentInstanceId>/<settingDefinitionId>~occ#<elementOrdinal>' (a name no real
    definitionId can collide with, since real definitionIds never contain '~occ') so
    children nested under element 0 and element 1 of the same collection can never share an
    instanceId even when their own definitionIds are identical.

    NAME/LABEL RESOLUTION against -DefinitionIndex (Get-PulseSettingDefinitionIndex's
    compact output - keyed by definitionId, holding only Name/DisplayName/RootDefinitionId/
    OptionLabels/Applicability/IsSecretCapable, see that function's own docstring):
    settingName = index[definitionId].DisplayName if present, else index[...].Name, else
    null; nameResolved = $true only when a DisplayName or Name was actually found.
    valueLabel for a Choice-shaped value looks up index[definitionId].OptionLabels[value];
    labelResolved = $true only when that lookup actually found a non-null label. A -null or
    empty -DefinitionIndex (the documented 'definitions corpus unavailable' case) makes
    EVERY settingName/valueLabel null and every *Resolved flag $false - this function does
    not throw for a missing index, since a caller may legitimately walk without one (a
    Failed-corpus policy is expected to reach Partial via the driver's own gap, not via an
    exception out of the walk).

    SECRET CONTRACT (P0, unconditional): a settingValue is secret whenever its own
    `@odata.type` matches `...SecretSettingValueDefinition`'s instance-level counterpart -
    `#microsoft.graph.deviceManagementConfigurationSecretSettingValue` (or any other
    `...SecretSettingValue` subtype, matched case-insensitively by suffix, the same
    pattern Get-PulseSettingDefinitionIndex's own IsSecretCapable check uses at the
    DEFINITION level - see that function's docstring for why this INSTANCE-level check,
    not the definition-level flag, is the one the contract actually depends on). A secret
    row's -value is ALWAYS null and -redacted is ALWAYS true, regardless of what raw value
    the payload carried - this function never reads a secret value into any variable that
    could leak into a row, an error message, or a gap string. -valueState is read verbatim
    off the secret value's own `valueState` property (Graph's own {notEncrypted|
    encryptedValueToken|invalidValueState} enum-ish string), or null if absent.

    DEPTH BUDGET (64, matching every other recursive walker in this module -
    ConvertTo-PulseCanonicalJson's own -Depth default, Protect-PulseGraphRowTenantId's own
    -MaxDepth default): checked before descending into any child/element, and a policy that
    exceeds it is reported as a Gap ('depth-budget-exceeded: ...') rather than throwing -
    matching the "unknown @odata.type -> Partial gap, walk continues" resilience the driver
    depends on; a pathologically deep or cyclic settingInstance graph must degrade this ONE
    policy to Partial, not abort the entire fan-out.
#>

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
        [int] $MaxDepth = 64
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[string]]::new()

    function Protect-PulseSettingPathSegment {
        param([string] $Segment)
        if ($null -eq $Segment) { return '' }
        return $Segment.Replace('/', '~s')
    }

    function Resolve-PulseSettingIsSecret {
        param($SettingValue)
        if ($null -eq $SettingValue) { return $false }
        if ($SettingValue -isnot [System.Management.Automation.PSObject]) { return $false }
        if (-not $SettingValue.PSObject.Properties['@odata.type']) { return $false }
        $odataType = [string] $SettingValue.'@odata.type'
        return ($odataType -match '(?i)SecretSettingValue$')
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

        if ($null -eq $Instance -or $Instance -isnot [System.Management.Automation.PSObject]) {
            return
        }

        $definitionId = if ($Instance.PSObject.Properties['settingDefinitionId']) { [string] $Instance.settingDefinitionId } else { $null }
        if ([string]::IsNullOrEmpty($definitionId)) {
            $gaps.Add("malformed-instance: missing settingDefinitionId under parent '$ParentInstanceId'") | Out-Null
            return
        }

        $escapedSegment = Protect-PulseSettingPathSegment -Segment $definitionId
        $settingPath = if ([string]::IsNullOrEmpty($ParentSettingPath)) { $escapedSegment } else { "$ParentSettingPath/$escapedSegment" }

        $instanceId = $NativeInstanceId
        if ([string]::IsNullOrEmpty($instanceId)) {
            $counterKey = "$ParentInstanceId|$definitionId"
            $ordinal = 0
            if ($OrdinalCounters.ContainsKey($counterKey)) {
                $ordinal = $OrdinalCounters[$counterKey]
            }
            $OrdinalCounters[$counterKey] = $ordinal + 1
            $instanceId = "$ParentInstanceId/$definitionId#$ordinal"
        }

        $odataType = if ($Instance.PSObject.Properties['@odata.type']) { [string] $Instance.'@odata.type' } else { $null }

        switch -Regex ($odataType) {
            'ChoiceSettingInstance$' {
                $choiceValue = $Instance.choiceSettingValue
                $rawValue = $null
                $children = @()
                if ($null -ne $choiceValue -and $choiceValue -is [System.Management.Automation.PSObject]) {
                    if ($choiceValue.PSObject.Properties['value']) { $rawValue = [string] $choiceValue.value }
                    if ($choiceValue.PSObject.Properties['children'] -and $null -ne $choiceValue.children) {
                        $children = @($choiceValue.children)
                    }
                }
                $entry = Resolve-PulseDefinitionEntry -DefinitionId $definitionId -Index $DefinitionIndex
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

            'SimpleSettingInstance$' {
                $simpleValue = $Instance.simpleSettingValue
                $isSecret = Resolve-PulseSettingIsSecret -SettingValue $simpleValue
                if ($isSecret) {
                    $valueState = if ($simpleValue.PSObject.Properties['valueState']) { $simpleValue.valueState } else { $null }
                    $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                                -InstanceId $instanceId -Value $null -ValueLabel $null -LabelResolved $false `
                                -Redacted $true -ValueState $valueState)) | Out-Null
                } else {
                    $rawValue = $null
                    if ($null -ne $simpleValue -and $simpleValue -is [System.Management.Automation.PSObject] -and $simpleValue.PSObject.Properties['value']) {
                        $rawValue = $simpleValue.value
                    }
                    $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                                -InstanceId $instanceId -Value $rawValue -ValueLabel $null -LabelResolved $false `
                                -Redacted $false -ValueState $null)) | Out-Null
                }
                return
            }

            'GroupSettingCollectionInstance$' {
                $rows.Add((New-PulseSettingRow -SettingPath $settingPath -SettingDefinitionId $definitionId `
                            -InstanceId $instanceId -Value $null -ValueLabel $null -LabelResolved $false `
                            -Redacted $false -ValueState $null)) | Out-Null

                $elements = if ($Instance.PSObject.Properties['groupSettingCollectionValue'] -and $null -ne $Instance.groupSettingCollectionValue) {
                    @($Instance.groupSettingCollectionValue)
                } else { @() }

                for ($elementOrdinal = 0; $elementOrdinal -lt $elements.Count; $elementOrdinal++) {
                    $element = $elements[$elementOrdinal]
                    $occurrenceParentId = "$instanceId/$definitionId~occ#$elementOrdinal"
                    $childList = if ($null -ne $element -and $element.PSObject.Properties['children'] -and $null -ne $element.children) {
                        @($element.children)
                    } else { @() }
                    foreach ($child in $childList) {
                        Invoke-PulseWalkInstance -Instance $child -ParentSettingPath $settingPath -ParentInstanceId $occurrenceParentId `
                            -NativeInstanceId $null -Depth ($Depth + 1) -OrdinalCounters $OrdinalCounters
                    }
                }
                return
            }

            'ChoiceSettingCollectionInstance$' {
                $elements = if ($Instance.PSObject.Properties['choiceSettingCollectionValue'] -and $null -ne $Instance.choiceSettingCollectionValue) {
                    @($Instance.choiceSettingCollectionValue)
                } else { @() }

                $entry = Resolve-PulseDefinitionEntry -DefinitionId $definitionId -Index $DefinitionIndex
                $values = [System.Collections.Generic.List[object]]::new()
                $labels = [System.Collections.Generic.List[object]]::new()
                $anyLabelResolved = $false
                for ($elementOrdinal = 0; $elementOrdinal -lt $elements.Count; $elementOrdinal++) {
                    $element = $elements[$elementOrdinal]
                    $elementValue = if ($null -ne $element -and $element.PSObject.Properties['value']) { [string] $element.value } else { $null }
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
                    $occurrenceParentId = "$instanceId/$definitionId~occ#$elementOrdinal"
                    $childList = if ($null -ne $element -and $element.PSObject.Properties['children'] -and $null -ne $element.children) {
                        @($element.children)
                    } else { @() }
                    foreach ($child in $childList) {
                        Invoke-PulseWalkInstance -Instance $child -ParentSettingPath $settingPath -ParentInstanceId $occurrenceParentId `
                            -NativeInstanceId $null -Depth ($Depth + 1) -OrdinalCounters $OrdinalCounters
                    }
                }
                return
            }

            'SimpleSettingCollectionInstance$' {
                $elements = if ($Instance.PSObject.Properties['simpleSettingCollectionValue'] -and $null -ne $Instance.simpleSettingCollectionValue) {
                    @($Instance.simpleSettingCollectionValue)
                } else { @() }

                $anySecret = $false
                $firstSecretValueState = $null
                $values = [System.Collections.Generic.List[object]]::new()
                foreach ($element in $elements) {
                    if (Resolve-PulseSettingIsSecret -SettingValue $element) {
                        if (-not $anySecret) {
                            $anySecret = $true
                            $firstSecretValueState = if ($element.PSObject.Properties['valueState']) { $element.valueState } else { $null }
                        }
                        continue
                    }
                    $elementValue = if ($null -ne $element -and $element.PSObject.Properties['value']) { $element.value } else { $null }
                    $values.Add($elementValue) | Out-Null
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

            default {
                $gaps.Add("unknown-instance-type: '$odataType' at settingPath '$settingPath'") | Out-Null
                return
            }
        }
    }

    $roots = @()
    if ($null -ne $SettingsPayload) {
        $roots = @($SettingsPayload)
    }

    $ordinalCounters = [System.Collections.Generic.Dictionary[string, int]]::new()

    foreach ($root in $roots) {
        if ($null -eq $root -or $root -isnot [System.Management.Automation.PSObject]) { continue }
        $nativeId = if ($root.PSObject.Properties['id'] -and -not [string]::IsNullOrEmpty([string] $root.id)) { [string] $root.id } else { $null }
        $settingInstance = if ($root.PSObject.Properties['settingInstance']) { $root.settingInstance } else { $null }
        if ($null -eq $settingInstance) { continue }

        Invoke-PulseWalkInstance -Instance $settingInstance -ParentSettingPath '' -ParentInstanceId $PolicyId `
            -NativeInstanceId $nativeId -Depth 1 -OrdinalCounters $ordinalCounters
    }

    return [pscustomobject]@{
        Rows = $rows.ToArray()
        Gaps = $gaps.ToArray()
    }
}
