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

    ONE LEVEL OF NESTING ONLY (mirrors ConvertTo-PulseTypedPolicyRows.ps1's own Nested
    contract exactly - TypedPolicyMaps.psd1's schema does not describe anything deeper): a
    `Nested` property's raw value is walked once, per-element if it is an array
    (omaSettings) or once directly if it is a single object (installationSchedule), and
    only the Nested.Properties entries flagged Sensitive are redacted within it - the
    Nested container itself, and every non-Sensitive nested property, is left untouched.
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
        -SensitiveNames. Shape-preserving for both [IDictionary] and [PSObject] inputs;
        anything else (a scalar sitting where an object was expected - an already-malformed
        shape) is returned as-is, since there is nothing structured here to redact into.
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

    return $Element
}

function Protect-PulseTypedPolicyRow {
    <#
        Private helper: clone ONE raw policy row, redacting Sensitive top-level and
        one-level-nested properties per -TypeMap (the relevant policyType sub-map from
        TypedPolicyMaps.psd1). An unmapped `@odata.type` (or a row with none at all)
        returns the ORIGINAL row object unchanged - see this file's own UNMAPPED
        @odata.type docstring section.
    #>
    param($Row, [System.Collections.IDictionary] $TypeMap)

    $odataTypeRaw = Get-PulseSettingsCatalogValueProperty -Node $Row -PropertyName '@odata.type'
    $odataType = if ($null -ne $odataTypeRaw) { [string] $odataTypeRaw } else { $null }

    if ([string]::IsNullOrEmpty($odataType) -or -not $TypeMap.Contains($odataType)) {
        return $Row
    }

    $typeEntry = $TypeMap[$odataType]

    $sensitiveTopNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $nestedSpecByName = @{}
    foreach ($propertySpec in @($typeEntry.Properties)) {
        $propertyName = [string] $propertySpec.Name
        if ([bool] $propertySpec.Sensitive) { [void] $sensitiveTopNames.Add($propertyName) }
        if ($propertySpec.Contains('Nested') -and $null -ne $propertySpec.Nested) {
            $nestedSensitiveNames = @($propertySpec.Nested.Properties | Where-Object { [bool] $_.Sensitive } | ForEach-Object { [string] $_.Name })
            if ($nestedSensitiveNames.Count -gt 0) { $nestedSpecByName[$propertyName] = $nestedSensitiveNames }
        }
    }

    if ($sensitiveTopNames.Count -eq 0 -and $nestedSpecByName.Count -eq 0) {
        # Nothing this map flags Sensitive for this type at all - no clone needed, return
        # the original row (avoids an unnecessary allocation for the common case).
        return $Row
    }

    function Protect-PulseTypedPolicyPropertyValue {
        param([string] $Name, $Value)

        if ($sensitiveTopNames.Contains($Name)) {
            return New-PulseRedactedMarker
        }

        if ($nestedSpecByName.ContainsKey($Name)) {
            $nestedSensitiveNames = $nestedSpecByName[$Name]

            if ($null -eq $Value) { return $Value }

            if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string] -and -not (Test-PulseSettingsCatalogNode -Node $Value)) {
                $elements = @($Value)
                $clonedElements = [object[]]::new($elements.Count)
                for ($i = 0; $i -lt $elements.Count; $i++) {
                    $clonedElements[$i] = Protect-PulseTypedPolicyNestedElement -Element $elements[$i] -SensitiveNames $nestedSensitiveNames
                }
                return , $clonedElements
            }

            if (Test-PulseSettingsCatalogNode -Node $Value) {
                return Protect-PulseTypedPolicyNestedElement -Element $Value -SensitiveNames $nestedSensitiveNames
            }

            return $Value
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
