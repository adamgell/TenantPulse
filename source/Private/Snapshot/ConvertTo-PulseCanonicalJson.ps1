<#
    Private: serialize an object graph to deterministic, canonical JSON.

    This is the determinism primitive every snapshot/finding artifact serializes through:
    object property names sorted ordinally, LF-only line endings, no trailing whitespace,
    invariant-culture number formatting. The same object graph - regardless of the order its
    properties were inserted in - always produces byte-identical output, which is what lets
    dataset hashes and canonical-JSON diffs be meaningful.
#>

function ConvertTo-PulseCanonicalJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        [object] $InputObject,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int] $Depth = 64
    )

    $builder = [System.Text.StringBuilder]::new()

    Write-PulseCanonicalJsonValue -Value $InputObject -Builder $builder -IndentLevel 0 -MaxDepth $Depth -CurrentDepth 0

    return $builder.ToString()
}

function Write-PulseCanonicalJsonValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Value,

        [Parameter(Mandatory)]
        [System.Text.StringBuilder] $Builder,

        [Parameter(Mandatory)]
        [int] $IndentLevel,

        [Parameter(Mandatory)]
        [int] $MaxDepth,

        [Parameter(Mandatory)]
        [int] $CurrentDepth
    )

    if ($CurrentDepth -gt $MaxDepth) {
        throw "ConvertTo-PulseCanonicalJson: input exceeds the maximum depth of $MaxDepth."
    }

    $indent = '  ' * $IndentLevel
    $childIndent = '  ' * ($IndentLevel + 1)

    if ($null -eq $Value) {
        [void] $Builder.Append('null')
        return
    }

    if ($Value -is [bool]) {
        [void] $Builder.Append($(if ($Value) { 'true' } else { 'false' }))
        return
    }

    if ($Value -is [string]) {
        [void] $Builder.Append((ConvertTo-PulseCanonicalJsonString -Value $Value))
        return
    }

    if ($Value -is [System.Management.Automation.PSObject] -and $Value.BaseObject -is [datetime]) {
        $Value = [datetime] $Value.BaseObject
    }

    if ($Value -is [datetime]) {
        # Kind=Unspecified (post-review fix): .ToUniversalTime() on an Unspecified-kind
        # DateTime silently ASSUMES the value is local time and converts it as such - wrong
        # for this codebase, where every DateTime that reaches here is either already UTC
        # or was parsed with no timezone information at all (and this module's own
        # convention, see Test-PulseStaleDevices's ConvertTo-PulseNullableUtcDateTime, is
        # to treat an unspecified-offset timestamp as UTC, never local). SpecifyKind marks
        # the value UTC WITHOUT converting it - the correct operation for a value that is
        # already UTC but was not tagged as such - whereas ToUniversalTime would still be
        # correct (a no-op) for a value already tagged Utc, so only Unspecified needs the
        # different call.
        $utcValue = if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) {
            [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
        } else {
            $Value.ToUniversalTime()
        }
        $iso = $utcValue.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
        [void] $Builder.Append((ConvertTo-PulseCanonicalJsonString -Value $iso))
        return
    }

    if ($Value -is [System.Management.Automation.PSObject] -and $Value.BaseObject -is [datetimeoffset]) {
        $Value = [datetimeoffset] $Value.BaseObject
    }

    # Graph timestamps routinely arrive as DateTimeOffset, not DateTime. Format with an
    # explicit offset (rather than normalizing to UTC 'Z') so no information is discarded -
    # 'z' would be lossy for any non-UTC producer.
    if ($Value -is [datetimeoffset]) {
        $iso = $Value.ToString('yyyy-MM-ddTHH:mm:ss.fffffffzzz', [System.Globalization.CultureInfo]::InvariantCulture)
        [void] $Builder.Append((ConvertTo-PulseCanonicalJsonString -Value $iso))
        return
    }

    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or `
            $Value -is [sbyte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        [void] $Builder.Append([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
        return
    }

    if ($Value -is [single] -or $Value -is [double]) {
        $doubleValue = [double] $Value
        if ([double]::IsNaN($doubleValue) -or [double]::IsInfinity($doubleValue)) {
            throw "ConvertTo-PulseCanonicalJson: cannot serialize non-finite number '$doubleValue' - JSON has no representation for NaN or Infinity."
        }
        [void] $Builder.Append([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
        return
    }

    if ($Value -is [decimal]) {
        [void] $Builder.Append([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
        return
    }

    # Dictionaries (hashtable / ordered dictionary) - treat as a JSON object, keys sorted.
    #
    # Sorting must be ordinal, not culture-aware: Sort-Object -Culture is case-INSENSITIVE
    # collation, so keys that differ only by case ('apple'/'Apple') compare equal and keep
    # their original insertion order - the exact non-determinism this function exists to
    # eliminate. JSON keys are case-sensitive, so ordinal is the only defensible order.
    # A sort-by-index is used rather than [Array]::Sort(keys, items) - the two-array
    # "parallel sort" overload does not reliably reorder the second (items) array under
    # PowerShell's method binder in this environment (verified empirically: keys end up
    # sorted, items stay in original insertion order, silently pairing every key with the
    # wrong value). Sorting an index array with a Comparison<int> delegate and indexing
    # into the original arrays through it sidesteps that overload entirely.
    if ($Value -is [System.Collections.IDictionary]) {
        $originalKeys = @($Value.Keys)

        if ($originalKeys.Count -eq 0) {
            [void] $Builder.Append('{}')
            return
        }

        $stringKeys = [string[]] @($originalKeys | ForEach-Object { [string] $_ })

        # Group-Object's default equality comparer is case-INSENSITIVE, which would treat
        # 'apple' and 'Apple' as the same group and miss exactly the collision this check
        # exists to catch (e.g. int key 1 and string key '1' both stringify to '1', but so
        # would 'Apple' and 'apple' if compared case-insensitively - only ordinal is correct
        # for JSON's case-sensitive keys).
        $seenKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $duplicates = [System.Collections.Generic.List[string]]::new()
        foreach ($stringKey in $stringKeys) {
            if (-not $seenKeys.Add($stringKey)) {
                $duplicates.Add($stringKey)
            }
        }
        if ($duplicates.Count -gt 0) {
            throw "ConvertTo-PulseCanonicalJson: duplicate object keys after string normalization: $($duplicates -join ', ')."
        }

        $order = [int[]] (0 .. ($stringKeys.Count - 1))
        $comparison = [System.Comparison[int]] { param($a, $b) [string]::CompareOrdinal($stringKeys[$a], $stringKeys[$b]) }
        [System.Array]::Sort($order, $comparison)

        [void] $Builder.Append("{`n")
        for ($i = 0; $i -lt $order.Count; $i++) {
            $sourceIndex = $order[$i]
            $key = $originalKeys[$sourceIndex]
            [void] $Builder.Append($childIndent)
            [void] $Builder.Append((ConvertTo-PulseCanonicalJsonString -Value $stringKeys[$sourceIndex]))
            [void] $Builder.Append(': ')
            Write-PulseCanonicalJsonValue -Value $Value[$key] -Builder $Builder -IndentLevel ($IndentLevel + 1) -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
            if ($i -lt $order.Count - 1) {
                [void] $Builder.Append(',')
            }
            [void] $Builder.Append("`n")
        }
        [void] $Builder.Append($indent)
        [void] $Builder.Append('}')
        return
    }

    # Strings are IEnumerable too, so they were already handled above. Arrays/lists next.
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)

        if ($items.Count -eq 0) {
            [void] $Builder.Append('[]')
            return
        }

        [void] $Builder.Append("[`n")
        for ($i = 0; $i -lt $items.Count; $i++) {
            [void] $Builder.Append($childIndent)
            Write-PulseCanonicalJsonValue -Value $items[$i] -Builder $Builder -IndentLevel ($IndentLevel + 1) -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
            if ($i -lt $items.Count - 1) {
                [void] $Builder.Append(',')
            }
            [void] $Builder.Append("`n")
        }
        [void] $Builder.Append($indent)
        [void] $Builder.Append(']')
        return
    }

    # PSCustomObject and similar - treat properties as a JSON object, keys sorted ordinally
    # (see the IDictionary branch above for why -Culture sorting is wrong here).
    if ($Value -is [System.Management.Automation.PSObject]) {
        $propertyNames = [string[]] @($Value.PSObject.Properties | ForEach-Object { $_.Name })

        if ($propertyNames.Count -eq 0) {
            [void] $Builder.Append('{}')
            return
        }

        $seenProperties = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $duplicateProperties = [System.Collections.Generic.List[string]]::new()
        foreach ($propertyName in $propertyNames) {
            if (-not $seenProperties.Add($propertyName)) {
                $duplicateProperties.Add($propertyName)
            }
        }
        if ($duplicateProperties.Count -gt 0) {
            throw "ConvertTo-PulseCanonicalJson: duplicate object properties: $($duplicateProperties -join ', ')."
        }

        [System.Array]::Sort($propertyNames, [System.StringComparer]::Ordinal)

        [void] $Builder.Append("{`n")
        for ($i = 0; $i -lt $propertyNames.Count; $i++) {
            $name = $propertyNames[$i]
            [void] $Builder.Append($childIndent)
            [void] $Builder.Append((ConvertTo-PulseCanonicalJsonString -Value $name))
            [void] $Builder.Append(': ')
            Write-PulseCanonicalJsonValue -Value $Value.$name -Builder $Builder -IndentLevel ($IndentLevel + 1) -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
            if ($i -lt $propertyNames.Count - 1) {
                [void] $Builder.Append(',')
            }
            [void] $Builder.Append("`n")
        }
        [void] $Builder.Append($indent)
        [void] $Builder.Append('}')
        return
    }

    # Fallback: format any remaining scalar type (e.g. enum, guid) as an invariant string.
    [void] $Builder.Append((ConvertTo-PulseCanonicalJsonString -Value ([string] $Value)))
}

function ConvertTo-PulseCanonicalJsonString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $escaped = [System.Text.StringBuilder]::new($Value.Length + 2)
    [void] $escaped.Append('"')

    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '"' { [void] $escaped.Append('\"'); continue }
            '\' { [void] $escaped.Append('\\'); continue }
            "`n" { [void] $escaped.Append('\n'); continue }
            "`r" { [void] $escaped.Append('\r'); continue }
            "`t" { [void] $escaped.Append('\t'); continue }
            "`b" { [void] $escaped.Append('\b'); continue }
            "`f" { [void] $escaped.Append('\f'); continue }
            default {
                if ([int] $ch -lt 0x20) {
                    [void] $escaped.Append([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '\u{0:x4}', [int] $ch))
                }
                else {
                    [void] $escaped.Append($ch)
                }
            }
        }
    }

    [void] $escaped.Append('"')
    return $escaped.ToString()
}
