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
        $iso = $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
        [void] $Builder.Append((ConvertTo-PulseCanonicalJsonString -Value $iso))
        return
    }

    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or `
            $Value -is [sbyte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        [void] $Builder.Append([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
        return
    }

    if ($Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        [void] $Builder.Append([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
        return
    }

    # Dictionaries (hashtable / ordered dictionary) - treat as a JSON object, keys sorted.
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = @($Value.Keys | Sort-Object -Culture ([System.Globalization.CultureInfo]::InvariantCulture))

        if ($keys.Count -eq 0) {
            [void] $Builder.Append('{}')
            return
        }

        [void] $Builder.Append("{`n")
        for ($i = 0; $i -lt $keys.Count; $i++) {
            $key = $keys[$i]
            [void] $Builder.Append($childIndent)
            [void] $Builder.Append((ConvertTo-PulseCanonicalJsonString -Value ([string] $key)))
            [void] $Builder.Append(': ')
            Write-PulseCanonicalJsonValue -Value $Value[$key] -Builder $Builder -IndentLevel ($IndentLevel + 1) -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
            if ($i -lt $keys.Count - 1) {
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

    # PSCustomObject and similar - treat properties as a JSON object, keys sorted.
    if ($Value -is [System.Management.Automation.PSObject]) {
        $propertyNames = @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object -Culture ([System.Globalization.CultureInfo]::InvariantCulture))

        if ($propertyNames.Count -eq 0) {
            [void] $Builder.Append('{}')
            return
        }

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
