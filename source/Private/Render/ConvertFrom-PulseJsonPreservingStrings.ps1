<#
    Private: parse a JSON document the same way -DateKind String does, WITHOUT requiring
    -DateKind String (CI BLOCKER fix - PowerShell 7.4 module floor).

    ConvertFrom-Json's -DateKind parameter does not exist at all on PowerShell 7.4 - it
    shipped in 7.5 - so every direct `ConvertFrom-Json ... -DateKind String` call in this
    module (Export-PulseReport.ps1's findings-read path, Export-PulseJsonReport.ps1's
    -RedactionMap deep-clone path) fails at PARAMETER BIND time on the 7.4 leg of the CI
    matrix, before the cmdlet body ever runs - not a runtime behavior difference, a hard
    bind failure. Every caller of either of those two functions is routed through THIS
    function instead of calling ConvertFrom-Json directly, so the 7.4/7.5+ branch lives in
    exactly one place.

    FEATURE DETECTION, CACHED ONCE: Test-PulseConvertFromJsonSupportsDateKind checks
    `(Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')` - the same
    reflection-based pattern this module already uses elsewhere (see
    Invoke-PulseEvaluation.ps1's own $ruleCommand.Parameters.ContainsKey('Context') check)
    - and caches the answer in $script:PulseConvertFromJsonSupportsDateKind so the
    reflection call happens at most once per module session, not once per parse. A test
    can force the fallback branch on ANY PowerShell version by setting that script-scope
    variable directly before calling this function (bypassing the cache's null-check) -
    see this module's own test suite for the byte-identity tests that do exactly that to
    exercise both branches regardless of the PowerShell version actually running them.

    PLAIN ConvertFrom-Json (NO -DateKind AT ALL) IS FORBIDDEN AS THE FALLBACK, EVEN ON
    7.4: its default behavior parses any ISO-8601-looking JSON string into a [datetime],
    which ConvertTo-PulseCanonicalJson then reformats at millisecond precision - silently
    dropping a 7-digit-fraction Graph timestamp's extra digits and re-opening the exact
    byte-identity bug -DateKind String was added to close in the first place (see
    Export-PulseReport.ps1/Export-PulseJsonReport.ps1's own docstrings for that history).
    A 7.4 caller therefore gets a genuinely different parser, not a degraded one:

    JsonDocument-BASED FALLBACK (PowerShell < 7.5): walks a
    System.Text.Json.JsonDocument by hand instead. JsonDocument never infers a CLR type
    for a JSON string - every string round-trips as a [string] exactly like -DateKind
    String's own behavior - so a Graph timestamp string survives untouched regardless of
    how many fractional digits it carries. The walk maps Object -> [pscustomobject] (an
    ordered hashtable built up property-by-property, then cast once - preserves source
    property order, though ConvertTo-PulseCanonicalJson re-sorts ordinally anyway),
    Array -> [object[]], String -> [string], True/False -> [bool], Null -> $null, and
    Number -> parsed from JsonElement.GetRawText() (never .GetDouble()/.GetInt64(), which
    can round-trip a value through a different numeric representation than what was
    actually written) - an integral raw text parses to [long] (a [double] only on
    overflow), anything with a decimal point or exponent parses to [double]. This mirrors
    what ConvertFrom-Json's own built-in JSON number handling does closely enough that
    ConvertTo-PulseCanonicalJson's own invariant-culture number formatting (which does not
    distinguish long 1 from double 1.0 in its own output - both format to the literal
    text "1") produces IDENTICAL canonical JSON from either parser for the same input
    document, which is the actual invariant this function's test suite verifies: both
    branches, run on the same findings JSON, produce byte-identical
    ConvertTo-PulseCanonicalJson output.
#>

function Test-PulseConvertFromJsonSupportsDateKind {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($null -eq $script:PulseConvertFromJsonSupportsDateKind) {
        $script:PulseConvertFromJsonSupportsDateKind = [bool] (Get-Command -Name 'ConvertFrom-Json' -CommandType Cmdlet).Parameters.ContainsKey('DateKind')
    }

    return $script:PulseConvertFromJsonSupportsDateKind
}

function ConvertFrom-PulseJsonElement {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [System.Text.Json.JsonElement] $Element,

        [Parameter(Mandatory)]
        [int] $CurrentDepth,

        [Parameter(Mandatory)]
        [int] $MaxDepth,

        # AsHashtable (Part E, T3.4): when set, an Object node builds an [ordered][hashtable]
        # instead of a [pscustomobject] - the same shape ConvertFrom-Json -AsHashtable
        # produces, needed by callers (Get-PulseSnapshotManifest) that mutate the parsed tree
        # in place (Set-PulseManifestEntry). A [pscustomobject] tree is otherwise preferred
        # (matches plain ConvertFrom-Json's own default shape) so every existing caller of
        # this function that expects PSObject property access keeps working unchanged.
        [switch] $AsHashtable
    )

    if ($CurrentDepth -gt $MaxDepth) {
        throw "ConvertFrom-PulseJsonPreservingStrings: input exceeds the maximum depth of $MaxDepth."
    }

    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            if ($AsHashtable) {
                # [System.Management.Automation.OrderedHashtable], NOT [ordered]@{}
                # (System.Collections.Specialized.OrderedDictionary): OrderedDictionary
                # has no ContainsKey method on PowerShell 7.4's runtime, and this tree
                # flows into dozens of .ContainsKey call sites (manifest reads, the
                # evaluator, artifact readers) - CI's 7.4 legs failed ~500 tests on it.
                # OrderedHashtable is the EXACT type ConvertFrom-Json -AsHashtable
                # itself returns (which this switch documents itself as mimicking):
                # insertion-ordered enumeration, derives from Hashtable, so ContainsKey,
                # Contains and case-insensitive keys all behave identically on 7.4/7.6.
                $map = [System.Management.Automation.OrderedHashtable]::new()
                foreach ($property in $Element.EnumerateObject()) {
                    $map[$property.Name] = ConvertFrom-PulseJsonElement -Element $property.Value -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth -AsHashtable:$AsHashtable
                }
                return $map
            }
            $ordered = [ordered] @{}
            foreach ($property in $Element.EnumerateObject()) {
                $ordered[$property.Name] = ConvertFrom-PulseJsonElement -Element $property.Value -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth -AsHashtable:$AsHashtable
            }
            return [pscustomobject] $ordered
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            $items = [System.Collections.Generic.List[object]]::new()
            foreach ($element in $Element.EnumerateArray()) {
                $items.Add((ConvertFrom-PulseJsonElement -Element $element -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth -AsHashtable:$AsHashtable)) | Out-Null
            }
            return , [object[]] @($items.ToArray())
        }
        ([System.Text.Json.JsonValueKind]::String) {
            # The entire point of this fallback: a JSON string ALWAYS comes back as a
            # [string], never inferred/parsed into a [datetime] - see this file's own
            # docstring.
            return $Element.GetString()
        }
        ([System.Text.Json.JsonValueKind]::Number) {
            # GetRawText (post-review, this task) - never .GetDouble()/.GetInt64(), which
            # round the value through a specific numeric representation before this
            # function ever sees it. Parsing the RAW on-disk text ourselves is what avoids
            # precision drift for a value like a large integer id or a many-digit decimal.
            $rawText = $Element.GetRawText()
            if ($rawText.IndexOfAny([char[]] @('.', 'e', 'E')) -ge 0) {
                return [double]::Parse($rawText, [System.Globalization.CultureInfo]::InvariantCulture)
            }
            $longValue = [long] 0
            if ([long]::TryParse($rawText, [System.Globalization.NumberStyles]::AllowLeadingSign, [System.Globalization.CultureInfo]::InvariantCulture, [ref] $longValue)) {
                return $longValue
            }
            # Integral text too large for [long] (rare, but not a gap) - a [double] is the
            # same overflow behavior ConvertFrom-Json's own parser falls back to.
            return [double]::Parse($rawText, [System.Globalization.CultureInfo]::InvariantCulture)
        }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $false }
        ([System.Text.Json.JsonValueKind]::Null) { return $null }
        ([System.Text.Json.JsonValueKind]::Undefined) { return $null }
        default {
            throw "ConvertFrom-PulseJsonPreservingStrings: unexpected JsonValueKind '$($Element.ValueKind)'."
        }
    }
}

function ConvertFrom-PulseJsonPreservingStrings {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Json,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $Depth = 64,

        # AsHashtable (Part E, T3.4 - manifest createdUtc culture-coercion fix): same
        # "preserve every JSON string exactly, never let a date-looking string parse into
        # [datetime]" contract this function already provides, but returning a mutable
        # hashtable tree instead of a pscustomobject tree - the shape
        # Get-PulseSnapshotManifest needs (Set-PulseManifestEntry mutates the parsed
        # manifest in place). Both branches below stay behind the SAME cached feature-detect
        # this function already used, so a caller opting into -AsHashtable gets the exact
        # same 7.4-vs-7.5+ branch split, and the exact same test-forced-branch pattern this
        # file's own test suite already exercises, as every existing non-hashtable caller.
        [switch] $AsHashtable
    )

    if (Test-PulseConvertFromJsonSupportsDateKind) {
        if ($AsHashtable) {
            return ConvertFrom-Json -InputObject $Json -Depth $Depth -DateKind String -AsHashtable
        }
        return ConvertFrom-Json -InputObject $Json -Depth $Depth -DateKind String
    }

    $document = [System.Text.Json.JsonDocument]::Parse($Json)
    try {
        return ConvertFrom-PulseJsonElement -Element $document.RootElement -CurrentDepth 0 -MaxDepth $Depth -AsHashtable:$AsHashtable
    } finally {
        $document.Dispose()
    }
}
