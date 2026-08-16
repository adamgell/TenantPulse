<#
    QA gate: every file under tests/Fixtures/ has a declared, checkable provenance in
    tests/Fixtures/PROVENANCE.md - so a fixture copied out of a real tenant (or any other
    third-party source) without attribution cannot land silently.

    Get-PulseFixtureProvenanceViolations does the actual comparison and is unit-tested
    directly, against small synthetic in-memory inputs, BEFORE it is ever pointed at the
    real repo tree - this both drives the gate's own logic with fast, deterministic cases
    (unlisted file, listed-but-missing file, malformed origin, the all-clear case) and
    proves the gate can fail, the same role the mutation-check in ReadOnly.tests.ps1 plays
    for the read-only gate. Only after that is the function run once more against the real
    tests/Fixtures/ tree and the real PROVENANCE.md.
#>

BeforeAll {
    $projectPath = "$($PSScriptRoot)\..\.." | Convert-Path
    $script:fixturesPath = Join-Path -Path $projectPath -ChildPath 'tests/Fixtures'
    $script:provenancePath = Join-Path -Path $script:fixturesPath -ChildPath 'PROVENANCE.md'

    <#
        Parses a PROVENANCE.md-shaped set of lines into an ordered map of
        relative-path -> origin-declaration. Only lines shaped like:

            - `tests/Fixtures/some/path.psd1` — synthetic
            - `tests/Fixtures/some/path.psd1` — sanitized(some source)

        are recognised as entries; every other line (headings, prose, blank lines) is
        ignored. Accepts either an em dash or a plain hyphen between the path and the
        origin so a hand-edited line does not silently vanish from the parse.

        THROWS if the same path (compared ORDINAL/case-sensitive - PROVENANCE.md paths are
        real filesystem paths, and two entries differing only in case are either a real
        typo or two genuinely different files on a case-sensitive filesystem, never the
        same entry) appears more than once: a hashtable assignment would otherwise make the
        second occurrence silently win, which could hide a stale, wrong, or downgraded
        origin declaration (e.g. a real 'sanitized(...)' entry quietly shadowed by a
        later, mistaken 'synthetic' one) behind whichever line happens to be last.
    #>
    function ConvertFrom-PulseProvenanceMarkdown {
        [CmdletBinding()]
        [OutputType([hashtable])]
        param(
            # Deliberately NOT [Parameter(Mandatory)] combined with [AllowEmptyCollection()]:
            # PowerShell's binder applies AllowEmptyCollection's implied not-null-or-empty
            # check to each ELEMENT of the array, not just the array as a whole, so an
            # empty-string line (a blank line in PROVENANCE.md, which must be ignored, not
            # rejected) fails to bind at all. A plain default keeps blank lines legal.
            [string[]] $Line = @()
        )

        # An explicit Ordinal comparer, NOT [ordered]@{}'s own default: PowerShell's
        # [ordered]@{}/@{} both use a case-INSENSITIVE comparer for string keys by
        # default, which would silently collapse 'tests/Fixtures/A.psd1' and
        # 'tests/Fixtures/a.psd1' into a single entry (last-write-wins) - exactly the
        # case-sensitivity hole this whole file's path comparisons exist to close.
        $entries = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
        $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

        foreach ($text in $Line) {
            if ($text -match '^\s*-\s*`([^`]+)`\s*(?:—|-)\s*(.+?)\s*$') {
                $path = $Matches[1]

                if (-not $seenPaths.Add($path)) {
                    throw "PROVENANCE.md: duplicate entry for '$path' - the same path must be listed exactly once; a hashtable assignment would otherwise let the later line silently win over the earlier one, hiding whichever origin declaration lost."
                }

                $entries[$path] = $Matches[2]
            }
        }

        return $entries
    }

    <#
        Compares the fixture files that actually exist on disk against the entries parsed
        out of PROVENANCE.md and returns every violation as a string (empty array = clean):

            - a file on disk with no PROVENANCE.md entry ("unlisted")
            - a PROVENANCE.md entry whose file does not exist on disk ("listed-but-missing")
            - a PROVENANCE.md entry whose origin is neither 'synthetic' nor
              'sanitized(<source>)' (source must contain at least one non-whitespace
              character - 'sanitized()' and 'sanitized(   )' are both rejected, not just
              the empty-parens case)

        Path membership is checked ORDINAL/case-sensitive in BOTH directions (disk-file ->
        listed, and listed -> disk-file) via a HashSet[string] with StringComparer.Ordinal,
        not the -contains/-notcontains operators, which compare case-INSENSITIVELY by
        default - on a case-sensitive filesystem (Linux CI runners, notably) 'A.psd1' and
        'a.psd1' are different files, and a case-insensitive comparison here would let a
        genuinely unlisted file (or a genuinely missing one) hide behind a same-looking
        entry that differs only in case.

        Paths in both inputs are expected pre-normalized to forward-slash, repo-relative
        form (e.g. 'tests/Fixtures/Checks/valid/a-second.psd1') - callers own that
        normalization so this function stays a pure, filesystem-free comparison.
    #>
    function Get-PulseFixtureProvenanceViolations {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [string[]] $ActualFile,

            [Parameter(Mandatory)]
            [hashtable] $ProvenanceEntry
        )

        $violations = [System.Collections.Generic.List[string]]::new()
        $listedPaths = @($ProvenanceEntry.Keys)

        $actualFileLookup = [System.Collections.Generic.HashSet[string]]::new([string[]] $ActualFile, [System.StringComparer]::Ordinal)
        $listedPathLookup = [System.Collections.Generic.HashSet[string]]::new([string[]] $listedPaths, [System.StringComparer]::Ordinal)

        foreach ($file in ($ActualFile | Sort-Object -Culture ([System.Globalization.CultureInfo]::InvariantCulture))) {
            if (-not $listedPathLookup.Contains($file)) {
                $violations.Add("Unlisted fixture file (not in PROVENANCE.md): $file")
            }
        }

        foreach ($listed in ($listedPaths | Sort-Object -Culture ([System.Globalization.CultureInfo]::InvariantCulture))) {
            if (-not $actualFileLookup.Contains($listed)) {
                $violations.Add("PROVENANCE.md lists a file that does not exist on disk: $listed")
            }
        }

        foreach ($listed in ($listedPaths | Sort-Object -Culture ([System.Globalization.CultureInfo]::InvariantCulture))) {
            $origin = $ProvenanceEntry[$listed]
            # -cnotmatch: origin declarations are case-sensitive. PowerShell's plain
            # -match/-notmatch operators are case-INSENSITIVE by default, which would
            # silently accept 'Synthetic' or 'SANITIZED(x)' as valid. The
            # 'sanitized\(\s*[^\s)][^)]*\)' branch additionally requires the parens'
            # content to start with a character that is neither whitespace NOR the closing
            # paren itself - plain '.+' would accept both 'sanitized()' (empty) and
            # 'sanitized(   )' (whitespace only) as a "valid" but meaningless,
            # unattributed source; note '\S' alone is not enough here, since ')' itself
            # matches '\S' (it is non-whitespace), which is exactly why 'sanitized()'
            # needs the closing paren excluded explicitly, not just whitespace.
            if ($origin -cnotmatch '^(synthetic|sanitized\(\s*[^\s)][^)]*\))$') {
                $violations.Add("PROVENANCE.md entry for '$listed' has an invalid origin declaration '$origin' - must be exactly 'synthetic' or 'sanitized(<source>)' with a non-empty, non-whitespace-only <source>")
            }
        }

        return $violations.ToArray()
    }
}

Describe 'Fixture provenance gate logic' -Tag 'QA', 'FixtureProvenance' {

    Context 'ConvertFrom-PulseProvenanceMarkdown' {
        It 'parses an em-dash entry line' {
            $entries = ConvertFrom-PulseProvenanceMarkdown -Line @('- `tests/Fixtures/a.psd1` — synthetic')

            $entries['tests/Fixtures/a.psd1'] | Should -Be 'synthetic'
        }

        It 'parses a plain-hyphen entry line' {
            $entries = ConvertFrom-PulseProvenanceMarkdown -Line @('- `tests/Fixtures/a.psd1` - sanitized(contoso export, 2026-01-01)')

            $entries['tests/Fixtures/a.psd1'] | Should -Be 'sanitized(contoso export, 2026-01-01)'
        }

        It 'ignores headings and prose lines' {
            $entries = ConvertFrom-PulseProvenanceMarkdown -Line @(
                '# Fixture provenance'
                ''
                'Every file under `tests/Fixtures/` must be listed here.'
                '- `tests/Fixtures/a.psd1` — synthetic'
            )

            $entries.Count | Should -Be 1
            $entries.Keys | Should -Be @('tests/Fixtures/a.psd1')
        }

        It 'throws on a duplicate path entry instead of letting the later line silently win' {
            {
                ConvertFrom-PulseProvenanceMarkdown -Line @(
                    '- `tests/Fixtures/a.psd1` — synthetic'
                    '- `tests/Fixtures/a.psd1` — sanitized(a later, different claim)'
                )
            } | Should -Throw -ExpectedMessage '*duplicate entry*tests/Fixtures/a.psd1*'
        }

        It 'treats two paths differing only by case as DIFFERENT entries, not a duplicate' {
            # Path comparison throughout this file is ordinal/case-sensitive (see
            # Get-PulseFixtureProvenanceViolations's own docstring) - two entries differing
            # only in case are two distinct filesystem paths on a case-sensitive
            # filesystem, not a duplicate to reject here.
            $entries = ConvertFrom-PulseProvenanceMarkdown -Line @(
                '- `tests/Fixtures/A.psd1` — synthetic'
                '- `tests/Fixtures/a.psd1` — synthetic'
            )

            $entries.Count | Should -Be 2
        }
    }

    Context 'Get-PulseFixtureProvenanceViolations (unit-tested against synthetic inputs, proving the gate logic itself)' {
        It 'reports zero violations when every file is listed with a valid origin' {
            $violations = @(Get-PulseFixtureProvenanceViolations `
                -ActualFile @('tests/Fixtures/a.psd1', 'tests/Fixtures/b.psd1') `
                -ProvenanceEntry ([ordered]@{
                    'tests/Fixtures/a.psd1' = 'synthetic'
                    'tests/Fixtures/b.psd1' = 'sanitized(contoso demo tenant export)'
                }))

            $violations | Should -BeNullOrEmpty
        }

        It 'flags a fixture file on disk that PROVENANCE.md never mentions' {
            $violations = @(Get-PulseFixtureProvenanceViolations `
                -ActualFile @('tests/Fixtures/a.psd1', 'tests/Fixtures/unlisted.psd1') `
                -ProvenanceEntry ([ordered]@{ 'tests/Fixtures/a.psd1' = 'synthetic' }))

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'Unlisted fixture file'
            $violations[0] | Should -Match ([regex]::Escape('tests/Fixtures/unlisted.psd1'))
        }

        It 'treats a case-differing path as unlisted AND as a separate missing entry, never as a match' {
            # 'tests/Fixtures/a.psd1' (on disk) and 'tests/Fixtures/A.psd1' (in
            # PROVENANCE.md) must never be treated as the same path - a case-INSENSITIVE
            # comparison here would silently accept a real file as "listed" by an entry
            # that names a differently-cased path, and vice versa.
            $violations = @(Get-PulseFixtureProvenanceViolations `
                -ActualFile @('tests/Fixtures/a.psd1') `
                -ProvenanceEntry ([ordered]@{ 'tests/Fixtures/A.psd1' = 'synthetic' }))

            $violations.Count | Should -Be 2
            ($violations -join "`n") | Should -Match 'Unlisted fixture file.*tests/Fixtures/a\.psd1'
            ($violations -join "`n") | Should -Match 'does not exist on disk.*tests/Fixtures/A\.psd1'
        }

        It 'rejects sanitized() with empty parens' {
            $violations = @(Get-PulseFixtureProvenanceViolations `
                -ActualFile @('tests/Fixtures/a.psd1') `
                -ProvenanceEntry ([ordered]@{ 'tests/Fixtures/a.psd1' = 'sanitized()' }))

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'invalid origin declaration'
        }

        It 'rejects sanitized(   ) with whitespace-only content' {
            $violations = @(Get-PulseFixtureProvenanceViolations `
                -ActualFile @('tests/Fixtures/a.psd1') `
                -ProvenanceEntry ([ordered]@{ 'tests/Fixtures/a.psd1' = 'sanitized(   )' }))

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'invalid origin declaration'
        }

        It 'flags a PROVENANCE.md entry whose file does not exist on disk' {
            $violations = @(Get-PulseFixtureProvenanceViolations `
                -ActualFile @('tests/Fixtures/a.psd1') `
                -ProvenanceEntry ([ordered]@{
                    'tests/Fixtures/a.psd1'       = 'synthetic'
                    'tests/Fixtures/deleted.psd1' = 'synthetic'
                }))

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'lists a file that does not exist on disk'
            $violations[0] | Should -Match ([regex]::Escape('tests/Fixtures/deleted.psd1'))
        }

        It 'flags an origin that is neither synthetic nor sanitized(<source>)' -TestCases @(
            @{ Origin = 'real tenant export' }
            @{ Origin = 'sanitized' }
            @{ Origin = 'sanitized()' }
            @{ Origin = '' }
            @{ Origin = 'Synthetic' }
        ) {
            $violations = @(Get-PulseFixtureProvenanceViolations `
                -ActualFile @('tests/Fixtures/a.psd1') `
                -ProvenanceEntry ([ordered]@{ 'tests/Fixtures/a.psd1' = $Origin }))

            $violations.Count | Should -Be 1 -Because "origin '$Origin' must not be accepted"
            $violations[0] | Should -Match 'invalid origin declaration'
        }

        It 'accepts a sanitized(<source>) origin with parentheses/commas inside the source text' {
            $violations = @(Get-PulseFixtureProvenanceViolations `
                -ActualFile @('tests/Fixtures/a.psd1') `
                -ProvenanceEntry ([ordered]@{ 'tests/Fixtures/a.psd1' = 'sanitized(export from lab tenant, redacted 2026-08-15)' }))

            $violations | Should -BeNullOrEmpty
        }

        It 'reports every violation in one pass rather than stopping at the first' {
            # Four independent violations in one call: the on-disk file is unlisted; both
            # PROVENANCE.md entries point at files that do not exist; and the second entry's
            # origin is invalid on top of that.
            $violations = @(Get-PulseFixtureProvenanceViolations `
                -ActualFile @('tests/Fixtures/unlisted.psd1') `
                -ProvenanceEntry ([ordered]@{
                    'tests/Fixtures/deleted.psd1'  = 'synthetic'
                    'tests/Fixtures/bad-origin.md' = 'not a real origin'
                }))

            $violations.Count | Should -Be 4
        }
    }
}

Describe 'Fixture provenance gate' -Tag 'QA', 'FixtureProvenance' {

    BeforeAll {
        Test-Path -LiteralPath $script:provenancePath -PathType Leaf | Should -BeTrue -Because 'tests/Fixtures/PROVENANCE.md must exist for this gate to run at all'

        # -Force: without it, Get-ChildItem silently skips hidden/dotfile fixtures on every
        # platform this matters on - a hidden fixture file would be invisible to this walk
        # (never flagged as unlisted, never counted at all) while still sitting on disk,
        # which is a worse failure mode for a provenance gate than simply seeing it.
        $script:actualFixtureFiles = @(
            Get-ChildItem -Path $script:fixturesPath -Recurse -File -Force |
                Where-Object { $_.FullName -ne $script:provenancePath } |
                ForEach-Object { ($_.FullName.Substring($projectPath.Length + 1)) -replace '\\', '/' }
        )

        $script:provenanceEntries = ConvertFrom-PulseProvenanceMarkdown -Line @(Get-Content -Path $script:provenancePath)
    }

    It 'PROVENANCE.md declares at least one fixture (the parser is not silently matching nothing)' {
        $script:provenanceEntries.Count | Should -BeGreaterThan 0
    }

    It 'the real tests/Fixtures/ tree has zero provenance violations' {
        $violations = @(Get-PulseFixtureProvenanceViolations -ActualFile $script:actualFixtureFiles -ProvenanceEntry $script:provenanceEntries)

        $violations | Should -BeNullOrEmpty -Because ("every fixture file must be listed in PROVENANCE.md with a valid origin, and every listed file must exist; violations found:`n" + ($violations -join "`n"))
    }
}
