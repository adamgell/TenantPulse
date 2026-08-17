<#
    QA gate (T3.4 dual-review fix round 1, item 3 - NEW STANDING GATE): every
    `device_vendor_msft_*`-shaped settingDefinitionId/option-itemId string literal hard-
    coded in any check's rule function must exist in the compact corpus fixture
    (tests/Fixtures/SettingsCatalogCorpus/checked-definitions.json, a sanitized extraction
    of scratch/live-27/snapshot/reference/settingDefinitions.json - the Phase 2 captured
    corpus, 18,227 real Settings Catalog definitions). This makes the class of defect fixed
    in this round (TP.INT.0016 shipped GUID-suffixed IDs that do not exist anywhere in
    Intune's real schema; TP.INT.0031 shipped the wrong settingDefinitionId entirely -
    parent toggle instead of child dropdown) structurally impossible to regress silently:
    a future check that hard-codes an ID without adding it to the corpus fixture fails
    THIS gate, not just "maybe someone notices in review."

    Get-PulseSettingDefinitionCorpusCrossCheckViolations does the actual comparison and is
    unit-tested directly first, against small synthetic in-memory inputs (mirrors
    FixtureProvenance.tests.ps1's own "prove the gate can fail" discipline - a known-bad ID
    must be caught before this function is ever pointed at the real repo tree). Only after
    that is it run once more against the real source/Private/Checks/*.ps1 tree and the real
    corpus fixture.

    SCOPE, HONESTLY BOUNDED: this gate catches literal `device_vendor_msft_*` string
    tokens appearing ANYWHERE in a check's rule-function source file (code AND docstring
    prose) - it does not (and cannot, via static regex) verify that a string built via
    runtime interpolation (e.g. "${definitionId}_block") is correct; it verifies that
    every LITERAL base definitionId and every LITERAL full option-itemId string is real.
    Combined with each check's own Pester fixture suite (which DOES exercise the
    interpolated values end-to-end against real corpus-derived option suffixes), this
    closes the actual fabrication risk this round's review found without requiring a full
    PowerShell AST/string-interpolation evaluator.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:corpusFixturePath = Join-Path $script:repoRoot 'tests/Fixtures/SettingsCatalogCorpus/checked-definitions.json'
    $script:checksSourcePath = Join-Path $script:repoRoot 'source/Private/Checks'

    <#
        Returns an array of violation strings (empty when clean). -CorpusDefinitions is the
        already-parsed compact fixture array ({id; displayName; options:[{itemId;name}]}).
        -SourceFiles is the set of *.ps1 files to scan for literal
        `device_vendor_msft_[a-z0-9_]*` tokens.
    #>
    function Get-PulseSettingDefinitionCorpusCrossCheckViolations {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]] $CorpusDefinitions,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [string[]] $SourceFiles
        )

        $knownIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($definition in $CorpusDefinitions) {
            [void] $knownIds.Add([string] $definition.id)
            foreach ($option in @($definition.options)) {
                [void] $knownIds.Add([string] $option.itemId)
            }
        }

        $violations = [System.Collections.Generic.List[string]]::new()
        $tokenPattern = [regex] 'device_vendor_msft_[a-z0-9_]*[a-z0-9]'

        foreach ($file in $SourceFiles) {
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
            $content = Get-Content -LiteralPath $file -Raw
            $matchedTokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($match in $tokenPattern.Matches($content)) {
                [void] $matchedTokens.Add($match.Value)
            }
            foreach ($token in $matchedTokens) {
                if (-not $knownIds.Contains($token)) {
                    $violations.Add("$([System.IO.Path]::GetFileName($file)): references '$token', which is not a known settingDefinitionId or option itemId in the corpus fixture ($([System.IO.Path]::GetFileName($script:corpusFixturePath))).") | Out-Null
                }
            }
        }

        return , [string[]] @($violations.ToArray())
    }
}

Describe 'Get-PulseSettingDefinitionCorpusCrossCheckViolations (self-check against synthetic input)' {
    It 'reports zero violations when every referenced token is a known corpus id' {
        $corpus = @([pscustomobject]@{ id = 'device_vendor_msft_fake_real'; options = @([pscustomobject]@{ itemId = 'device_vendor_msft_fake_real_block'; name = 'Block' }) })
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString() + '.ps1')
        Set-Content -LiteralPath $tempFile -Value "`$x = 'device_vendor_msft_fake_real_block'" -NoNewline
        try {
            $violations = Get-PulseSettingDefinitionCorpusCrossCheckViolations -CorpusDefinitions $corpus -SourceFiles @($tempFile)
            @($violations).Count | Should -Be 0
        } finally {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    It 'PROVES THE GATE CAN FAIL: flags a fabricated id/option that is not in the corpus, naming the file and the bad token' {
        $corpus = @([pscustomobject]@{ id = 'device_vendor_msft_fake_real'; options = @([pscustomobject]@{ itemId = 'device_vendor_msft_fake_real_block'; name = 'Block' }) })
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString() + '.ps1')
        Set-Content -LiteralPath $tempFile -Value "`$x = 'device_vendor_msft_fake_totally_fabricated_guid_suffix_1'" -NoNewline
        try {
            $violations = Get-PulseSettingDefinitionCorpusCrossCheckViolations -CorpusDefinitions $corpus -SourceFiles @($tempFile)
            @($violations).Count | Should -Be 1
            $violations[0] | Should -Match 'device_vendor_msft_fake_totally_fabricated_guid_suffix_1'
            $violations[0] | Should -Match ([regex]::Escape([System.IO.Path]::GetFileName($tempFile)))
        } finally {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    It 'a token that exists as a definitionId (not an option itemId) is still accepted' {
        $corpus = @([pscustomobject]@{ id = 'device_vendor_msft_fake_parent'; options = @() })
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString() + '.ps1')
        Set-Content -LiteralPath $tempFile -Value "`$x = 'device_vendor_msft_fake_parent'" -NoNewline
        try {
            $violations = Get-PulseSettingDefinitionCorpusCrossCheckViolations -CorpusDefinitions $corpus -SourceFiles @($tempFile)
            @($violations).Count | Should -Be 0
        } finally {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Setting-definition corpus cross-check (real repo tree)' {
    It 'every device_vendor_msft_* literal referenced by a check under source/Private/Checks exists in the compact corpus fixture' {
        Test-Path -LiteralPath $script:corpusFixturePath -PathType Leaf | Should -BeTrue -Because 'the compact corpus fixture must exist for this gate to mean anything'

        $corpusDefinitions = @(Get-Content -LiteralPath $script:corpusFixturePath -Raw | ConvertFrom-Json -Depth 10)
        $sourceFiles = @(Get-ChildItem -LiteralPath $script:checksSourcePath -Filter '*.ps1' -File | ForEach-Object { $_.FullName })
        $sourceFiles.Count | Should -BeGreaterThan 0 -Because 'the scan must actually cover real check source files, not silently scan zero'

        $violations = Get-PulseSettingDefinitionCorpusCrossCheckViolations -CorpusDefinitions $corpusDefinitions -SourceFiles $sourceFiles

        (@($violations) -join "`n") | Should -BeNullOrEmpty
    }
}
