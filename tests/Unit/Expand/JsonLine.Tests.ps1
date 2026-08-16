BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'ConvertTo-PulseCanonicalJsonLine' {
    It 'emits a byte-exact compact line for a simple ordered object, keys sorted ordinally' {
        $line = InModuleScope TenantPulse {
            ConvertTo-PulseCanonicalJsonLine -InputObject ([pscustomobject]@{ zeta = 1; alpha = 'a'; Mid = $true })
        }

        $line | Should -Be "{`"Mid`":true,`"alpha`":`"a`",`"zeta`":1}`n"
    }

    It 'emits exactly one trailing LF and no leading/internal whitespace' {
        $line = InModuleScope TenantPulse {
            ConvertTo-PulseCanonicalJsonLine -InputObject ([pscustomobject]@{ a = 1; b = 2 })
        }

        $line | Should -Be "{`"a`":1,`"b`":2}`n"
        $line.EndsWith("`n") | Should -BeTrue
        ($line.Substring(0, $line.Length - 1)).Contains("`n") | Should -BeFalse
        $line.Contains(' ') | Should -BeFalse
    }

    It 'escapes an embedded newline in a string value to the two-character sequence \n, never a real line break' {
        $line = InModuleScope TenantPulse {
            ConvertTo-PulseCanonicalJsonLine -InputObject ([pscustomobject]@{ text = "line1`nline2" })
        }

        $line | Should -Be "{`"text`":`"line1\nline2`"}`n"
        # exactly one real newline - the trailing terminator - even though the value logically had one
        (@($line.ToCharArray() | Where-Object { $_ -eq "`n" })).Count | Should -Be 1
    }

    It 'serializes null, array, and nested object values compactly' {
        $line = InModuleScope TenantPulse {
            ConvertTo-PulseCanonicalJsonLine -InputObject ([pscustomobject]@{
                    n = $null
                    arr = @(1, 2, 3)
                    nested = [pscustomobject]@{ b = 2; a = 1 }
                })
        }

        $line | Should -Be "{`"arr`":[1,2,3],`"n`":null,`"nested`":{`"a`":1,`"b`":2}}`n"
    }

    It 'produces the same key order and escaping as the pretty serializer, minus whitespace' {
        $value = [pscustomobject]@{ zeta = 'has "quotes" and \backslash'; alpha = 5 }
        $pretty = InModuleScope TenantPulse -ArgumentList $value {
            param($value)
            ConvertTo-PulseCanonicalJson -InputObject $value
        }
        $line = InModuleScope TenantPulse -ArgumentList $value {
            param($value)
            ConvertTo-PulseCanonicalJsonLine -InputObject $value
        }

        $compactedPretty = (($pretty -replace '\r?\n\s*', '') -replace ': ', ':')
        ($line.Substring(0, $line.Length - 1)) | Should -Be $compactedPretty
    }

    It 'throws for input exceeding the depth budget, naming the budget' {
        $deep = $null
        for ($i = 0; $i -lt 70; $i++) {
            $deep = [pscustomobject]@{ child = $deep }
        }

        { InModuleScope TenantPulse -ArgumentList $deep {
                param($deep)
                ConvertTo-PulseCanonicalJsonLine -InputObject $deep -Depth 64
            } } | Should -Throw '*maximum depth*'
    }

    It 'reorder-input determinism: two objects built with properties added in different orders produce identical lines' {
        $a = [pscustomobject]@{}
        Add-Member -InputObject $a -NotePropertyName 'zeta' -NotePropertyValue 1
        Add-Member -InputObject $a -NotePropertyName 'alpha' -NotePropertyValue 2

        $b = [pscustomobject]@{}
        Add-Member -InputObject $b -NotePropertyName 'alpha' -NotePropertyValue 2
        Add-Member -InputObject $b -NotePropertyName 'zeta' -NotePropertyValue 1

        $lineA = InModuleScope TenantPulse -ArgumentList $a { param($a) ConvertTo-PulseCanonicalJsonLine -InputObject $a }
        $lineB = InModuleScope TenantPulse -ArgumentList $b { param($b) ConvertTo-PulseCanonicalJsonLine -InputObject $b }

        $lineA | Should -Be $lineB
    }
}
