<#
    QA gate: completeness-producing Graph collectors must retain the GraphKit envelope.

    Rows-only Get-GraphObject discards Outcome, Certainty, Truncated, page caps, and
    child-operation incompleteness. AC-26 / TPP1 require every completeness-producing
    Graph path - ordinary collection, composite children, expansion, app-health, and
    future Graph-backed plans - to request -PassThruResult (or an equivalent envelope
    switch) so authorization success cannot silently become Collected.
#>

BeforeAll {
    $script:projectPath = "$($PSScriptRoot)\..\.." | Convert-Path
    $script:scanRoots = @(
        (Join-Path $script:projectPath 'source/Private/Collect')
        (Join-Path $script:projectPath 'source/Private/Expand')
        (Join-Path $script:projectPath 'source/Public/Get-PulseTenantSnapshot.ps1')
        (Join-Path $script:projectPath 'source/Public/Invoke-PulseAssessment.ps1')
        (Join-Path $script:projectPath 'source/Public/Invoke-PulseCheck.ps1')
    )

    function Get-PulseGraphObjectCallSpans {
        param(
            [Parameter(Mandatory)]
            [string] $Path
        )

        $lines = Get-Content -LiteralPath $Path
        $spans = [System.Collections.Generic.List[object]]::new()
        $inBlockComment = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            $trimmed = $line.Trim()

            if ($inBlockComment) {
                if ($trimmed -match '#>') { $inBlockComment = $false }
                continue
            }
            if ($trimmed.StartsWith('<#')) {
                if ($trimmed -notmatch '#>') { $inBlockComment = $true }
                continue
            }
            if ($trimmed.StartsWith('#')) { continue }
            if ($trimmed -notmatch '(^|[=\s\(\|@])Get-GraphObject\b') { continue }
            if ($trimmed -match 'function\s+Get-GraphObject\b') { continue }

            $start = $i
            if ($trimmed -match 'Get-GraphObject\s+@(\w+)') {
                $splatName = $Matches[1]
                for ($lookback = $i - 1; $lookback -ge 0; $lookback--) {
                    if ($lines[$lookback] -match ('\${0}\s*=' -f [regex]::Escape($splatName))) {
                        $start = $lookback
                        break
                    }
                }
            }

            $end = $i
            $parenDepth = ([regex]::Matches($line, '\(')).Count - ([regex]::Matches($line, '\)')).Count
            while (($parenDepth -gt 0 -or $lines[$end].Trim().EndsWith('`') -or $lines[$end].Trim().EndsWith('|')) -and $end -lt ($lines.Count - 1)) {
                $end++
                $next = $lines[$end]
                $parenDepth += ([regex]::Matches($next, '\(')).Count - ([regex]::Matches($next, '\)')).Count
            }

            $text = ($lines[$start..$end] -join "`n")
            $spans.Add([pscustomobject]@{
                    Path      = $Path
                    StartLine = $start + 1
                    EndLine   = $end + 1
                    Text      = $text
                })
        }

        return @($spans)
    }


    function Get-PulseRowsOnlyGraphObjectViolations {
        param(
            [Parameter(Mandatory)]
            [string[]] $Roots
        )

        $files = foreach ($root in $Roots) {
            if (Test-Path -LiteralPath $root -PathType Leaf) {
                Get-Item -LiteralPath $root
            }
            elseif (Test-Path -LiteralPath $root -PathType Container) {
                Get-ChildItem -LiteralPath $root -Recurse -Filter *.ps1
            }
        }

        $violations = [System.Collections.Generic.List[string]]::new()
        foreach ($file in $files) {
            foreach ($span in @(Get-PulseGraphObjectCallSpans -Path $file.FullName)) {
                if ($span.Text -notmatch '(?i)PassThruResult') {
                    $relative = $file.FullName.Substring($script:projectPath.Length).TrimStart('\', '/')
                    $violations.Add("${relative}:$($span.StartLine) rows-only Get-GraphObject (missing -PassThruResult)")
                }
            }
        }

        return @($violations)
    }
}

Describe 'Graph envelope usage' -Tag 'QA', 'GraphEnvelope' {
    It 'rejects rows-only Get-GraphObject in completeness-producing Graph collectors, composite children, expansion, app-health, and future Graph-backed plans' {
        $violations = @(Get-PulseRowsOnlyGraphObjectViolations -Roots $script:scanRoots)
        $violations | Should -BeNullOrEmpty -Because ("completeness-producing Graph paths must retain the GraphKit envelope:`n" + ($violations -join "`n"))
    }

    It 'discovers at least one Get-GraphObject call so an empty scan cannot pass silently' {
        $spans = foreach ($root in $script:scanRoots) {
            $files = if (Test-Path -LiteralPath $root -PathType Leaf) {
                @(Get-Item -LiteralPath $root)
            }
            elseif (Test-Path -LiteralPath $root -PathType Container) {
                @(Get-ChildItem -LiteralPath $root -Recurse -Filter *.ps1)
            }
            else {
                @()
            }
            foreach ($file in $files) {
                Get-PulseGraphObjectCallSpans -Path $file.FullName
            }
        }
        @($spans).Count | Should -BeGreaterThan 0
    }
}
