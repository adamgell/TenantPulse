<#
    QA gate: scripted license/attribution audit (Task 3.6, item 5). Reconciles the
    check-descriptor `Origin` field (the machine-readable provenance record every
    `.psd1` under source/Data/Checks carries) against THIRD-PARTY-NOTICES.md's prose
    file-listing, in BOTH directions, so the two can never silently drift apart the way
    a purely eyeballed review could miss. Also carries the Maester MIT-notice verbatim
    check, a CIS cite-only prose sweep (References.Cis's own regex gate - see
    Test-PulseCheckDescriptor.ps1 / CheckCatalog.Tests.ps1 - validates the SHAPE of a
    References.Cis value when present; this file extends that with a sweep for actual
    copied CIS Benchmark prose anywhere in the repo, cited text excluded), and a
    Learn-quote attribution spot-check. Runs every build via `./build.ps1 -Tasks test`
    - a permanent suite member, not a one-off script.

    Each Context computes its own inputs fresh, inline, inside its own `BeforeAll`
    (deliberately not factored into a shared function or a Describe-level shared
    `BeforeAll`) - both of those shapes were observed, in this environment's Pester 6,
    to throw instead of running the tests (a Describe-level `BeforeAll` threw an
    unrelated internal `CommandNotFoundException: '$-' is not recognized`; a top-level
    function defined in this file was reported as not recognized from inside a
    `BeforeAll` scriptblock). Small per-context duplication in exchange for tests that
    actually run and report their real result.

    The very first `Context` in this Describe block is a deliberate no-op: whichever
    `Context`/`BeforeAll` runs FIRST within this file was observed, reproducibly, to
    throw the same unrelated internal Pester error (see above) regardless of its own
    content - proved by moving different real contexts to the front one at a time and
    watching the failure follow whichever was first. A trivial leading no-op absorbs
    that positional quirk so every real check below it runs and reports its actual
    result. Tracked upstream-adjacent as pester/Pester#2669 in spirit, if not the exact
    match; remove this workaround if a future Pester version fixes it and the real
    first Context runs clean on its own.
#>

Describe 'License/attribution audit' {
    Context 'Pester container warm-up 1 (no-op, see file docstring)' {
        BeforeAll { $script:Warmup1 = $true }
        It 'is a placeholder that does no filesystem/path work, absorbing a positional Pester quirk' {
            $script:Warmup1 | Should -Be $true
        }
    }

    Context 'Pester container warm-up 2 (no-op, see file docstring)' {
        BeforeAll { $script:Warmup2 = $true }
        It 'is a second placeholder - the quirk above was observed to affect more than one leading position' {
            $script:Warmup2 | Should -Be $true
        }
    }

    Context 'Origin field and THIRD-PARTY-NOTICES reconciliation' {
        BeforeAll {
            $repoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $PSCommandPath) '../..')).ProviderPath
            $checksDir = Join-Path $repoRoot 'source/Data/Checks'
            $noticesText = Get-Content -LiteralPath (Join-Path $repoRoot 'THIRD-PARTY-NOTICES.md') -Raw

            $originFileNames = New-Object System.Collections.Generic.List[string]
            $noOriginFileNames = New-Object System.Collections.Generic.List[string]
            $originProjectsRaw = New-Object System.Collections.Generic.List[string]
            foreach ($f in (Get-ChildItem -LiteralPath $checksDir -Filter 'TP.*.psd1' -File)) {
                $data = Import-PowerShellDataFile -Path $f.FullName
                if ($data.Origin) {
                    $originFileNames.Add($f.Name)
                    $originProjectsRaw.Add([string]$data.Origin.Project)
                } else {
                    $noOriginFileNames.Add($f.Name)
                }
            }

            $noticesFileRefsRaw = New-Object System.Collections.Generic.List[string]
            $matches = [regex]::Matches($noticesText, 'source/Data/Checks/(TP\.[A-Z]+\.\d+\.psd1)')
            foreach ($match in $matches) {
                $noticesFileRefsRaw.Add($match.Groups[1].Value)
            }

            $script:OriginFileNames = @($originFileNames | Select-Object -Unique)
            $script:NoOriginFileNames = @($noOriginFileNames | Select-Object -Unique)
            $script:OriginProjects = @($originProjectsRaw | Select-Object -Unique)
            $script:NoticesFileRefs = @($noticesFileRefsRaw | Select-Object -Unique)
            $script:NoticesTextForHeadings = $noticesText
        }

        # NOTE: this is deliberately one It covering four assertions, not four separate
        # Its - multiple Its sharing this Context's BeforeAll-produced arrays were
        # observed, in this environment's Pester 6.1.0, to intermittently throw an
        # unrelated internal error ("A 'break' or 'continue' statement with a label that
        # does not match any enclosing loop escaped from your code" / a `$-` "not
        # recognized" CommandNotFoundException) instead of running - a known upstream
        # Pester issue class (see pester/Pester#2669) rather than a defect in this
        # file's own logic. One It with four checked conditions, each reported by name
        # on failure, does not reproduce it and gives the same regression coverage.
        It 'Origin field and THIRD-PARTY-NOTICES.md file listing reconcile in both directions' {
            $failures = New-Object System.Collections.Generic.List[string]

            $missingFromNotices = @($script:OriginFileNames | Where-Object { $script:NoticesFileRefs -notcontains $_ })
            if ($missingFromNotices.Count -gt 0) {
                $failures.Add("Origin-bearing descriptors with no THIRD-PARTY-NOTICES.md mention: $($missingFromNotices -join ', ')")
            }

            $missingOrigin = @($script:NoticesFileRefs | Where-Object { $script:OriginFileNames -notcontains $_ })
            if ($missingOrigin.Count -gt 0) {
                $failures.Add("THIRD-PARTY-NOTICES.md references files with no matching Origin-bearing descriptor: $($missingOrigin -join ', ')")
            }

            $falselyListed = @($script:NoticesFileRefs | Where-Object { $script:NoOriginFileNames -contains $_ })
            if ($falselyListed.Count -gt 0) {
                $failures.Add("Listed in notices as adapted third-party content but Origin is unset on the descriptor: $($falselyListed -join ', ')")
            }

            $missingHeadings = @($script:OriginProjects | Where-Object { $script:NoticesTextForHeadings -notmatch [regex]::Escape("### $_") })
            if ($missingHeadings.Count -gt 0) {
                $failures.Add("Origin.Project values with no '### <project>' heading in THIRD-PARTY-NOTICES.md: $($missingHeadings -join ', ')")
            }

            $failuresArray = @($failures)
            if ($failuresArray.Count -gt 0) {
                Write-Host ($failuresArray -join "`n")
            }
            $failuresArray.Count | Should -Be 0
        }
    }

    Context 'Maester MIT notice' {
        BeforeAll {
            $repoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $PSCommandPath) '../..')).ProviderPath
            $script:NoticesText = Get-Content -LiteralPath (Join-Path $repoRoot 'THIRD-PARTY-NOTICES.md') -Raw
        }

        It 'the Maester MIT license and copyright notice is present verbatim' {
            $script:NoticesText | Should -Match '(?s)MIT License\s*\r?\n\s*\r?\nCopyright \(c\) 2024 Maester Team\s*\r?\n\s*\r?\nPermission is hereby granted, free of charge, to any person obtaining a copy'
            $script:NoticesText | Should -Match 'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR'
            $script:NoticesText | Should -Match 'IN NO EVENT SHALL THE\s*\r?\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE'
        }
    }

    Context 'CIS benchmark text (cite-only) - prose sweep' {
        BeforeAll {
            # References.Cis's own regex gate (Test-PulseCheckDescriptor.ps1, exercised via
            # tests/Unit/CheckCatalog.Tests.ps1's invalid/*-cis fixtures) validates the SHAPE
            # of a References.Cis value when present (a short control-id/URL citation, never
            # empty/scalar/lowercase/prose). This sweep is the complementary check: nowhere
            # else in the repo's prose (check descriptors, docs/, root .md files) may a CIS
            # mention be sitting inside a long paragraph - the shape actual copied CIS
            # Benchmark rationale/recommendation text would take, versus a short citation
            # OR this project's own methodology/schema prose describing the cite-only rule.
            $repoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $PSCommandPath) '../..')).ProviderPath
            $proseFiles = New-Object System.Collections.Generic.List[object]
            foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $repoRoot 'source') -Recurse -File -Include '*.psd1', '*.ps1' -ErrorAction SilentlyContinue)) { $proseFiles.Add($f) }
            foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs') -Recurse -File -Include '*.md' -ErrorAction SilentlyContinue)) { $proseFiles.Add($f) }
            foreach ($f in (Get-ChildItem -LiteralPath $repoRoot -File -Filter '*.md' -ErrorAction SilentlyContinue)) { $proseFiles.Add($f) }
            $script:RepoRoot = $repoRoot
            $script:CisProseFiles = @($proseFiles | Sort-Object FullName -Unique)
        }

        It 'contains no long CIS-benchmark-prose-shaped paragraph anywhere in the repo' {
            $cisTextPattern = '(?i)Center for Internet Security|CIS Benchmark|CIS Control'
            $selfReferentialPattern = '(?i)cite-only|References\.Cis|citation|cross-reference|regex gate|schema|TenantPulse|does not claim|not affiliated|not certified'
            $offenders = New-Object System.Collections.Generic.List[string]
            foreach ($f in $script:CisProseFiles) {
                $text = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
                if (-not $text) { continue }
                $paragraphs = [regex]::Split($text, '\r?\n\r?\n')
                foreach ($paragraph in $paragraphs) {
                    if ($paragraph -match $cisTextPattern -and $paragraph.Trim().Length -gt 400 -and $paragraph -notmatch $selfReferentialPattern) {
                        $offenders.Add("$($f.FullName.Replace($script:RepoRoot, '.')) ($($paragraph.Trim().Length) chars)")
                    }
                }
            }
            $offendersArray = @($offenders)
            if ($offendersArray.Count -gt 0) {
                Write-Host "CIS mention inside a long (>400 char), non-self-referential paragraph - the shape copied CIS Benchmark prose would take: $($offendersArray -join ' | ')"
            }
            $offendersArray.Count | Should -Be 0
        }
    }

    Context 'Microsoft Learn attribution' {
        BeforeAll {
            $repoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $PSCommandPath) '../..')).ProviderPath
            $checksDir = Join-Path $repoRoot 'source/Data/Checks'
            $script:Descriptors = foreach ($f in (Get-ChildItem -LiteralPath $checksDir -Filter 'TP.*.psd1' -File)) {
                $data = Import-PowerShellDataFile -Path $f.FullName
                [pscustomobject]@{ Id = $data.Id; Raw = $data }
            }
        }

        It 'every check descriptor whose Consulting text contains a quoted passage cites at least one authority for it' {
            # A quoted passage in Consulting text (WhatItMeans/WhyItMatters/etc.) must be
            # traceable to SOME cited source in References.Authorities - not necessarily a
            # learn.microsoft.com URL specifically, since this catalog legitimately quotes
            # ScuBA baseline control text (e.g. MS.AAD.5.1v1) attributed via a maester.dev/
            # EIDSCA authority link instead. The point is "never an unattributed quote",
            # not "every quote must specifically be a Learn quote".
            $offenders = New-Object System.Collections.Generic.List[string]
            foreach ($d in $script:Descriptors) {
                $consultingValues = @()
                if ($d.Raw.Consulting) { $consultingValues = @($d.Raw.Consulting.Values) }
                $consultingText = $consultingValues -join "`n"
                if ($consultingText -match '"[^"]{20,}"') {
                    $authorities = @($d.Raw.References.Authorities)
                    if ($authorities.Count -eq 0) {
                        $offenders.Add($d.Id)
                    }
                }
            }
            $offendersArray = @($offenders)
            if ($offendersArray.Count -gt 0) {
                Write-Host "Checks quoting text (20+ char double-quoted passage) in Consulting fields with zero References.Authorities citations: $($offendersArray -join ', ')"
            }
            $offendersArray.Count | Should -Be 0
        }
    }
}
