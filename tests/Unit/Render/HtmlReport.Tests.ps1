BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:New-PulseHtmlFixtureFinding {
        param(
            [Parameter(Mandatory)]
            [string] $Id,
            [string] $Title = 'Fixture finding',
            [string] $Category = 'Entra.ConditionalAccess',
            [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
            [string] $Severity = 'Medium',
            [ValidateSet('Pass', 'Warn', 'Fail', 'NotApplicable', 'Error')]
            [string] $Status = 'Pass',
            [object[]] $Evidence = @(),
            [string] $Reason,
            [string[]] $Remediation = @('Apply the documented control.'),
            [string[]] $PortalLinks = @(),
            [string] $Research = 'docs/research/fixture.md',
            [string[]] $Authorities = @('MS.AAD.1.1v1'),
            [string[]] $Cis = @(),
            [object[]] $Gaps = @(),
            [string] $PrivacyClass
        )

        $finding = [pscustomobject]@{
            id         = $Id
            title      = $Title
            category   = $Category
            severity   = $Severity
            status     = $Status
            evidence   = @($Evidence)
            reason     = $Reason
            effort     = 'Low'
            impact     = 'High'
            consulting = [pscustomobject]@{
                whatItMeans  = 'What this check means.'
                whyItMatters = 'Why this check matters.'
                remediation  = @($Remediation)
                portalLinks  = @($PortalLinks)
            }
            references = [pscustomobject]@{
                research    = $Research
                authorities = @($Authorities)
                cis         = @($Cis)
            }
            origin     = $null
            gaps       = @($Gaps)
        }

        if (-not [string]::IsNullOrEmpty($PrivacyClass)) {
            $finding | Add-Member -NotePropertyName privacyClass -NotePropertyValue $PrivacyClass
        }

        return $finding
    }

    function script:New-PulseHtmlFixtureDocument {
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]] $Findings,
            [object] $Notices,
            [object] $Gaps,
            [object] $Caps
        )

        if ($null -eq $Notices) {
            $Notices = [pscustomobject]@{ cisDisclaimer = $null }
        }

        $document = [pscustomobject]@{
            schemaVersion = '1.0'
            generatedUtc  = '2026-08-15T21:30:41.123Z'
            tenant        = 'tp-fixturetenant'
            producer      = [pscustomobject]@{
                tenantPulse         = '0.3.0'
                graphKit             = '0.3.0'
                scoringModelVersion = '1.0'
            }
            coverage      = [pscustomobject]@{
                overall    = [pscustomobject]@{ assessed = 3; applicable = 5; percent = 60.0 }
                byCategory = [ordered]@{
                    'Intune.Compliance'        = [pscustomobject]@{ assessed = 1; applicable = 3; percent = 33.3 }
                    'Entra.ConditionalAccess'  = [pscustomobject]@{ assessed = 2; applicable = 2; percent = 100.0 }
                }
            }
            scores        = [pscustomobject]@{
                overall    = [pscustomobject]@{ earned = 6.0; possible = 16.0; percent = 37.5 }
                byCategory = [ordered]@{
                    'Intune.Compliance'        = [pscustomobject]@{ earned = 3.0; possible = 3.0; percent = 100.0 }
                    'Entra.ConditionalAccess'  = [pscustomobject]@{ earned = 3.0; possible = 13.0; percent = 23.1 }
                }
            }
            findings      = @($Findings)
            notices       = $Notices
        }

        if ($null -ne $Gaps) {
            $document | Add-Member -NotePropertyName gaps -NotePropertyValue $Gaps
        }
        if ($null -ne $Caps) {
            $document | Add-Member -NotePropertyName caps -NotePropertyValue $Caps
        }

        return $document
    }

    function script:New-PulseHtmlAllOutcomeDocument {
        param(
            [switch] $WithCis,
            [switch] $InjectMarkup,
            [switch] $TotalFailure
        )

        $injectionTitle = if ($InjectMarkup) {
            '<script>alert(1)</script> & more'
        } else {
            'Legacy authentication is blocked'
        }
        $injectionIdentity = if ($InjectMarkup) {
            '" onclick="alert(1)'
        } else {
            'policy-legacy-auth'
        }

        $cisRefs = if ($WithCis) {
            @('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)')
        } else {
            @()
        }
        $cisNotice = if ($WithCis) {
            'CIS Benchmarks are (c) Center for Internet Security, Inc. Recommendation references in this report are provided for cross-reference only. This project is not affiliated with, endorsed by, or certified by CIS, and its results do not constitute a claim of CIS Benchmark compliance.'
        } else {
            $null
        }

        if ($TotalFailure) {
            $findings = @(
                (New-PulseHtmlFixtureFinding -Id 'TP.ENT.0001' -Title 'Collector failed' -Severity 'Critical' -Status 'Error' -Reason 'dataset conditionalAccessPolicies Failed' -Category 'Entra.ConditionalAccess'),
                (New-PulseHtmlFixtureFinding -Id 'TP.INT.0001' -Title 'Snapshot unreadable' -Severity 'High' -Status 'Error' -Reason 'dataset deviceCompliancePolicies Failed' -Category 'Intune.Compliance')
            )
            $document = New-PulseHtmlFixtureDocument -Findings $findings -Notices ([pscustomobject]@{ cisDisclaimer = $null })
            $document.coverage = [pscustomobject]@{
                overall    = [pscustomobject]@{ assessed = 0; applicable = 2; percent = 0.0 }
                byCategory = [ordered]@{
                    'Entra.ConditionalAccess' = [pscustomobject]@{ assessed = 0; applicable = 1; percent = 0.0 }
                    'Intune.Compliance'       = [pscustomobject]@{ assessed = 0; applicable = 1; percent = 0.0 }
                }
            }
            $document.scores = [pscustomobject]@{
                overall    = [pscustomobject]@{ earned = 0.0; possible = 0.0; percent = 0.0 }
                byCategory = [ordered]@{
                    'Entra.ConditionalAccess' = [pscustomobject]@{ earned = 0.0; possible = 0.0; percent = 0.0 }
                    'Intune.Compliance'       = [pscustomobject]@{ earned = 0.0; possible = 0.0; percent = 0.0 }
                }
            }
            return $document
        }

        $failEvidence = @(
            [pscustomobject]@{
                identity     = $injectionIdentity
                detail       = [pscustomobject]@{ state = 'disabled'; note = 'value <b>raw</b>' }
                sortKey      = $injectionIdentity
                privacyClass = 'identity'
                truncated    = $true
            }
        )
        $warnEvidence = @(
            [pscustomobject]@{
                identity     = 'role-global-admin'
                detail       = [pscustomobject]@{ count = 12 }
                sortKey      = 'role-global-admin'
                privacyClass = 'safe-technical-value'
            }
        )

        $findings = @(
            (New-PulseHtmlFixtureFinding -Id 'TP.ENT.0002' -Title 'Privileged role count is high' -Severity 'High' -Status 'Warn' -Evidence $warnEvidence -Reason '12 permanent assignments' -Category 'Entra.Identity' -Authorities @('MS.AAD.7.1v1')),
            (New-PulseHtmlFixtureFinding -Id 'TP.INT.0002' -Title 'Compliance policy coverage could not be assessed' -Severity 'Low' -Status 'NotApplicable' -Reason 'dataset deviceCompliancePolicies Skipped' -Category 'Intune.Compliance' -Gaps @([pscustomobject]@{ scope = 'deviceCompliancePolicies'; failureClass = 'PermissionDenied'; reasonCode = 'permission-denied' })),
            (New-PulseHtmlFixtureFinding -Id 'TP.INT.0001' -Title 'Windows update rings are configured' -Severity 'Medium' -Status 'Pass' -Category 'Intune.Update'),
            (New-PulseHtmlFixtureFinding -Id 'TP.ENT.0001' -Title $injectionTitle -Severity 'Critical' -Status 'Fail' -Evidence $failEvidence -Reason 'Legacy auth is allowed' -Remediation @('Block legacy authentication.') -PortalLinks @('https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess') -Cis $cisRefs -PrivacyClass 'bounded-reviewed-text'),
            (New-PulseHtmlFixtureFinding -Id 'TP.INT.0003' -Title 'Rule threw during evaluation' -Severity 'Info' -Status 'Error' -Reason 'engine: rule returned an unusable shape' -Category 'Intune.Compliance')
        )

        $notices = [pscustomobject]@{
            cisDisclaimer = $cisNotice
            extraNotice   = 'Operator notice with <em>markup</em>.'
        }

        return (New-PulseHtmlFixtureDocument -Findings $findings -Notices $notices -Gaps @(
            [pscustomobject]@{ scope = 'deviceCompliancePolicies'; failureClass = 'PermissionDenied'; reasonCode = 'permission-denied' }
        ) -Caps @(
            [pscustomobject]@{ path = 'findings[TP.ENT.0001].evidence'; limit = 50; omitted = 12 }
        ))
    }

    function script:Invoke-PulseHtmlRender {
        param(
            [Parameter(Mandatory)]
            [pscustomobject] $Document,
            [Parameter(Mandatory)]
            [string] $OutputPath
        )

        InModuleScope TenantPulse -ArgumentList $Document, $OutputPath {
            param($Document, $OutputPath)
            Export-PulseHtmlReport -Document $Document -OutputPath $OutputPath
        }
    }

    function script:Get-PulseHtmlNormalized {
        param([Parameter(Mandatory)][string] $Html)
        return (($Html -replace "`r`n", "`n") -replace "`r", "`n")
    }
}

Describe 'Export-PulseHtmlReport' {
    BeforeEach {
        $script:outputRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $script:outputRoot -ItemType Directory -Force | Out-Null
        Mock Get-GraphContext -ModuleName TenantPulse { throw 'HTML renderer must not call Graph.' }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'HTML renderer must not call Graph.' }
        Mock Get-GraphOperation -ModuleName TenantPulse { throw 'HTML renderer must not call Graph.' }
        Mock Get-PulseTenantSnapshot -ModuleName TenantPulse { throw 'HTML renderer must not read a snapshot store.' }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes a self-contained HTML file with executive summary, score, coverage, findings, unassessed scope, gaps/caps, and notices' {
        $document = New-PulseHtmlAllOutcomeDocument -WithCis
        $reportPath = Invoke-PulseHtmlRender -Document $document -OutputPath $script:outputRoot

        $reportPath | Should -Be (Join-Path ((Resolve-Path -LiteralPath $script:outputRoot).ProviderPath) 'tenantpulse-report.html')
        Test-Path -LiteralPath $reportPath -PathType Leaf | Should -BeTrue

        $html = Get-Content -LiteralPath $reportPath -Raw
        $html | Should -Match '(?s)<!DOCTYPE html>'
        $html | Should -Match 'id="executive-summary"'
        $html | Should -Match 'id="score-coverage"'
        $html | Should -Match 'id="findings"'
        $html | Should -Match 'id="unassessed"'
        $html | Should -Match 'id="gaps-caps"'
        $html | Should -Match 'id="notices"'
        $html | Should -Match ([regex]::Escape('tp-fixturetenant'))
        $html | Should -Match ([regex]::Escape('2026-08-15T21:30:41.123Z'))
        $html | Should -Match '37\.5'
        $html | Should -Match '60\.0'
        $html | Should -Match 'TP\.ENT\.0001'
        $html | Should -Match 'TP\.ENT\.0002'
        $html | Should -Match 'TP\.INT\.0001'
        $html | Should -Match 'Block legacy authentication\.'
        $html | Should -Match ([regex]::Escape('docs/research/fixture.md'))
        $html | Should -Match ([regex]::Escape('MS.AAD.1.1v1'))
        $html | Should -Match ([regex]::Escape('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)'))
        $html | Should -Match 'dataset deviceCompliancePolicies Skipped'
        $html | Should -Match 'PermissionDenied'
        $html | Should -Match 'omitted'
        $html | Should -Match 'identity'
        $html | Should -Match 'bounded-reviewed-text'
    }

    It 'is CSP-safe, uses inline CSS/assets only, and contains no network-loading URLs, scripts, or event handlers' {
        $document = New-PulseHtmlAllOutcomeDocument -WithCis -InjectMarkup
        $reportPath = Invoke-PulseHtmlRender -Document $document -OutputPath $script:outputRoot
        $html = Get-Content -LiteralPath $reportPath -Raw

        $html | Should -Match '(?i)<meta[^>]+http-equiv="Content-Security-Policy"'
        $html | Should -Match "default-src 'none'"
        $html | Should -Match "style-src 'unsafe-inline'"
        $html | Should -Match '(?i)<style[\s>]'
        $html | Should -Not -Match '(?i)<script\b'
        $html | Should -Not -Match '(?i)<link\b'
        $html | Should -Not -Match '(?i)<iframe\b'
        $html | Should -Not -Match '(?i)<img\b'
        $html | Should -Not -Match '(?i)@import'
        $html | Should -Not -Match '(?i)\b(?:src|href)\s*=\s*[''"]\s*https?:'
        $html | Should -Not -Match '(?i)url\s*\(\s*[''"]?\s*https?:'
        $html | Should -Not -Match '(?i)<[^>]+\son\w+\s*='
        $html | Should -Not -Match '(?i)javascript:'
    }

    It 'escapes text and attributes so markup and script payloads cannot inject' {
        $document = New-PulseHtmlAllOutcomeDocument -InjectMarkup
        $reportPath = Invoke-PulseHtmlRender -Document $document -OutputPath $script:outputRoot
        $html = Get-Content -LiteralPath $reportPath -Raw

        $html | Should -Not -Match '<script>alert\(1\)</script>'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should -Not -Match 'onclick="alert\(1\)"'
        $html | Should -Match '&quot; onclick=&quot;alert\(1\)'
        $html | Should -Not -Match '<b>raw</b>'
        $html | Should -Match '&lt;b&gt;raw&lt;/b&gt;'
        $html | Should -Not -Match '<em>markup</em>'
        $html | Should -Match 'Operator notice with &lt;em&gt;markup&lt;/em&gt;\.'
    }

    It 'renders every non-null canonical notice as escaped text-equivalent content and never invents or recomputes notices' {
        $document = New-PulseHtmlAllOutcomeDocument
        $document.notices = [pscustomobject]@{
            cisDisclaimer = $null
            extraNotice   = 'Keep this notice verbatim <br>'
        }
        $document.findings[3].references.cis = @('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)')

        $reportPath = Invoke-PulseHtmlRender -Document $document -OutputPath $script:outputRoot
        $html = Get-Content -LiteralPath $reportPath -Raw

        $html | Should -Match 'Keep this notice verbatim &lt;br&gt;'
        $html | Should -Match ([regex]::Escape('CIS Microsoft 365 Foundations Benchmark v7.0.0, Rec. 5.2.2.1 (E3 Level 1)'))
        $html | Should -Not -Match 'CIS Benchmarks are'
        $html | Should -Not -Match 'not constitute a claim of CIS Benchmark compliance'
    }

    It 'renders the canonical CIS notice only when that notice is present on the findings document' {
        $withCis = New-PulseHtmlAllOutcomeDocument -WithCis
        $pathWithCis = Invoke-PulseHtmlRender -Document $withCis -OutputPath $script:outputRoot
        $htmlWithCis = Get-Content -LiteralPath $pathWithCis -Raw
        $htmlWithCis | Should -Match 'CIS Benchmarks are \(c\) Center for Internet Security, Inc\.'
        $htmlWithCis | Should -Match 'not constitute a claim of CIS Benchmark compliance'

        $withoutCisRoot = Join-Path $script:outputRoot 'no-cis'
        New-Item -Path $withoutCisRoot -ItemType Directory -Force | Out-Null
        $withoutCis = New-PulseHtmlAllOutcomeDocument
        $pathWithoutCis = Invoke-PulseHtmlRender -Document $withoutCis -OutputPath $withoutCisRoot
        $htmlWithoutCis = Get-Content -LiteralPath $pathWithoutCis -Raw
        $htmlWithoutCis | Should -Not -Match 'CIS Benchmarks are'
        $htmlWithoutCis | Should -Match 'Operator notice with'
    }

    It 'includes Pass, Warn, Fail, NotApplicable, and Error in a deterministic severity-then-id order' {
        $document = New-PulseHtmlAllOutcomeDocument
        $reportPath = Invoke-PulseHtmlRender -Document $document -OutputPath $script:outputRoot
        $html = Get-Content -LiteralPath $reportPath -Raw

        $html | Should -Match 'Fail'
        $html | Should -Match 'Warn'
        $html | Should -Match 'Pass'
        $html | Should -Match 'NotApplicable'
        $html | Should -Match 'Error'

        $failIndex = $html.IndexOf('TP.ENT.0001', [System.StringComparison]::Ordinal)
        $warnIndex = $html.IndexOf('TP.ENT.0002', [System.StringComparison]::Ordinal)
        $passIndex = $html.IndexOf('TP.INT.0001', [System.StringComparison]::Ordinal)
        $naIndex = $html.IndexOf('TP.INT.0002', [System.StringComparison]::Ordinal)
        $errorIndex = $html.IndexOf('TP.INT.0003', [System.StringComparison]::Ordinal)

        $failIndex | Should -BeGreaterThan 0
        $warnIndex | Should -BeGreaterThan $failIndex
        $passIndex | Should -BeGreaterThan $warnIndex
        $naIndex | Should -BeGreaterThan 0
        $errorIndex | Should -BeGreaterThan 0
        $unassessedIndex = $html.IndexOf('id="unassessed"', [System.StringComparison]::Ordinal)
        $naIndex | Should -BeGreaterThan $unassessedIndex
        $errorIndex | Should -BeGreaterThan $unassessedIndex
    }

    It 'renders the same normalized HTML twice under shuffled findings and a different culture' {
        $document = New-PulseHtmlAllOutcomeDocument -WithCis
        $firstPath = Invoke-PulseHtmlRender -Document $document -OutputPath $script:outputRoot
        $firstHtml = Get-PulseHtmlNormalized (Get-Content -LiteralPath $firstPath -Raw)

        $shuffled = New-PulseHtmlAllOutcomeDocument -WithCis
        $order = [int[]] (0 .. ($shuffled.findings.Count - 1))
        [System.Array]::Reverse($order)
        $shuffled.findings = [object[]] @(foreach ($i in $order) { $shuffled.findings[$i] })

        $originalCulture = [System.Globalization.CultureInfo]::CurrentCulture
        $originalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture
        $secondRoot = Join-Path $script:outputRoot 'culture'
        New-Item -Path $secondRoot -ItemType Directory -Force | Out-Null
        try {
            $turkish = [System.Globalization.CultureInfo]::GetCultureInfo('tr-TR')
            [System.Globalization.CultureInfo]::CurrentCulture = $turkish
            [System.Globalization.CultureInfo]::CurrentUICulture = $turkish
            $secondPath = Invoke-PulseHtmlRender -Document $shuffled -OutputPath $secondRoot
            $secondHtml = Get-PulseHtmlNormalized (Get-Content -LiteralPath $secondPath -Raw)
        } finally {
            [System.Globalization.CultureInfo]::CurrentCulture = $originalCulture
            [System.Globalization.CultureInfo]::CurrentUICulture = $originalUICulture
        }

        $secondHtml | Should -Be $firstHtml
    }

    It 'still produces a useful report when every finding is Error' {
        $document = New-PulseHtmlAllOutcomeDocument -TotalFailure
        $reportPath = Invoke-PulseHtmlRender -Document $document -OutputPath $script:outputRoot
        $html = Get-Content -LiteralPath $reportPath -Raw

        Test-Path -LiteralPath $reportPath -PathType Leaf | Should -BeTrue
        $html | Should -Match 'id="executive-summary"'
        $html | Should -Match 'id="unassessed"'
        $html | Should -Match 'TP\.ENT\.0001'
        $html | Should -Match 'TP\.INT\.0001'
        $html | Should -Match 'dataset conditionalAccessPolicies Failed'
        $html | Should -Match '0\.0'
    }

    It 'throws if -Document is the evaluation wrapper carrying RedactionMap' {
        $wrapper = [pscustomobject]@{
            Document     = New-PulseHtmlAllOutcomeDocument
            RedactionMap = @{ 'admin@contoso.example' = 'tp-deadbeef' }
        }

        {
            Invoke-PulseHtmlRender -Document $wrapper -OutputPath $script:outputRoot
        } | Should -Throw -ExpectedMessage '*RedactionMap*'
    }

    It 'does not mutate the input findings document' {
        $document = New-PulseHtmlAllOutcomeDocument
        $beforeTitle = [string] $document.findings[3].title
        $beforeCount = @($document.findings).Count
        Invoke-PulseHtmlRender -Document $document -OutputPath $script:outputRoot | Out-Null
        [string] $document.findings[3].title | Should -Be $beforeTitle
        @($document.findings).Count | Should -Be $beforeCount
    }
}

Describe 'Export-PulseReport -Format Html' {
    BeforeEach {
        $script:outputRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $script:outputRoot -ItemType Directory -Force | Out-Null
        Mock Get-GraphContext -ModuleName TenantPulse { throw 'Export-PulseReport Html must not call Graph.' }
        Mock Get-GraphObject -ModuleName TenantPulse { throw 'Export-PulseReport Html must not call Graph.' }
        Mock Get-GraphOperation -ModuleName TenantPulse { throw 'Export-PulseReport Html must not call Graph.' }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'renders HTML from canonical findings JSON only and returns ReportPaths.Html' {
        $document = New-PulseHtmlAllOutcomeDocument -WithCis
        $findingsJson = InModuleScope TenantPulse -ArgumentList $document {
            param($document)
            ConvertTo-PulseCanonicalJson -InputObject $document
        }
        $findingsPath = Join-Path $script:outputRoot 'tenantpulse-findings.json'
        Set-Content -LiteralPath $findingsPath -Value $findingsJson -NoNewline -Encoding utf8NoBOM

        $htmlRoot = Join-Path $script:outputRoot 'html'
        $result = Export-PulseReport -FindingsPath $findingsPath -Format Html -OutputPath $htmlRoot

        $result.FindingsPath | Should -Be $findingsPath
        Test-Path -LiteralPath $result.ReportPaths.Html -PathType Leaf | Should -BeTrue
        $result.ReportPaths.Html | Should -Match 'tenantpulse-report\.html$'
        $html = Get-Content -LiteralPath $result.ReportPaths.Html -Raw
        $html | Should -Match 'id="executive-summary"'
        $html | Should -Match 'CIS Benchmarks are'
        $html | Should -Not -Match '(?i)<script\b'
    }
}
