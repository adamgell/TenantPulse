<#
    Private: render a scored findings document to a self-contained HTML file
    (TP7 findings-only HTML renderer).

    Always writes <OutputPath>/tenantpulse-report.html through the shared same-directory
    atomic publication primitive. The file is a single UTF-8-without-BOM HTML document:
    inline CSS only, no scripts, no external stylesheets/fonts/images, and a
    Content-Security-Policy that sets default-src 'none', img-src data:, style-src
    'unsafe-inline', base-uri 'none', form-action 'none', and frame-ancestors 'none'.
    Portal links and authority URLs are emitted as escaped text, never as href/src
    attributes, so opening the file cannot initiate a network request.

    HTML CONSUMES CANONICAL FINDINGS ONLY. This function never talks to Graph, never
    opens a snapshot store, and never re-evaluates or re-scores. Callers pass the same
    findings document JSON renderers consume (Export-PulseReport -Format Html reads
    findings JSON; Invoke-PulseAssessment -Format Html renders from the JSON it just
    wrote). Privacy-class members, terminal statuses, gaps, caps, and report-level
    notices are preserved as escaped text-equivalent content. Notices are never
    recomputed, suppressed, or invented: every non-null notices.* value is rendered
    after HTML encoding; a null cisDisclaimer stays absent even if a finding cites CIS.

    CHOKE-POINT GUARD: -Document is rejected if it has a top-level RedactionMap
    property, matching Export-PulseJsonReport. Pass the findings document, never the
    Invoke-PulseEvaluation wrapper.

    DETERMINISM: findings in the severity section are ordered by a fixed severity rank
    (Critical, High, Medium, Low, Info) then ordinal id. Unassessed (NotApplicable,
    Error) findings are ordered by ordinal id. Category tables and notice names use
    [string]::CompareOrdinal. Percents use InvariantCulture. No wall-clock values are
    added. The input document is never mutated.

    Returns the full path to the file written.
#>

function ConvertTo-PulseHtmlEncoded {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string] $Value)
}

function ConvertTo-PulseHtmlInvariantNumber {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Value,

        [Parameter()]
        [string] $Format = '0.0'
    )

    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [string] -and [string]::IsNullOrEmpty([string] $Value)) {
        return ''
    }

    $number = [double] $Value
    return $number.ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-PulseHtmlMemberNames {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Node
    )

    if ($null -eq $Node) {
        return [string[]] @()
    }

    if ($Node -is [System.Collections.IDictionary]) {
        return [string[]] @($Node.Keys)
    }

    return [string[]] @($Node.PSObject.Properties.Name)
}

function Get-PulseHtmlMemberValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Node,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($null -eq $Node) {
        return $null
    }

    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains($Name)) {
            return $Node[$Name]
        }
        return $null
    }

    $property = $Node.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-PulseHtmlOrdinalNames {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [string[]] $Names
    )

    $items = [string[]] @($Names)
    if ($items.Count -le 1) {
        return $items
    }

    $order = [int[]] (0 .. ($items.Count - 1))
    $comparison = [System.Comparison[int]] {
        param($a, $b)
        [string]::CompareOrdinal($items[$a], $items[$b])
    }
    [System.Array]::Sort($order, $comparison)
    return [string[]] @(foreach ($i in $order) { $items[$i] })
}

function ConvertTo-PulseHtmlNoticeText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [System.ValueType]) {
        return [string] $Value
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $keys = Get-PulseHtmlOrdinalNames (Get-PulseHtmlMemberNames $Value)
        $parts = foreach ($key in $keys) {
            '{0}: {1}' -f $key, (ConvertTo-PulseHtmlNoticeText (Get-PulseHtmlMemberValue -Node $Value -Name $key))
        }
        return [string] ($parts -join '; ')
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $parts = foreach ($item in @($Value)) {
            ConvertTo-PulseHtmlNoticeText $item
        }
        return [string] ($parts -join '; ')
    }

    $names = Get-PulseHtmlOrdinalNames (Get-PulseHtmlMemberNames $Value)
    $parts = foreach ($name in $names) {
        '{0}: {1}' -f $name, (ConvertTo-PulseHtmlNoticeText (Get-PulseHtmlMemberValue -Node $Value -Name $name))
    }
    return [string] ($parts -join '; ')
}

function ConvertTo-PulseHtmlDetailText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Detail
    )

    if ($null -eq $Detail) {
        return ''
    }

    if ($Detail -is [string] -or $Detail -is [System.ValueType]) {
        return [string] $Detail
    }

    $names = @(Get-PulseHtmlMemberNames $Detail | Where-Object { $_ -ne 'PSTypeName' })
    $names = Get-PulseHtmlOrdinalNames $names
    $parts = foreach ($name in $names) {
        $value = Get-PulseHtmlMemberValue -Node $Detail -Name $name
        '{0}={1}' -f $name, (ConvertTo-PulseHtmlNoticeText $value)
    }
    return [string] ($parts -join '; ')
}

function Export-PulseHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Document,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath
    )

    if ($Document.PSObject.Properties.Name -contains 'RedactionMap') {
        throw 'Export-PulseHtmlReport: -Document has a top-level RedactionMap property - this looks like the Invoke-PulseEvaluation wrapper {Document;RedactionMap} was passed directly instead of its .Document member. Pass the findings document only; never serialize the wrapper itself.'
    }

    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $severityRank = @{
        Critical = 0
        High     = 1
        Medium   = 2
        Low      = 3
        Info     = 4
    }

    $findings = @($Document.findings)
    $assessed = New-Object System.Collections.Generic.List[object]
    $unassessed = New-Object System.Collections.Generic.List[object]
    $statusCounts = [ordered]@{
        Pass          = 0
        Warn          = 0
        Fail          = 0
        NotApplicable = 0
        Error         = 0
    }

    foreach ($finding in $findings) {
        $status = [string] (Get-PulseHtmlMemberValue -Node $finding -Name 'status')
        if ($statusCounts.Contains($status)) {
            $statusCounts[$status] = [int] $statusCounts[$status] + 1
        }
        if ($status -eq 'NotApplicable' -or $status -eq 'Error') {
            [void] $unassessed.Add($finding)
        } else {
            [void] $assessed.Add($finding)
        }
    }

    $sortFindings = {
        param([System.Collections.IList] $Items, [bool] $BySeverity)
        $array = @($Items)
        if ($array.Count -le 1) {
            return $array
        }

        $order = [int[]] (0 .. ($array.Count - 1))
        $comparison = [System.Comparison[int]] {
            param($a, $b)
            if ($BySeverity) {
                $rankA = 99
                $rankB = 99
                $sevA = [string] (Get-PulseHtmlMemberValue -Node $array[$a] -Name 'severity')
                $sevB = [string] (Get-PulseHtmlMemberValue -Node $array[$b] -Name 'severity')
                if ($severityRank.ContainsKey($sevA)) { $rankA = [int] $severityRank[$sevA] }
                if ($severityRank.ContainsKey($sevB)) { $rankB = [int] $severityRank[$sevB] }
                if ($rankA -ne $rankB) {
                    return $rankA.CompareTo($rankB)
                }
            }
            $idA = [string] (Get-PulseHtmlMemberValue -Node $array[$a] -Name 'id')
            $idB = [string] (Get-PulseHtmlMemberValue -Node $array[$b] -Name 'id')
            return [string]::CompareOrdinal($idA, $idB)
        }
        [System.Array]::Sort($order, $comparison)
        return @(foreach ($i in $order) { $array[$i] })
    }

    $assessedSorted = & $sortFindings $assessed $true
    $unassessedSorted = & $sortFindings $unassessed $false

    $builder = [System.Text.StringBuilder]::new()
    $append = {
        param([string] $Line)
        [void] $builder.Append($Line)
        [void] $builder.Append("`n")
    }

    $tenant = ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $Document -Name 'tenant')
    $generatedUtc = ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $Document -Name 'generatedUtc')
    $privacy = Get-PulseHtmlMemberValue -Node $Document -Name 'privacy'
    $privacyClassification = Get-PulseHtmlMemberValue -Node $privacy -Name 'classification'
    $privacyBoundary = Get-PulseHtmlMemberValue -Node $privacy -Name 'boundary'
    $privacyComplete = Get-PulseHtmlMemberValue -Node $privacy -Name 'complete'
    $privacyCompatLayer = Get-PulseHtmlMemberValue -Node $privacy -Name 'compatLayer'
    $privacyProtection = Get-PulseHtmlMemberValue -Node $privacy -Name 'protection'
    $isClassifiedForSharing = (
        $privacyClassification -is [string] -and
        [string]::Equals([string] $privacyClassification, '1.0', [System.StringComparison]::Ordinal) -and
        $privacyBoundary -is [string] -and
        [string]::Equals([string] $privacyBoundary, 'classified', [System.StringComparison]::Ordinal) -and
        $privacyComplete -is [bool] -and
        $privacyComplete -and
        $privacyCompatLayer -is [bool] -and
        -not $privacyCompatLayer -and
        $privacyProtection -is [string] -and
        [string]::Equals([string] $privacyProtection, 'safe-share-v1', [System.StringComparison]::Ordinal)
    )
    $producer = Get-PulseHtmlMemberValue -Node $Document -Name 'producer'
    $tenantPulseVersion = ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $producer -Name 'tenantPulse')
    $graphKitVersion = ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $producer -Name 'graphKit')
    $scoringModel = ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $producer -Name 'scoringModelVersion')

    $scores = Get-PulseHtmlMemberValue -Node $Document -Name 'scores'
    $coverage = Get-PulseHtmlMemberValue -Node $Document -Name 'coverage'
    $scoreOverall = Get-PulseHtmlMemberValue -Node $scores -Name 'overall'
    $coverageOverall = Get-PulseHtmlMemberValue -Node $coverage -Name 'overall'
    $scorePercent = ConvertTo-PulseHtmlInvariantNumber (Get-PulseHtmlMemberValue -Node $scoreOverall -Name 'percent')
    $scoreEarned = ConvertTo-PulseHtmlInvariantNumber (Get-PulseHtmlMemberValue -Node $scoreOverall -Name 'earned')
    $scorePossible = ConvertTo-PulseHtmlInvariantNumber (Get-PulseHtmlMemberValue -Node $scoreOverall -Name 'possible')
    $coveragePercent = ConvertTo-PulseHtmlInvariantNumber (Get-PulseHtmlMemberValue -Node $coverageOverall -Name 'percent')
    $coverageAssessed = ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $coverageOverall -Name 'assessed')
    $coverageApplicable = ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $coverageOverall -Name 'applicable')

    & $append '<!DOCTYPE html>'
    & $append '<html lang="en">'
    & $append '<head>'
    & $append '<meta charset="utf-8">'
    & $append '<meta http-equiv="Content-Security-Policy" content="default-src ''none''; img-src data:; style-src ''unsafe-inline''; base-uri ''none''; form-action ''none''; frame-ancestors ''none''">'
    & $append '<title>TenantPulse assessment report</title>'
    & $append '<style>'
    & $append 'body{font-family:ui-sans-serif,system-ui,sans-serif;margin:1.5rem;color:#1a1a1a;background:#fff;line-height:1.45}'
    & $append 'h1,h2,h3,h4{line-height:1.25}'
    & $append 'table{border-collapse:collapse;width:100%;margin:0.75rem 0}'
    & $append 'th,td{border:1px solid #ccc;padding:0.4rem 0.6rem;text-align:left;vertical-align:top}'
    & $append 'th{background:#f3f3f3}'
    & $append 'article{margin:1rem 0;padding:0.75rem 1rem;border:1px solid #ddd;border-left-width:4px}'
    & $append '.sev-critical{border-left-color:#8b0000}'
    & $append '.sev-high{border-left-color:#b45309}'
    & $append '.sev-medium{border-left-color:#a16207}'
    & $append '.sev-low{border-left-color:#1d4ed8}'
    & $append '.sev-info{border-left-color:#4b5563}'
    & $append '.privacy-warning{margin:1rem 0;padding:1rem;border:3px solid #991b1b;background:#fef2f2;color:#7f1d1d}'
    & $append '.privacy-warning strong{display:block;font-size:1.15rem}'
    & $append 'footer{margin-top:2rem;font-size:0.95rem}'
    & $append '</style>'
    & $append '</head>'
    & $append '<body>'
    & $append '<header>'
    & $append '<h1>TenantPulse assessment report</h1>'
    if (-not $isClassifiedForSharing) {
        & $append '<aside id="privacy-warning" class="privacy-warning" role="alert">'
        & $append '<strong>Local-only audit material - not safe to share.</strong>'
        & $append '<span>This report may contain unprotected tenant identifiers or other sensitive values. Create a classified safe-share document before distribution.</span>'
        & $append '</aside>'
    }
    & $append '<section id="executive-summary">'
    & $append '<h2>Executive summary</h2>'
    & $append ("<p>Tenant: {0}</p>" -f $tenant)
    & $append ("<p>Generated UTC: {0}</p>" -f $generatedUtc)
    & $append ("<p>Score: {0} percent (earned {1} of {2})</p>" -f $scorePercent, $scoreEarned, $scorePossible)
    & $append ("<p>Coverage: {0} percent (assessed {1} of {2})</p>" -f $coveragePercent, $coverageAssessed, $coverageApplicable)
    & $append ("<p>Outcomes: Pass {0}; Warn {1}; Fail {2}; NotApplicable {3}; Error {4}</p>" -f @(
            $statusCounts.Pass, $statusCounts.Warn, $statusCounts.Fail, $statusCounts.NotApplicable, $statusCounts.Error
        ))
    if ($tenantPulseVersion) {
        & $append ("<p>Producer: TenantPulse {0}; GraphKit {1}; scoring model {2}</p>" -f $tenantPulseVersion, $graphKitVersion, $scoringModel)
    }
    & $append '</section>'
    & $append '</header>'

    & $append '<section id="score-coverage">'
    & $append '<h2>Score and coverage</h2>'
    & $append '<table>'
    & $append '<thead><tr><th>Category</th><th>Score percent</th><th>Earned</th><th>Possible</th><th>Coverage percent</th><th>Assessed</th><th>Applicable</th></tr></thead>'
    & $append '<tbody>'

    $scoreByCategory = Get-PulseHtmlMemberValue -Node $scores -Name 'byCategory'
    $coverageByCategory = Get-PulseHtmlMemberValue -Node $coverage -Name 'byCategory'
    $categoryNames = Get-PulseHtmlOrdinalNames @(
        @(Get-PulseHtmlMemberNames $scoreByCategory) + @(Get-PulseHtmlMemberNames $coverageByCategory) |
            Where-Object { $_ -and $_ -ne 'PSTypeName' } |
            Select-Object -Unique
    )
    foreach ($category in $categoryNames) {
        $scoreRow = Get-PulseHtmlMemberValue -Node $scoreByCategory -Name $category
        $coverageRow = Get-PulseHtmlMemberValue -Node $coverageByCategory -Name $category
        & $append ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f @(
                (ConvertTo-PulseHtmlEncoded $category),
                (ConvertTo-PulseHtmlInvariantNumber (Get-PulseHtmlMemberValue -Node $scoreRow -Name 'percent')),
                (ConvertTo-PulseHtmlInvariantNumber (Get-PulseHtmlMemberValue -Node $scoreRow -Name 'earned')),
                (ConvertTo-PulseHtmlInvariantNumber (Get-PulseHtmlMemberValue -Node $scoreRow -Name 'possible')),
                (ConvertTo-PulseHtmlInvariantNumber (Get-PulseHtmlMemberValue -Node $coverageRow -Name 'percent')),
                (ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $coverageRow -Name 'assessed')),
                (ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $coverageRow -Name 'applicable'))
            ))
    }
    & $append '</tbody></table>'
    & $append '</section>'

    $writeFinding = {
        param($Finding)
        $id = [string] (Get-PulseHtmlMemberValue -Node $Finding -Name 'id')
        $title = [string] (Get-PulseHtmlMemberValue -Node $Finding -Name 'title')
        $severity = [string] (Get-PulseHtmlMemberValue -Node $Finding -Name 'severity')
        $status = [string] (Get-PulseHtmlMemberValue -Node $Finding -Name 'status')
        $category = [string] (Get-PulseHtmlMemberValue -Node $Finding -Name 'category')
        $reason = Get-PulseHtmlMemberValue -Node $Finding -Name 'reason'
        $privacyClass = Get-PulseHtmlMemberValue -Node $Finding -Name 'privacyClass'
        $sevClass = 'sev-info'
        switch ($severity) {
            'Critical' { $sevClass = 'sev-critical' }
            'High' { $sevClass = 'sev-high' }
            'Medium' { $sevClass = 'sev-medium' }
            'Low' { $sevClass = 'sev-low' }
        }

        & $append ('<article class="finding {0}" id="finding-{1}">' -f $sevClass, (ConvertTo-PulseHtmlEncoded $id))
        & $append ('<h3>{0}: {1}</h3>' -f (ConvertTo-PulseHtmlEncoded $id), (ConvertTo-PulseHtmlEncoded $title))
        & $append ('<p>Status: {0}; Severity: {1}; Category: {2}</p>' -f @(
                (ConvertTo-PulseHtmlEncoded $status),
                (ConvertTo-PulseHtmlEncoded $severity),
                (ConvertTo-PulseHtmlEncoded $category)
            ))
        if ($null -ne $reason -and [string] $reason -ne '') {
            & $append ('<p>Reason: {0}</p>' -f (ConvertTo-PulseHtmlEncoded $reason))
        }
        if ($null -ne $privacyClass -and [string] $privacyClass -ne '') {
            & $append ('<p>Privacy class: {0}</p>' -f (ConvertTo-PulseHtmlEncoded $privacyClass))
        }

        $evidence = @(Get-PulseHtmlMemberValue -Node $Finding -Name 'evidence')
        & $append '<h4>Evidence</h4>'
        if ($evidence.Count -eq 0) {
            & $append '<p>No evidence rows.</p>'
        } else {
            & $append '<table><thead><tr><th>Identity</th><th>Sort key</th><th>Privacy class</th><th>Detail</th><th>Caps</th></tr></thead><tbody>'
            foreach ($row in $evidence) {
                $truncated = Get-PulseHtmlMemberValue -Node $row -Name 'truncated'
                $capped = Get-PulseHtmlMemberValue -Node $row -Name 'capped'
                $capBits = New-Object System.Collections.Generic.List[string]
                if ($true -eq $truncated) { [void] $capBits.Add('truncated') }
                if ($true -eq $capped) { [void] $capBits.Add('capped') }
                $capText = if ($capBits.Count -gt 0) { $capBits -join ', ' } else { '' }
                & $append ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f @(
                        (ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $row -Name 'identity')),
                        (ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $row -Name 'sortKey')),
                        (ConvertTo-PulseHtmlEncoded (Get-PulseHtmlMemberValue -Node $row -Name 'privacyClass')),
                        (ConvertTo-PulseHtmlEncoded (ConvertTo-PulseHtmlDetailText (Get-PulseHtmlMemberValue -Node $row -Name 'detail'))),
                        (ConvertTo-PulseHtmlEncoded $capText)
                    ))
            }
            & $append '</tbody></table>'
        }

        $consulting = Get-PulseHtmlMemberValue -Node $Finding -Name 'consulting'
        $remediation = @(Get-PulseHtmlMemberValue -Node $consulting -Name 'remediation')
        & $append '<h4>Remediation</h4>'
        if ($remediation.Count -eq 0) {
            & $append '<p>No remediation steps.</p>'
        } else {
            & $append '<ul>'
            foreach ($step in $remediation) {
                & $append ('<li>{0}</li>' -f (ConvertTo-PulseHtmlEncoded $step))
            }
            & $append '</ul>'
        }
        $portalLinks = @(Get-PulseHtmlMemberValue -Node $consulting -Name 'portalLinks')
        foreach ($link in $portalLinks) {
            if ($null -ne $link -and [string] $link -ne '') {
                & $append ('<p>Portal: {0}</p>' -f (ConvertTo-PulseHtmlEncoded $link))
            }
        }

        $references = Get-PulseHtmlMemberValue -Node $Finding -Name 'references'
        & $append '<h4>References</h4>'
        & $append '<ul>'
        $research = Get-PulseHtmlMemberValue -Node $references -Name 'research'
        if ($null -ne $research -and [string] $research -ne '') {
            & $append ('<li>Research: {0}</li>' -f (ConvertTo-PulseHtmlEncoded $research))
        }
        foreach ($authority in @(Get-PulseHtmlMemberValue -Node $references -Name 'authorities')) {
            if ($null -ne $authority -and [string] $authority -ne '') {
                & $append ('<li>Authority: {0}</li>' -f (ConvertTo-PulseHtmlEncoded $authority))
            }
        }
        foreach ($cis in @(Get-PulseHtmlMemberValue -Node $references -Name 'cis')) {
            if ($null -ne $cis -and [string] $cis -ne '') {
                & $append ('<li>CIS: {0}</li>' -f (ConvertTo-PulseHtmlEncoded $cis))
            }
        }
        & $append '</ul>'

        $findingGaps = @(Get-PulseHtmlMemberValue -Node $Finding -Name 'gaps')
        if ($findingGaps.Count -gt 0) {
            & $append '<h4>Gaps</h4><ul>'
            foreach ($gap in $findingGaps) {
                & $append ('<li>{0}</li>' -f (ConvertTo-PulseHtmlEncoded (ConvertTo-PulseHtmlNoticeText $gap)))
            }
            & $append '</ul>'
        }

        & $append '</article>'
    }

    & $append '<section id="findings">'
    & $append '<h2>Findings by severity</h2>'
    if ($assessedSorted.Count -eq 0) {
        & $append '<p>No assessed findings.</p>'
    } else {
        foreach ($finding in $assessedSorted) {
            & $writeFinding $finding
        }
    }
    & $append '</section>'

    & $append '<section id="unassessed">'
    & $append '<h2>What was not assessed</h2>'
    if ($unassessedSorted.Count -eq 0) {
        & $append '<p>Every selected check was assessed.</p>'
    } else {
        foreach ($finding in $unassessedSorted) {
            & $writeFinding $finding
        }
    }
    & $append '</section>'

    & $append '<section id="gaps-caps">'
    & $append '<h2>Gaps and caps</h2>'
    $gapItems = New-Object System.Collections.Generic.List[string]
    $assessedCount = Get-PulseHtmlMemberValue -Node $coverageOverall -Name 'assessed'
    $applicableCount = Get-PulseHtmlMemberValue -Node $coverageOverall -Name 'applicable'
    if ($null -ne $assessedCount -and $null -ne $applicableCount) {
        $notAssessedCount = ([int] $applicableCount) - ([int] $assessedCount)
        if ($notAssessedCount -gt 0) {
            [void] $gapItems.Add(('Coverage shortfall: {0} of {1} selected checks were not assessed.' -f $notAssessedCount, $applicableCount))
        }
    }
    foreach ($gap in @(Get-PulseHtmlMemberValue -Node $Document -Name 'gaps')) {
        [void] $gapItems.Add((ConvertTo-PulseHtmlNoticeText $gap))
    }
    foreach ($cap in @(Get-PulseHtmlMemberValue -Node $Document -Name 'caps')) {
        [void] $gapItems.Add((ConvertTo-PulseHtmlNoticeText $cap))
    }
    $findingsForGaps = & $sortFindings $findings $false
    foreach ($finding in $findingsForGaps) {
        foreach ($gap in @(Get-PulseHtmlMemberValue -Node $finding -Name 'gaps')) {
            $findingId = [string] (Get-PulseHtmlMemberValue -Node $finding -Name 'id')
            [void] $gapItems.Add(('{0}: {1}' -f $findingId, (ConvertTo-PulseHtmlNoticeText $gap)))
        }
        foreach ($row in @(Get-PulseHtmlMemberValue -Node $finding -Name 'evidence')) {
            $truncated = Get-PulseHtmlMemberValue -Node $row -Name 'truncated'
            $capped = Get-PulseHtmlMemberValue -Node $row -Name 'capped'
            if ($true -eq $truncated -or $true -eq $capped) {
                $findingId = [string] (Get-PulseHtmlMemberValue -Node $finding -Name 'id')
                $flag = if ($true -eq $truncated) { 'truncated' } else { 'capped' }
                [void] $gapItems.Add(('{0} evidence {1}' -f $findingId, $flag))
            }
        }
    }
    if ($gapItems.Count -eq 0) {
        & $append '<p>No gaps or caps recorded.</p>'
    } else {
        & $append '<ul>'
        foreach ($item in $gapItems) {
            if ($null -ne $item -and [string] $item -ne '') {
                & $append ('<li>{0}</li>' -f (ConvertTo-PulseHtmlEncoded $item))
            }
        }
        & $append '</ul>'
    }
    & $append '</section>'

    & $append '<footer id="notices">'
    & $append '<h2>Notices</h2>'
    $notices = Get-PulseHtmlMemberValue -Node $Document -Name 'notices'
    $noticeNames = Get-PulseHtmlOrdinalNames @(
        Get-PulseHtmlMemberNames $notices | Where-Object { $_ -and $_ -ne 'PSTypeName' }
    )
    $renderedNotice = $false
    foreach ($name in $noticeNames) {
        $noticeValue = Get-PulseHtmlMemberValue -Node $notices -Name $name
        if ($null -eq $noticeValue) {
            continue
        }
        $noticeText = ConvertTo-PulseHtmlNoticeText $noticeValue
        if ($null -eq $noticeText) {
            continue
        }
        $renderedNotice = $true
        & $append ('<p>{0}: {1}</p>' -f (ConvertTo-PulseHtmlEncoded $name), (ConvertTo-PulseHtmlEncoded $noticeText))
    }
    if (-not $renderedNotice) {
        & $append '<p>No report notices.</p>'
    }
    & $append '</footer>'
    & $append '</body>'
    & $append '</html>'

    $resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
    $reportPath = Join-Path $resolvedOutputPath 'tenantpulse-report.html'
    $html = $builder.ToString().TrimEnd("`n")
    $htmlBytes = [System.Text.Encoding]::UTF8.GetBytes($html)
    $null = Publish-PulseAtomicStreamFile -Path $reportPath -WriteAction {
        param($fileStream)
        $fileStream.Write($htmlBytes, 0, $htmlBytes.Length)
    }
    return $reportPath
}
