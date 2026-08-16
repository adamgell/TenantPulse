<#
    .SYNOPSIS
        Runs a scoped mini-assessment against just the named check(s) or categories.

    .DESCRIPTION
        Invoke-PulseCheck is a thin, scoped wrapper over Invoke-PulseAssessment: it
        translates -Id into -IncludeCheck and -Category into -IncludeCategory and delegates
        the entire collect-or-reuse -> evaluate -> score -> render pipeline to that
        function via splatting, so it carries IDENTICAL guarantees (same selection
        semantics, same collection-scoping optimization, same redaction/rendering
        contract) rather than a second, potentially-diverging implementation of the same
        pipeline.

        At least one of -Id or -Category is required. An unscoped call collecting and
        evaluating the ENTIRE catalog defeats the point of a "scoped mini-collect" command -
        that is exactly what Invoke-PulseAssessment (with no selection parameters at all)
        is for, so Invoke-PulseCheck refuses to silently become that.

    .EXAMPLE
        Invoke-PulseCheck -Id 'TP.ENT.0001' -ProfileId 'contoso' -OutputPath './out'

        Collects only the datasets 'TP.ENT.0001' needs, evaluates just that one check, and
        writes a scored, unredacted report to ./out.

    .EXAMPLE
        Invoke-PulseCheck -Category 'Entra.ConditionalAccess' -ProfileId 'contoso' -OutputPath './out' -Redact

        Collects and evaluates every check under the Entra.ConditionalAccess category tree
        and writes a redacted report.

    .PARAMETER Id
        One or more check Ids to run (exact ordinal match). Translated to -IncludeCheck.

    .PARAMETER Category
        One or more category dotted-path prefixes to run. Translated to -IncludeCategory.

    .PARAMETER ProfileId
        The GraphKit tenant profile identifier used to collect a fresh snapshot. Always the
        GraphKit tenant profile, never the TenantPulse selection profile.

    .PARAMETER OutputPath
        Directory this run writes into: a fresh snapshot subdirectory (unless -FromSnapshot
        is given) plus the rendered findings report. Created if it does not already exist.

    .PARAMETER FromSnapshot
        Path to an already-collected snapshot directory to re-evaluate instead of
        collecting fresh. Skips Get-PulseTenantSnapshot entirely - no GraphKit call is made.

    .PARAMETER Format
        Output report format. Phase 1 supports only 'Json', the default and only accepted
        value today - kept as an explicit parameter so a future renderer is additive.

    .PARAMETER Redact
        Replace every evidence identity in the rendered report with its pseudonym, built
        from this call's own fresh evaluation.
#>
function Invoke-PulseCheck {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string[]] $Id,

        [Parameter()]
        [string[]] $Category,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath,

        [Parameter()]
        [string] $FromSnapshot,

        [Parameter()]
        [ValidateSet('Json')]
        [string] $Format = 'Json',

        [Parameter()]
        [switch] $Redact
    )

    $idBound = $PSBoundParameters.ContainsKey('Id') -and $Id -and $Id.Count -gt 0
    $categoryBound = $PSBoundParameters.ContainsKey('Category') -and $Category -and $Category.Count -gt 0

    if (-not $idBound -and -not $categoryBound) {
        throw 'Invoke-PulseCheck: at least one of -Id or -Category is required - an unscoped call would collect and evaluate the entire catalog, which is what Invoke-PulseAssessment is for.'
    }

    $assessmentParams = @{
        ProfileId  = $ProfileId
        OutputPath = $OutputPath
        Format     = $Format
    }
    if ($idBound) { $assessmentParams.IncludeCheck = $Id }
    if ($categoryBound) { $assessmentParams.IncludeCategory = $Category }
    if ($PSBoundParameters.ContainsKey('FromSnapshot') -and -not [string]::IsNullOrWhiteSpace($FromSnapshot)) {
        $assessmentParams.FromSnapshot = $FromSnapshot
    }
    if ($Redact) { $assessmentParams.Redact = $true }

    return Invoke-PulseAssessment @assessmentParams
}
