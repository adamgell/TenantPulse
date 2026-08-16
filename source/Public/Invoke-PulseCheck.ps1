<#
    .SYNOPSIS
        Runs a scoped mini-assessment against just the named check(s) or categories.

    .DESCRIPTION
        Invoke-PulseCheck is a thin, scoped wrapper over Invoke-PulseAssessment: it
        translates -Id into -IncludeCheck and -Category into -IncludeCategory, forwards
        -AssessmentProfile untouched, and delegates the entire collect-or-reuse ->
        evaluate -> score -> render pipeline to that function via splatting, so it
        carries IDENTICAL guarantees (same selection semantics, same collection-scoping
        optimization, same -Context/BreakGlassAccounts/ServiceAccounts wiring, same
        redaction/rendering contract) rather than a second, potentially-diverging
        implementation of the same pipeline. -AssessmentProfile forwarding matters here
        specifically: without it, a context-dependent check rule (one that reads
        $Context.BreakGlassAccounts/$Context.ServiceAccounts) would silently see an empty
        $Context through Invoke-PulseCheck even when a caller supplied a profile file with
        real values - the "identical guarantees" claim above would be false for exactly
        that class of check without this forwarding.

        At least one of -Id or -Category is required. An unscoped call collecting and
        evaluating the ENTIRE catalog defeats the point of a "scoped mini-collect" command -
        that is exactly what Invoke-PulseAssessment (with no selection parameters at all)
        is for, so Invoke-PulseCheck refuses to silently become that.

        TWO PARAMETER SETS, mutually exclusive, mirroring Invoke-PulseAssessment: 'Collect'
        requires -ProfileId and forbids -FromSnapshot; 'FromSnapshot' requires
        -FromSnapshot and forbids -ProfileId - see Invoke-PulseAssessment's own docstring
        for why -ProfileId has no meaning at all on a -FromSnapshot re-evaluation.

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
        GraphKit tenant profile, never the TenantPulse selection profile. Mandatory on the
        'Collect' parameter set; not accepted at all on the 'FromSnapshot' set.

    .PARAMETER OutputPath
        Directory this run writes into: a fresh snapshot subdirectory (Collect set only)
        plus the rendered findings report. Created if it does not already exist.

    .PARAMETER FromSnapshot
        Path to an already-collected snapshot directory to re-evaluate instead of
        collecting fresh. Skips Get-PulseTenantSnapshot entirely - no GraphKit call is
        made. Mandatory on the 'FromSnapshot' parameter set; not accepted at all on the
        'Collect' set.

    .PARAMETER AssessmentProfile
        Path to a TenantPulse selection-profile .psd1 file, forwarded untouched to
        Invoke-PulseAssessment - supplies BreakGlassAccounts/ServiceAccounts context to
        rules alongside this call's own -Id/-Category scoping.

    .PARAMETER Format
        Output report format. Phase 1 supports only 'Json', the default and only accepted
        value today - kept as an explicit parameter so a future renderer is additive.

    .PARAMETER Redact
        Replace every evidence identity in the rendered report with its pseudonym, built
        from this call's own fresh evaluation.
#>
function Invoke-PulseCheck {
    [CmdletBinding(DefaultParameterSetName = 'Collect')]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string[]] $Id,

        [Parameter()]
        [string[]] $Category,

        [Parameter(Mandatory, ParameterSetName = 'Collect')]
        [ValidateNotNullOrEmpty()]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath,

        [Parameter(Mandatory, ParameterSetName = 'FromSnapshot')]
        [ValidateNotNullOrEmpty()]
        [string] $FromSnapshot,

        [Parameter()]
        [string] $AssessmentProfile,

        [Parameter()]
        [ValidateSet('Json')]
        [string] $Format = 'Json',

        [Parameter()]
        [switch] $Redact
    )

    # Explicit $null-and-Count checks, never `$Id -and $Id.Count -gt 0` - a single-element
    # array collapses to that element's own truthiness in a PowerShell boolean context, so
    # `-Id @('')` would otherwise evaluate $idBound to $false even though Count is 1 (see
    # Select-PulseCheck's own docstring for the same trap and fix elsewhere in this
    # module). Select-PulseCheck's own blank-element guard is the actual hard rejection of
    # `@('')`; this local check only decides whether -Id/-Category was meaningfully bound.
    $idBound = $PSBoundParameters.ContainsKey('Id') -and $null -ne $Id -and $Id.Count -gt 0
    $categoryBound = $PSBoundParameters.ContainsKey('Category') -and $null -ne $Category -and $Category.Count -gt 0

    if (-not $idBound -and -not $categoryBound) {
        throw 'Invoke-PulseCheck: at least one of -Id or -Category is required - an unscoped call would collect and evaluate the entire catalog, which is what Invoke-PulseAssessment is for.'
    }

    $assessmentParams = @{
        OutputPath = $OutputPath
        Format     = $Format
    }
    if ($PSCmdlet.ParameterSetName -eq 'FromSnapshot') {
        $assessmentParams.FromSnapshot = $FromSnapshot
    } else {
        $assessmentParams.ProfileId = $ProfileId
    }
    if ($idBound) { $assessmentParams.IncludeCheck = $Id }
    if ($categoryBound) { $assessmentParams.IncludeCategory = $Category }
    if ($PSBoundParameters.ContainsKey('AssessmentProfile')) { $assessmentParams.AssessmentProfile = $AssessmentProfile }
    if ($Redact) { $assessmentParams.Redact = $true }

    return Invoke-PulseAssessment @assessmentParams
}
