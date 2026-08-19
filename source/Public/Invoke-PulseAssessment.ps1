<#
    .SYNOPSIS
        Runs (or re-runs) a full TenantPulse assessment: collect, evaluate, score, render.

    .DESCRIPTION
        Invoke-PulseAssessment is TenantPulse's main pipeline command - the one that wires
        collection (Get-PulseTenantSnapshot), evaluation (Invoke-PulseEvaluation), scoring
        (Add-PulseScores) and rendering (the private JSON renderer) into a single call.
        -ProfileId is ALWAYS the GraphKit tenant profile passed to Get-GraphContext during
        collection; -AssessmentProfile is ALWAYS the path to a TenantPulse selection-profile
        psd1 file - the two names never blur, even though both commonly get shortened to
        "profile" in conversation.

        TWO PARAMETER SETS, mutually exclusive (post-review fix): 'Collect' requires
        -ProfileId and forbids -FromSnapshot; 'FromSnapshot' requires -FromSnapshot and
        forbids -ProfileId. Earlier, -ProfileId was unconditionally mandatory even on the
        -FromSnapshot path, where it is never actually used for anything (redaction
        determinism depends only on the local operator key, not on -ProfileId) - that
        forced a caller to supply a meaningless dummy value, and a -FromSnapshot bound to
        an empty/whitespace string silently fell through to a full live Graph collection
        instead of failing loudly. PowerShell's own parameter-set binding now rejects both
        mistakes before this function's body ever runs.

        SELECTION IS RESOLVED EXACTLY ONCE. The full check catalog is loaded and narrowed
        through Select-PulseCheck (folding in -AssessmentProfile's Include/Exclude arrays
        for any axis not explicitly bound on the command line - see the shared
        Resolve-PulseSelectionParams helper, also used by Get-PulseTenantSnapshot) before
        collection ever starts. The resulting check Id list is what actually drives
        collection scope (passed to Get-PulseTenantSnapshot as -IncludeCheck, so only the
        datasets those exact checks need are ever fetched) AND is the same check set
        handed to Invoke-PulseEvaluation - there is exactly one place selection can
        happen, so collection and evaluation can never see two different check sets from
        the same run.

        OUTPUT LAYOUT: when collecting fresh (Collect parameter set), the snapshot store
        is written to <OutputPath>/snapshot/ and the scored findings JSON report to
        <OutputPath>/tenantpulse-findings.json - kept in separate locations so the report
        file and the snapshot's own manifest.json/datasets never collide in the same
        directory listing.

        -FromSnapshot <dir> skips collection entirely: the directory is opened as an
        existing store via the private Get-PulseSnapshotStore helper (which validates it
        really is a snapshot root, including its schemaVersion, before anything else
        happens) and re-evaluated from there - this path makes NO Graph call and touches
        no GraphKit descriptor at all, because nothing in it ever calls
        Get-PulseTenantSnapshot.

        -Redact applies the evaluation's in-memory redaction map (built fresh by THIS
        call's own Invoke-PulseEvaluation - see that function and Export-PulseJsonReport's
        docstrings for why the map is never persisted or passed as anything but a same-call
        in-memory value) to every evidence identity (and, where it defaults to a raw
        identity, evidence sortKey - see Export-PulseJsonReport) in the rendered JSON,
        substituting each with its 'tp-...' pseudonym. Re-evaluating the same snapshot with
        -Redact is still byte-identical across runs, because the pseudonym HMAC is keyed
        and stable (Get-PulsePseudonym, Task 1.3) - "fresh redaction map" does not mean
        "different output" for the same input snapshot and operator key.

        DETAIL-KEY MECHANISM (Phase 3 closing fix series, item 4 - supersedes the earlier
        "identity fields only" framing below, closing a live proof: a real Apple ID UPN
        surfaced raw in rendered findings evidence Detail under -Redact, 2026-08-17,
        TP.INT.0020/0021's appleIdentifier/organizationName detail keys): evidence Detail is
        NOT blanket-redacted, and never will be - a rule author is free to put whatever
        fields it judges useful into Detail, and most of that is deliberately NOT
        identity-shaped (tenant-resource GUIDs and policy display names stay unredacted by
        design). Person-identifying Detail keys are the opposite: TP.INT.0005's
        deviceName/displayName are marked device-name-class keys, the same class as
        appleIdentifier. A rule MAY mark specific Detail keys as identity-bearing on a
        per-evidence-entry basis via -RedactDetailKeys (a string array naming the keys,
        e.g. `@('appleIdentifier')` - see New-PulseFinding's own docstring for the full
        mechanism). Invoke-PulseEvaluation's redaction-map-building
        step adds each marked-and-present raw Detail value to the SAME HMAC map an
        evidence Identity is pseudonymized through, and Export-PulseJsonReport substitutes
        it under -Redact using the identical lookup-and-substitute logic already applied to
        identity/sortKey. A Detail value never marked this way is never added to the map
        and is therefore never touched, regardless of what it looks like - this is an
        explicit, per-check, per-key opt-in, not a scanner or heuristic. HONEST RESIDUAL,
        narrowed but not eliminated by this fix: a rule-authored Reason or an engine Error
        reason is still only capped (Protect-PulseReason), never identity-substituted, so a
        raw identifier embedded in free-text exception or reason text can still survive a
        redacted report; and a Detail key that carries a person-identifying value but has
        not (yet) been marked by its rule's author is likewise still unredacted -
        -RedactDetailKeys closes the specific gap this fix round audited and marked, not
        every possible one. -Redact should be read as "identity fields, plus every Detail
        key its own rule author has explicitly marked, are pseudonymized" - not "this
        report is fully de-identified".

        Returns a summary object: { SnapshotPath; FindingsPath; ReportPaths; Scores;
        Coverage }. SnapshotPath is the store's root directory. FindingsPath is the
        canonical-JSON scored findings file this call wrote - the same file ReportPaths.Json
        points at (ReportPaths exists as a format-keyed lookup for future renderers; Phase 1
        ships only Json). Scores/Coverage are the scored document's own .scores/.coverage
        properties, handed back directly so a caller does not have to re-open the report
        file just to read them.

    .EXAMPLE
        Invoke-PulseAssessment -ProfileId 'contoso' -OutputPath './out'

        Collects a fresh snapshot for the GraphKit 'contoso' profile, evaluates every check
        in the catalog against it, scores the result, and writes an unredacted
        tenantpulse-findings.json to ./out.

    .EXAMPLE
        Invoke-PulseAssessment -OutputPath './out' -FromSnapshot './out/snapshot' -Redact

        Re-evaluates an already-collected snapshot (no Graph call at all, no -ProfileId
        needed) and writes a redacted report, with every evidence identity replaced by its
        pseudonym.

    .PARAMETER ProfileId
        The GraphKit tenant profile identifier used to collect a fresh snapshot. Always the
        GraphKit tenant profile, never the TenantPulse selection profile - see
        -AssessmentProfile. Mandatory on the 'Collect' parameter set; not accepted at all
        on the 'FromSnapshot' set (see -FromSnapshot), since re-evaluating an existing
        snapshot never talks to GraphKit or needs a tenant profile.

    .PARAMETER OutputPath
        Directory this run writes into: a fresh snapshot subdirectory (Collect set only)
        plus the rendered findings report. Created if it does not already exist.

    .PARAMETER FromSnapshot
        Path to an already-collected snapshot directory to re-evaluate instead of
        collecting fresh. Skips Get-PulseTenantSnapshot entirely - no GraphKit call is
        made. Mandatory on the 'FromSnapshot' parameter set; not accepted at all on the
        'Collect' set (see -ProfileId).

    .PARAMETER AssessmentProfile
        Path to a TenantPulse selection-profile .psd1 file supplying default Include/
        Exclude/BreakGlassAccounts/ServiceAccounts values. Never the GraphKit tenant
        profile - see -ProfileId. Explicit CLI selection parameters always win.

    .PARAMETER IncludeCategory
        Only select checks whose Category dotted-path prefix-matches one of these values.
        Combines with every other selection parameter; every supplied filter narrows further.

    .PARAMETER ExcludeCategory
        Drop checks whose Category dotted-path prefix-matches one of these values. Always
        wins over an Include match for the same check, on any axis.

    .PARAMETER IncludeCheck
        Only select checks whose Id exactly equals one of these values (ordinal match).

    .PARAMETER ExcludeCheck
        Drop checks whose Id exactly equals one of these values. Always wins over an
        Include match for the same check, on any axis.

    .PARAMETER Format
        Output report format. Phase 1 supports only 'Json', the default and only accepted
        value today - kept as an explicit parameter so a future renderer is additive.

    .PARAMETER Redact
        Replace every evidence identity in the rendered report with its pseudonym, built
        from this call's own fresh evaluation. Not available on Export-PulseReport, whose
        render-only path never has an evaluation-time redaction map to draw from.

    .PARAMETER ExpandSettings
        Phase 2 (T2.2): pass-through to Get-PulseTenantSnapshot's own -ExpandSettings.
        Default OFF this task - runs the Settings Catalog per-policy fan-out/walk after
        collection when set. Only accepted on the 'Collect' parameter set.
#>
function Invoke-PulseAssessment {
    [CmdletBinding(DefaultParameterSetName = 'Collect')]
    [OutputType([pscustomobject])]
    param(
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
        [string[]] $IncludeCategory,

        [Parameter()]
        [string[]] $ExcludeCategory,

        [Parameter()]
        [string[]] $IncludeCheck,

        [Parameter()]
        [string[]] $ExcludeCheck,

        [Parameter()]
        [ValidateSet('Json')]
        [string] $Format = 'Json',

        [Parameter()]
        [switch] $Redact,

        # Phase 2 (T2.2): pass-through to Get-PulseTenantSnapshot's own -ExpandSettings -
        # default OFF this task (see that parameter's own docstring - T2.7 evaluated and
        # deliberately DEFERRED flipping this default; see its own docstring's Findings
        # note). Not accepted on the 'FromSnapshot' parameter set: re-evaluating an
        # existing snapshot never collects anything, so there is nothing here to expand
        # fresh.
        [Parameter(ParameterSetName = 'Collect')]
        [switch] $ExpandSettings
    )

    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    $resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath

    # Selection is resolved exactly once, against the FULL catalog, before collection ever
    # starts - see the docstring's SELECTION IS RESOLVED EXACTLY ONCE section.
    $fullCatalog = @(Import-PulseCheckCatalog)

    $resolvedSelection = Resolve-PulseSelectionParams -BoundParameters $PSBoundParameters `
        -IncludeCategory $IncludeCategory -ExcludeCategory $ExcludeCategory `
        -IncludeCheck $IncludeCheck -ExcludeCheck $ExcludeCheck -AssessmentProfile $AssessmentProfile
    $selectParams = $resolvedSelection.SelectParams
    $selectParams.Checks = $fullCatalog
    $evaluationContext = $resolvedSelection.Context

    $selectedChecks = @(Select-PulseCheck @selectParams)
    $selectedIds = [string[]] @($selectedChecks | ForEach-Object { [string] $_.Id })

    if ($PSCmdlet.ParameterSetName -eq 'FromSnapshot') {
        $store = Get-PulseSnapshotStore -Path $FromSnapshot
        # P1-11 review fix: if this snapshot was collected with -ExpandSettings, verify its
        # settingsCatalog expansion is still hash-valid, or re-derive it from the captured
        # payloads already on disk - never Graph. See that function's own docstring; a
        # snapshot that never used -ExpandSettings is a fast, immediate no-op here.
        Resolve-PulseSettingsCatalogSnapshotExpansion -Store $store
        # Task 2.3 sibling: the same verify-or-rederive-from-captured-payloads decision,
        # for the compliance/deviceConfiguration typed-policy expansions - see that
        # function's own docstring.
        Resolve-PulseTypedPolicySnapshotExpansion -Store $store
        # Task 2.6 sibling: verify-or-rederive the conflicts artifact - from the family
        # jsonl artifacts already on disk, never Graph. See that function's own docstring.
        Resolve-PulseConflictSnapshotExpansion -Store $store
        # Part A, T3.4 sibling: verify-or-rederive the setting-presence index - same
        # verify-or-rederive-from-already-on-disk-family-artifacts decision. See that
        # function's own docstring.
        Resolve-PulseSettingPresenceIndexSnapshotExpansion -Store $store
    } else {
        $snapshotPath = Join-Path $resolvedOutputPath 'snapshot'
        $collectParams = @{
            ProfileId  = $ProfileId
            OutputPath = $snapshotPath
        }

        if ($selectedIds.Count -gt 0) {
            # An -IncludeCheck array narrows collection to exactly the selected checks'
            # datasets - the same "one place selection happens" guarantee the docstring
            # promises.
            $collectParams.IncludeCheck = $selectedIds
        } elseif ($fullCatalog.Count -gt 0) {
            # A genuinely empty selection ("nothing matched the given filters") is a real,
            # legitimate outcome - but an EMPTY -IncludeCheck array means "do not filter on
            # this axis" (matches everything) everywhere else in this module, not "match
            # nothing" (see Select-PulseCheck's own docstring). Force the true
            # empty-selection outcome onto collection by excluding every known Id instead
            # of including none, so an empty selection never silently collects the whole
            # catalog's datasets.
            $collectParams.ExcludeCheck = [string[]] @($fullCatalog | ForEach-Object { [string] $_.Id })
        }

        # T2.7 fix: EXPLICITLY forward the boolean either way, not only when true.
        # -ExpandSettings still defaults to $false on both this function and
        # Get-PulseTenantSnapshot - the on-by-default flip was evaluated and deliberately
        # DEFERRED this task (see -ExpandSettings's own docstring on both functions for
        # why). Forwarding unconditionally is the correct fix regardless of either
        # default: the OLD code only ever SET $collectParams.ExpandSettings when
        # $ExpandSettings was true, never explicitly forwarding $false - harmless while
        # both default false (omitting the key and passing $false reach the same place),
        # but it would have silently defeated an explicit -ExpandSettings:$false opt-out
        # the moment either function's own default ever changes independently of the
        # other. Forwarding .IsPresent unconditionally keeps that latent trap closed no
        # matter what either default is.
        $collectParams.ExpandSettings = $ExpandSettings.IsPresent

        $store = Get-PulseTenantSnapshot @collectParams
    }

    $evaluationParams = @{
        Store  = $store
        Checks = $selectedChecks
    }
    if ($null -ne $evaluationContext) {
        $evaluationParams.Context = $evaluationContext
    }

    $evaluation = Invoke-PulseEvaluation @evaluationParams
    $scoredDocument = Add-PulseScores -Findings $evaluation.Document

    # -Redact only ever draws on THIS call's own fresh evaluation - see the T1.6-deferred
    # contract documented in Export-PulseJsonReport's own docstring for why the wrapper
    # itself must never be serialized and why only .Document/.RedactionMap are ever passed
    # onward separately.
    $redactionMapToApply = if ($Redact) { $evaluation.RedactionMap } else { $null }

    # Dispatches on -Format even though ValidateSet allows only 'Json' today - kept
    # explicit (rather than always calling the Json renderer unconditionally) so a future
    # renderer is additive here, not a rewrite of this dispatch. The 'default' arm is
    # unreachable while ValidateSet allows only 'Json' - documented scaffolding for a
    # future format, kept deliberately rather than removed.
    $reportPath = switch ($Format) {
        'Json' { Export-PulseJsonReport -Document $scoredDocument -OutputPath $resolvedOutputPath -RedactionMap $redactionMapToApply }
        default { throw "Invoke-PulseAssessment: unsupported -Format '$Format'." }
    }

    return [pscustomobject]@{
        SnapshotPath = $store.Root
        FindingsPath = $reportPath
        ReportPaths  = [pscustomobject]@{ Json = $reportPath }
        Scores       = $scoredDocument.scores
        Coverage     = $scoredDocument.coverage
    }
}
