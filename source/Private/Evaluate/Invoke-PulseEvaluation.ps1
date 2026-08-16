<#
    Private: run every check descriptor against a snapshot and produce the findings
    document (spec Task 1.6 - the contract every renderer and the scoring layer, T1.7,
    consume).

    Returns a pscustomobject with two top-level properties:
        Document     - the findings document itself (schemaVersion, generatedUtc, tenant,
                        producer, coverage, scores, findings[]). This is what gets handed to
                        ConvertTo-PulseCanonicalJson for serialization.
        RedactionMap - @{ <raw evidence identity> = 'tp-...' }, one entry per DISTINCT
                        evidence identity seen across every finding, built here under the
                        local operator key (spec section 2f: "built at evaluate, applied at
                        render"). Kept in memory only - callers must never serialize this;
                        Document never contains it. Render-only paths (Export-PulseReport)
                        therefore cannot redact - only a full Invoke-PulseAssessment run
                        (T1.8) has both a fresh Document and its matching RedactionMap.

    generatedUtc is the snapshot manifest's own createdUtc, NOT wall clock - re-evaluating
    the same snapshot with the same catalog must be byte-identical through
    ConvertTo-PulseCanonicalJson every time, and reading Get-Date at evaluation time would
    break that on every run.

    coverage/scores are left as explicit $null placeholders: T1.7 (scoring) fills them in.
    They are keyed into the document now so the schema is complete from this task onward -
    no later task needs to decide where those fields belong in the object graph.

    SERIALIZATION CAVEAT (verified empirically, corrected from an earlier draft of this
    note): `[pscustomobject]@{ PSTypeName = 'X'; ... }` (the construction
    Import-PulseCheckCatalog's descriptor objects and New-PulseFinding's RuleResult objects
    both use) does NOT leave PSTypeName as a visible property - PowerShell consumes it
    entirely into the object's .PSObject.TypeNames, so it never appears in
    ConvertTo-PulseCanonicalJson output for an object built that way. The real leak vector
    is different: a plain HASHTABLE literally keyed 'PSTypeName' (not cast to
    [pscustomobject]) serializes that key like any other, and so would a NoteProperty named
    'PSTypeName' added via Add-Member. The findings document (and every nested object
    inside it - each finding, its evidence entries, consulting/references/origin) is still
    built WITHOUT ever using the PSTypeName-key construction as a matter of discipline, and
    ConvertTo-PulseNormalizedEvidence (New-PulseFinding.ps1) defensively rejects any
    evidence Detail whose serialized JSON contains a `"PSTypeName"` key by either route.

    REASON REDACTION (post-review): a rule-authored Reason (Pass/Warn/Fail) or an engine
    Error reason (a caught exception's .Message) can embed identifying text an author never
    intended to leak - a raw tenant GUID or UPN surfacing in an exception message the same
    way Task 1.5's collector reasons could. Every such reason is routed through
    Protect-PulseReason before it lands in a finding - this evaluator does not have a raw
    -ProfileId or tenant id to substitute (the manifest's own `tenant` field is already the
    pseudonym, not the raw id, by the time evaluation runs), so the call passes an empty
    -ProfileId: no substring replacement happens, only Protect-PulseReason's 500-character
    cap is applied. A NotApplicable reason is the one exception - it quotes the snapshot
    manifest's own dataset reason, which Task 1.5's collector already redacted at
    collection time; running it through Protect-PulseReason again here would only
    (harmlessly) re-cap it, but the task brief is explicit that this reason must be quoted
    verbatim, so it is left untouched.

    Per-check resolution order (see Invoke-PulseCheckEvaluation below):
        1. Every gate the check declares (Data.Gates) is resolved via Get-PulseGateStatus,
           which returns {Status; Detail}. Phase 1: that function always answers Status
           'Unknown' (see its own docstring) - both 'Unknown' and 'Available' let the check
           run; 'Unavailable' degrades it to NotApplicable with reason "gate '<name>'
           unavailable: <detail>". This function's stub never returns 'Unavailable' today,
           but the wiring is real and exercised in tests via an overridden
           Get-PulseGateStatus - a later task teaching real gate detection only has to
           change that one function.
        2. Every dataset the check declares (Data.Datasets) must have a manifest entry with
           status 'Collected'. A missing entry, or one recorded Failed/Skipped, degrades the
           check to NotApplicable - the reason is the manifest's own (already-redacted,
           Task 1.5) reason string, quoted verbatim, or a synthesized one for a missing
           entry / a Failed-or-Skipped entry with no reason on file.
        3. Only once every declared dataset is confirmed Collected are the datasets actually
           read (Read-PulseDataset, cached per dataset name across the whole run - the same
           dataset is frequently declared by more than one check), then DEEP-CLONED per
           check via ConvertTo-PulseClonedDatasets (see that function below) before being
           handed to the rule - no rule, Function or Expression, ever receives a live
           reference into the shared cache. This closes an isolation gap proven during
           review: an in-place mutation by one check's rule must never change what a LATER
           check sees, and results must never depend on check evaluation order.
             - Rule.Type 'Function': `& <Rule.Function> -Datasets <cloned hashtable>` (its
               2>&1 stream partitioned so a non-terminating error is captured, never
               silently dropped - see below) must emit EXACTLY ONE output that is a
               TenantPulse.RuleResult-shaped object (Status/Evidence/Reason) -
               New-PulseFinding is how a rule builds one, though nothing requires a rule to
               use it (see H2 fix note on ConvertTo-PulseNormalizedEvidence). Zero outputs,
               more than one output, a non-RuleResult-shaped single output, an invalid
               Status, or an evidence entry that fails normalization are all treated as an
               engine Error, same as an uncaught throw or a captured non-terminating error.
             - Rule.Type 'Expression': the expression text is evaluated by
               Invoke-PulseSandboxedExpression - a FRESH, isolated runspace per rule (see
               that function's own docstring for the C1 security fix and its honestly
               documented residual). Must resolve to exactly one [bool] output: $true ->
               Pass, $false -> Fail, no evidence. Anything else is Error.
             - A rule that throws is caught here and never aborts the run - the exception's
               message becomes the finding's Reason under status Error, and evaluation moves
               on to the next check ("no silent gaps": one bad rule never hides every other
               check's result).

    CONTEXT (Task 1.8): an optional -Context <hashtable> (e.g.
    @{ BreakGlassAccounts = @(...); ServiceAccounts = @(...) }, folded in by
    Invoke-PulseAssessment from an -AssessmentProfile file) is made available to a rule as
    a variable named $Context, alongside $Datasets - for BOTH rule types, but via two
    different mechanisms:
        - Rule.Type 'Expression': always threaded through to
          Invoke-PulseSandboxedExpression's own -Context param, which sets it as a sandbox
          variable exactly like $Datasets. Since that runspace is fresh and isolated per
          call, an always-present (defaulting to empty) $Context is harmless and needs no
          opt-in gating - see that function's own docstring.
        - Rule.Type 'Function': Function rules are plain PowerShell functions, not
          sandboxed, so passing an unconditional -Context to `& $ruleFunction` would break
          every EXISTING rule-function-shaped test double that declares only a -Datasets
          param (PowerShell throws "a parameter cannot be found that matches parameter
          name 'Context'" for a function that never declares it). -Context is therefore
          OPT-IN on this path: it is passed to the rule function only when (a) -Context was
          actually supplied to Invoke-PulseEvaluation itself AND (b) the target function's
          own parameter set actually declares a -Context parameter (checked via
          `(Get-Command $ruleFunction).Parameters.ContainsKey('Context')`). This keeps
          every pre-Task-1.8 rule function working completely unchanged while giving a
          Task 1.9+ check an opt-in $Context the moment it declares the parameter.
    Omitting -Context entirely (the default, an empty hashtable) behaves exactly as before
    this parameter existed - both paths still receive a (now merely empty, rather than
    absent) $Context, which is indistinguishable from "no context" for any rule that reads
    it defensively (e.g. `$Context.BreakGlassAccounts`, which is simply $null on an empty
    hashtable).

    Evidence within a finding is sorted ordinally by SortKey then Identity
    ([System.StringComparer]::Ordinal / [string]::CompareOrdinal - the same ordinal-only
    rule ConvertTo-PulseCanonicalJson documents for its own key sort, since
    Sort-Object -Culture collation is case-insensitive and therefore non-deterministic
    across locales for this "deterministic ordering everywhere" codebase). Before sorting,
    evidence entries are checked for a duplicate (SortKey, Identity) pair within the same
    finding - [Array]::Sort's underlying introsort is not guaranteed stable, so two entries
    that compare exactly equal on both sort keys could otherwise land in either relative
    order across runs and break the "re-evaluating the same snapshot is byte-identical"
    guarantee; a duplicate degrades that check to Error rather than risk it. Findings are
    sorted ordinally by check Id - -Checks is defensively re-sorted here even though
    Import-PulseCheckCatalog already returns Id-sorted output, so a caller that hands in an
    unsorted or hand-built array still gets a correctly ordered document.
#>

function Invoke-PulseEvaluation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Checks,

        [Parameter()]
        [string] $OperatorKeyPath = (Join-Path $HOME '.tenantpulse/operator.key'),

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $manifest = Get-PulseSnapshotManifest -Store $Store
    $operatorKey = Get-PulseOperatorKey -KeyPath $OperatorKeyPath

    # Used only to satisfy Protect-PulseReason's mandatory -Pseudonym parameter (see the
    # REASON REDACTION note above) - -ProfileId is always empty here, so -Pseudonym is
    # never actually substituted into anything; it exists so a future caller that DOES
    # have a raw id to redact can pass -TenantId and have it work.
    $reasonPseudonym = if ($manifest.tenant) { [string] $manifest.tenant } else { '' }

    # Ordinal sort by Id - index-sort rather than [Array]::Sort(keys, items); see
    # Import-PulseCheckCatalog's own docstring for why that two-array overload is avoided
    # throughout this codebase.
    $sortedChecks = @($Checks)
    if ($sortedChecks.Count -gt 0) {
        $ids = [string[]] @($sortedChecks | ForEach-Object { [string] $_.Id })
        $order = [int[]] (0 .. ($sortedChecks.Count - 1))
        $comparison = [System.Comparison[int]] { param($a, $b) [string]::CompareOrdinal($ids[$a], $ids[$b]) }
        [System.Array]::Sort($order, $comparison)
        $sortedChecks = @(foreach ($i in $order) { $sortedChecks[$i] })
    }

    $datasetCache = @{}
    $redactionMap = @{}
    $findings = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($check in $sortedChecks) {
        $result = Invoke-PulseCheckEvaluation -Check $check -Store $Store -Manifest $manifest -DatasetCache $datasetCache -Context $Context

        # H2 fix: by the time control reaches here, $result.Evidence entries are guaranteed
        # (by Invoke-PulseCheckEvaluation's own try/catch around evidence normalization) to
        # each carry a non-null, non-empty [string] Identity - ContainsKey($item.Identity)
        # below can never see $null. A malformed evidence entry degrades ITS check to Error
        # before ever reaching this loop; it can no longer throw here and take down every
        # other check's result with it.
        $evidenceItems = @($result.Evidence)
        foreach ($item in $evidenceItems) {
            if (-not $redactionMap.ContainsKey($item.Identity)) {
                $redactionMap[$item.Identity] = Get-PulsePseudonym -Value $item.Identity -Key $operatorKey
            }
        }

        if ($evidenceItems.Count -gt 1) {
            $sortKeys = [string[]] @($evidenceItems | ForEach-Object { [string] $_.SortKey })
            $identities = [string[]] @($evidenceItems | ForEach-Object { [string] $_.Identity })
            $order = [int[]] (0 .. ($evidenceItems.Count - 1))
            $comparison = [System.Comparison[int]] {
                param($a, $b)
                $bySortKey = [string]::CompareOrdinal($sortKeys[$a], $sortKeys[$b])
                if ($bySortKey -ne 0) { return $bySortKey }
                return [string]::CompareOrdinal($identities[$a], $identities[$b])
            }
            [System.Array]::Sort($order, $comparison)
            $evidenceItems = @(foreach ($i in $order) { $evidenceItems[$i] })
        }

        $evidenceOut = @(foreach ($item in $evidenceItems) {
            [pscustomobject]@{
                identity = $item.Identity
                detail   = $item.Detail
                sortKey  = $item.SortKey
            }
        })

        $reason = $result.Reason
        if ($result.Status -ne 'NotApplicable' -and -not [string]::IsNullOrEmpty($reason)) {
            $reason = Protect-PulseReason -Message $reason -ProfileId '' -Pseudonym $reasonPseudonym
        }

        $consultingSource = $check.Consulting
        $referencesSource = $check.References
        $originSource = $check.Origin

        $finding = [pscustomobject]@{
            id         = $check.Id
            title      = $check.Title
            category   = $check.Category
            severity   = $check.Severity
            status     = $result.Status
            evidence   = $evidenceOut
            reason     = $reason
            effort     = $check.Effort
            impact     = $check.Impact
            consulting = [pscustomobject]@{
                whatItMeans  = $consultingSource.WhatItMeans
                whyItMatters = $consultingSource.WhyItMatters
                remediation  = @($consultingSource.Remediation)
                portalLinks  = @($consultingSource.PortalLinks)
            }
            references = [pscustomobject]@{
                research    = $referencesSource.Research
                authorities = @($referencesSource.Authorities)
            }
            origin     = if ($null -eq $originSource) {
                $null
            } else {
                [pscustomobject]@{
                    project = $originSource.Project
                    id      = $originSource.Id
                    license = $originSource.License
                }
            }
        }

        $findings.Add($finding)
    }

    $moduleVersion = $null
    if ($MyInvocation.MyCommand.Module) {
        $moduleVersion = $MyInvocation.MyCommand.Module.Version.ToString()
    }

    $document = [pscustomobject]@{
        schemaVersion = '1.0'
        generatedUtc  = $manifest.createdUtc
        tenant        = $manifest.tenant
        producer      = [pscustomobject]@{
            tenantPulse         = $moduleVersion
            graphKit             = $manifest.producer.graphKit
            scoringModelVersion = '1.0'
        }
        coverage      = $null
        scores        = $null
        findings      = $findings.ToArray()
    }

    return [pscustomobject]@{
        Document     = $document
        RedactionMap = $redactionMap
    }
}

# Private helper (not exported): resolves one check descriptor against the manifest/store
# to an engine-normalized result hashtable @{ Status; Evidence; Reason }. Evidence is always
# an array of {Identity; Detail; SortKey} pscustomobjects (possibly empty) regardless of
# which path produced it - Invoke-PulseEvaluation never has to special-case NA/Error/
# Pass-Fail-Warn shapes differently.
function Invoke-PulseCheckEvaluation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Check,

        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [hashtable] $Manifest,

        [Parameter(Mandatory)]
        [hashtable] $DatasetCache,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $gateNames = @($Check.Data.Gates)
    foreach ($gate in $gateNames) {
        # Gate wiring (post-review): 'Unavailable' now genuinely degrades the check -
        # Get-PulseGateStatus's Phase 1 stub never returns it, but the branch is real and
        # covered by tests that override the function. 'Unknown'/'Available' fall through
        # and the check runs.
        $gateStatus = Get-PulseGateStatus -Gate $gate -Manifest $Manifest
        if ($gateStatus.Status -eq 'Unavailable') {
            $detail = if ($gateStatus.PSObject.Properties.Name -contains 'Detail' -and $gateStatus.Detail) {
                [string] $gateStatus.Detail
            } else {
                'no detail provided'
            }
            return @{
                Status   = 'NotApplicable'
                Evidence = @()
                Reason   = "gate '$gate' unavailable: $detail"
            }
        }
    }

    $datasetNames = @($Check.Data.Datasets)
    $datasets = @{}

    foreach ($name in $datasetNames) {
        $manifestDatasets = $Manifest.datasets

        if ($null -eq $manifestDatasets -or -not $manifestDatasets.ContainsKey($name)) {
            return @{
                Status   = 'NotApplicable'
                Evidence = @()
                Reason   = "dataset '$name' is missing from the snapshot manifest."
            }
        }

        $entry = $manifestDatasets[$name]

        if ($entry.status -eq 'Failed' -or $entry.status -eq 'Skipped') {
            $reason = $entry.reason
            if ([string]::IsNullOrEmpty($reason)) {
                $reason = "dataset '$name' has status '$($entry.status)' with no reason recorded."
            }
            return @{
                Status   = 'NotApplicable'
                Evidence = @()
                Reason   = $reason
            }
        }

        if (-not $DatasetCache.ContainsKey($name)) {
            $DatasetCache[$name] = Read-PulseDataset -Store $Store -Name $name
        }

        $datasets[$name] = $DatasetCache[$name]
    }

    try {
        # Isolation fix (post-review, IMPORTANT): every rule - Function or Expression -
        # receives a deep clone of $datasets, never a live reference into $DatasetCache.
        # Without this, one check's in-place mutation of its $Datasets could change what a
        # LATER check (sharing the same cached dataset) sees, making results order-
        # dependent - proven empirically: a hashtable handed to a nested runspace via
        # SessionStateProxy.SetVariable is still the SAME object, so an unclonded mutation
        # inside a sandboxed Expression rule was observed to corrupt the shared cache too.
        $clonedDatasets = ConvertTo-PulseClonedDatasets -Datasets $datasets

        if ($Check.Rule.Type -eq 'Function') {
            $ruleFunction = $Check.Rule.Function

            # Non-terminating-error capture (post-review, do-now minor): 2>&1 merges the
            # error stream into pipeline output so it can be partitioned out explicitly,
            # rather than a rule's Write-Error silently vanishing (the default behavior
            # when a caller neither redirects nor observes the error stream).
            #
            # -Context opt-in (Task 1.8, see this file's own docstring CONTEXT section):
            # only passed to the rule function when the caller actually supplied -Context
            # AND the target function itself declares a -Context parameter - this is what
            # keeps every pre-Task-1.8 rule-function-shaped test double (declaring only
            # -Datasets) working completely unchanged.
            $ruleCommand = Get-Command -Name $ruleFunction -ErrorAction SilentlyContinue
            $ruleAcceptsContext = ($null -ne $ruleCommand) -and $ruleCommand.Parameters.ContainsKey('Context')

            $rawOutputs = if ($PSBoundParameters.ContainsKey('Context') -and $ruleAcceptsContext) {
                @(& $ruleFunction -Datasets $clonedDatasets -Context $Context 2>&1)
            } else {
                @(& $ruleFunction -Datasets $clonedDatasets 2>&1)
            }
            $errorRecords = @($rawOutputs | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
            $outputs = @($rawOutputs | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })

            if ($errorRecords.Count -gt 0) {
                return @{
                    Status   = 'Error'
                    Evidence = @()
                    Reason   = "rule function '$ruleFunction' raised a non-terminating error: $($errorRecords[0].Exception.Message)"
                }
            }

            # Multi-output fix (post-review, do-now minor): the previous
            # `@($ruleOutput) | Select-Object -Last 1` silently accepted any number of
            # pipeline outputs and truncated to the last one, masking an authoring bug
            # (e.g. a stray Write-Output before the real New-PulseFinding call) as a
            # normal single result. Anything other than exactly one output is now Error.
            if ($outputs.Count -ne 1) {
                return @{
                    Status   = 'Error'
                    Evidence = @()
                    Reason   = "rule function '$ruleFunction' emitted $($outputs.Count) output(s), expected exactly 1."
                }
            }

            $ruleOutput = $outputs[0]

            if ($null -eq $ruleOutput -or $ruleOutput.PSObject.Properties.Name -notcontains 'Status') {
                return @{
                    Status   = 'Error'
                    Evidence = @()
                    Reason   = "rule function '$ruleFunction' did not return a TenantPulse.RuleResult object."
                }
            }

            $status = [string] $ruleOutput.Status
            if ($status -notin @('Pass', 'Warn', 'Fail')) {
                return @{
                    Status   = 'Error'
                    Evidence = @()
                    Reason   = "rule function '$ruleFunction' returned an invalid Status '$status'."
                }
            }

            # H2 fix: re-normalize (and validate) whatever the rule returned as Evidence,
            # INSIDE this try/catch, regardless of whether the rule built it through
            # New-PulseFinding. A duck-typed RuleResult with e.g. an evidence entry
            # missing Identity now throws HERE, is caught below, and degrades only this
            # check to Error - it can no longer escape to Invoke-PulseEvaluation's
            # redaction-map loop and crash the whole run on ContainsKey($null).
            $evidence = @()
            if ($ruleOutput.PSObject.Properties.Name -contains 'Evidence' -and $null -ne $ruleOutput.Evidence) {
                $evidence = ConvertTo-PulseNormalizedEvidence -Evidence @($ruleOutput.Evidence)
            }
            Assert-PulseEvidenceNoDuplicates -Evidence $evidence

            $reason = $null
            if ($ruleOutput.PSObject.Properties.Name -contains 'Reason') {
                $reason = $ruleOutput.Reason
            }

            return @{ Status = $status; Evidence = $evidence; Reason = $reason }
        }

        if ($Check.Rule.Type -eq 'Expression') {
            # C1 fix: evaluated in a fresh, isolated runspace - see
            # Invoke-PulseSandboxedExpression's own docstring for the full security
            # rationale and its honestly documented residual. -Context is always threaded
            # through (see this file's own CONTEXT docstring section) - no opt-in gating
            # needed here, unlike the Function-rule path above.
            $sandboxResult = Invoke-PulseSandboxedExpression -Expression $Check.Rule.Expression -Datasets $clonedDatasets -Context $Context
            return @{ Status = $sandboxResult.Status; Evidence = @(); Reason = $sandboxResult.Reason }
        }

        return @{
            Status   = 'Error'
            Evidence = @()
            Reason   = "unrecognized Rule.Type '$($Check.Rule.Type)'."
        }
    } catch {
        return @{
            Status   = 'Error'
            Evidence = @()
            Reason   = $_.Exception.Message
        }
    }
}

# Private helper (not exported): deep-clones a dataset-name -> object[] hashtable via the
# existing ConvertTo-PulseCanonicalJson -> ConvertFrom-Json round-trip, so it reuses the
# already-tested serializer instead of hand-rolling a recursive clone. The clone's record
# objects come back as ordered hashtables (ConvertFrom-Json -AsHashtable) rather than the
# original PSCustomObjects Read-PulseDataset returns - a deliberate, documented type change:
# rule authors get normal member/dot-access either way (PowerShell supports it on both), and
# the round-trip through canonical JSON incidentally proves the data is itself serializable.
function ConvertTo-PulseClonedDatasets {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    if ($Datasets.Count -eq 0) {
        return @{}
    }

    $json = ConvertTo-PulseCanonicalJson -InputObject $Datasets
    return ConvertFrom-Json -InputObject $json -AsHashtable -Depth 64
}

# Private helper (not exported): throws if two evidence entries within the same finding
# share both SortKey and Identity - see Invoke-PulseEvaluation's own docstring for why an
# undetected duplicate could make [Array]::Sort's result non-deterministic across runs.
# Called from inside Invoke-PulseCheckEvaluation's try/catch, so a throw here degrades only
# the current check to Error.
function Assert-PulseEvidenceNoDuplicates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Evidence
    )

    if ($Evidence.Count -lt 2) {
        return
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in $Evidence) {
        # ` ` (NUL) can never appear in a SortKey/Identity string built from normal
        # text, so it is a safe, simple tuple separator for the uniqueness check.
        $tupleKey = "$($item.SortKey)$([char]0)$($item.Identity)"
        if (-not $seen.Add($tupleKey)) {
            throw "duplicate evidence entry (SortKey='$($item.SortKey)', Identity='$($item.Identity)')."
        }
    }
}
