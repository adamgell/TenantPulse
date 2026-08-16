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

    SERIALIZATION CAVEAT (do not regress this): `[pscustomobject]@{ PSTypeName = 'X'; ... }`
    leaves PSTypeName as a real, visible NoteProperty in addition to setting the object's
    TypeNames - see Import-PulseCheckCatalog's descriptor objects, which do this
    deliberately for internal identification. The findings document (and every nested
    object inside it - each finding, its evidence entries, consulting/references/origin)
    is therefore built WITHOUT a PSTypeName key anywhere, so ConvertTo-PulseCanonicalJson
    never emits a "PSTypeName" property into the findings JSON.

    Per-check resolution order (see Invoke-PulseCheckEvaluation below):
        1. Every gate the check declares (Data.Gates) is resolved via Get-PulseGateStatus.
           Phase 1: that function always answers 'Unknown', which never degrades a check -
           see its own docstring. The call is still made per gate so a later task that
           teaches real gate detection only has to change Get-PulseGateStatus itself.
        2. Every dataset the check declares (Data.Datasets) must have a manifest entry with
           status 'Collected'. A missing entry, or one recorded Failed/Skipped, degrades the
           check to NotApplicable - the reason is the manifest's own (already-redacted,
           Task 1.5) reason string, quoted verbatim, or a synthesized one for a missing
           entry / a Failed-or-Skipped entry with no reason on file.
        3. Only once every declared dataset is confirmed Collected are the datasets actually
           read (Read-PulseDataset, cached per dataset name across the whole run - the same
           dataset is frequently declared by more than one check) and the rule evaluated:
             - Rule.Type 'Function': `& <Rule.Function> -Datasets <hashtable>` must return a
               TenantPulse.RuleResult-shaped object (Status/Evidence/Reason) - New-PulseFinding
               is how a rule builds one. Anything else (wrong shape, invalid Status) is
               treated as an engine Error, same as an uncaught throw.
             - Rule.Type 'Expression': the expression text is evaluated with $Datasets bound
               to the same hashtable, via ScriptBlock.InvokeWithContext (explicit variable
               binding - no reliance on scriptblock dynamic-scoping behavior). Must resolve
               to [bool]: $true -> Pass, $false -> Fail, no evidence. Anything else is Error.
             - A rule that throws is caught here and never aborts the run - the exception's
               message becomes the finding's Reason under status Error, and evaluation moves
               on to the next check ("no silent gaps": one bad rule never hides every other
               check's result).

    Evidence within a finding is sorted ordinally by SortKey then Identity
    ([System.StringComparer]::Ordinal / [string]::CompareOrdinal - the same ordinal-only
    rule ConvertTo-PulseCanonicalJson documents for its own key sort, since
    Sort-Object -Culture collation is case-insensitive and therefore non-deterministic
    across locales for this "deterministic ordering everywhere" codebase). Findings are
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
        [string] $OperatorKeyPath = (Join-Path $HOME '.tenantpulse/operator.key')
    )

    $manifest = Get-PulseSnapshotManifest -Store $Store
    $operatorKey = Get-PulseOperatorKey -KeyPath $OperatorKeyPath

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
        $result = Invoke-PulseCheckEvaluation -Check $check -Store $Store -Manifest $manifest -DatasetCache $datasetCache

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
            reason     = $result.Reason
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
        [hashtable] $DatasetCache
    )

    $gateNames = @($Check.Data.Gates)
    foreach ($gate in $gateNames) {
        # Phase 1 stub - see Get-PulseGateStatus's own docstring. 'Unknown' never degrades
        # a check; the call is made so a later task's real gate detection only has to
        # change that one function.
        [void] (Get-PulseGateStatus -Gate $gate -Manifest $Manifest)
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
        if ($Check.Rule.Type -eq 'Function') {
            $ruleFunction = $Check.Rule.Function
            $ruleOutput = & $ruleFunction -Datasets $datasets
            $ruleOutput = @($ruleOutput) | Select-Object -Last 1

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

            $evidence = @()
            if ($ruleOutput.PSObject.Properties.Name -contains 'Evidence' -and $null -ne $ruleOutput.Evidence) {
                $evidence = @($ruleOutput.Evidence)
            }

            $reason = $null
            if ($ruleOutput.PSObject.Properties.Name -contains 'Reason') {
                $reason = $ruleOutput.Reason
            }

            return @{ Status = $status; Evidence = $evidence; Reason = $reason }
        }

        if ($Check.Rule.Type -eq 'Expression') {
            $scriptBlock = [scriptblock]::Create($Check.Rule.Expression)
            $variables = [System.Collections.Generic.List[psvariable]]::new()
            $variables.Add([psvariable]::new('Datasets', $datasets))

            # ScriptBlock.InvokeWithContext returns a Collection<PSObject>. Indexing it here
            # already yields the unwrapped .NET value (its real CLR type, e.g. [bool]) -
            # deliberately NOT unwrapped further via `-is [PSObject]` / `.BaseObject`: that
            # check is a well-known PowerShell trap where `-is [System.Management.Automation.
            # PSObject]` returns $true for virtually any value (not just genuine PSObject
            # wrappers), so calling `.BaseObject` on an already-unwrapped [bool] silently
            # resolves to $null (no such member => loose member access => null, no error)
            # and corrupts a legitimate $true/$false result into "not a boolean".
            $invokeResult = @($scriptBlock.InvokeWithContext($null, $variables))
            $lastValue = $null
            if ($invokeResult.Count -gt 0) {
                $lastValue = $invokeResult[$invokeResult.Count - 1]
            }

            if ($lastValue -isnot [bool]) {
                $typeName = if ($null -eq $lastValue) { 'null' } else { $lastValue.GetType().Name }
                return @{
                    Status   = 'Error'
                    Evidence = @()
                    Reason   = "expression rule did not evaluate to a boolean (got $typeName)."
                }
            }

            $status = if ($lastValue) { 'Pass' } else { 'Fail' }
            return @{ Status = $status; Evidence = @(); Reason = $null }
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
