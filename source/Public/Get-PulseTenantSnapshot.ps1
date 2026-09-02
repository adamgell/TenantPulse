<#
    .SYNOPSIS
        Collects a read-only, pseudonymized tenant health snapshot through GraphKit.

    .DESCRIPTION
        Get-PulseTenantSnapshot is TenantPulse's only Graph-touching layer and the module's
        first public command. It loads the check catalog (optionally narrowed by category
        or check id), resolves every dataset those checks need through the shared
        DatasetMap.psd1 table, creates a snapshot store, and attempts to collect each
        dataset through GraphKit - one read per dataset, attempted independently, never
        through anything but a read-only (ThrottleClass 'Read', ReplayPolicy 'Safe')
        GraphKit descriptor.

        Collection is attempt-and-classify: GraphKit has no per-operation permission
        pre-flight, so every dataset is actually attempted and the outcome classified
        afterwards. A clean read is written Collected. A 403 is written Skipped with a
        reason naming the descriptor's required permissions - "not permitted", not
        "broken". Any other failure is written Failed with the caught error's message. A
        A dataset flagged Pending in DatasetMap.psd1 is first resolved through TenantPulse's
        built-in provider-plan registry. Shipped composites run there; an entry with no
        registered plan is written Skipped with reason
        'descriptor-pending: awaiting GraphKit release' and never attempted at all.

        Two distinct paths cover a total authentication failure, because GraphKit's
        Get-GraphContext performs zero network calls and never acquires a token (see its
        own docstring): if resolving a context for -ProfileId fails outright before any
        dataset could even be attempted (a malformed profile, a broken profile store), the
        snapshot is still written with every dataset Failed and the top-level
        collectionFailure set. If context resolution succeeds but the *first* dataset
        attempt is the one that actually discovers the auth failure (an expired
        certificate, a revoked app registration - an AADSTS-shaped error), that dataset is
        written Failed, collectionFailure is set from that same reason, and every
        remaining dataset is written Failed with reason 'authentication-failed: collection aborted'
        with no further Graph calls - they would all fail identically. Either way,
        collection never silently produces an empty, unexplained snapshot.

        PSEUDONYM INPUT (spec section 2a - post-review fix): the manifest's `tenant` field
        is the HMAC pseudonym of the TENANT ID, never of -ProfileId. -ProfileId is only a
        local, operator-chosen label for a GraphKit profile - the same tenant can be
        reached under two differently-named profiles, and a profile can be renamed without
        the tenant itself changing. Pseudonymizing -ProfileId would let a profile rename
        silently change the pseudonym for the same tenant, breaking every cross-run
        correlation the pseudonym exists to support. Get-GraphContext performs zero network
        calls (see its own docstring) so $context.TenantId is available immediately after
        it succeeds, with no extra Graph round-trip - Get-GraphContext is therefore called
        BEFORE the snapshot store is created, so the pseudonym is always derived from the
        real tenant id when one is obtainable at all. The ONE exception is the pre-context
        total-failure path below: if Get-GraphContext itself throws, there is no context
        and therefore no TenantId to pseudonymize - that path falls back to pseudonymizing
        -ProfileId instead (the pre-fix behavior, kept only because there is nothing else
        to key the snapshot's tenant field on), which is why a caller must not treat the
        `tenant` field on a total-failure snapshot as tenant-stable across a profile
        rename the way every other snapshot's `tenant` field is.

    .EXAMPLE
        Get-PulseTenantSnapshot -ProfileId 'contoso' -OutputPath './snapshot'

        Collects every dataset the loaded check catalog needs for the GraphKit 'contoso'
        profile and writes a pseudonymized snapshot store to ./snapshot.

    .EXAMPLE
        Get-PulseTenantSnapshot -ProfileId 'contoso' -OutputPath './snapshot' -ExcludeCategory 'Entra.ConditionalAccess'

        Same as above, but skips every check (and therefore every dataset needed only by
        those checks) whose Category is 'Entra.ConditionalAccess'.

    .PARAMETER ProfileId
        The GraphKit tenant profile identifier to resolve into a context via
        Get-GraphContext. No longer the value pseudonymized into the snapshot manifest's
        `tenant` field on a normal run - see the PSEUDONYM INPUT section above; it is used
        for that field only on the pre-context total-failure fallback path.

    .PARAMETER OutputPath
        The directory to create (or reuse) as the snapshot store; passed straight through
        to New-PulseSnapshotStore. Named -OutputPath because it is always an OUTPUT
        directory this command writes into, never an input to read from.

    .PARAMETER Path
        DEPRECATED alias for -OutputPath, kept for one release for backward compatibility.
        Use -OutputPath instead; this alias will be removed in a future release.

    .PARAMETER IncludeCategory
        Only load checks whose Category dotted-path prefix-matches one of these values
        (e.g. 'Entra' matches 'Entra.ConditionalAccess', 'Entra.Identity', ... but never
        'EntraFoo' - see Select-PulseCheck's own docstring for the exact matching rule).
        Combines with -ExcludeCategory, -IncludeCheck and -ExcludeCheck; every supplied
        filter narrows the set further.

    .PARAMETER ExcludeCategory
        Drop checks whose Category dotted-path prefix-matches one of these values. Always
        wins over an Include match for the same check, on any axis.

    .PARAMETER IncludeCheck
        Only load checks whose Id is one of these values.

    .PARAMETER ExcludeCheck
        Drop checks whose Id is one of these values.

    .PARAMETER AssessmentProfile
        Path to a .psd1 file supplying default Include/Exclude arrays for this run
        (Task 1.8: unified with Invoke-PulseAssessment's assessment-profile schema, a
        breaking change from this parameter's original IncludeCategory/ExcludeCategory/
        IncludeCheck/ExcludeCheck key shape). Each entry in Include/Exclude is matched
        against BOTH a check's Category (dotted-prefix) and its Id (exact) - see
        Select-PulseCheck's own docstring for the full precedence rules. -IncludeCategory/
        -ExcludeCategory/-IncludeCheck/-ExcludeCheck passed explicitly on the command line
        always win over the profile file's Include/Exclude, even an empty array.

    .PARAMETER ExpandSettings
        Phase 2 (T2.2): default OFF this task (flipped on by default in T2.7 after the
        live gate). When set, after the normal check-driven dataset collection above has
        finished, this also collects `configurationPolicies`, captures the settings-
        definitions corpus, and runs the Settings Catalog per-policy fan-out/walk (see
        Invoke-PulseSettingsCatalogExpansionPipeline's own docstring). GraphKit 0.3.0's
        ConfigurationPolicyAssignment.ListBeta descriptor supplies each policy's real
        assignment targets; an unavailable assignment payload gaps that policy.

    .PARAMETER ProviderPlanRegistry
        Optional dataset-name keyed overrides for TenantPulse-owned provider plan commands.
        TenantPulse wires its five shipped plans by default. A supplied entry replaces the
        matching built-in plan and runs sequentially with the same resolved Graph context;
        other built-in plans remain active.
#>
function Get-PulseTenantSnapshot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [Alias('Path')]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath,

        [Parameter()]
        [string[]] $IncludeCategory,

        [Parameter()]
        [string[]] $ExcludeCategory,

        [Parameter()]
        [string[]] $IncludeCheck,

        [Parameter()]
        [string[]] $ExcludeCheck,

        [Parameter()]
        [string] $AssessmentProfile,

        # Phase 2 (T2.2): default OFF this task, per the plan's own G-gate sequencing
        # amendment. STILL OFF BY DEFAULT after T2.7 (deliberate deviation from this
        # parameter's own earlier docstring, which said "flipped on by default in T2.7
        # after the live gate" - see task-2.7-report.md's own Findings section for why):
        # the live gate against Ivy24 DID pass clean end to end (see
        # docs/spike/2026-08-16-t27-perf-container.md), which is the functional gate this
        # flip was conditioned on - but actually trying the flip live during T2.7 surfaced
        # two real, wider-blast-radius costs a one-line default change should not absorb
        # under the same task's own time budget: (1) `[switch] $X = $true` trips
        # PSScriptAnalyzer's own PSAvoidDefaultValueSwitchParameter rule, which this repo's
        # QA gate enforces - a real, not cosmetic, lint failure; (2) at least two existing
        # Get-PulseTenantSnapshot unit tests assert on the exact manifest shape a
        # default-on -ExpandSettings changes (new configurationPolicies/expansions activity
        # even for callers that never asked for it), meaning the flip is a genuine breaking
        # change to this function's existing contract, not a purely additive one. Both are
        # real, fixable work - a dedicated follow-up task doing the flip WITH its own full
        # test/lint triage, not a footnote merged under this task's own time pressure. When
        # set, AFTER the normal check-driven dataset collection below has finished, this
        # collects `configurationPolicies`, captures the settings-definitions corpus, and
        # runs the Settings Catalog per-policy fan-out/walk (see
        # Invoke-PulseSettingsCatalogExpansionPipeline's own docstring), including the
        # released ConfigurationPolicyAssignment.ListBeta read for every eligible policy.
        [Parameter()]
        [switch] $ExpandSettings,
        # Optional overrides for TenantPulse-owned composite plans, keyed only by dataset
        # name. Shipped plans are wired by default below.
        [Parameter()]
        [AllowNull()]
        [hashtable] $ProviderPlanRegistry = @{}

    )

    $moduleBase = if ($MyInvocation.MyCommand.Module) {
        $MyInvocation.MyCommand.Module.ModuleBase
    } else {
        $PSScriptRoot
    }

    $datasetMapPath = Join-Path $moduleBase 'Data/DatasetMap.psd1'
    $datasetMap = Import-PowerShellDataFile -LiteralPath $datasetMapPath -ErrorAction Stop

    $checks = @(Import-PulseCheckCatalog -DatasetMapPath $datasetMapPath)

    # -AssessmentProfile loading and CLI-precedence folding is shared with
    # Invoke-PulseAssessment via this one helper - see its own docstring.
    $resolvedSelection = Resolve-PulseSelectionParams -BoundParameters $PSBoundParameters `
        -IncludeCategory $IncludeCategory -ExcludeCategory $ExcludeCategory `
        -IncludeCheck $IncludeCheck -ExcludeCheck $ExcludeCheck -AssessmentProfile $AssessmentProfile
    $selectParams = $resolvedSelection.SelectParams
    $selectParams.Checks = $checks

    $checks = @(Select-PulseCheck @selectParams)

    $manifest = @(Get-PulseCollectionManifest -Checks $checks -DatasetMap $datasetMap)

    $resolvedProviderPlanRegistry = Resolve-PulseProviderPlanRegistry -Overrides $ProviderPlanRegistry

    $operatorKey = Get-PulseOperatorKey

    # producer.graphKit (post-review fix, previously always null - see
    # New-PulseSnapshotStore's own -GraphKitVersion docstring): resolved once, from
    # whatever GraphKit module is actually loaded in THIS session, regardless of which
    # branch below ends up creating the store - a failed Get-GraphContext call does not by
    # itself mean GraphKit is not loaded, only that this ProfileId could not be resolved.
    # Left $null, honestly, only when GraphKit truly is not loaded/available.
    $graphKitModule = Get-Module -Name GraphKit
    $graphKitVersion = if ($graphKitModule) { $graphKitModule.Version.ToString() } else { $null }

    # GraphKit's Get-GraphContext performs zero network calls and never acquires a token
    # (see its own docstring) - called BEFORE the snapshot store is created specifically so
    # $context.TenantId is available to pseudonymize before anything is written to disk
    # (see the PSEUDONYM INPUT docstring section above). This can fail on a malformed/
    # unknown ProfileId or a broken profile store, but a real *authentication* failure will
    # not surface here. That case is handled inside Invoke-PulseCollection instead, at the
    # first dataset attempt that actually talks to Graph (see its AuthFailure handling) -
    # both paths converge on the same collectionFailure contract, this one just covers the
    # failure mode that genuinely happens before any dataset could be attempted.
    try {
        $context = Get-GraphContext -ProfileId $ProfileId -ErrorAction Stop
    } catch {
        # Total collection failure: no context (and therefore no TenantId) was ever
        # obtained. There is nothing else to key the snapshot's tenant field on, so this
        # ONE path falls back to pseudonymizing -ProfileId instead - see the PSEUDONYM
        # INPUT docstring section above for why this is documented, not an oversight.
        $tenantPseudonym = Get-PulsePseudonym -Value $ProfileId -Key $operatorKey
        $store = New-PulseSnapshotStore -Path $OutputPath -Tenant $tenantPseudonym -GraphKitVersion $graphKitVersion

        # Context resolution happens before any request. Persist only a closed canonical
        # reason: exception text can contain provider response bodies, UPNs, or client ids.
        $failureReason = Protect-PulseReason -Message 'authentication-failed: context unavailable before request' `
            -ProfileId $ProfileId -Pseudonym $tenantPseudonym

        foreach ($entry in $manifest) {
            Write-PulseDataset -Store $store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' `
                -Reason $failureReason -ReasonCode 'authentication-failed' `
                -Detail @{ status = 'context unavailable before request' } -FailureClass 'AuthenticationFailed' `
                -Provider 'GraphKit' -Operations @($entry.Operation)
        }

        Set-PulseManifestEntry -Store $store -CollectionFailure $failureReason

        return $store
    }

    $contextTenantId = $null
    if ($null -ne $context -and $context.PSObject.Properties['TenantId'] -and $context.TenantId) {
        $contextTenantId = [string] $context.TenantId
    }

    # Pseudonym source is the real tenant id whenever the context actually carries one
    # (the normal case - see the PSEUDONYM INPUT docstring section above). A context that
    # succeeded but did not carry a TenantId (not expected from a real GraphKit context,
    # but not assumed away either) falls back to -ProfileId so the snapshot always gets a
    # tenant pseudonym rather than one derived from $null.
    $pseudonymSource = if ($contextTenantId) { $contextTenantId } else { $ProfileId }
    $tenantPseudonym = Get-PulsePseudonym -Value $pseudonymSource -Key $operatorKey

    $store = New-PulseSnapshotStore -Path $OutputPath -Tenant $tenantPseudonym -GraphKitVersion $graphKitVersion

    # One shared network-abort signal spans ordinary collection and the optional expansion
    # phase. Only AuthenticationFailed may set it; every other failure remains isolated.
    $networkAbortState = [pscustomobject]@{
        AuthenticationAborted = $false
        Reason                = $null
    }

    $preflightOperations = @(Get-PulsePermissionPreflightOperations -Manifest $manifest -ExpandSettings:$ExpandSettings)
    $authorizationDecision = Invoke-PulsePermissionPreflight -Context $context -Operations $preflightOperations

    Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId $ProfileId `
        -TenantPseudonym $tenantPseudonym -ProviderPlanRegistry $resolvedProviderPlanRegistry `
        -NetworkAbortState $networkAbortState -AuthorizationDecision $authorizationDecision


    if ($ExpandSettings) {
        $expansionSuppressedReason = Protect-PulseReason -Message 'authentication-failed: network expansion suppressed' `
            -ProfileId $ProfileId -Pseudonym $tenantPseudonym -TenantId $contextTenantId
        $expansionBlocked = $false
        $expansionBlockReasonCode = $null
        foreach ($expansionOperation in @(Get-PulsePermissionPreflightOperations -Manifest @() -ExpandSettings)) {
            $expansionDecision = Get-PulseOperationAuthorization -AuthorizationDecision $authorizationDecision `
                -Type $expansionOperation.Type -Operation $expansionOperation.Operation
            if ($expansionDecision.Decision -ne 'Granted') {
                $expansionBlocked = $true
                $expansionBlockReasonCode = $expansionDecision.ReasonCode
                break
            }
        }
        if ($expansionBlocked) {
            $expansionSuppressedReason = Protect-PulseReason -Message ("permission-preflight: {0}" -f $expansionBlockReasonCode) `
                -ProfileId $ProfileId -Pseudonym $tenantPseudonym -TenantId $contextTenantId
        }
        $skipExpansionGraph = $networkAbortState.AuthenticationAborted -or $expansionBlocked

        if ($skipExpansionGraph) {
            # No request was sent for the expansion root, so Skipped is accurate here. Do
            # not overwrite an ordinary-manifest entry if a future check starts consuming
            # this dataset directly and collection already recorded its attempted outcome.
            if (@($manifest | Where-Object { $_.Dataset -eq 'configurationPolicies' }).Count -eq 0) {
                $expansionFailureClass = if ($expansionBlocked) {
                    if ($expansionBlockReasonCode -eq 'authentication-unknown' -or $expansionBlockReasonCode -eq 'malformed-finding-set' -or $expansionBlockReasonCode -eq 'bootstrap-trap') {
                        'GateUnknown'
                    }
                    else { 'PermissionDenied' }
                }
                else { 'AuthenticationFailed' }
                $expansionReasonCode = if ($expansionBlocked) { $expansionBlockReasonCode } else { 'authentication-failed' }
                Write-PulseDataset -Store $store -Name 'configurationPolicies' -ApiVersion 'beta' -Status 'Skipped' `
                    -Reason $expansionSuppressedReason -ReasonCode $expansionReasonCode `
                    -Detail @{ status = 'network expansion suppressed' } -FailureClass $expansionFailureClass `
                    -Provider 'GraphKit' -Operations @('ListBeta')
            }
            Set-PulseExpansionEntry -Store $store -Name 'settingsCatalog' -Status 'NotExpanded' -Reason $expansionSuppressedReason
        } else {
            # P0-1 review fix: explicitly discarded - see the pipeline's VOID RETURN
            # contract. The shared state lets a root authentication failure suppress every
            # later network expansion without emitting another object.
            $null = Invoke-PulseSettingsCatalogExpansionPipeline -Store $store -Context $context `
                -ProfileId $ProfileId -TenantPseudonym $tenantPseudonym -NetworkAbortState $networkAbortState
        }

        # Task 2.3: compliance + legacy typed-policy expansion. Reads back
        # deviceCompliancePolicies/deviceConfigurations - already collected by the ordinary
        # check-driven Invoke-PulseCollection call above - and fans out assignments (both
        # descriptors already released, unlike T2.2's own deferred assignments). Same void-
        # return discipline as the call above - see this file's own docstring.
        if ($skipExpansionGraph) {
            foreach ($expansionName in @('compliance', 'deviceConfiguration')) {
                Set-PulseExpansionEntry -Store $store -Name $expansionName -Status 'NotExpanded' -Reason $expansionSuppressedReason
            }
        } else {
            $null = Invoke-PulseTypedPolicyExpansionPipeline -Store $store -Context $context -ProfileId $ProfileId `
                -TenantPseudonym $tenantPseudonym -NetworkAbortState $networkAbortState
        }


        # Task 2.6: conflict detection - purely derived from the family expansion jsonl
        # artifacts just produced above, never Graph. Same void-return discipline as the
        # two calls above - see this file's own docstring. Invoke-PulseConflictDetection
        # treats NotExpanded/Failed families (including authentication-suppressed typed-
        # policy walks) as omitted-family gaps, so TP.INT.0006 cannot Pass a 1-of-3 scan.
        $null = Invoke-PulseConflictDetection -Store $store -ProfileId $ProfileId -Pseudonym $tenantPseudonym -TenantId $contextTenantId

        # Part A, T3.4: per-family setting-presence index - purely derived from the SAME
        # family expansion jsonl artifacts, never Graph, same void-return discipline. Runs
        # after conflict detection (not before/interleaved) for no dependency reason -
        # both derive independently from the family artifacts - but to keep the family
        # jsonl artifacts' own two derived-artifact consumers grouped together at the end
        # of this block, matching the order they were added in.
        $null = Invoke-PulseSettingPresenceIndexBuild -Store $store -ProfileId $ProfileId -Pseudonym $tenantPseudonym -TenantId $contextTenantId
    }

    return $store
}
