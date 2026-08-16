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
        dataset flagged Pending in DatasetMap.psd1 (no GraphKit descriptor exists yet) is
        written Skipped with reason 'descriptor-pending: awaiting GraphKit release' and
        never attempted at all.

        Two distinct paths cover a total authentication failure, because GraphKit's
        Get-GraphContext performs zero network calls and never acquires a token (see its
        own docstring): if resolving a context for -ProfileId fails outright before any
        dataset could even be attempted (a malformed profile, a broken profile store), the
        snapshot is still written with every dataset Failed and the top-level
        collectionFailure set. If context resolution succeeds but the *first* dataset
        attempt is the one that actually discovers the auth failure (an expired
        certificate, a revoked app registration - an AADSTS-shaped error), that dataset is
        written Failed, collectionFailure is set from that same reason, and every
        remaining dataset is written Failed with reason 'auth-failure: collection aborted'
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
        Invoke-PulseSettingsCatalogExpansionPipeline's own docstring). Every emitted row
        carries assignments:null - the ConfigurationPolicyAssignment sub-fetch is
        unreleased GraphKit per the G-gate sequencing amendment and slots in later, in
        Phase 2b.
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
        # amendment - flipped on by default in T2.7 after the live gate. When set, AFTER
        # the normal check-driven dataset collection below has finished, this collects
        # `configurationPolicies`, captures the settings-definitions corpus, and runs the
        # Settings Catalog per-policy fan-out/walk (see
        # Invoke-PulseSettingsCatalogExpansionPipeline's own docstring) - every emitted row
        # carries assignments:null (the G-gate sequencing amendment: the
        # ConfigurationPolicyAssignment sub-fetch is unreleased GraphKit and slots in later,
        # in Phase 2b).
        [Parameter()]
        [switch] $ExpandSettings
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

        # The tenant id is never resolved on this path, so Protect-PulseReason has only
        # -ProfileId to redact out of the caught exception message before it is written to
        # the snapshot.
        $failureReason = Protect-PulseReason -Message "auth-failure: $($_.Exception.Message)" -ProfileId $ProfileId -Pseudonym $tenantPseudonym

        foreach ($entry in $manifest) {
            Write-PulseDataset -Store $store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' -Reason $failureReason
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

    Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId $ProfileId -TenantPseudonym $tenantPseudonym

    if ($ExpandSettings) {
        # P0-1 review fix: explicitly discarded - see Invoke-PulseSettingsCatalogExpansionPipeline's
        # own VOID RETURN docstring section for why an uncaptured call here previously made
        # this function return TWO objects instead of one.
        $null = Invoke-PulseSettingsCatalogExpansionPipeline -Store $store -Context $context -ProfileId $ProfileId -TenantPseudonym $tenantPseudonym

        # Task 2.3: compliance + legacy typed-policy expansion. Reads back
        # deviceCompliancePolicies/deviceConfigurations - already collected by the ordinary
        # check-driven Invoke-PulseCollection call above - and fans out assignments (both
        # descriptors already released, unlike T2.2's own deferred assignments). Same void-
        # return discipline as the call above - see this file's own docstring.
        $null = Invoke-PulseTypedPolicyExpansionPipeline -Store $store -Context $context -ProfileId $ProfileId -TenantPseudonym $tenantPseudonym

        # Task 2.6: conflict detection - purely derived from the family expansion jsonl
        # artifacts just produced above, never Graph. Same void-return discipline as the
        # two calls above - see this file's own docstring.
        $null = Invoke-PulseConflictDetection -Store $store -ProfileId $ProfileId -Pseudonym $tenantPseudonym -TenantId $contextTenantId
    }

    return $store
}
