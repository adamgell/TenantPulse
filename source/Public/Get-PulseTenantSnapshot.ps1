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

        The tenant identifier is never written to the snapshot in the clear, in the
        `tenant` field or in any reason string: the manifest's `tenant` field is always the
        HMAC pseudonym of -ProfileId (Get-PulsePseudonym under the local operator key),
        and every reason is routed through Protect-PulseReason, which redacts -ProfileId
        (and the raw tenant id, once resolved) out of any caught exception message before
        it is ever written to the snapshot.

    .EXAMPLE
        Get-PulseTenantSnapshot -ProfileId 'contoso' -Path './snapshot'

        Collects every dataset the loaded check catalog needs for the GraphKit 'contoso'
        profile and writes a pseudonymized snapshot store to ./snapshot.

    .EXAMPLE
        Get-PulseTenantSnapshot -ProfileId 'contoso' -Path './snapshot' -ExcludeCategory 'Entra.ConditionalAccess'

        Same as above, but skips every check (and therefore every dataset needed only by
        those checks) whose Category is 'Entra.ConditionalAccess'.

    .PARAMETER ProfileId
        The GraphKit tenant profile identifier to resolve into a context via
        Get-GraphContext. Also the value pseudonymized into the snapshot manifest's
        `tenant` field.

    .PARAMETER Path
        The directory to create (or reuse) as the snapshot store; passed straight through
        to New-PulseSnapshotStore.

    .PARAMETER IncludeCategory
        Only load checks whose Category is one of these values. Combines with
        -ExcludeCategory, -IncludeCheck and -ExcludeCheck; every supplied filter narrows
        the set further.

    .PARAMETER ExcludeCategory
        Drop checks whose Category is one of these values.

    .PARAMETER IncludeCheck
        Only load checks whose Id is one of these values.

    .PARAMETER ExcludeCheck
        Drop checks whose Id is one of these values.

    .PARAMETER AssessmentProfile
        Path to a .psd1 file supplying default IncludeCategory/ExcludeCategory/
        IncludeCheck/ExcludeCheck values for this run. Any of the four filter parameters
        passed explicitly on the command line always wins over the same key in this file.
#>
function Get-PulseTenantSnapshot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter()]
        [string[]] $IncludeCategory,

        [Parameter()]
        [string[]] $ExcludeCategory,

        [Parameter()]
        [string[]] $IncludeCheck,

        [Parameter()]
        [string[]] $ExcludeCheck,

        [Parameter()]
        [string] $AssessmentProfile
    )

    $moduleBase = if ($MyInvocation.MyCommand.Module) {
        $MyInvocation.MyCommand.Module.ModuleBase
    } else {
        $PSScriptRoot
    }

    # -AssessmentProfile only ever supplies DEFAULTS: an explicitly-bound CLI filter
    # parameter always wins over the same key in the file, even an empty array.
    if ($PSBoundParameters.ContainsKey('AssessmentProfile') -and -not [string]::IsNullOrWhiteSpace($AssessmentProfile)) {
        $profileData = Import-PowerShellDataFile -LiteralPath $AssessmentProfile -ErrorAction Stop

        if (-not $PSBoundParameters.ContainsKey('IncludeCategory') -and $profileData.ContainsKey('IncludeCategory')) {
            $IncludeCategory = @($profileData.IncludeCategory)
        }
        if (-not $PSBoundParameters.ContainsKey('ExcludeCategory') -and $profileData.ContainsKey('ExcludeCategory')) {
            $ExcludeCategory = @($profileData.ExcludeCategory)
        }
        if (-not $PSBoundParameters.ContainsKey('IncludeCheck') -and $profileData.ContainsKey('IncludeCheck')) {
            $IncludeCheck = @($profileData.IncludeCheck)
        }
        if (-not $PSBoundParameters.ContainsKey('ExcludeCheck') -and $profileData.ContainsKey('ExcludeCheck')) {
            $ExcludeCheck = @($profileData.ExcludeCheck)
        }
    }

    $datasetMapPath = Join-Path $moduleBase 'Data/DatasetMap.psd1'
    $datasetMap = Import-PowerShellDataFile -LiteralPath $datasetMapPath -ErrorAction Stop

    $checks = @(Import-PulseCheckCatalog -DatasetMapPath $datasetMapPath)

    if ($IncludeCategory) { $checks = @($checks | Where-Object { $_.Category -in $IncludeCategory }) }
    if ($ExcludeCategory) { $checks = @($checks | Where-Object { $_.Category -notin $ExcludeCategory }) }
    if ($IncludeCheck) { $checks = @($checks | Where-Object { $_.Id -in $IncludeCheck }) }
    if ($ExcludeCheck) { $checks = @($checks | Where-Object { $_.Id -notin $ExcludeCheck }) }

    $manifest = @(Get-PulseCollectionManifest -Checks $checks -DatasetMap $datasetMap)

    # Tenant id is pseudonymized before it ever reaches the store - the raw id is never
    # written to the manifest, see Get-PulsePseudonym and the module-wide pseudonymization
    # rule.
    $operatorKey = Get-PulseOperatorKey
    $tenantPseudonym = Get-PulsePseudonym -Value $ProfileId -Key $operatorKey

    $store = New-PulseSnapshotStore -Path $Path -Tenant $tenantPseudonym

    try {
        # GraphKit's Get-GraphContext performs zero network calls and never acquires a
        # token (see its own docstring) - this can fail on a malformed/unknown ProfileId
        # or a broken profile store, but a real *authentication* failure will not surface
        # here. That case is handled inside Invoke-PulseCollection instead, at the first
        # dataset attempt that actually talks to Graph (see its AuthFailure handling) -
        # both paths converge on the same collectionFailure contract, this one just covers
        # the failure mode that genuinely happens before any dataset could be attempted.
        $context = Get-GraphContext -ProfileId $ProfileId -ErrorAction Stop
    } catch {
        # Total collection failure: no dataset could even be attempted. The snapshot is
        # still written - every dataset Failed, plus the top-level collectionFailure - so
        # a caller never mistakes "we never got a token" for "the tenant has no data" or
        # loses the run's provenance entirely.
        $failureReason = Protect-PulseReason -Message "auth: $($_.Exception.Message)" -ProfileId $ProfileId -Pseudonym $tenantPseudonym

        foreach ($entry in $manifest) {
            Write-PulseDataset -Store $store -Name $entry.Dataset -ApiVersion $entry.ApiVersion -Status 'Failed' -Reason $failureReason
        }

        Set-PulseManifestEntry -Store $store -CollectionFailure $failureReason

        return $store
    }

    Invoke-PulseCollection -Store $store -Manifest $manifest -Context $context -ProfileId $ProfileId -TenantPseudonym $tenantPseudonym

    return $store
}
