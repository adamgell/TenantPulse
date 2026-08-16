<#
    Private: orchestration glue for -ExpandSettings - collects `configurationPolicies`,
    captures the settings-definitions corpus, and runs the Settings Catalog fan-out/walk,
    called by Get-PulseTenantSnapshot AFTER its normal check-driven dataset collection has
    already finished. Kept out of Get-PulseTenantSnapshot's own body so that function's
    already-large collection flow does not grow a second, differently-shaped attempt-and-
    classify block inline; this function owns exactly one thing - "if -ExpandSettings was
    asked for, do the extra Settings Catalog work" - and Get-PulseTenantSnapshot's own
    caller-facing contract (dataset collection first, one dataset at a time, own
    Invoke-PulseCollection) does not change shape at all.

    `configurationPolicies` IS NOT (yet) a DatasetMap.psd1 entry - no T2.2-era check
    consumes it, so it is never fetched by the ordinary check-driven Invoke-PulseCollection
    loop above. This function fetches it directly (ConfigurationPolicy.ListBeta, the one
    G-gate descriptor already released in 0.1.1 this whole task depends on) and writes it
    through the SAME Write-PulseDataset path every other dataset uses - a caller reading
    manifest.datasets.configurationPolicies sees a normal Collected/Failed/Skipped entry,
    not a special case.

    ATTEMPT-AND-CLASSIFY, one more failure surface than the check-driven loop: a failed
    `configurationPolicies` fetch here does NOT abort the run (Get-PulseTenantSnapshot has
    already returned everything else it collected) - it writes that ONE dataset Failed and
    then Invoke-PulseSettingsCatalogExpansion is never called at all: there is no policy
    list to fan out over. A -DefinitionIndex capture failure (Save-PulseSettingDefinitionCorpus
    returning $null) still reaches Invoke-PulseSettingsCatalogExpansion - that function's
    own $null-index branch is what actually writes the NotExpanded 'definitions corpus
    unavailable' expansion entry (see its own docstring), so this function does not
    duplicate that check.

    VOID RETURN (P0-1 review fix - reproduced: Get-PulseTenantSnapshot -ExpandSettings
    returned TWO objects on its own output pipeline - the snapshot $store from its own
    `return $store`, AND this function's own last-statement expression, since
    Invoke-PulseSettingsCatalogExpansion's return value was never captured/voided here and
    PowerShell streams any uncaptured expression's output up through every enclosing,
    non-capturing call frame. That broke Invoke-PulseAssessment: `$store = Get-PulseTenantSnapshot
    @collectParams` silently became a two-element ARRAY, and `$store.Root` downstream
    returned two Root values instead of one string). This function's own summary is now
    explicitly discarded ($null = ...) rather than left as the last, uncaptured statement -
    belt-and-suspenders alongside Get-PulseTenantSnapshot's own call-site fix, so a THIRD
    caller of this function directly can never reintroduce the same leak by omission.

    READ-ONLY ENFORCEMENT (task-review Critical): Assert-PulseReadOnlyDescriptor guards the
    `configurationPolicies` fetch, exactly once, before Get-GraphObject is ever called -
    matching Invoke-PulseCollection's own runtime-assertion pattern for every other dataset
    this module collects. `configurationPolicies` is declared in DatasetMap.psd1 (so the
    static read-only gate enumerates it too, alongside every check-driven dataset) even
    though no T2.2-era check pulls it through the ordinary collection loop - see that file's
    own comment for why a map entry with no consuming check is still the correct home for
    it, not a "documented exception" carve-out from either the static gate or this runtime
    assertion.

    OUTER FAILURE BOUNDARY (task-review Critical/omp High): everything AFTER a successful
    `configurationPolicies` fetch - the dataset write, the definitions-corpus capture, the
    fan-out call itself - is now wrapped in one more try/catch. An unexpected exception
    anywhere in that sequence (a disk-full mid-write, a coding defect surfacing as a real
    throw) is caught here and turned into manifest.expansions.settingsCatalog 'Failed', NOT
    allowed to propagate - Get-PulseTenantSnapshot has ALREADY collected and durably written
    every ordinary check-driven dataset by the time this function runs (see this file's own
    docstring), and an uncaught exception here would otherwise abort Get-PulseTenantSnapshot
    entirely, discarding a snapshot that was otherwise complete and usable, over a failure in
    the ADDITIONAL, opt-in Settings Catalog expansion alone.
#>

function Invoke-PulseSettingsCatalogExpansionPipeline {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [pscustomobject] $Context,

        [Parameter(Mandatory)]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [string] $TenantPseudonym
    )

    $contextTenantId = $null
    if ($null -ne $Context -and $Context.PSObject.Properties['TenantId'] -and $null -ne $Context.TenantId) {
        $contextTenantId = [string] $Context.TenantId
    }

    try {
        Assert-PulseReadOnlyDescriptor -Type 'ConfigurationPolicy' -Operation 'ListBeta' -ApiVersion 'beta'
    } catch {
        if ($_.Exception.Message -match 'descriptor-version-drift') {
            $reason = Protect-PulseReason -Message $_.Exception.Message -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
            Write-PulseDataset -Store $Store -Name 'configurationPolicies' -ApiVersion 'beta' -Status 'Failed' -Reason $reason
            Set-PulseExpansionEntry -Store $Store -Name 'settingsCatalog' -Status 'NotExpanded' `
                -Reason (Protect-PulseReason -Message 'configurationPolicies unavailable' -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId)
            return
        }
        # A real read-only-predicate violation is a module-authoring bug - re-throw to
        # abort, matching Assert-PulseReadOnlyDescriptor's own contract and
        # Invoke-PulseCollection's identical handling of the same distinction.
        throw
    }

    try {
        $policies = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicy' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $reason = Protect-PulseReason -Message "fetch-failed: $($_.Exception.Message)" -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
        Write-PulseDataset -Store $Store -Name 'configurationPolicies' -ApiVersion 'beta' -Status 'Failed' -Reason $reason
        Set-PulseExpansionEntry -Store $Store -Name 'settingsCatalog' -Status 'NotExpanded' `
            -Reason (Protect-PulseReason -Message 'configurationPolicies unavailable' -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId)
        return
    }

    try {
        Write-PulseDataset -Store $Store -Name 'configurationPolicies' -Data $policies -ApiVersion 'beta' -Status 'Collected' -TenantId $contextTenantId -Pseudonym $TenantPseudonym

        $definitionIndex = Save-PulseSettingDefinitionCorpus -Store $Store -Context $Context

        $null = Invoke-PulseSettingsCatalogExpansion -Store $Store -Context $Context -Policies $policies -DefinitionIndex $definitionIndex `
            -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
    } catch {
        # OUTER FAILURE BOUNDARY - see this file's own docstring: never let an unexpected
        # exception here escape and abort a snapshot that is otherwise already complete.
        Write-Verbose "Invoke-PulseSettingsCatalogExpansionPipeline: unexpected exception after configurationPolicies fetch: $($_.Exception.Message)"
        $reason = Protect-PulseReason -Message 'unexpected-pipeline-failure' -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
        Set-PulseExpansionEntry -Store $Store -Name 'settingsCatalog' -Status 'Failed' -Reason $reason
    }
}
