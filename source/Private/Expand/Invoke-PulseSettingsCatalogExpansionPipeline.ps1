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
#>

function Invoke-PulseSettingsCatalogExpansionPipeline {
    [CmdletBinding()]
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
        $policies = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicy' -Operation 'ListBeta' -ErrorAction Stop)
    } catch {
        $reason = Protect-PulseReason -Message "fetch-failed: $($_.Exception.Message)" -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
        Write-PulseDataset -Store $Store -Name 'configurationPolicies' -ApiVersion 'beta' -Status 'Failed' -Reason $reason
        Set-PulseExpansionEntry -Store $Store -Name 'settingsCatalog' -Status 'NotExpanded' `
            -Reason (Protect-PulseReason -Message 'configurationPolicies unavailable' -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId)
        return
    }

    Write-PulseDataset -Store $Store -Name 'configurationPolicies' -Data $policies -ApiVersion 'beta' -Status 'Collected' -TenantId $contextTenantId -Pseudonym $TenantPseudonym

    $definitionIndex = Save-PulseSettingDefinitionCorpus -Store $Store -Context $Context

    Invoke-PulseSettingsCatalogExpansion -Store $Store -Context $Context -Policies $policies -DefinitionIndex $definitionIndex `
        -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
}
