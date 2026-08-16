<#
    Private: fetch (or re-read), redact, and walk ONE policy's Settings Catalog payload.

    Extracted as its own top-level module function (rather than a closure nested inside
    Invoke-PulseSettingsCatalogExpansion) for exactly one reason: the parallel worker-pool
    path in that function runs this per-policy unit inside a SEPARATE runspace via a
    RunspacePool, and only functions that are part of a module's own function table -
    which a nested closure is NOT, it exists only for the lifetime of the enclosing call -
    survive being invoked from a different runspace that re-imports the module by path (see
    Invoke-PulseSettingsCatalogExpansion's own WORKER POOL docstring section). Both the
    sequential and parallel paths call this exact same function - there is only ONE
    implementation of "how a policy is fetched, redacted, walked and classified" regardless
    of which path ran it.

    Returns { PolicyId; Rows=[rowSchemaV1...]; Gap=<string>|$null } - never throws for an
    ordinary fetch/read/walk failure (those become -Gap), matching this module's
    attempt-and-classify convention; a genuinely unexpected exception (a coding bug, not a
    Graph/IO failure) is allowed to propagate, since swallowing it here would hide the bug
    behind a routine-looking gap entry.
#>

function Invoke-PulseSettingsCatalogPolicy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [pscustomobject] $Policy,

        [Parameter()]
        [AllowNull()]
        [pscustomobject] $Context,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary] $DefinitionIndex,

        [Parameter(Mandatory)]
        [bool] $FromCapturedPayloads,

        [Parameter(Mandatory)]
        [string] $RawDatasetName,

        [Parameter()]
        [string] $ProfileId = '',

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown',

        [Parameter()]
        [AllowNull()]
        [string] $TenantId
    )

    $policyId = [string] $Policy.id
    $policyName = if ($Policy.PSObject.Properties['name']) { [string] $Policy.name } else { $null }
    $templateFamily = $null
    $templateId = $null
    if ($Policy.PSObject.Properties['templateReference'] -and $null -ne $Policy.templateReference) {
        if ($Policy.templateReference.PSObject.Properties['templateFamily']) { $templateFamily = [string] $Policy.templateReference.templateFamily }
        if ($Policy.templateReference.PSObject.Properties['templateId']) { $templateId = [string] $Policy.templateReference.templateId }
    }
    $isBaseline = (-not [string]::IsNullOrEmpty($templateId)) -and ($templateFamily -ne 'none')

    $settingsPayload = $null
    $fetchError = $null

    if ($FromCapturedPayloads) {
        try {
            $settingsPayload = Read-PulseDataset -Store $Store -Name $RawDatasetName
        } catch {
            $fetchError = "captured-payload-unreadable: $($_.Exception.Message)"
        }
    } else {
        try {
            $raw = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicySetting' -Operation 'ListBeta' -Parameters @{ id = $policyId } -ErrorAction Stop)
            $redacted = Protect-PulseSettingsCatalogSecretPayload -Data $raw
            # SECRET-REDACTED at write: this dataset gets the same hash-verified persistence
            # contract every other collected dataset in this module gets (see this
            # function's own docstring and Write-PulseDataset's).
            Write-PulseDataset -Store $Store -Name $RawDatasetName -Data $redacted -ApiVersion 'beta' -Status 'Collected' -TenantId $TenantId -Pseudonym $Pseudonym
            $settingsPayload = $redacted
        } catch {
            $fetchError = "fetch-failed: $($_.Exception.Message)"
        }
    }

    if ($fetchError) {
        return [pscustomobject]@{ PolicyId = $policyId; Rows = @(); Gap = $fetchError }
    }

    $walkResult = ConvertTo-PulseSettingRows -PolicyId $policyId -PolicyType 'settingsCatalog' `
        -PolicyName $policyName -TemplateFamily $templateFamily -IsBaseline $isBaseline `
        -SettingsPayload $settingsPayload -DefinitionIndex $DefinitionIndex -MaxDepth 64

    $gap = $null
    if ($walkResult.Gaps.Count -gt 0) {
        $gap = "walk-gap: $($walkResult.Gaps -join '; ')"
    }

    return [pscustomobject]@{ PolicyId = $policyId; Rows = $walkResult.Rows; Gap = $gap }
}
