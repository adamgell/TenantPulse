<#
    Private: orchestration glue for Task 2.3 - runs the compliance + legacy-configuration
    typed-policy expansion for both families, called by Get-PulseTenantSnapshot under
    -ExpandSettings, AFTER Invoke-PulseCollection has already run (mirrors
    Invoke-PulseSettingsCatalogExpansionPipeline's own placement, see that file's own
    docstring). Unlike that pipeline, this one does NOT fetch its own top-level policy list
    from Graph - `deviceCompliancePolicies`/`deviceConfigurations` are ALREADY DatasetMap.psd1
    entries the ordinary check-driven flow collects (TP.INT.0002 already consumes
    deviceCompliancePolicies) - this function only READS BACK whatever
    Invoke-PulseCollection already durably wrote, via Read-PulseDataset.

    A dataset that was not Collected (Skipped/Failed/absent - Read-PulseDataset throws in
    every one of those cases, see its own docstring) is NOT a pipeline failure - it is the
    expected, honest 'unavailable' outcome: manifest.expansions.<name> is written
    NotExpanded with a reason naming which raw dataset was unavailable, and the OTHER
    family is still attempted independently (a compliance dataset failure must never block
    the deviceConfiguration expansion, and vice versa - two fully independent attempt-and-
    classify units, exactly like Invoke-PulseCollection's own per-dataset independence).

    TypedPolicyMaps.psd1 is loaded once here (not per-family) from the SAME module-relative
    'Data/' path DatasetMap.psd1 already uses (Get-PulseTenantSnapshot's own
    $moduleBase/Data/DatasetMap.psd1 pattern) - a load failure here is a module-authoring
    bug (a missing/malformed shipped file), not a per-tenant runtime outcome, so it is
    allowed to propagate exactly like a DatasetMap.psd1 load failure would.

    OUTER FAILURE BOUNDARY per family (mirrors T2.2's own pipeline): an unexpected exception
    anywhere in ONE family's attempt is caught and turned into that family's own
    manifest.expansions.<name> 'Failed', never allowed to propagate and abort a snapshot
    that has already collected everything else.
#>

function Invoke-PulseTypedPolicyExpansionPipeline {
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

    $moduleBase = if ($MyInvocation.MyCommand.Module) { $MyInvocation.MyCommand.Module.ModuleBase } else { $PSScriptRoot }
    $typedPolicyMapPath = Join-Path $moduleBase 'Data/TypedPolicyMaps.psd1'
    $typedPolicyMaps = Import-PowerShellDataFile -LiteralPath $typedPolicyMapPath -ErrorAction Stop

    $families = @(
        [pscustomobject]@{ ExpansionName = 'compliance'; DatasetName = 'deviceCompliancePolicies'; PolicyType = 'compliance'; AssignmentType = 'DeviceCompliancePolicyAssignment'; TypeMap = $typedPolicyMaps.compliance }
        [pscustomobject]@{ ExpansionName = 'deviceConfiguration'; DatasetName = 'deviceConfigurations'; PolicyType = 'deviceConfiguration'; AssignmentType = 'DeviceConfigurationAssignment'; TypeMap = $typedPolicyMaps.deviceConfiguration }
    )

    foreach ($family in $families) {
        try {
            $policies = $null
            try {
                $policies = Read-PulseDataset -Store $Store -Name $family.DatasetName
            } catch {
                Write-Verbose "Invoke-PulseTypedPolicyExpansionPipeline: '$($family.DatasetName)' unavailable: $($_.Exception.Message)"
                $reason = Protect-PulseReason -Message "$($family.DatasetName) unavailable" -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
                Set-PulseExpansionEntry -Store $Store -Name $family.ExpansionName -Status 'NotExpanded' -Reason $reason
                continue
            }

            $null = Invoke-PulseTypedPolicyExpansion -Store $Store -Context $Context -Policies $policies `
                -PolicyType $family.PolicyType -TypeMap $family.TypeMap -AssignmentType $family.AssignmentType `
                -Name $family.ExpansionName -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
        } catch {
            Write-Verbose "Invoke-PulseTypedPolicyExpansionPipeline: unexpected exception in '$($family.ExpansionName)': $($_.Exception.Message)"
            $reason = Protect-PulseReason -Message 'unexpected-pipeline-failure' -ProfileId $ProfileId -Pseudonym $TenantPseudonym -TenantId $contextTenantId
            Set-PulseExpansionEntry -Store $Store -Name $family.ExpansionName -Status 'Failed' -Reason $reason
        }
    }
}
