<#
    .SYNOPSIS
        Lists every check descriptor in the catalog as a lightweight, read-only view.

    .DESCRIPTION
        Get-PulseCheckCatalog is the simplest of TenantPulse's public commands: it loads
        the check catalog through Import-PulseCheckCatalog (the same catalog loader every
        other command in this module uses) and projects each descriptor down to the five
        fields an operator most often needs at a glance - id, title, category, severity,
        and authorities (the check's References.Authorities array, kept as an array even
        when empty or single-valued). It touches no snapshot and no Graph descriptor - it
        is a pure, read-only view over the catalog on disk, useful for discovering what
        -IncludeCategory/-IncludeCheck/-Id/-Category values are available before running a
        real assessment with Invoke-PulseAssessment or a scoped one with Invoke-PulseCheck.

        Output preserves Import-PulseCheckCatalog's own ordinal-by-Id ordering; this
        function never re-sorts.

    .EXAMPLE
        Get-PulseCheckCatalog

        Lists every check descriptor from the module's default catalog directory
        (<ModuleBase>/Data/Checks) as {id; title; category; severity; authorities} rows.

    .EXAMPLE
        Get-PulseCheckCatalog -Path './my-checks' | Where-Object { $_.category -like 'Entra.*' }

        Lists every check descriptor from a custom catalog directory, then filters the
        projected view down to the Entra category tree using ordinary pipeline filtering
        (Get-PulseCheckCatalog itself applies no category/id selection - see
        Select-PulseCheck for the module's actual selection filter, used by the commands
        that run an assessment rather than merely list one).

    .PARAMETER Path
        Directory containing check descriptor .psd1 files. Defaults to
        Import-PulseCheckCatalog's own default (<ModuleBase>/Data/Checks) when omitted.

    .PARAMETER DatasetMapPath
        Path to the shared DatasetMap.psd1 used to cross-check each descriptor's declared
        datasets. Defaults to Import-PulseCheckCatalog's own default
        (<ModuleBase>/Data/DatasetMap.psd1) when omitted.
#>
function Get-PulseCheckCatalog {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [string] $Path,

        [Parameter()]
        [string] $DatasetMapPath
    )

    $catalogParams = @{}
    if ($PSBoundParameters.ContainsKey('Path')) { $catalogParams.Path = $Path }
    if ($PSBoundParameters.ContainsKey('DatasetMapPath')) { $catalogParams.DatasetMapPath = $DatasetMapPath }

    $checks = @(Import-PulseCheckCatalog @catalogParams)

    $result = [pscustomobject[]] @(foreach ($check in $checks) {
        [pscustomobject]@{
            id          = $check.Id
            title       = $check.Title
            category    = $check.Category
            severity    = $check.Severity
            authorities = @($check.References.Authorities)
        }
    })

    return $result
}
