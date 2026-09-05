<#
    Returns canonical, de-duplicated operator-approved account identifiers that CA
    coverage checks may honor as direct-user exclusions. Only BreakGlassAccounts and
    ServiceAccounts participate; ActiveGlobalAdmins are observational evidence and never
    become approved exceptions merely because they are privileged. Ordinal sorting keeps
    evidence deterministic, and case-insensitive de-duplication prevents a cross-listed
    account from producing duplicate evidence rows.
#>
function Get-PulseAcceptedCaExcludedIdentifiers {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $ExclusionContext
    )

    $accepted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $ExclusionContext) {
        $breakGlass = Get-PulseSettingsCatalogValueProperty -Node $ExclusionContext -PropertyName 'BreakGlassAccounts'
        $serviceAccounts = Get-PulseSettingsCatalogValueProperty -Node $ExclusionContext -PropertyName 'ServiceAccounts'
        foreach ($value in @($breakGlass) + @($serviceAccounts)) {
            $identifier = [string] $value
            $parsedIdentifier = [guid]::Empty
            if ([guid]::TryParseExact($identifier, 'D', [ref] $parsedIdentifier) -and
                [string]::Equals($parsedIdentifier.ToString('D'), $identifier, [System.StringComparison]::OrdinalIgnoreCase)) {
                [void] $accepted.Add($parsedIdentifier.ToString('D').ToLowerInvariant())
            }
        }
    }

    return , (ConvertTo-PulseOrdinalStringArray -Values $accepted)
}
