<#
    Returns the stable identity used for Conditional Access policy evidence rows.
    Collected policy ids remain authoritative when present. A policy with a blank id uses
    its zero-based collection ordinal so every evidence projection of the same row can
    correlate without emitting an invalid blank Identity.
#>
function Get-PulseCaPolicyEvidenceIdentity {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Policy,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int] $CollectionOrdinal
    )

    $policyId = [string] (Get-PulseSettingsCatalogValueProperty -Node $Policy -PropertyName 'id')
    if ([string]::IsNullOrWhiteSpace($policyId)) {
        return "conditional-access-policy:$CollectionOrdinal"
    }

    return $policyId
}
