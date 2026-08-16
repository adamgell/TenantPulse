<#
    Private: read one named setting out of the `directorySettings` dataset (see
    DatasetMap.psd1 - GET /settings, beta, returns one directorySetting object PER
    TEMPLATE THE TENANT HAS EXPLICITLY CUSTOMIZED, each carrying a `values[]` array of
    {name;value} pairs).

    NOT the field-absence-lens "absent decidable field -> Error" convention every other
    T4.1/T4.2 view/check in this codebase follows (see ConvertTo-PulseAuthMethodView's own
    ABSENT STATE THROWS section): a directorySetting object for a given template is a REAL,
    common, ENTIRELY EXPECTED absence on a tenant that has never touched that setting -
    Microsoft's own directorySetting resource docs are explicit that GET /settings only
    returns objects for templates an admin has explicitly instantiated, never a synthesized
    "here is what every default currently resolves to" row. Treating that absence as an
    engine Error would misfire on the single most common real-world tenant shape (nothing
    customized) for every one of CP01/PR01/ST08. Instead, a name not found anywhere in the
    dataset resolves to the caller-supplied -DefaultValue - the EIDSCA config's own
    documented default for that setting (verified against
    https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json
    at implementation time; see each check's own References.Research pointer). This is a
    real, meaningful difference between clusters - ST08's default ('false') already matches
    its recommended value (an untouched tenant PASSES), while CP01's default ('True') and
    PR01's default ('Audit') do not (an untouched tenant FAILS) - the shared accessor makes
    that distinction a per-call parameter, never a hardcoded assumption.

    Shape-neutral: every raw-node property read goes through the shared
    Get-PulseSettingsCatalogValueProperty accessor (Resolve-PulseSettingsCatalogValueClassification.ps1),
    exactly like every other T4.1/T4.2 raw-shape read in this module - see that function's
    own SHAPE NEUTRALITY docstring for the [PSObject]-vs-[IDictionary] trap this avoids
    repeating.

    Returns a plain [pscustomobject]@{ Value; Found } - Found distinguishes "explicitly
    customized to exactly -DefaultValue" from "not present, defaulted" for evidence/Reason
    text, even though both resolve to the identical .Value for the Fail/Pass decision.
#>

function Get-PulseDirectorySettingValue {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $DirectorySettings,

        [Parameter(Mandatory)]
        [string] $SettingName,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $DefaultValue
    )

    foreach ($settingObject in @($DirectorySettings)) {
        if ($null -eq $settingObject) { continue }

        $values = Get-PulseSettingsCatalogValueProperty -Node $settingObject -PropertyName 'values'
        foreach ($valueEntry in @($values)) {
            if ($null -eq $valueEntry) { continue }
            $entryName = Get-PulseSettingsCatalogValueProperty -Node $valueEntry -PropertyName 'name'
            if ($null -ne $entryName -and [string]::Equals([string] $entryName, $SettingName, [System.StringComparison]::Ordinal)) {
                $entryValue = Get-PulseSettingsCatalogValueProperty -Node $valueEntry -PropertyName 'value'
                return [pscustomobject]@{
                    Value = if ($null -ne $entryValue) { [string] $entryValue } else { $null }
                    Found = $true
                }
            }
        }
    }

    return [pscustomobject]@{
        Value = $DefaultValue
        Found = $false
    }
}
