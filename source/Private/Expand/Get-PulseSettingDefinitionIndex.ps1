<#
    Private: build a compact, in-memory lookup from a raw ConfigurationSettingDefinition.
    ListBeta corpus.

    Input: the full array of raw definition objects GraphKit returns (18,227 items / ~1.2 GB
    managed heap on the T2.0 spike tenant - see Save-PulseSettingDefinitionCorpus's own
    docstring for the accepted memory-floor budget this function's ONE-PASS contract exists
    to protect). Output: an ordered hashtable keyed by definition id, each value holding
    ONLY the five fields T2.2's settings-catalog walk actually needs to resolve an instance
    against its definition - Name, DisplayName, RootDefinitionId, OptionLabels (a compact
    optionId -> label map for choice-shaped definitions), Applicability, and IsSecretCapable
    - never the full raw definition object. This compactness is structural and tested: the
    index's per-entry shape holds exactly these six members, nothing else, regardless of
    how many other fields the raw definition carried.

    ONE PASS (Task 2.1 memory contract): this function walks -Data exactly once, in a single
    foreach loop, building the index entry-by-entry. It does not build any intermediate
    full-size collection alongside the index. Save-PulseSettingDefinitionCorpus's own
    docstring covers the caller-side half of "release the full corpus" (dropping its
    reference to -Data once this function returns) - this function's own half of that
    contract is not holding anything MORE than -Data plus the index being built while doing
    it.

    IsSecretCapable determination (flagged, not just asserted - see this task's own report):
    a definition is treated as secret-capable when its `valueDefinition.@odata.type` names a
    `...SecretSettingValueDefinition` subtype (deviceManagementConfigurationSecretSettingValue
    is the corresponding INSTANCE-level type the T2.2 walk detects independently; this is the
    DEFINITION-level signal, checked once per definition rather than once per policy
    instance). No T2.0-spike fixture exercises the raw definitions corpus itself (the spike's
    fixtures are all per-policy SETTING INSTANCES, a different Graph resource) or a
    secret-capable definition specifically, so this rule is a documented best-effort read of
    the public Settings Catalog schema shape, not a fixture-verified one - see this task's
    report for the explicit flag. It is defense-in-depth only: the T2.2 walk's own
    instance-level secret detection (checking each SETTING VALUE's own @odata.type) is the
    line the SECRET CONTRACT actually depends on: a definition missed here degrades to "not
    flagged secret-capable at the index level," it does not defeat the instance-level
    redaction downstream.

    SHAPE NEUTRALITY (Task 2.2 P0 re-review): -Data is GraphKit's raw
    ConfigurationSettingDefinition.ListBeta response - an OrderedHashtable tree in
    production (`ConvertFrom-Json -AsHashtable`), never pscustomobject. Every read below
    goes through the shared Get-PulseSettingsCatalogValueProperty/Test-PulseSettingsCatalogNode
    accessors (see ConvertTo-PulseSettingRows.ps1's own docstring for the full story of the
    bug class this fixes) rather than `.PSObject.Properties[...]`/`-is [PSObject]` - a
    hashtable-shaped corpus previously indexed to zero usable entries (every `id` read came
    back $null and was skipped), which would have silently defeated name/label resolution
    and the IsSecretCapable signal for the entire walk, not just this function's own tests.
#>

function Get-PulseSettingDefinitionIndex {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Data
    )

    $index = [ordered]@{}

    foreach ($definition in $Data) {
        if (-not (Test-PulseSettingsCatalogNode -Node $definition)) { continue }

        $idRaw = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'id'
        $id = if ($null -ne $idRaw) { [string] $idRaw } else { $null }
        if ([string]::IsNullOrEmpty($id)) { continue }

        $nameRaw = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'name'
        $name = if ($null -ne $nameRaw) { [string] $nameRaw } else { $null }

        $displayNameRaw = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'displayName'
        $displayName = if ($null -ne $displayNameRaw) { [string] $displayNameRaw } else { $null }

        $rootDefinitionIdRaw = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'rootDefinitionId'
        $rootDefinitionId = if ($null -ne $rootDefinitionIdRaw) { [string] $rootDefinitionIdRaw } else { $null }

        $applicability = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'applicability'

        $optionLabels = [ordered]@{}
        $optionsRaw = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'options'
        if ($null -ne $optionsRaw) {
            foreach ($option in @($optionsRaw)) {
                if (-not (Test-PulseSettingsCatalogNode -Node $option)) { continue }

                $optionIdRaw = Get-PulseSettingsCatalogValueProperty -Node $option -PropertyName 'itemId'
                $optionId = if ($null -ne $optionIdRaw) { [string] $optionIdRaw } else { $null }
                if ([string]::IsNullOrEmpty($optionId)) { continue }

                $optionLabelRaw = Get-PulseSettingsCatalogValueProperty -Node $option -PropertyName 'displayName'
                $optionLabel = if ($null -ne $optionLabelRaw) { [string] $optionLabelRaw } else { $null }

                $optionLabels[$optionId] = $optionLabel
            }
        }

        $isSecretCapable = $false
        $valueDefinition = Get-PulseSettingsCatalogValueProperty -Node $definition -PropertyName 'valueDefinition'
        if (Test-PulseSettingsCatalogNode -Node $valueDefinition) {
            $odataTypeRaw = Get-PulseSettingsCatalogValueProperty -Node $valueDefinition -PropertyName '@odata.type'
            if ($null -ne $odataTypeRaw) {
                $odataType = [string] $odataTypeRaw
                if ($odataType -match '(?i)SecretSettingValueDefinition$') {
                    $isSecretCapable = $true
                }
            }
        }

        $index[$id] = [ordered]@{
            Name             = $name
            DisplayName      = $displayName
            RootDefinitionId = $rootDefinitionId
            OptionLabels     = $optionLabels
            Applicability    = $applicability
            IsSecretCapable  = $isSecretCapable
        }
    }

    return $index
}
