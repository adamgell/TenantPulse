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
        if ($null -eq $definition) { continue }
        if ($definition -isnot [System.Management.Automation.PSObject]) { continue }
        if (-not $definition.PSObject.Properties['id']) { continue }

        $id = [string] $definition.id
        if ([string]::IsNullOrEmpty($id)) { continue }

        $name = $null
        if ($definition.PSObject.Properties['name']) { $name = [string] $definition.name }

        $displayName = $null
        if ($definition.PSObject.Properties['displayName']) { $displayName = [string] $definition.displayName }

        $rootDefinitionId = $null
        if ($definition.PSObject.Properties['rootDefinitionId']) { $rootDefinitionId = [string] $definition.rootDefinitionId }

        $applicability = $null
        if ($definition.PSObject.Properties['applicability']) { $applicability = $definition.applicability }

        $optionLabels = [ordered]@{}
        if ($definition.PSObject.Properties['options'] -and $null -ne $definition.options) {
            foreach ($option in @($definition.options)) {
                if ($null -eq $option) { continue }
                if ($option -isnot [System.Management.Automation.PSObject]) { continue }
                if (-not $option.PSObject.Properties['itemId']) { continue }

                $optionId = [string] $option.itemId
                if ([string]::IsNullOrEmpty($optionId)) { continue }

                $optionLabel = $null
                if ($option.PSObject.Properties['displayName']) { $optionLabel = [string] $option.displayName }

                $optionLabels[$optionId] = $optionLabel
            }
        }

        $isSecretCapable = $false
        if ($definition.PSObject.Properties['valueDefinition'] -and $null -ne $definition.valueDefinition) {
            $valueDefinition = $definition.valueDefinition
            if ($valueDefinition -is [System.Management.Automation.PSObject] -and $valueDefinition.PSObject.Properties['@odata.type']) {
                $odataType = [string] $valueDefinition.'@odata.type'
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
