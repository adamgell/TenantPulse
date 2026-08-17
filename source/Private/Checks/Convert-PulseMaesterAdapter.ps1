<#
    Private: the Maester adapter layer (Task 3.1's own "Maester shim") - a thin
    result-translation helper so a Maester Intune check body (Test-Mt*.ps1, MIT-licensed,
    ported in T3.2/T3.3) maps onto TenantPulse's own RuleResult contract mechanically
    rather than each ported check re-inventing the same two translations by hand.

    KEPT DELIBERATELY MINIMAL (YAGNI, per this task's own brief): exactly the two
    conveniences the port pattern needs today, nothing a future task might want -
    Get-MtLicenseInformation-equivalent gate reads from ALREADY-COLLECTED datasets (never
    a live Graph call of its own - Maester's own function calls Graph directly at
    evaluation time, which TenantPulse's read-only-snapshot model forbids a rule from
    doing), and Add-MtTestResultDetail-equivalent -> New-PulseFinding evidence. Neither
    function is check-specific; both are generic over whatever -Datasets/-Rows a caller
    hands in. This file is expected to grow (more Maester-shape translations) once T3.2
    starts porting actual Test-Mt*.ps1 bodies and finds out what else the pattern needs -
    it is not meant to anticipate that work now.

    Test-PulseMaesterLicenseGate mirrors Maester's Get-MtLicenseInformation: that function
    inspects the tenant's licensed SKUs/service plans (a live Graph call under Maester's
    own model) to decide whether a check's underlying feature is even licensed before the
    check body runs. TenantPulse never calls Graph from a rule - the equivalent gate reads
    an ALREADY-COLLECTED dataset (declared via the check's own Data.Datasets, exactly like
    every other rule input) that carries subscribedSku-shaped rows
    ({skuPartNumber; servicePlans:[{servicePlanName; provisioningStatus}]}, the same shape
    Microsoft Graph's own /subscribedSkus returns), and answers the same "is this feature
    licensed" question from data already sitting in $Datasets. -RequiredServicePlanNames
    is satisfied if ANY named service plan appears on ANY sku row with a 'Success'
    provisioningStatus - Maester's own "any qualifying plan is enough" semantics.

    ConvertTo-PulseMaesterEvidence mirrors Maester's Add-MtTestResultDetail: that function
    takes a list of Graph objects and a column mapping and builds the markdown detail table
    Maester attaches to a test result. The TenantPulse-equivalent has no markdown table (a
    finding's evidence is structured {Identity;Detail;SortKey}, not prose) - this function
    performs the same "list of raw objects + a mapping" translation, but INTO evidence
    entries a caller then hands to New-PulseFinding's own -Evidence, which owns all
    validation (non-empty Identity, serializable Detail, etc.) - this function does not
    duplicate that validation, it only shapes the input.
#>

function Test-PulseMaesterLicenseGate {
    <#
        .SYNOPSIS
        Get-MtLicenseInformation-equivalent: decides whether a required feature is
        licensed, from an already-collected dataset rather than a live Graph call.

        .PARAMETER Datasets
        The rule's own -Datasets hashtable (Data.Datasets-declared, already collected and
        cloned by the evaluator - never fetched here).

        .PARAMETER DatasetName
        Which key of -Datasets carries the subscribedSku-shaped rows.

        .PARAMETER RequiredServicePlanNames
        One or more Graph servicePlanName values - the gate is satisfied if ANY of them
        appears, with provisioningStatus 'Success', on ANY row of the named dataset.

        .EXAMPLE
        Test-PulseMaesterLicenseGate -Datasets $Datasets -DatasetName 'subscribedSkus' -RequiredServicePlanNames @('AAD_PREMIUM_P2')
        Returns { Available = $true/$false; Reason = <string, only when $false> }.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter(Mandatory)]
        [string] $DatasetName,

        [Parameter(Mandatory)]
        [string[]] $RequiredServicePlanNames
    )

    if (-not $Datasets.ContainsKey($DatasetName) -or $null -eq $Datasets[$DatasetName]) {
        return [pscustomobject]@{
            Available = $false
            Reason    = "dataset '$DatasetName' is not present in this snapshot's rule input - the license/feature gate cannot be evaluated."
        }
    }

    $requiredSet = [System.Collections.Generic.HashSet[string]]::new([string[]] $RequiredServicePlanNames, [System.StringComparer]::OrdinalIgnoreCase)
    $skuRows = @($Datasets[$DatasetName])

    foreach ($sku in $skuRows) {
        if ($null -eq $sku) { continue }
        foreach ($plan in @($sku.servicePlans)) {
            if ($null -eq $plan) { continue }
            $planName = [string] $plan.servicePlanName
            $provisioningStatus = [string] $plan.provisioningStatus
            if ($requiredSet.Contains($planName) -and $provisioningStatus -eq 'Success') {
                return [pscustomobject]@{ Available = $true; Reason = $null }
            }
        }
    }

    return [pscustomobject]@{
        Available = $false
        Reason    = "none of the required service plan(s) ($($RequiredServicePlanNames -join ', ')) are licensed with a 'Success' provisioning status in dataset '$DatasetName'."
    }
}

function ConvertTo-PulseMaesterEvidence {
    <#
        .SYNOPSIS
        Add-MtTestResultDetail-equivalent: maps a flat list of Maester-style result rows
        onto the {Identity;Detail;SortKey} shape New-PulseFinding's own -Evidence expects.

        .PARAMETER Rows
        The raw objects to translate - one evidence entry per row. Never mutated.

        .PARAMETER IdentityProperty
        The row property to use as the evidence Identity (must resolve to a non-empty
        value for every row - a row that does not is skipped, matching
        ConvertTo-PulseNormalizedEvidence's own "no non-empty Identity" rejection, except
        surfaced here as a silent skip rather than a throw, since this function runs
        BEFORE New-PulseFinding's own validation gets a chance to report it per-entry with
        full context).

        .PARAMETER SortKeyProperty
        Optional row property to use as SortKey; omitted or blank on a row falls back to
        that row's own Identity value, matching New-PulseFinding's own default.

        .PARAMETER DetailProperties
        Optional subset of row property names to carry into Detail. Omitted entirely ->
        every property on the row is carried through unfiltered.

        .EXAMPLE
        ConvertTo-PulseMaesterEvidence -Rows $conflicts -IdentityProperty 'settingDefinitionId'
        Returns an array of hashtables ready to pass straight to New-PulseFinding -Evidence.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Rows,

        [Parameter(Mandatory)]
        [string] $IdentityProperty,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $SortKeyProperty,

        [Parameter()]
        [AllowNull()]
        [string[]] $DetailProperties
    )

    $evidence = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }

        $identity = $row.$IdentityProperty
        if ($null -eq $identity -or [string]::IsNullOrEmpty([string] $identity)) { continue }

        $sortKey = $null
        if (-not [string]::IsNullOrEmpty($SortKeyProperty)) {
            $sortKey = $row.$SortKeyProperty
        }
        if ($null -eq $sortKey -or [string]::IsNullOrEmpty([string] $sortKey)) {
            $sortKey = $identity
        }

        $detail = @{}
        $propertyNames = if ($DetailProperties -and $DetailProperties.Count -gt 0) {
            $DetailProperties
        } else {
            $row.PSObject.Properties.Name
        }
        foreach ($propertyName in $propertyNames) {
            $detail[$propertyName] = $row.$propertyName
        }

        $evidence.Add(@{ Identity = [string] $identity; Detail = $detail; SortKey = [string] $sortKey })
    }

    # Comma-wrap (same convention as ConvertTo-PulseConflictRecords/Read-PulseDataset's own
    # return statements): this IS a pipeline return, so a bare `return $evidence.ToArray()`
    # unrolls a single-element result to that one hashtable itself at the call site (whose
    # own .Count would then mean "how many keys does this hashtable have", not "how many
    # evidence entries" - a real bug this task's own single-row fixture test caught) and
    # unrolls an empty result to $null. [hashtable[]] @(...) alone is not enough to prevent
    # either unroll once the result crosses a `return`; the explicit leading comma is.
    return , [hashtable[]] @($evidence.ToArray())
}
