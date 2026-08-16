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

    Returns { PolicyId; Rows=[rowSchemaV1...]; Gap=<structured string>|$null } - never
    throws for an ordinary fetch/read/walk failure (those become -Gap); a genuine
    instanceId-collision throw out of ConvertTo-PulseSettingRows (see that function's own
    docstring) IS caught here and turned into a Gap too, same as any other per-policy
    failure - it is a data-integrity anomaly for exactly this one policy, not a coding bug
    this module should ever let escape and abort the whole fan-out.

    STRUCTURED GAP REASONS ONLY (P0-3 review fix - reproduced defect): every -Gap this
    function returns is a small, closed set of {category[:statusCode]} tokens - never a
    raw caught exception's .Message text. The review reproduced a real leak: a worker
    exception's message can echo back arbitrary content from whatever failed (a
    deserialization error that quotes a fragment of the response body, a transport error
    that includes request details) - and a PLANTED SECRET VALUE in that message text
    previously reached the manifest verbatim through this function's old
    "fetch-failed: $($_.Exception.Message)"-shaped reasons. The raw exception is now
    ONLY ever handed to Write-Verbose (this process's own diagnostic stream - never
    persisted to any snapshot artifact); the -Gap string this function returns names a
    CATEGORY (FetchFailed, PermissionDenied, AuthFailure, CapturedPayloadMissing,
    CapturedPayloadUnreadable, WalkGap, InstanceIdCollision) and, where available, a
    Graph HTTP status code - both closed, bounded-content fields that cannot smuggle
    exception text.

    SECRET CONTRACT (P0-2): -DefinitionIndex is forwarded to
    Protect-PulseSettingsCatalogSecretPayload so the raw-dataset redaction pass has the
    SAME IsSecretCapable signal the row walk uses - both go through the one shared
    classifier, Resolve-PulseSettingsCatalogValueClassification (see its own docstring).

    SHAPE NEUTRALITY (Task 2.2 P0 re-review): -Policy is one row of the
    `configurationPolicies` dataset - GraphKit's raw response shape, an OrderedHashtable in
    production, not pscustomobject (see ConvertTo-PulseSettingRows.ps1's own docstring for
    the full story). -Policy is now untyped (was `[pscustomobject]`, which PowerShell's
    parameter binder silently top-level-coerced a Hashtable INTO - masking the bug for
    -Policy's own direct fields like `id`/`name` while leaving `.templateReference`, a
    NESTED value, still hashtable-shaped and unreadable through `.PSObject.Properties[...]`
    underneath that one-level coercion). Every metadata read below goes through the shared
    Get-PulseSettingsCatalogValueProperty accessor instead.
#>

function Invoke-PulseSettingsCatalogPolicy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        $Policy,

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
        [AllowNull()]
        [AllowEmptyString()]
        [string] $TenantId,

        [Parameter()]
        [string] $Pseudonym = 'tp-unknown'
    )

    function New-PulseStructuredGapReason {
        param([string] $Category, [System.Nullable[int]] $StatusCode = $null)
        if ($null -ne $StatusCode) { return "category:$Category;statusCode:$StatusCode" }
        return "category:$Category"
    }

    function Get-PulseGraphErrorStatusCode {
        # Small, tolerant status-code reader over GraphKit's own ErrorRecord.TargetObject.
        # Telemetry envelope (same signal Get-PulseFailureClass reads as its own "signal
        # 2") - never throws, returns $null when no numeric status is available.
        param([System.Management.Automation.ErrorRecord] $ErrorRecord)
        try {
            if ($null -eq $ErrorRecord) { return $null }
            $targetObjectProperty = $ErrorRecord.PSObject.Properties['TargetObject']
            if ($null -eq $targetObjectProperty -or $null -eq $targetObjectProperty.Value) { return $null }
            $telemetryProperty = $targetObjectProperty.Value.PSObject.Properties['Telemetry']
            if ($null -eq $telemetryProperty -or $null -eq $telemetryProperty.Value) { return $null }
            $attempts = @($telemetryProperty.Value)
            if ($attempts.Count -eq 0) { return $null }
            $statusProperty = $attempts[$attempts.Count - 1].PSObject.Properties['StatusCode']
            if ($null -eq $statusProperty -or $null -eq $statusProperty.Value) { return $null }
            $rawValue = $statusProperty.Value
            if ($rawValue -is [int]) { return $rawValue }
            if ($rawValue -is [System.Enum]) { return [int] $rawValue }
            $parsed = 0
            if ([int]::TryParse([string] $rawValue, [ref] $parsed)) { return $parsed }
            return $null
        } catch {
            return $null
        }
    }

    $policyIdRaw = Get-PulseSettingsCatalogValueProperty -Node $Policy -PropertyName 'id'
    $policyId = if ($null -ne $policyIdRaw) { [string] $policyIdRaw } else { $null }

    $policyNameRaw = Get-PulseSettingsCatalogValueProperty -Node $Policy -PropertyName 'name'
    $policyName = if ($null -ne $policyNameRaw) { [string] $policyNameRaw } else { $null }

    $templateFamily = $null
    $templateId = $null
    $templateReference = Get-PulseSettingsCatalogValueProperty -Node $Policy -PropertyName 'templateReference'
    if (Test-PulseSettingsCatalogNode -Node $templateReference) {
        $templateFamilyRaw = Get-PulseSettingsCatalogValueProperty -Node $templateReference -PropertyName 'templateFamily'
        if ($null -ne $templateFamilyRaw) { $templateFamily = [string] $templateFamilyRaw }
        $templateIdRaw = Get-PulseSettingsCatalogValueProperty -Node $templateReference -PropertyName 'templateId'
        if ($null -ne $templateIdRaw) { $templateId = [string] $templateIdRaw }
    }
    $isBaseline = (-not [string]::IsNullOrEmpty($templateId)) -and ($templateFamily -ne 'none')

    $settingsPayload = $null
    $fetchGap = $null

    if ($FromCapturedPayloads) {
        try {
            $settingsPayload = Read-PulseDataset -Store $Store -Name $RawDatasetName
        } catch {
            Write-Verbose "Invoke-PulseSettingsCatalogPolicy: captured payload for '$policyId' unreadable: $($_.Exception.Message)"
            $category = if ($_.Exception.Message -match '(?i)no manifest entry|missing from the snapshot') { 'CapturedPayloadMissing' } else { 'CapturedPayloadUnreadable' }
            $fetchGap = New-PulseStructuredGapReason -Category $category
        }
    } else {
        # READ-ONLY ENFORCEMENT (task-review Critical, symmetric with
        # Invoke-PulseSettingsCatalogExpansionPipeline's own ConfigurationPolicy guard):
        # asserted once per policy, immediately before the Get-GraphObject call it guards -
        # matches Invoke-PulseCollection's own runtime-assertion pattern for every
        # check-driven dataset. A version-drift is downgraded to this policy's own gap (the
        # fan-out continues over the rest); any other assertion failure is a
        # module-authoring bug and is allowed to propagate, aborting the whole run - it is
        # never classified as a per-policy Graph failure.
        $readOnlyDriftGap = $null
        try {
            Assert-PulseReadOnlyDescriptor -Type 'ConfigurationPolicySetting' -Operation 'ListBeta' -ApiVersion 'beta'
        } catch {
            if ($_.Exception.Message -match 'descriptor-version-drift') {
                Write-Verbose "Invoke-PulseSettingsCatalogPolicy: $($_.Exception.Message)"
                $readOnlyDriftGap = New-PulseStructuredGapReason -Category 'FetchFailed'
            } else {
                throw
            }
        }

        if ($readOnlyDriftGap) {
            return [pscustomobject]@{ PolicyId = $policyId; Rows = @(); Gap = $readOnlyDriftGap }
        }

        try {
            $raw = @(Get-GraphObject -Context $Context -Type 'ConfigurationPolicySetting' -Operation 'ListBeta' -Parameters @{ id = $policyId } -ErrorAction Stop)
            $redacted = Protect-PulseSettingsCatalogSecretPayload -Data $raw -DefinitionIndex $DefinitionIndex
            # SECRET-REDACTED at write: this dataset gets the same hash-verified persistence
            # contract every other collected dataset in this module gets (see this
            # function's own docstring and Write-PulseDataset's). -Depth matches the
            # redactor's own budget (DEPTH BUDGET ALIGNMENT, see
            # Invoke-PulseSettingsCatalogExpansion.ps1's own docstring) - Write-PulseDataset's
            # default -Depth (64) is a raw-JSON-node count, the same units the redactor
            # counts in, so a chain the redactor accepted must not then trip a SHALLOWER
            # default here and get misclassified as a fetch failure one step later.
            Write-PulseDataset -Store $Store -Name $RawDatasetName -Data $redacted -ApiVersion 'beta' -Status 'Collected' `
                -Depth $script:PulseSettingsCatalogRawPayloadMaxDepth -TenantId $TenantId -Pseudonym $Pseudonym
            $settingsPayload = $redacted
        } catch {
            Write-Verbose "Invoke-PulseSettingsCatalogPolicy: fetch failed for policy '$policyId': $($_.Exception.Message)"
            $failureClass = Get-PulseFailureClass -ErrorRecord $_
            $statusCode = Get-PulseGraphErrorStatusCode -ErrorRecord $_
            $category = switch ($failureClass) {
                'PermissionDenied' { 'PermissionDenied' }
                'AuthFailure' { 'AuthFailure' }
                default { 'FetchFailed' }
            }
            $fetchGap = New-PulseStructuredGapReason -Category $category -StatusCode $statusCode
        }
    }

    if ($fetchGap) {
        return [pscustomobject]@{ PolicyId = $policyId; Rows = @(); Gap = $fetchGap }
    }

    try {
        $walkResult = ConvertTo-PulseSettingRows -PolicyId $policyId -PolicyType 'settingsCatalog' `
            -PolicyName $policyName -TemplateFamily $templateFamily -IsBaseline $isBaseline `
            -SettingsPayload $settingsPayload -DefinitionIndex $DefinitionIndex -MaxDepth $script:PulseSettingsCatalogWalkerMaxDepth
    } catch {
        # An instanceId collision (or any other internal walk invariant failure) is a
        # data-integrity anomaly scoped to THIS policy - see ConvertTo-PulseSettingRows's
        # own docstring for why it throws rather than silently continuing. Caught here so
        # one policy's anomalous data degrades the fan-out to Partial, never aborts it.
        Write-Verbose "Invoke-PulseSettingsCatalogPolicy: walk failed for policy '$policyId': $($_.Exception.Message)"
        return [pscustomobject]@{ PolicyId = $policyId; Rows = @(); Gap = (New-PulseStructuredGapReason -Category 'InstanceIdCollision') }
    }

    $gap = $null
    if ($walkResult.Gaps.Count -gt 0) {
        # Walk gaps are NOT exception text - they are built entirely from schema-safe
        # fields (settingDefinitionId, settingPath, @odata.type) this function's own code
        # constructs, never from a caught exception's .Message - so they are kept, capped
        # by Protect-PulseReason at the driver, rather than collapsed to a bare category.
        $gap = New-PulseStructuredGapReason -Category 'WalkGap'
        $gap = "$gap;detail:$($walkResult.Gaps -join '| ')"
    }

    return [pscustomobject]@{ PolicyId = $policyId; Rows = $walkResult.Rows; Gap = $gap }
}
