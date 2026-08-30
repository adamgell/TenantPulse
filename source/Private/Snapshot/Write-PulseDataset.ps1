<#
    Private: write one collected dataset into a snapshot store.

    For -Status Collected, strips GraphKit's per-row provenance stamps (_Tenant,
    _RetrievedUtc, _GraphPath, _ApiVersion - see Remove-PulseGraphRowProvenance for why:
    all four duplicate a manifest field this dataset's own entry already carries, or carry
    nothing TenantPulse's schema needs), redacts the raw tenant GUID out of the row
    CONTENT itself when -TenantId/-Pseudonym are supplied (see Protect-PulseGraphRowTenantId
    for why - some Graph payloads, e.g. Organization.id and
    DirectoryRoleAssignment.principalOrganizationId, carry the tenant's own id as a
    genuine response field, not a GraphKit-added stamp), serializes -Data through the
    canonical JSON primitive, writes datasets/<Name>.json, hashes the exact bytes written,
    and records status/apiVersion/sha256/itemCount/collectedUtc in the manifest. For
    -Status Failed or -Status Skipped, no dataset file is written - only the manifest
    entry, via Set-PulseManifestEntry, which is the sole function allowed to touch
    manifest.json.

    -TenantId/-Pseudonym are optional (both must be supplied together to take effect;
    Invoke-PulseCollection's own catch-all callers for Failed/Skipped never pass -Data at
    all, so there is nothing to redact there) - omitting either leaves row content exactly
    as GraphKit returned it minus the provenance stamps, matching this function's
    pre-existing behavior for every caller that has no tenant id in scope.

    -Depth (Task 2.2 depth-alignment fix): forwarded straight through to
    ConvertTo-PulseCanonicalJson's own -Depth. Defaults to 64, unchanged for every existing
    caller. Added specifically because Invoke-PulseSettingsCatalogPolicy's raw
    `configurationPolicySettings-<policyId>` write can legitimately need MORE than 64 raw
    JSON node levels for a walker-valid Settings Catalog tree (raw-node depth counts every
    object AND array, not one level per settingInstance - see ConvertTo-PulseSettingRows.ps1's
    own $script:PulseSettingsCatalogWalkerMaxDepth docstring) - a caller that does not pass
    -Depth explicitly gets the exact same default this function has always had.
#>

function Write-PulseDataset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter()]
        [object[]] $Data = @(),

        [Parameter(Mandatory)]
        [ValidateSet('v1.0', 'beta')]
        [string] $ApiVersion,

        [Parameter(Mandatory)]
        [ValidateSet('Collected', 'Partial', 'Failed', 'Skipped')]
        [string] $Status,

        # Reason is the legacy compatibility adapter. New callers should use ReasonCode and
        # Detail; retaining this parameter keeps existing collectors source-compatible.
        [Parameter()]
        [AllowNull()]
        $Reason,

        [Parameter()]
        [AllowNull()]
        [ValidateNotNullOrEmpty()]
        [string] $ReasonCode,

        [Parameter()]
        [AllowNull()]
        [hashtable] $Detail = $null,

        [Parameter()]
        [AllowNull()]
        $FailureClass = $null,

        [Parameter()]
        [AllowNull()]
        $Provider = $null,

        [Parameter()]
        [AllowNull()]
        [object[]] $Gaps = @(),

        [Parameter()]
        [AllowNull()]
        [object[]] $Operations = @(),

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $TenantId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Pseudonym,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $Depth = 64
    )

    Assert-PulseDatasetName -Name $Name

    $effectiveReasonCode = if (-not [string]::IsNullOrWhiteSpace($ReasonCode)) {
        $ReasonCode
    } elseif ($null -ne $Reason -and -not [string]::IsNullOrWhiteSpace([string] $Reason)) {
        [string] $Reason
    } else {
        $Status.ToLowerInvariant()
    }

    $effectiveFailureClass = $FailureClass
    if ($Status -in @('Failed', 'Skipped') -and $null -eq $effectiveFailureClass) {
        # Legacy callers supplied only free-form -Reason. Never parse that text to infer a
        # class; use the contract's conservative compatibility defaults instead.
        $effectiveFailureClass = if ($Status -eq 'Skipped') { 'GateUnknown' } else { 'ProviderFailed' }
    }

    $outcome = New-PulseCollectionOutcome -Dataset $Name -Status $Status -Rows $Data -Gaps $Gaps `
        -FailureClass $effectiveFailureClass -ReasonCode $effectiveReasonCode -Detail $Detail `
        -Provider $Provider -ApiVersion $ApiVersion -Operations $Operations

    if ($Status -in @('Failed', 'Skipped')) {
        Set-PulseManifestEntry -Store $Store -Name $Name -Status $Status -Reason $Reason `
            -ReasonCode $outcome.ReasonCode -Detail $outcome.Detail -FailureClass $outcome.FailureClass `
            -Provider $outcome.Provider -Operations $outcome.Operations -Gaps $outcome.Gaps `
            -ApiVersion $outcome.ApiVersion
        return
    }

    $items = @($outcome.Rows)
    # NOT wrapped in @(...): Remove-PulseGraphRowProvenance already returns a proper
    # array via the unary comma operator, so the direct assignment preserves every row.
    $items = Remove-PulseGraphRowProvenance -Data $items
    if (-not [string]::IsNullOrEmpty($TenantId) -and -not [string]::IsNullOrEmpty($Pseudonym)) {
        $items = Protect-PulseGraphRowTenantId -Data $items -TenantId $TenantId -Pseudonym $Pseudonym
    }
    $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $items -Depth $Depth
    $datasetPath = Join-Path $Store.DatasetsPath "$Name.json"

    # Hash-what-you-write: the exact UTF-8 byte array is both persisted and hashed.
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
    Set-PulseAtomicFileContent -Path $datasetPath -Bytes $bytes

    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

    $collectedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)

    Set-PulseManifestEntry -Store $Store -Name $Name -Status $Status -Reason $Reason `
        -ReasonCode $outcome.ReasonCode -Detail $outcome.Detail -FailureClass $outcome.FailureClass `
        -Provider $outcome.Provider -Operations $outcome.Operations -Gaps $outcome.Gaps `
        -ApiVersion $outcome.ApiVersion -Sha256 $sha256 -ItemCount $items.Count -CollectedUtc $collectedUtc
}
