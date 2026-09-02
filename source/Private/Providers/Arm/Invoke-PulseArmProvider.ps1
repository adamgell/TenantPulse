<#
    Private: ARM provider adapter entry point.

    No live Azure client lives here. Without an injected Send delegate the
    adapter records the deferred diagnostic-settings disposition and returns.
    Injected tests cover paging, throttle, deadline, cancellation, permission
    denial, and malformed bodies without touching Azure.
#>

function Get-PulseArmResponseHeader {
    param(
        [AllowNull()]
        $Headers,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($null -eq $Headers) { return $null }
    if ($Headers -is [System.Collections.IDictionary]) {
        foreach ($key in $Headers.Keys) {
            if ([string]::Equals([string] $key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Headers[$key]
            }
        }
        return $null
    }

    $property = $Headers.PSObject.Properties | Where-Object {
        [string]::Equals([string] $_.Name, $Name, [System.StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-PulseArmPageContent {
    param(
        [AllowNull()]
        $Body
    )

    if ($null -eq $Body) {
        throw 'ARM page body is missing.'
    }
    if ($Body -is [string] -or $Body -is [ValueType]) {
        throw 'ARM page body is not an object.'
    }

    $value = $null
    $nextLink = $null
    if ($Body -is [System.Collections.IDictionary]) {
        if (-not $Body.Contains('value')) {
            throw 'ARM page body has no value array.'
        }
        $value = $Body['value']
        if ($Body.Contains('nextLink')) { $nextLink = $Body['nextLink'] }
        elseif ($Body.Contains('@odata.nextLink')) { $nextLink = $Body['@odata.nextLink'] }
    }
    else {
        $valueProperty = $Body.PSObject.Properties['value']
        if ($null -eq $valueProperty) {
            throw 'ARM page body has no value array.'
        }
        $value = $valueProperty.Value
        $nextProperty = $Body.PSObject.Properties['nextLink']
        if ($null -eq $nextProperty) {
            $nextProperty = $Body.PSObject.Properties['@odata.nextLink']
        }
        if ($null -ne $nextProperty) { $nextLink = $nextProperty.Value }
    }

    if ($null -eq $value) {
        throw 'ARM page value is null.'
    }

    return [pscustomobject]@{
        Rows     = @($value)
        NextLink = $nextLink
    }
}

function Invoke-PulseArmProvider {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Dataset,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceId,

        [Parameter()]
        [AllowNull()]
        [string] $ApiVersion = $null,

        [Parameter()]
        [ValidateSet('Global', 'USGov', 'China')]
        [string] $Cloud = 'Global',

        [Parameter()]
        [AllowNull()]
        [string] $BoundTenantId = $null,

        [Parameter()]
        [AllowNull()]
        [string] $BoundSubscriptionId = $null,

        [Parameter()]
        [AllowNull()]
        [hashtable] $Injections = $null,

        [Parameter()]
        [System.Threading.CancellationToken] $CancellationToken = [System.Threading.CancellationToken]::None,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int] $MaxAttempts = 5,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int] $DeadlineSeconds = 300,

        [Parameter()]
        [ValidateRange(1, 2000)]
        [int] $MaxPages = 200
    )

    $send = $null
    $utcNow = { [datetime]::UtcNow }
    $delay = { param([double] $Seconds) Start-Sleep -Seconds $Seconds }
    $jitter = { 0.0 }
    $canRefresh = $false
    if ($null -ne $Injections) {
        if ($Injections.ContainsKey('Send')) { $send = $Injections['Send'] }
        if ($Injections.ContainsKey('UtcNow') -and $null -ne $Injections['UtcNow']) { $utcNow = $Injections['UtcNow'] }
        if ($Injections.ContainsKey('Delay') -and $null -ne $Injections['Delay']) { $delay = $Injections['Delay'] }
        if ($Injections.ContainsKey('Jitter') -and $null -ne $Injections['Jitter']) { $jitter = $Injections['Jitter'] }
        if ($Injections.ContainsKey('CanRefresh')) { $canRefresh = [bool] $Injections['CanRefresh'] }
    }

    if ($null -eq $send) {
        $contract = Get-PulseArmDiagnosticSettingsContract
        $detail = @{
            Disposition       = [string] $contract.Disposition
            Provider          = 'ARM'
            RecheckTrigger    = [string] $contract.RecheckTrigger
            MissingDependency = [string] $contract.MissingDependency
            LiveAccess        = 'NotAttempted'
            ResourceId        = [string] $contract.ResourceId
            ChildProvider     = [string] $contract.ChildProvider
            ChildType         = [string] $contract.ChildType
            ApiVersion        = $contract.ApiVersion
            ApiVersionStatus  = [string] $contract.ApiVersionStatus
            RbacActions       = @($contract.RbacActions)
        }
        return ConvertTo-PulseArmCollectionOutcome -Dataset $Dataset -Status 'Skipped' `
            -FailureClass 'DependencyUnavailable' -ReasonCode 'arm-live-contract-deferred' `
            -Detail $detail -ApiVersion $contract.ApiVersion
    }

    $request = New-PulseArmRequest -ResourceId $ResourceId -ApiVersion $ApiVersion -Cloud $Cloud `
        -BoundTenantId $BoundTenantId -BoundSubscriptionId $BoundSubscriptionId
    $provenance = New-PulseArmProvenance -ResourceId $ResourceId -ApiVersion $ApiVersion -Cloud $Cloud `
        -BoundTenantId $BoundTenantId -BoundSubscriptionId $BoundSubscriptionId
    $provenanceTable = ConvertTo-PulseArmProvenanceHashtable -Provenance $provenance
    $rbac = @($request.RbacActions)

    $startUtc = & $utcNow
    $deadlineUtc = $startUtc.AddSeconds([double] $DeadlineSeconds)

    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    $pageUri = $request.Uri
    $pageCount = 0
    $forceRefreshUsed = $false

    function New-ArmFailureDetail {
        param(
            [AllowNull()] $StatusCode = $null,
            [AllowNull()] [string] $Certainty = $null
        )
        $table = @{
            Provenance  = $provenanceTable
            RbacActions = $rbac
        }
        if ($null -ne $StatusCode) { $table.StatusCode = $StatusCode }
        if (-not [string]::IsNullOrWhiteSpace($Certainty)) { $table.Certainty = $Certainty }
        return $table
    }

    function Test-ArmBudget {
        if ($CancellationToken.IsCancellationRequested) { return 'Cancelled' }
        if ((& $utcNow) -ge $deadlineUtc) { return 'DeadlineExpired' }
        return $null
    }

    while ($null -ne $pageUri -and $pageCount -lt $MaxPages) {
        $budget = Test-ArmBudget
        if ($null -ne $budget) {
            if ($rows.Count -eq 0) {
                $class = $budget
                $code = if ($budget -eq 'Cancelled') { 'cancelled' } else { 'deadline-expired' }
                return ConvertTo-PulseArmCollectionOutcome -Dataset $Dataset -Status 'Failed' `
                    -FailureClass $class -ReasonCode $code -Detail (New-ArmFailureDetail -Certainty 'Indeterminate') `
                    -ApiVersion $ApiVersion
            }
            $gaps.Add((New-PulseCollectionGap -Scope 'page' -FailureClass $budget `
                    -ReasonCode $(if ($budget -eq 'Cancelled') { 'cancelled' } else { 'deadline-expired' }) `
                    -Detail @{ certainty = 'Indeterminate' } -Operation 'GET' -ApiVersion $ApiVersion)) | Out-Null
            break
        }

        try {
            $null = Test-PulseArmAuthority -Uri $pageUri -Cloud $Cloud
        }
        catch {
            if ($rows.Count -eq 0) {
                return ConvertTo-PulseArmCollectionOutcome -Dataset $Dataset -Status 'Failed' `
                    -FailureClass 'InvalidProviderData' -ReasonCode 'untrusted-arm-authority' `
                    -Detail (New-ArmFailureDetail) -ApiVersion $ApiVersion
            }
            $gaps.Add((New-PulseCollectionGap -Scope 'nextLink' -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'untrusted-arm-authority' -Detail @{ message = $_.Exception.Message } `
                    -Operation 'GET' -ApiVersion $ApiVersion)) | Out-Null
            break
        }

        $transport = $null
        $decision = $null
        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
            $budget = Test-ArmBudget
            if ($null -ne $budget) {
                $decision = [pscustomobject]@{
                    ShouldRetry  = $false
                    Outcome      = $budget
                    Certainty    = 'Indeterminate'
                    ForceRefresh = $false
                    FailureClass = $budget
                }
                break
            }

            $transport = & $send -Uri $pageUri -Method 'GET'
            $responseReceived = $true
            $statusCode = 0
            if ($null -eq $transport) {
                $responseReceived = $false
            }
            else {
                if ($null -ne $transport.PSObject.Properties['ResponseReceived']) {
                    $responseReceived = [bool] $transport.ResponseReceived
                }
                if ($null -ne $transport.PSObject.Properties['StatusCode']) {
                    $statusCode = [int] $transport.StatusCode
                }
            }

            $certainty = Get-PulseArmAttemptCertainty -StatusCode $statusCode -ResponseReceived $responseReceived
            $decision = Get-PulseArmRetryDecision -Method 'GET' -StatusCode $statusCode `
                -AttemptCertainty $certainty -ForceRefreshUsed $forceRefreshUsed -CanRefresh $canRefresh
            if ($decision.ForceRefresh) { $forceRefreshUsed = $true }
            if (-not $decision.ShouldRetry) { break }

            $retryAfter = $null
            if ($null -ne $transport) {
                $retryAfter = Get-PulseArmResponseHeader -Headers $transport.Headers -Name 'Retry-After'
            }
            $wait = Get-PulseArmRetryDelay -RetryAfter $retryAfter -Attempt $attempt -Jitter $jitter
            & $delay -Seconds $wait
        }

        if ($null -eq $decision) {
            return ConvertTo-PulseArmCollectionOutcome -Dataset $Dataset -Status 'Failed' `
                -FailureClass 'ProviderFailed' -ReasonCode 'provider-failed' `
                -Detail (New-ArmFailureDetail) -ApiVersion $ApiVersion
        }

        if ($decision.Outcome -ne 'Succeeded') {
            $class = $decision.FailureClass
            if ([string]::IsNullOrWhiteSpace($class)) { $class = 'ProviderFailed' }
            $reason = switch ($class) {
                'PermissionDenied' { 'permission-denied' }
                'AuthenticationFailed' { 'authentication-failed' }
                'DeadlineExpired' { 'deadline-expired' }
                'Cancelled' { 'cancelled' }
                'InvalidProviderData' { 'invalid-provider-data' }
                'Indeterminate' { 'indeterminate' }
                default { 'provider-failed' }
            }
            $statusCode = $null
            if ($null -ne $transport -and $null -ne $transport.PSObject.Properties['StatusCode']) {
                $statusCode = $transport.StatusCode
            }
            if ($rows.Count -eq 0) {
                return ConvertTo-PulseArmCollectionOutcome -Dataset $Dataset -Status 'Failed' `
                    -FailureClass $class -ReasonCode $reason `
                    -Detail (New-ArmFailureDetail -StatusCode $statusCode -Certainty $decision.Certainty) `
                    -ApiVersion $ApiVersion
            }
            $gaps.Add((New-PulseCollectionGap -Scope 'page' -FailureClass $class -ReasonCode $reason `
                    -Detail @{ statusCode = $statusCode } -Operation 'GET' -ApiVersion $ApiVersion)) | Out-Null
            break
        }

        try {
            $page = Get-PulseArmPageContent -Body $transport.Body
        }
        catch {
            if ($rows.Count -eq 0) {
                return ConvertTo-PulseArmCollectionOutcome -Dataset $Dataset -Status 'Failed' `
                    -FailureClass 'InvalidProviderData' -ReasonCode 'invalid-provider-data' `
                    -Detail (New-ArmFailureDetail -StatusCode $transport.StatusCode) -ApiVersion $ApiVersion
            }
            $gaps.Add((New-PulseCollectionGap -Scope 'page' -FailureClass 'InvalidProviderData' `
                    -ReasonCode 'invalid-provider-data' -Detail @{ message = $_.Exception.Message } `
                    -Operation 'GET' -ApiVersion $ApiVersion)) | Out-Null
            break
        }

        foreach ($row in $page.Rows) {
            $rows.Add($row) | Out-Null
        }
        $pageCount++
        if ([string]::IsNullOrWhiteSpace([string] $page.NextLink)) {
            $pageUri = $null
        }
        else {
            $pageUri = [uri] $page.NextLink
        }
    }

    if ($pageCount -ge $MaxPages -and $null -ne $pageUri) {
        $gaps.Add((New-PulseCollectionGap -Scope 'page' -FailureClass 'ProviderFailed' `
                -ReasonCode 'arm-page-cap' -Detail @{ maxPages = $MaxPages } `
                -Operation 'GET' -ApiVersion $ApiVersion)) | Out-Null
    }

    $detail = @{
        Provenance  = $provenanceTable
        RbacActions = $rbac
        PageCount   = $pageCount
    }

    if ($gaps.Count -gt 0) {
        return ConvertTo-PulseArmCollectionOutcome -Dataset $Dataset -Status 'Partial' -Rows $rows.ToArray() `
            -Gaps $gaps.ToArray() -ReasonCode 'partial' -Detail $detail -ApiVersion $ApiVersion
    }

    return ConvertTo-PulseArmCollectionOutcome -Dataset $Dataset -Status 'Collected' -Rows $rows.ToArray() `
        -ReasonCode 'collected' -Detail $detail -ApiVersion $ApiVersion
}
