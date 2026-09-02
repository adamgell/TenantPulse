<#
    Private: catalog-wide GraphKit permission preflight and no-send gate.

    Test-GraphPermission runs once per immutable context with TargetAppId = Context.ClientId
    and Baseline = the exact selected descriptor union (ordinary datasets, composite
    children, expansion operations, and caller-supplied future Graph-backed plans such as
    app-health). Directory reads are authoritative; token claims are never consulted.
    Findings normalize to TenantPulse Granted / Denied / Unknown. NotApplicable remains a
    license/product outcome, not a GraphKit permission state.

    No target data operation is sent until an authorization decision exists. MissingGrant,
    ServicePrincipalMissing, incompatible or unknown authentication, bootstrap-trap errors,
    and malformed finding sets are fail-closed no-send.
#>

$script:PulseNoNetworkPreflightDatasets = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
[void] $script:PulseNoNetworkPreflightDatasets.Add('dataProcessorServiceForWindowsFeaturesOnboarding')

$script:PulseCompositeChildOperations = [ordered]@{
    intuneRbacGroupProtection = @(
        @{ Type = 'DeviceManagementUnifiedRoleAssignment'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'Group'; Operation = 'Get'; ApiVersion = 'v1.0' }
    )
    endpointSecurityDiskEncryptionPolicies = @(
        @{ Type = 'ConfigurationPolicy'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    )
    endpointSecurityLapsPolicies = @(
        @{ Type = 'ConfigurationPolicy'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    )
    securityBaselinesAssignedAndCurrent = @(
        @{ Type = 'DeviceManagementTemplate'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'DeviceManagementConfigurationPolicyTemplate'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'ConfigurationPolicy'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'DeviceManagementIntent'; Operation = 'ListBeta'; ApiVersion = 'beta' }
        @{ Type = 'ConfigurationPolicyAssignment'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    )
}

$script:PulseExpansionOperations = @(
    @{ Type = 'ConfigurationPolicy'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    @{ Type = 'ConfigurationPolicySetting'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    @{ Type = 'ConfigurationPolicyAssignment'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    @{ Type = 'ConfigurationSettingDefinition'; Operation = 'ListBeta'; ApiVersion = 'beta' }
    @{ Type = 'DeviceCompliancePolicyAssignment'; Operation = 'List'; ApiVersion = 'v1.0' }
    @{ Type = 'DeviceConfigurationAssignment'; Operation = 'List'; ApiVersion = 'v1.0' }
)

function Get-PulsePermissionOperationKey {
    param(
        [Parameter(Mandatory)]
        [string] $Type,
        [Parameter(Mandatory)]
        [string] $Operation
    )
    return '{0}/{1}' -f $Type, $Operation
}

function Add-PulsePermissionPreflightOperation {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary] $Operations,
        [Parameter(Mandatory)]
        [AllowNull()]
        $Candidate
    )

    if ($null -eq $Candidate) { return }

    $type = [string] $Candidate.Type
    $operation = [string] $Candidate.Operation
    if ([string]::IsNullOrWhiteSpace($type) -or [string]::IsNullOrWhiteSpace($operation)) { return }

    $key = Get-PulsePermissionOperationKey -Type $type -Operation $operation
    if ($Operations.Contains($key)) { return }

    $apiVersion = 'v1.0'
    if ($Candidate -is [System.Collections.IDictionary] -and $Candidate.Contains('ApiVersion') -and $Candidate.ApiVersion) {
        $apiVersion = [string] $Candidate.ApiVersion
    }
    elseif ($Candidate.PSObject.Properties['ApiVersion'] -and $Candidate.ApiVersion) {
        $apiVersion = [string] $Candidate.ApiVersion
    }

    $Operations[$key] = [pscustomobject]@{
        Type       = $type
        Operation  = $operation
        ApiVersion = $apiVersion
    }
}

function Get-PulsePermissionPreflightOperations {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Manifest = @(),

        [Parameter()]
        [switch] $ExpandSettings,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $AdditionalOperations = @()
    )

    $operations = [ordered]@{}
    foreach ($entry in @($Manifest)) {
        if ($null -eq $entry) { continue }
        $dataset = [string] $entry.Dataset
        if ($script:PulseNoNetworkPreflightDatasets.Contains($dataset)) { continue }

        if ($script:PulseCompositeChildOperations.Contains($dataset)) {
            foreach ($child in @($script:PulseCompositeChildOperations[$dataset])) {
                Add-PulsePermissionPreflightOperation -Operations $operations -Candidate $child
            }
            continue
        }

        $isPending = $false
        if ($entry.PSObject.Properties['Pending'] -and $entry.Pending) { $isPending = [bool] $entry.Pending }
        if ($isPending) { continue }

        Add-PulsePermissionPreflightOperation -Operations $operations -Candidate $entry
    }

    if ($ExpandSettings) {
        foreach ($expansion in $script:PulseExpansionOperations) {
            Add-PulsePermissionPreflightOperation -Operations $operations -Candidate $expansion
        }
    }

    foreach ($additional in @($AdditionalOperations)) {
        Add-PulsePermissionPreflightOperation -Operations $operations -Candidate $additional
    }

    $keys = @($operations.Keys)
    if ($keys.Count -gt 1) {
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
    }
    return @(foreach ($key in $keys) { $operations[$key] })
}

function Get-PulsePermissionFinding {
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Findings,
        [Parameter(Mandatory)]
        [string] $Name
    )

    foreach ($finding in @($Findings)) {
        if ($null -ne $finding -and [string] $finding.Finding -eq $Name) {
            return $finding
        }
    }
    return $null
}

function Test-PulsePermissionFindingsWellFormed {
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Findings
    )

    if ($null -eq $Findings -or @($Findings).Count -eq 0) { return $false }
    foreach ($required in @('Configured', 'Granted', 'MissingGrant', 'ExcessGranted', 'AuthenticationCompatible')) {
        $finding = Get-PulsePermissionFinding -Findings $Findings -Name $required
        if ($null -eq $finding) { return $false }
        if (-not $finding.PSObject.Properties['Value']) { return $false }
        if ($null -eq $finding.Value) { return $false }
    }
    return $true
}

function Get-PulseMissingGrantValues {
    param([AllowNull()] $Value)

    $text = [string] $Value
    if ([string]::IsNullOrWhiteSpace($text) -or [string]::Equals($text, 'None', [System.StringComparison]::OrdinalIgnoreCase)) {
        return @()
    }

    return @(
        $text.Split(',') |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not [string]::Equals($_, 'None', [System.StringComparison]::OrdinalIgnoreCase) }
    )
}

function Get-PulseRequiredPermissionValues {
    param([AllowNull()] $Descriptor)

    $values = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Descriptor) { return @() }

    $permissions = $null
    if ($Descriptor -is [System.Collections.IDictionary] -and $Descriptor.Contains('RequiredPermissions')) {
        $permissions = $Descriptor['RequiredPermissions']
    }
    elseif ($Descriptor.PSObject.Properties['RequiredPermissions']) {
        $permissions = $Descriptor.RequiredPermissions
    }

    foreach ($permission in @($permissions)) {
        if ($null -eq $permission) { continue }
        $value = $null
        if ($permission -is [System.Collections.IDictionary] -and $permission.Contains('Value')) {
            $value = [string] $permission['Value']
        }
        elseif ($permission.PSObject.Properties['Value']) {
            $value = [string] $permission.Value
        }
        else {
            $value = [string] $permission
        }
        if (-not [string]::IsNullOrWhiteSpace($value)) { $values.Add($value) }
    }

    return @($values)
}

function New-PulsePermissionOperationDecision {
    param(
        [Parameter(Mandatory)] [string] $Type,
        [Parameter(Mandatory)] [string] $Operation,
        [string] $ApiVersion = 'v1.0',
        [AllowNull()] $Stability = $null,
        [Parameter(Mandatory)] [ValidateSet('Granted', 'Denied', 'Unknown')] [string] $Decision,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $RequiredPermissions = @()
    )

    return [pscustomobject][ordered]@{
        Type                = $Type
        Operation           = $Operation
        ApiVersion          = $ApiVersion
        Stability           = $Stability
        Decision            = $Decision
        ReasonCode          = $ReasonCode
        RequiredPermissions = @($RequiredPermissions)
    }
}

function New-PulsePermissionPreflightResult {
    param(
        [AllowNull()] $TargetAppId,
        [Parameter(Mandatory)] [ValidateSet('Granted', 'Denied', 'Unknown')] [string] $Decision,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] $Decisions,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Findings = @()
    )

    return [pscustomobject][ordered]@{
        PSTypeName  = 'TenantPulse.PermissionPreflight'
        TargetAppId = $TargetAppId
        Decision    = $Decision
        ReasonCode  = $ReasonCode
        Decisions   = $Decisions
        Findings    = @($Findings)
    }
}

function Set-PulsePermissionPreflightDecisions {
    param(
        [Parameter(Mandatory)] [System.Collections.Specialized.OrderedDictionary] $Decisions,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Operations,
        [Parameter(Mandatory)] [ValidateSet('Granted', 'Denied', 'Unknown')] [string] $Decision,
        [Parameter(Mandatory)] [string] $ReasonCode
    )

    foreach ($operation in @($Operations)) {
        $key = Get-PulsePermissionOperationKey -Type $operation.Type -Operation $operation.Operation
        $Decisions[$key] = New-PulsePermissionOperationDecision -Type $operation.Type -Operation $operation.Operation `
            -ApiVersion $operation.ApiVersion -Decision $Decision -ReasonCode $ReasonCode `
            -RequiredPermissions @($operation.RequiredPermissions)
    }
}

function Invoke-PulsePermissionPreflight {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Context,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Operations = @(),

        [Parameter()]
        [AllowNull()]
        $HomeTenantContext = $null
    )

    $targetAppId = $null
    if ($null -ne $Context -and $Context.PSObject.Properties['ClientId'] -and $null -ne $Context.ClientId) {
        $targetAppId = $Context.ClientId
    }

    $selected = @($Operations | Where-Object { $null -ne $_ -and $_.Type -and $_.Operation })
    $decisions = [ordered]@{}
    if ($selected.Count -eq 0) {
        return New-PulsePermissionPreflightResult -TargetAppId $targetAppId -Decision 'Granted' `
            -ReasonCode 'granted' -Decisions $decisions -Findings @()
    }

    if ($null -eq $targetAppId) {
        $targetAppId = [guid]::Empty
    }


    $baseline = [System.Collections.Generic.List[object]]::new()
    $resolved = [System.Collections.Generic.List[object]]::new()
    foreach ($operation in $selected) {
        $descriptor = $null
        try {
            $descriptor = Get-GraphOperation -Type $operation.Type -Operation $operation.Operation -ErrorAction Stop
        }
        catch {
            $descriptor = $null
        }

        $required = Get-PulseRequiredPermissionValues -Descriptor $(if ($null -ne $descriptor) { $descriptor } else { $operation })
        $apiVersion = $operation.ApiVersion
        $stability = $null
        if ($null -ne $descriptor) {
            if ($descriptor -is [System.Collections.IDictionary]) {
                if ($descriptor.Contains('ApiVersion') -and $descriptor.ApiVersion) { $apiVersion = [string] $descriptor.ApiVersion }
                if ($descriptor.Contains('Stability')) { $stability = $descriptor.Stability }
                [void] $baseline.Add($descriptor)
            }
            else {
                if ($descriptor.PSObject.Properties['ApiVersion'] -and $descriptor.ApiVersion) { $apiVersion = [string] $descriptor.ApiVersion }
                if ($descriptor.PSObject.Properties['Stability']) { $stability = $descriptor.Stability }
                [void] $baseline.Add($descriptor)
            }
        }

        $resolved.Add([pscustomobject]@{
                Type                = $operation.Type
                Operation           = $operation.Operation
                ApiVersion          = $apiVersion
                Stability           = $stability
                RequiredPermissions = $required
                Resolved            = ($null -ne $descriptor)
            }) | Out-Null
    }

    $findings = $null
    try {
        $preflightParams = @{
            Context      = $Context
            TargetAppId  = $targetAppId
            Baseline     = @($baseline)
            ErrorAction  = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('HomeTenantContext')) {
            $preflightParams.HomeTenantContext = $HomeTenantContext
        }
        $findings = @(Test-GraphPermission @preflightParams)
    }
    catch {
        $message = [string] $_.Exception.Message
        $reasonCode = 'permission-preflight-failed'
        if ($message -match 'Application\.Read\.All' -or $message -match 'Directory\.Read\.All' -or $message -match 'bootstrap-trap') {
            $reasonCode = 'bootstrap-trap'
        }
        Set-PulsePermissionPreflightDecisions -Decisions $decisions -Operations $resolved -Decision 'Unknown' -ReasonCode $reasonCode
        return New-PulsePermissionPreflightResult -TargetAppId $targetAppId -Decision 'Unknown' `
            -ReasonCode $reasonCode -Decisions $decisions -Findings @()
    }

    if (-not (Test-PulsePermissionFindingsWellFormed -Findings $findings)) {
        Set-PulsePermissionPreflightDecisions -Decisions $decisions -Operations $resolved -Decision 'Unknown' -ReasonCode 'malformed-finding-set'
        return New-PulsePermissionPreflightResult -TargetAppId $targetAppId -Decision 'Unknown' `
            -ReasonCode 'malformed-finding-set' -Decisions $decisions -Findings $findings
    }

    $servicePrincipalMissing = Get-PulsePermissionFinding -Findings $findings -Name 'ServicePrincipalMissing'
    if ($null -ne $servicePrincipalMissing -and [string] $servicePrincipalMissing.Value -and
        -not [string]::Equals([string] $servicePrincipalMissing.Value, 'No', [System.StringComparison]::OrdinalIgnoreCase) -and
        -not [string]::Equals([string] $servicePrincipalMissing.Value, 'None', [System.StringComparison]::OrdinalIgnoreCase)) {
        Set-PulsePermissionPreflightDecisions -Decisions $decisions -Operations $resolved -Decision 'Denied' -ReasonCode 'service-principal-missing'
        return New-PulsePermissionPreflightResult -TargetAppId $targetAppId -Decision 'Denied' `
            -ReasonCode 'service-principal-missing' -Decisions $decisions -Findings $findings
    }

    $authentication = Get-PulsePermissionFinding -Findings $findings -Name 'AuthenticationCompatible'
    $authenticationValue = [string] $authentication.Value
    if ([string]::Equals($authenticationValue, 'No', [System.StringComparison]::OrdinalIgnoreCase)) {
        Set-PulsePermissionPreflightDecisions -Decisions $decisions -Operations $resolved -Decision 'Denied' -ReasonCode 'authentication-incompatible'
        return New-PulsePermissionPreflightResult -TargetAppId $targetAppId -Decision 'Denied' `
            -ReasonCode 'authentication-incompatible' -Decisions $decisions -Findings $findings
    }
    if ([string]::Equals($authenticationValue, 'Unknown', [System.StringComparison]::OrdinalIgnoreCase)) {
        Set-PulsePermissionPreflightDecisions -Decisions $decisions -Operations $resolved -Decision 'Unknown' -ReasonCode 'authentication-unknown'
        return New-PulsePermissionPreflightResult -TargetAppId $targetAppId -Decision 'Unknown' `
            -ReasonCode 'authentication-unknown' -Decisions $decisions -Findings $findings
    }

    $missingValues = Get-PulseMissingGrantValues -Value (Get-PulsePermissionFinding -Findings $findings -Name 'MissingGrant').Value
    $missingSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($value in $missingValues) { [void] $missingSet.Add($value) }

    $anyDenied = $false
    $anyUnknown = $false
    foreach ($operation in $resolved) {
        $key = Get-PulsePermissionOperationKey -Type $operation.Type -Operation $operation.Operation
        $blocked = @($operation.RequiredPermissions | Where-Object { $missingSet.Contains($_) })
        if ($blocked.Count -gt 0) {
            $anyDenied = $true
            $decisions[$key] = New-PulsePermissionOperationDecision -Type $operation.Type -Operation $operation.Operation `
                -ApiVersion $operation.ApiVersion -Stability $operation.Stability -Decision 'Denied' `
                -ReasonCode 'missing-grant' -RequiredPermissions @($operation.RequiredPermissions)
            continue
        }

        $decisions[$key] = New-PulsePermissionOperationDecision -Type $operation.Type -Operation $operation.Operation `
            -ApiVersion $operation.ApiVersion -Stability $operation.Stability -Decision 'Granted' `
            -ReasonCode 'granted' -RequiredPermissions @($operation.RequiredPermissions)
    }

    $overall = 'Granted'
    $reasonCode = 'granted'
    if ($anyDenied) {
        $overall = 'Denied'
        $reasonCode = 'missing-grant'
    }
    elseif ($anyUnknown) {
        $overall = 'Unknown'
        $reasonCode = 'permission-unknown'
    }

    return New-PulsePermissionPreflightResult -TargetAppId $targetAppId -Decision $overall `
        -ReasonCode $reasonCode -Decisions $decisions -Findings $findings
}

function Get-PulseOperationAuthorization {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()] $AuthorizationDecision,
        [Parameter(Mandatory)] [string] $Type,
        [Parameter(Mandatory)] [string] $Operation
    )

    $key = Get-PulsePermissionOperationKey -Type $Type -Operation $Operation
    if ($null -ne $AuthorizationDecision -and $null -ne $AuthorizationDecision.Decisions -and $AuthorizationDecision.Decisions.Contains($key)) {
        return $AuthorizationDecision.Decisions[$key]
    }

    return New-PulsePermissionOperationDecision -Type $Type -Operation $Operation -Decision 'Unknown' -ReasonCode 'missing-decision'
}

function Test-PulseOperationAuthorized {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()] $AuthorizationDecision,
        [Parameter(Mandatory)] [string] $Type,
        [Parameter(Mandatory)] [string] $Operation
    )

    if ($null -eq $AuthorizationDecision) { return $true }
    $decision = Get-PulseOperationAuthorization -AuthorizationDecision $AuthorizationDecision -Type $Type -Operation $Operation
    return $decision.Decision -eq 'Granted'
}

function Get-PulseDatasetAuthorization {
    [CmdletBinding()]
    param(
        [AllowNull()] $AuthorizationDecision,
        [Parameter(Mandatory)] $ManifestEntry
    )

    $dataset = [string] $ManifestEntry.Dataset
    if ($script:PulseNoNetworkPreflightDatasets.Contains($dataset)) {
        return [pscustomobject]@{ Decision = 'Granted'; ReasonCode = 'no-network'; Operations = @() }
    }

    $candidates = @()
    if ($script:PulseCompositeChildOperations.Contains($dataset)) {
        $candidates = @($script:PulseCompositeChildOperations[$dataset])
    }
    else {
        $isPending = $false
        if ($ManifestEntry.PSObject.Properties['Pending'] -and $ManifestEntry.Pending) { $isPending = [bool] $ManifestEntry.Pending }
        if (-not $isPending) {
            $candidates = @($ManifestEntry)
        }
    }

    if ($candidates.Count -eq 0) {
        return [pscustomobject]@{ Decision = 'Granted'; ReasonCode = 'no-graph-operation'; Operations = @() }
    }

    $denied = $null
    $unknown = $null
    foreach ($candidate in $candidates) {
        $decision = Get-PulseOperationAuthorization -AuthorizationDecision $AuthorizationDecision `
            -Type $candidate.Type -Operation $candidate.Operation
        if ($decision.Decision -eq 'Denied' -and $null -eq $denied) { $denied = $decision }
        if ($decision.Decision -eq 'Unknown' -and $null -eq $unknown) { $unknown = $decision }
    }

    if ($null -ne $denied) {
        return [pscustomobject]@{ Decision = 'Denied'; ReasonCode = $denied.ReasonCode; Operations = $candidates }
    }
    if ($null -ne $unknown) {
        return [pscustomobject]@{ Decision = 'Unknown'; ReasonCode = $unknown.ReasonCode; Operations = $candidates }
    }
    return [pscustomobject]@{ Decision = 'Granted'; ReasonCode = 'granted'; Operations = $candidates }
}

function Convert-PulseGraphObjectResult {
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Result
    )

    $items = @($Result)
    if ($items.Count -eq 1 -and $null -ne $items[0]) {
        $candidate = $items[0]
        $hasOutcome = $false
        $hasCertainty = $false
        if ($candidate -is [System.Collections.IDictionary]) {
            $hasOutcome = $candidate.Contains('Outcome')
            $hasCertainty = $candidate.Contains('Certainty')
        }
        else {
            $hasOutcome = [bool] $candidate.PSObject.Properties['Outcome']
            $hasCertainty = [bool] $candidate.PSObject.Properties['Certainty']
        }
        if ($hasOutcome -and $hasCertainty) { return $candidate }
    }

    return [pscustomobject]@{
        PSTypeName = 'GraphKit.OperationResult'
        Outcome    = 'Succeeded'
        Certainty  = 'Known'
        Truncated  = $false
        Data       = $items
    }
}

function Get-PulseGraphObjectRows {
    param([AllowNull()] $Envelope)

    if ($null -eq $Envelope) { return @() }
    if ($Envelope -is [System.Collections.IDictionary] -and $Envelope.Contains('Data')) {
        return @($Envelope['Data'])
    }
    if ($Envelope.PSObject.Properties['Data']) {
        return @($Envelope.Data)
    }
    return @()
}

function Test-PulseGraphEnvelopeIncomplete {
    param([AllowNull()] $Envelope)

    if ($null -eq $Envelope) { return $false }
    $truncated = $false
    $certainty = $null
    if ($Envelope -is [System.Collections.IDictionary]) {
        if ($Envelope.Contains('Truncated')) { $truncated = [bool] $Envelope['Truncated'] }
        if ($Envelope.Contains('Certainty')) { $certainty = [string] $Envelope['Certainty'] }
    }
    else {
        if ($Envelope.PSObject.Properties['Truncated']) { $truncated = [bool] $Envelope.Truncated }
        if ($Envelope.PSObject.Properties['Certainty']) { $certainty = [string] $Envelope.Certainty }
    }
    return ($truncated -or [string]::Equals($certainty, 'Indeterminate', [System.StringComparison]::OrdinalIgnoreCase))
}

function Invoke-PulseGraphRead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string] $Type,

        [Parameter(Mandatory)]
        [string] $Operation,

        [Parameter()]
        [hashtable] $Parameters
    )

    $graphObjectParams = @{
        Context        = $Context
        Type           = $Type
        Operation      = $Operation
        PassThruResult = $true
        ErrorAction    = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Parameters') -and $null -ne $Parameters) {
        $graphObjectParams.Parameters = $Parameters
    }

    $envelope = Convert-PulseGraphObjectResult -Result (Get-GraphObject @graphObjectParams)
    return @(Get-PulseGraphObjectRows -Envelope $envelope)
}

