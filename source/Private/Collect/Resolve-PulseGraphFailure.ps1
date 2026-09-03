<#
    Private: convert any caught GraphKit ErrorRecord into one provider-neutral failure DTO.

    This is the sole production interpreter of GraphKit outcome, certainty, category,
    telemetry status, and fallback message signals. It is deliberately total: malformed or
    hostile input can reduce fidelity only to ProviderFailed; it can never throw from a
    collector catch block.
#>

function Resolve-PulseGraphFailure {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    function New-Resolution {
        param(
            [string] $FailureClass,
            [string] $ReasonCode,
            [bool] $AbortCollection,
            [bool] $HasStructuredSignal,
            [AllowNull()] [object] $StatusCode
        )

        [pscustomobject]@{
            PSTypeName          = 'TenantPulse.GraphFailureResolution'
            FailureClass       = $FailureClass
            ReasonCode         = $ReasonCode
            AbortCollection    = $AbortCollection
            HasStructuredSignal = $HasStructuredSignal
            StatusCode         = $StatusCode
        }
    }

    function Get-SafeProperty {
        param(
            [AllowNull()] [object] $InputObject,
            [Parameter(Mandatory)] [string] $Name
        )

        try {
            if ($null -eq $InputObject) {
                return [pscustomobject]@{ Success = $false; Value = $null }
            }
            if ($InputObject -is [System.Collections.IDictionary]) {
                if (-not $InputObject.Contains($Name)) {
                    return [pscustomobject]@{ Success = $false; Value = $null }
                }
                return [pscustomobject]@{ Success = $true; Value = $InputObject[$Name] }
            }

            $property = $InputObject.PSObject.Properties[$Name]
            if ($null -eq $property) {
                return [pscustomobject]@{ Success = $false; Value = $null }
            }
            return [pscustomobject]@{ Success = $true; Value = $property.Value }
        } catch {
            return [pscustomobject]@{ Success = $false; Value = $null }
        }
    }

    function ConvertTo-SafeString {
        param([AllowNull()] [object] $Value)

        try {
            if ($null -eq $Value) { return $null }
            return [string] $Value
        } catch {
            return $null
        }
    }

    function ConvertTo-SafeStatusCode {
        param([AllowNull()] [object] $Value)

        try {
            if ($null -eq $Value) { return $null }
            if ($Value -is [System.Enum]) { return [int] $Value }
            if ($Value -is [int]) { return $Value }

            $text = ConvertTo-SafeString -Value $Value
            if ($null -eq $text) { return $null }
            $parsed = 0
            if ([int]::TryParse($text, [ref] $parsed)) { return $parsed }
        } catch {
            return $null
        }
        return $null
    }

    $fallback = New-Resolution -FailureClass 'ProviderFailed' -ReasonCode 'provider-failed' `
        -AbortCollection $false -HasStructuredSignal $false -StatusCode $null
    if ($null -eq $ErrorRecord) { return $fallback }

    try {
        $hasStructuredSignal = $false
        $outcome = $null
        $certainty = $null
        $statusCode = $null
        $category = $null
        $message = $null

        $targetRead = Get-SafeProperty -InputObject $ErrorRecord -Name 'TargetObject'
        $target = if ($targetRead.Success) { $targetRead.Value } else { $null }
        if ($null -ne $target) {
            $outcomeRead = Get-SafeProperty -InputObject $target -Name 'Outcome'
            if ($outcomeRead.Success) {
                $outcome = ConvertTo-SafeString -Value $outcomeRead.Value
                if (-not [string]::IsNullOrWhiteSpace($outcome)) { $hasStructuredSignal = $true }
            }

            $certaintyRead = Get-SafeProperty -InputObject $target -Name 'Certainty'
            if ($certaintyRead.Success) {
                $certainty = ConvertTo-SafeString -Value $certaintyRead.Value
                if (-not [string]::IsNullOrWhiteSpace($certainty)) { $hasStructuredSignal = $true }
            }

            $telemetryRead = Get-SafeProperty -InputObject $target -Name 'Telemetry'
            if ($telemetryRead.Success -and $null -ne $telemetryRead.Value -and
                $telemetryRead.Value -isnot [string] -and
                $telemetryRead.Value -isnot [System.Collections.IDictionary]) {
                try {
                    $attempts = @($telemetryRead.Value)
                    if ($attempts.Count -gt 0 -and $null -ne $attempts[-1]) {
                        $statusRead = Get-SafeProperty -InputObject $attempts[-1] -Name 'StatusCode'
                        if ($statusRead.Success) {
                            $statusCode = ConvertTo-SafeStatusCode -Value $statusRead.Value
                            if ($null -ne $statusCode) { $hasStructuredSignal = $true }
                        }
                    }
                } catch {
                    $statusCode = $null
                }
            }
        }

        $categoryInfoRead = Get-SafeProperty -InputObject $ErrorRecord -Name 'CategoryInfo'
        if ($categoryInfoRead.Success -and $null -ne $categoryInfoRead.Value) {
            $categoryRead = Get-SafeProperty -InputObject $categoryInfoRead.Value -Name 'Category'
            if ($categoryRead.Success) { $category = ConvertTo-SafeString -Value $categoryRead.Value }
        }
        $knownGraphKitCategories = @(
            'AuthenticationError', 'PermissionDenied', 'ObjectNotFound', 'OperationTimeout',
            'LimitsExceeded', 'ResourceUnavailable', 'InvalidResult'
        )
        if ($knownGraphKitCategories -contains $category) { $hasStructuredSignal = $true }

        $exceptionRead = Get-SafeProperty -InputObject $ErrorRecord -Name 'Exception'
        if ($exceptionRead.Success -and $null -ne $exceptionRead.Value) {
            $messageRead = Get-SafeProperty -InputObject $exceptionRead.Value -Name 'Message'
            if ($messageRead.Success) { $message = ConvertTo-SafeString -Value $messageRead.Value }
        }
        if ($null -eq $message) { $message = '' }

        if ([string]::Equals($outcome, 'DeadlineExpired', [System.StringComparison]::OrdinalIgnoreCase)) {
            return New-Resolution -FailureClass 'DeadlineExpired' -ReasonCode 'deadline-expired' `
                -AbortCollection $false -HasStructuredSignal $hasStructuredSignal -StatusCode $statusCode
        }
        if ([string]::Equals($outcome, 'Cancelled', [System.StringComparison]::OrdinalIgnoreCase)) {
            return New-Resolution -FailureClass 'Cancelled' -ReasonCode 'cancelled' `
                -AbortCollection $false -HasStructuredSignal $hasStructuredSignal -StatusCode $statusCode
        }
        if ([string]::Equals($certainty, 'Indeterminate', [System.StringComparison]::OrdinalIgnoreCase)) {
            return New-Resolution -FailureClass 'Indeterminate' -ReasonCode 'indeterminate' `
                -AbortCollection $false -HasStructuredSignal $hasStructuredSignal -StatusCode $statusCode
        }

        $isPermission = $statusCode -eq 403 -or $category -eq 'PermissionDenied' -or
            $message -match '(?i)\b403\b|\bforbidden\b|accessdenied'
        if ($isPermission) {
            return New-Resolution -FailureClass 'PermissionDenied' -ReasonCode 'permission-denied' `
                -AbortCollection $false -HasStructuredSignal $hasStructuredSignal -StatusCode $statusCode
        }

        $isAuthentication = $statusCode -eq 401 -or $category -eq 'AuthenticationError' -or
            $message -match '(?i)AADSTS\d+|token acquisition|\b401\b|\bunauthorized\b'
        if ($isAuthentication) {
            return New-Resolution -FailureClass 'AuthenticationFailed' -ReasonCode 'authentication-failed' `
                -AbortCollection $true -HasStructuredSignal $hasStructuredSignal -StatusCode $statusCode
        }

        return New-Resolution -FailureClass 'ProviderFailed' -ReasonCode 'provider-failed' `
            -AbortCollection $false -HasStructuredSignal $hasStructuredSignal -StatusCode $statusCode
    } catch {
        return $fallback
    }
}

# Private helper (not exported): safely reads one persisted Graph envelope signal (e.g.
# 'truncated' or 'certainty') from a detail/outcome object that may be either a hashtable
# or a PSCustomObject. This is the ONLY place outside Resolve-PulseGraphFailure itself that
# is allowed to interpret a GraphKit signal name: callers that need a raw signal value route
# through here rather than reading a named member directly, which keeps the
# "sole production interpreter" contract enforceable by the source scan in
# GraphFailureAdapterContracts.Tests.ps1. Totally non-throwing - an absent or unreadable
# signal returns $null.
function Get-PulseGraphSignal {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    try {
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($Name)) {
                return $InputObject[$Name]
            }
            return $null
        }

        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -eq $property) {
            return $null
        }
        return $property.Value
    } catch {
        return $null
    }
}
