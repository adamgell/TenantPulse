<#
    Private: ARM retry decision and Retry-After delay.

    The ARM adapter issues Safe GET reads only. POST is accepted on the decision
    surface so an accidental mutating call cannot replay an ambiguous attempt.
    Delay parsing never decides whether to retry.
#>

function Get-PulseArmAttemptCertainty {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int] $StatusCode,

        [Parameter(Mandatory)]
        [bool] $ResponseReceived
    )

    if ($ResponseReceived) {
        if ($StatusCode -ge 200 -and $StatusCode -lt 300) { return 'Succeeded' }
        if ($StatusCode -eq 408) { return 'Ambiguous' }
        if ($StatusCode -ge 500 -and $StatusCode -le 599) { return 'Ambiguous' }
        return 'Rejected'
    }

    return 'Ambiguous'
}

function Get-PulseArmRetryDelay {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter()]
        [AllowNull()]
        $RetryAfter,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int] $Attempt = 1,

        [Parameter()]
        [scriptblock] $Jitter = { 0.0 },

        [Parameter()]
        [double] $MaximumSeconds = 60
    )

    $delay = 0.0
    if ($null -ne $RetryAfter -and -not [string]::IsNullOrWhiteSpace([string] $RetryAfter)) {
        $raw = [string] $RetryAfter
        $seconds = 0
        if ([int]::TryParse($raw, [ref] $seconds) -and $seconds -gt 0) {
            $delay = [double] $seconds
        }
        else {
            $dto = [System.DateTimeOffset]::MinValue
            if ([System.DateTimeOffset]::TryParse(
                    $raw,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AllowWhiteSpaces,
                    [ref] $dto)) {
                $delta = ($dto.UtcDateTime - [datetime]::UtcNow).TotalSeconds
                if ($delta -gt 0) { $delay = $delta }
            }
        }
    }

    if ($delay -le 0) {
        $base = [Math]::Pow(2, [Math]::Min(5, [Math]::Max(0, $Attempt - 1)))
        $delay = $base + [double] (& $Jitter)
    }

    return [Math]::Max(0.0, [Math]::Min($MaximumSeconds, $delay))
}

function Get-PulseArmRetryDecision {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string] $Method,

        [Parameter(Mandatory)]
        [int] $StatusCode,

        [Parameter(Mandatory)]
        [ValidateSet('Succeeded', 'Rejected', 'Ambiguous', 'MayHaveCommitted')]
        [string] $AttemptCertainty,

        [Parameter()]
        [bool] $ForceRefreshUsed = $false,

        [Parameter()]
        [bool] $CanRefresh = $false
    )

    $isRead = $Method -in @('GET', 'HEAD')

    function New-ArmDecision {
        param(
            [bool] $ShouldRetry,
            $Outcome = $null,
            [string] $Certainty = 'Known',
            [bool] $ForceRefresh = $false,
            $FailureClass = $null
        )
        return [pscustomobject][ordered]@{
            ShouldRetry  = $ShouldRetry
            Outcome      = $Outcome
            Certainty    = $Certainty
            ForceRefresh = $ForceRefresh
            FailureClass = $FailureClass
        }
    }

    if ($AttemptCertainty -eq 'Succeeded') {
        return New-ArmDecision -ShouldRetry $false -Outcome 'Succeeded' -Certainty 'Known'
    }

    if ($StatusCode -ge 300 -and $StatusCode -lt 400) {
        return New-ArmDecision -ShouldRetry $false -Outcome 'Failed' -Certainty 'Known' -FailureClass 'ProviderFailed'
    }

    if ($StatusCode -eq 401) {
        if ($CanRefresh -and -not $ForceRefreshUsed) {
            return New-ArmDecision -ShouldRetry $true -ForceRefresh $true
        }
        return New-ArmDecision -ShouldRetry $false -Outcome 'Failed' -Certainty 'Known' -FailureClass 'AuthenticationFailed'
    }

    if ($StatusCode -eq 403) {
        return New-ArmDecision -ShouldRetry $false -Outcome 'Failed' -Certainty 'Known' -FailureClass 'PermissionDenied'
    }

    if ($StatusCode -eq 404) {
        return New-ArmDecision -ShouldRetry $false -Outcome 'Failed' -Certainty 'Known' -FailureClass 'ProviderFailed'
    }

    if ($StatusCode -eq 400) {
        return New-ArmDecision -ShouldRetry $false -Outcome 'Failed' -Certainty 'Known' -FailureClass 'InvalidProviderData'
    }

    if ($AttemptCertainty -eq 'Rejected') {
        if ($StatusCode -eq 429 -and $isRead) {
            return New-ArmDecision -ShouldRetry $true
        }
        return New-ArmDecision -ShouldRetry $false -Outcome 'Failed' -Certainty 'Known' -FailureClass 'ProviderFailed'
    }

    if ($isRead) {
        return New-ArmDecision -ShouldRetry $true
    }

    return New-ArmDecision -ShouldRetry $false -Outcome 'Failed' -Certainty 'Indeterminate' -FailureClass 'Indeterminate'
}
