BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function New-TestGraphErrorRecord {
        param(
            [AllowNull()] [object] $Outcome = 'Failed',
            [AllowNull()] [object] $Certainty = 'Known',
            [AllowNull()] [object] $StatusCode = $null,
            [System.Management.Automation.ErrorCategory] $Category = [System.Management.Automation.ErrorCategory]::NotSpecified,
            [string] $Message = 'Graph request failed.',
            [switch] $NoEnvelope,
            [switch] $NoTelemetry
        )

        $target = $null
        if (-not $NoEnvelope) {
            $target = [pscustomobject][ordered]@{
                PSTypeName = 'GraphKit.OperationResult'
                Outcome    = $Outcome
                Certainty  = $Certainty
                Telemetry  = if ($NoTelemetry) { @() } else { @([pscustomobject]@{ Attempt = 1; StatusCode = $StatusCode }) }
            }
        }

        [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new($Message),
            'GraphKit.OperationFailed.0',
            $Category,
            $target)
    }
}

Describe 'Resolve-PulseGraphFailure' {
    It 'maps <Name> to the exact provider-neutral failure tuple' -ForEach @(
        @{ Name = 'deadline expiry'; Outcome = 'DeadlineExpired'; Certainty = 'Indeterminate'; Status = 0; Category = [System.Management.Automation.ErrorCategory]::OperationTimeout; Message = 'deadline'; ExpectedClass = 'DeadlineExpired'; ExpectedReason = 'deadline-expired'; ExpectedAbort = $false; ExpectedStatus = 0 }
        @{ Name = 'cancellation'; Outcome = 'Cancelled'; Certainty = 'Indeterminate'; Status = 0; Category = [System.Management.Automation.ErrorCategory]::OperationStopped; Message = 'cancelled'; ExpectedClass = 'Cancelled'; ExpectedReason = 'cancelled'; ExpectedAbort = $false; ExpectedStatus = 0 }
        @{ Name = 'indeterminate failure'; Outcome = 'Failed'; Certainty = 'Indeterminate'; Status = 500; Category = [System.Management.Automation.ErrorCategory]::ResourceUnavailable; Message = 'server failed'; ExpectedClass = 'Indeterminate'; ExpectedReason = 'indeterminate'; ExpectedAbort = $false; ExpectedStatus = 500 }
        @{ Name = 'permission denial'; Outcome = 'Failed'; Certainty = 'Known'; Status = 403; Category = [System.Management.Automation.ErrorCategory]::PermissionDenied; Message = 'forbidden'; ExpectedClass = 'PermissionDenied'; ExpectedReason = 'permission-denied'; ExpectedAbort = $false; ExpectedStatus = 403 }
        @{ Name = 'authentication failure'; Outcome = 'Failed'; Certainty = 'Known'; Status = 401; Category = [System.Management.Automation.ErrorCategory]::AuthenticationError; Message = 'unauthorized'; ExpectedClass = 'AuthenticationFailed'; ExpectedReason = 'authentication-failed'; ExpectedAbort = $true; ExpectedStatus = 401 }
        @{ Name = 'not found'; Outcome = 'Failed'; Certainty = 'Known'; Status = 404; Category = [System.Management.Automation.ErrorCategory]::ObjectNotFound; Message = 'not found'; ExpectedClass = 'ProviderFailed'; ExpectedReason = 'provider-failed'; ExpectedAbort = $false; ExpectedStatus = 404 }
        @{ Name = 'throttling'; Outcome = 'Failed'; Certainty = 'Known'; Status = 429; Category = [System.Management.Automation.ErrorCategory]::LimitsExceeded; Message = 'throttled'; ExpectedClass = 'ProviderFailed'; ExpectedReason = 'provider-failed'; ExpectedAbort = $false; ExpectedStatus = 429 }
        @{ Name = 'service failure'; Outcome = 'Failed'; Certainty = 'Known'; Status = 503; Category = [System.Management.Automation.ErrorCategory]::ResourceUnavailable; Message = 'unavailable'; ExpectedClass = 'ProviderFailed'; ExpectedReason = 'provider-failed'; ExpectedAbort = $false; ExpectedStatus = 503 }
    ) {
        $record = New-TestGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $Status -Category $Category -Message $Message

        $result = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            Resolve-PulseGraphFailure -ErrorRecord $record
        }

        $result.PSObject.TypeNames[0] | Should -Be 'TenantPulse.GraphFailureResolution'
        $result.FailureClass | Should -Be $ExpectedClass
        $result.ReasonCode | Should -Be $ExpectedReason
        $result.AbortCollection | Should -Be $ExpectedAbort
        $result.HasStructuredSignal | Should -BeTrue
        $result.StatusCode | Should -Be $ExpectedStatus
        @($result.PSObject.Properties.Name) | Should -Be @('FailureClass', 'ReasonCode', 'AbortCollection', 'HasStructuredSignal', 'StatusCode')
    }

    It 'gives envelope outcome and certainty precedence over lossy status and message fallbacks' -ForEach @(
        @{ Outcome = 'DeadlineExpired'; Certainty = 'Indeterminate'; Status = 403; Category = [System.Management.Automation.ErrorCategory]::PermissionDenied; Message = 'AADSTS700016 unauthorized'; ExpectedClass = 'DeadlineExpired' }
        @{ Outcome = 'Cancelled'; Certainty = 'Known'; Status = 401; Category = [System.Management.Automation.ErrorCategory]::AuthenticationError; Message = 'token acquisition unauthorized'; ExpectedClass = 'Cancelled' }
        @{ Outcome = 'Failed'; Certainty = 'Indeterminate'; Status = 403; Category = [System.Management.Automation.ErrorCategory]::PermissionDenied; Message = 'forbidden'; ExpectedClass = 'Indeterminate' }
    ) {
        $record = New-TestGraphErrorRecord -Outcome $Outcome -Certainty $Certainty -StatusCode $Status -Category $Category -Message $Message

        $result = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            Resolve-PulseGraphFailure -ErrorRecord $record
        }

        $result.FailureClass | Should -Be $ExpectedClass
        $result.AbortCollection | Should -BeFalse
    }

    It 'accepts an enum-typed last-attempt status without stringifying away its numeric value' {
        $record = New-TestGraphErrorRecord -StatusCode ([System.Net.HttpStatusCode]::Forbidden)

        $result = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            Resolve-PulseGraphFailure -ErrorRecord $record
        }

        $result.FailureClass | Should -Be 'PermissionDenied'
        $result.StatusCode | Should -Be 403
    }

    It 'uses a known GraphKit category when telemetry is absent' {
        $record = New-TestGraphErrorRecord -Category ([System.Management.Automation.ErrorCategory]::AuthenticationError) -NoTelemetry

        $result = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            Resolve-PulseGraphFailure -ErrorRecord $record
        }

        $result.FailureClass | Should -Be 'AuthenticationFailed'
        $result.AbortCollection | Should -BeTrue
        $result.HasStructuredSignal | Should -BeTrue
        $result.StatusCode | Should -BeNullOrEmpty
    }

    It 'uses message-only fallbacks without calling the text structured telemetry' -ForEach @(
        @{ Message = 'AADSTS700016: application not found'; ExpectedClass = 'AuthenticationFailed'; ExpectedAbort = $true }
        @{ Message = 'token acquisition failed'; ExpectedClass = 'AuthenticationFailed'; ExpectedAbort = $true }
        @{ Message = '401 unauthorized'; ExpectedClass = 'AuthenticationFailed'; ExpectedAbort = $true }
        @{ Message = '403 forbidden'; ExpectedClass = 'PermissionDenied'; ExpectedAbort = $false }
        @{ Message = 'AccessDenied by provider'; ExpectedClass = 'PermissionDenied'; ExpectedAbort = $false }
    ) {
        $record = New-TestGraphErrorRecord -Message $Message -NoEnvelope

        $result = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            Resolve-PulseGraphFailure -ErrorRecord $record
        }

        $result.FailureClass | Should -Be $ExpectedClass
        $result.AbortCollection | Should -Be $ExpectedAbort
        $result.HasStructuredSignal | Should -BeFalse
        $result.StatusCode | Should -BeNullOrEmpty
    }

    It 'returns the conservative total fallback for null and structure-free provider errors' -ForEach @(
        @{ Record = $null }
        @{ Record = [System.Management.Automation.ErrorRecord]::new([System.InvalidOperationException]::new('plain provider failure'), 'Provider.Failed', [System.Management.Automation.ErrorCategory]::OperationStopped, $null) }
    ) {
        $result = InModuleScope TenantPulse -ArgumentList $Record {
            param($record)
            Resolve-PulseGraphFailure -ErrorRecord $record
        }

        $result.FailureClass | Should -Be 'ProviderFailed'
        $result.ReasonCode | Should -Be 'provider-failed'
        $result.AbortCollection | Should -BeFalse
        $result.HasStructuredSignal | Should -BeFalse
        $result.StatusCode | Should -BeNullOrEmpty
    }

    It 'never throws for hostile getters, malformed telemetry, or values whose string conversion throws' {
        $hostileValue = [pscustomobject]@{}
        $hostileValue | Add-Member -MemberType ScriptMethod -Name ToString -Value { throw 'hostile ToString' } -Force

        $target = [pscustomobject]@{}
        $target | Add-Member -MemberType ScriptProperty -Name Outcome -Value { throw 'hostile Outcome getter' }
        $target | Add-Member -MemberType NoteProperty -Name Certainty -Value $hostileValue
        $target | Add-Member -MemberType NoteProperty -Name Telemetry -Value @(
            $null,
            [pscustomobject]@{ StatusCode = $hostileValue }
        )
        $record = [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new('plain provider failure'),
            'GraphKit.OperationFailed.0',
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $target)

        $result = InModuleScope TenantPulse -ArgumentList $record {
            param($record)
            Resolve-PulseGraphFailure -ErrorRecord $record
        }

        $result.FailureClass | Should -Be 'ProviderFailed'
        $result.ReasonCode | Should -Be 'provider-failed'
        $result.HasStructuredSignal | Should -BeFalse
        $result.StatusCode | Should -BeNullOrEmpty
    }
}
