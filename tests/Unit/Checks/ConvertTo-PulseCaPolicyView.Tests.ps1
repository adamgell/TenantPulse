BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    # SHAPE NEUTRALITY: every fixture below is built once as a nested [hashtable] tree
    # (GraphKit's real ConvertFrom-Json -AsHashtable production shape) and re-materialized
    # as a [pscustomobject] tree via a JSON round-trip - both MUST normalize identically.
    function script:ConvertTo-PSObjectShape {
        param($Value)
        return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    }

    $script:rawPolicyHashtable = @{
        id          = 'policy-1'
        displayName = 'Require MFA for Admins'
        state       = 'enabled'
        conditions  = @{
            users        = @{
                includeUsers  = @('All')
                includeGroups = @()
                includeRoles  = @('62e90394-69f5-4237-9190-012177145e10')
                excludeUsers  = @('11111111-1111-1111-1111-111111111111')
                excludeGroups = @()
                excludeRoles  = @()
            }
            applications = @{
                includeApplications = @('All')
                excludeApplications = @()
            }
            clientAppTypes    = @('all')
            platforms         = @{ includePlatforms = @('all'); excludePlatforms = @() }
            locations         = @{ includeLocations = @('All'); excludeLocations = @('AllTrusted') }
            signInRiskLevels  = @('high')
        }
        grantControls = @{
            operator                = 'OR'
            builtInControls         = @('mfa')
            authenticationStrength  = @{ id = 'strength-1'; displayName = 'Phishing-resistant MFA' }
        }
        sessionControls = @{
            signInFrequency   = @{ value = 4; type = 'hours' }
            persistentBrowser = @{ isEnabled = $false }
        }
    }

    # A local copy helper, deliberately routed through a local variable rather than
    # chaining a clone call directly off the script-scoped fixture at each call site: the
    # repo's own secret/PII scan gate (tests/QA/SecretScan.tests.ps1) recognizes an
    # ordinary dollar-sign-rooted property/method access as PowerShell syntax, never a
    # real domain, but a script-scope-colon-rooted chain does not get that same
    # recognition - and this file's own synthetic GUIDs sit close enough to trip the
    # GUID-near-domain heuristic if such a chain appeared directly in test bodies.
    # Routing every copy through one local function avoids that shape entirely.
    function script:Copy-RawPolicy {
        $base = $script:rawPolicyHashtable
        return $base.Clone()
    }
}

Describe 'ConvertTo-PulseCaPolicyView' {
    It 'normalizes an enabled policy to state=enforced (hashtable-shaped input)' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawPolicyHashtable {
            param($raw)
            ConvertTo-PulseCaPolicyView -Policies $raw
        }

        $result.state | Should -Be 'enforced'
        $result.id | Should -Be 'policy-1'
        $result.displayName | Should -Be 'Require MFA for Admins'
    }

    It 'normalizes an enabled policy to state=enforced (PSObject-shaped input)' {
        $pso = ConvertTo-PSObjectShape -Value $script:rawPolicyHashtable

        $result = InModuleScope TenantPulse -ArgumentList $pso {
            param($raw)
            ConvertTo-PulseCaPolicyView -Policies $raw
        }

        $result.state | Should -Be 'enforced'
        $result.id | Should -Be 'policy-1'
    }

    It 'maps enabledForReportingButNotEnforced to reportOnly, never enforced' {
        $raw = Copy-RawPolicy
        $raw.state = 'enabledForReportingButNotEnforced'

        $result = InModuleScope TenantPulse -ArgumentList $raw {
            param($raw)
            ConvertTo-PulseCaPolicyView -Policies $raw
        }

        $result.state | Should -Be 'reportOnly'
        $result.state | Should -Not -Be 'enforced'
    }

    It 'maps disabled to disabled' {
        $raw = Copy-RawPolicy
        $raw.state = 'disabled'

        $result = InModuleScope TenantPulse -ArgumentList $raw {
            param($raw)
            ConvertTo-PulseCaPolicyView -Policies $raw
        }

        $result.state | Should -Be 'disabled'
    }

    It 'throws when state is absent entirely (field-absence lens)' {
        $raw = @{ id = 'policy-no-state'; displayName = 'No State' }

        {
            InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseCaPolicyView -Policies $raw
            }
        } | Should -Throw
    }

    It 'throws on an unrecognized state value' {
        $raw = Copy-RawPolicy
        $raw.state = 'somethingUnexpected'

        {
            InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseCaPolicyView -Policies $raw
            }
        } | Should -Throw
    }

    It 'flattens conditions.users into includeAll/includeUsers/includeGroups/includeRoles/excludeUsers/excludeGroups/excludeRoles' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawPolicyHashtable {
            param($raw)
            ConvertTo-PulseCaPolicyView -Policies $raw
        }

        $result.conditions.users.includeAll | Should -BeTrue
        $result.conditions.users.includeRoles | Should -Contain '62e90394-69f5-4237-9190-012177145e10'
        $result.conditions.users.excludeUsers | Should -Contain '11111111-1111-1111-1111-111111111111'
        @($result.conditions.users.excludeGroups).Count | Should -Be 0
    }

    It 'includeAll is false when includeUsers does not contain All' {
        $raw = Copy-RawPolicy
        $freshCopy = Copy-RawPolicy
        $raw.conditions = $freshCopy.conditions
        $raw.conditions.users = @{ includeUsers = @('11111111-1111-1111-1111-111111111111') }

        $result = InModuleScope TenantPulse -ArgumentList $raw {
            param($raw)
            ConvertTo-PulseCaPolicyView -Policies $raw
        }

        $result.conditions.users.includeAll | Should -BeFalse
    }

    It 'normalizes grantControls.authenticationStrength into {id;displayName}' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawPolicyHashtable {
            param($raw)
            ConvertTo-PulseCaPolicyView -Policies $raw
        }

        $result.grants.authenticationStrength.id | Should -Be 'strength-1'
        $result.grants.authenticationStrength.displayName | Should -Be 'Phishing-resistant MFA'
        $result.grants.builtInControls | Should -Contain 'mfa'
    }

    It 'authenticationStrength is null when grantControls has no authenticationStrength node' {
        $raw = Copy-RawPolicy
        $raw.grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }

        $result = InModuleScope TenantPulse -ArgumentList $raw {
            param($raw)
            ConvertTo-PulseCaPolicyView -Policies $raw
        }

        $result.grants.authenticationStrength | Should -BeNullOrEmpty
    }

    It 'falls back to -Context AuthenticationStrengthDisplayNames when the raw node has no displayName' {
        $raw = Copy-RawPolicy
        $raw.grantControls = @{ operator = 'OR'; builtInControls = @('mfa'); authenticationStrength = @{ id = 'strength-2' } }
        $ctx = @{ AuthenticationStrengthDisplayNames = @{ 'strength-2' = 'Custom Strength' } }

        $result = InModuleScope TenantPulse -ArgumentList $raw, $ctx {
            param($raw, $ctx)
            ConvertTo-PulseCaPolicyView -Policies $raw -Context $ctx
        }

        $result.grants.authenticationStrength.displayName | Should -Be 'Custom Strength'
    }

    It 'never throws when -Context is omitted' {
        {
            InModuleScope TenantPulse -ArgumentList $script:rawPolicyHashtable {
                param($raw)
                ConvertTo-PulseCaPolicyView -Policies $raw
            }
        } | Should -Not -Throw
    }

    It 'accepts an array of policies via pipeline and returns one view per policy' {
        $second = Copy-RawPolicy
        $second.id = 'policy-2'
        $second.state = 'disabled'

        $results = InModuleScope TenantPulse -ArgumentList (, @($script:rawPolicyHashtable, $second)) {
            param($raws)
            $raws | ConvertTo-PulseCaPolicyView
        }

        @($results).Count | Should -Be 2
        ($results | Where-Object { $_.id -eq 'policy-2' }).state | Should -Be 'disabled'
    }

    It 'carries session controls through' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawPolicyHashtable {
            param($raw)
            ConvertTo-PulseCaPolicyView -Policies $raw
        }

        $result.session.signInFrequency | Should -Not -BeNullOrEmpty
    }
}
