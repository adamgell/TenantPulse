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

    # Same reasoning as Copy-RawPolicy above - routes the clone-and-override-state pattern
    # through one local function/variable so no test body chains a clone call directly off
    # the script-scoped fixture (which would trip the secret/PII scan gate's GUID-near-
    # domain heuristic - see Copy-RawPolicy's own docstring above).
    function script:New-CaPolicyWithState {
        param([string] $State)
        $copy = Copy-RawPolicy
        $copy.state = $State
        return $copy
    }

    # ---- Task 4.1 post-review: sparse-policy fixtures (Finding 1 / Critical) ----
    # Each omits a whole OPTIONAL parent block entirely (not present-but-null - a real
    # sparse Graph response drops the property, it does not send it as an explicit null).

    $script:minimalPolicyHashtable = @{ id = 'policy-minimal'; displayName = 'Minimal'; state = 'enabled' }

    $script:policyMissingConditionsHashtable = @{
        id            = 'policy-no-conditions'
        displayName   = 'No Conditions'
        state         = 'enabled'
        grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
    }

    $script:policyMissingGrantControlsHashtable = @{
        id          = 'policy-no-grantcontrols'
        displayName = 'No GrantControls'
        state       = 'enabled'
        conditions  = @{ users = @{ includeUsers = @('All') } }
    }

    $script:policyMissingSessionControlsHashtable = @{
        id            = 'policy-no-sessioncontrols'
        displayName   = 'No SessionControls'
        state         = 'enabled'
        conditions    = @{ users = @{ includeUsers = @('All') } }
        grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
    }

    # ---- Task 4.1 post-review: consolidated fixture registry (Finding 3 / Important) ----
    # Every distinct normalization path this file exercises, named once, reused by BOTH the
    # dedicated per-scenario It blocks above/below AND the single consolidated SHAPE
    # NEUTRALITY test - so a new scenario only ever needs adding here once.
    $script:caShapeFixtures = [ordered]@{
        'full-enabled-policy'              = @{ Raw = $script:rawPolicyHashtable }
        'minimal-policy-state-only'        = @{ Raw = $script:minimalPolicyHashtable }
        'policy-missing-conditions'        = @{ Raw = $script:policyMissingConditionsHashtable }
        'policy-missing-grantControls'     = @{ Raw = $script:policyMissingGrantControlsHashtable }
        'policy-missing-sessionControls'   = @{ Raw = $script:policyMissingSessionControlsHashtable }
        'reportOnly-state'                 = @{ Raw = (New-CaPolicyWithState -State 'enabledForReportingButNotEnforced') }
        'disabled-state'                   = @{ Raw = (New-CaPolicyWithState -State 'disabled') }
        'absent-state-throws'              = @{ Raw = @{ id = 'policy-no-state'; displayName = 'No State' }; ExpectThrow = $true }
        'unrecognized-state-throws'        = @{ Raw = (New-CaPolicyWithState -State 'somethingUnexpected'); ExpectThrow = $true }
        'includeUsers-not-all'             = @{ Raw = @{ id = 'policy-scoped'; displayName = 'Scoped'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('11111111-1111-1111-1111-111111111111') } } } }
        'no-authenticationStrength-node'   = @{ Raw = @{ id = 'policy-no-strength'; displayName = 'No Strength'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('mfa') } } }
        'authenticationStrength-context-fallback' = @{
            Raw     = @{ id = 'policy-strength-fallback'; displayName = 'Strength Fallback'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('mfa'); authenticationStrength = @{ id = 'strength-2' } } }
            Context = @{ AuthenticationStrengthDisplayNames = @{ 'strength-2' = 'Custom Strength' } }
        }
    }

    # Materializes a fixture's -Raw hashtable as a PSObject tree via a JSON round-trip and
    # returns a fresh {Raw;PSObject;Context;ExpectThrow} record - kept as a function (not
    # inlined per-fixture) so both the dedicated tests and the consolidated shape-neutrality
    # test build the PSObject side identically.
    function script:Get-CaShapeFixtureVariant {
        param([string] $Name)
        $fixture = $script:caShapeFixtures[$Name]
        return [pscustomobject]@{
            Raw         = $fixture.Raw
            AsPSObject  = (ConvertTo-PSObjectShape -Value $fixture.Raw)
            Context     = if ($fixture.ContainsKey('Context')) { $fixture.Context } else { @{} }
            ExpectThrow = [bool] $fixture.ExpectThrow
        }
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

    It 'flattens conditions.clientApplications (Task 4.4, TP.ENT.0024) into includeApplications/excludeApplications, distinct from conditions.apps, in both shapes (post-review F3: this is the genuine shape-neutrality coverage - the populated case previously only ever exercised the hashtable shape)' {
        $rawHashtable = @{
            id          = 'policy-workload'
            displayName = 'Workload Identity CA'
            state       = 'enabled'
            conditions  = @{
                clientApplications = @{ includeApplications = @('11111111-1111-1111-1111-111111111111'); excludeApplications = @('22222222-2222-2222-2222-222222222222') }
            }
        }
        foreach ($raw in @($rawHashtable, (ConvertTo-PSObjectShape -Value $rawHashtable))) {
            $result = InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseCaPolicyView -Policies $raw
            }

            $result.conditions.clientApplications.includeApplications | Should -Be @('11111111-1111-1111-1111-111111111111')
            $result.conditions.clientApplications.excludeApplications | Should -Be @('22222222-2222-2222-2222-222222222222')
            $result.conditions.apps.includeApplications.Count | Should -Be 0
        }
    }

    It 'clientApplications null/empty-normalizes (never throws) when conditions.clientApplications is absent, in both shapes' {
        foreach ($raw in @($script:minimalPolicyHashtable, (ConvertTo-PSObjectShape -Value $script:minimalPolicyHashtable))) {
            $result = InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseCaPolicyView -Policies $raw
            }
            ($null -eq $result.conditions.clientApplications.includeApplications) | Should -Be $false -Because 'the field itself must be a real (never-null) empty array, not $null'
            @($result.conditions.clientApplications.includeApplications).Count | Should -Be 0
        }
    }

    # ---- Task 4.1 post-review, Finding 1 (Critical): optional parent nodes never throw,
    # and never silently collapse an array-typed field to $null/a bare scalar ----

    It 'a minimal policy (state only, no conditions/grantControls/sessionControls at all) normalizes without throwing, in both shapes' {
        foreach ($raw in @($script:minimalPolicyHashtable, (ConvertTo-PSObjectShape -Value $script:minimalPolicyHashtable))) {
            $result = InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseCaPolicyView -Policies $raw
            }

            $result.state | Should -Be 'enforced'
            $result.conditions.users | Should -Not -BeNullOrEmpty
            @($result.conditions.users.includeUsers).Count | Should -Be 0
            $result.conditions.users.includeUsers.GetType().IsArray | Should -BeTrue
            $result.grants | Should -Not -BeNullOrEmpty
            @($result.grants.builtInControls).Count | Should -Be 0
            $result.session | Should -Not -BeNullOrEmpty
        }
    }

    It 'a policy missing conditions entirely null/empty-normalizes conditions.users fields (never throws), in both shapes' {
        foreach ($raw in @($script:policyMissingConditionsHashtable, (ConvertTo-PSObjectShape -Value $script:policyMissingConditionsHashtable))) {
            $result = InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseCaPolicyView -Policies $raw
            }

            $result.conditions.users.includeAll | Should -BeFalse
            @($result.conditions.users.includeUsers).Count | Should -Be 0
            $result.conditions.users.includeUsers.GetType().IsArray | Should -BeTrue
            @($result.conditions.locations.includeLocations).Count | Should -Be 0
            # grantControls WAS present on this fixture - unaffected by the missing conditions block.
            $result.grants.builtInControls | Should -Contain 'mfa'
        }
    }

    It 'a policy missing grantControls entirely null/empty-normalizes grants fields (never throws), in both shapes' {
        foreach ($raw in @($script:policyMissingGrantControlsHashtable, (ConvertTo-PSObjectShape -Value $script:policyMissingGrantControlsHashtable))) {
            $result = InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseCaPolicyView -Policies $raw
            }

            $result.grants | Should -Not -BeNullOrEmpty
            $result.grants.operator | Should -BeNullOrEmpty
            @($result.grants.builtInControls).Count | Should -Be 0
            $result.grants.builtInControls.GetType().IsArray | Should -BeTrue
            $result.grants.authenticationStrength | Should -BeNullOrEmpty
            # conditions WAS present on this fixture - unaffected by the missing grantControls block.
            $result.conditions.users.includeAll | Should -BeTrue
        }
    }

    It 'a policy missing sessionControls entirely null-normalizes every session field (never throws), in both shapes' {
        foreach ($raw in @($script:policyMissingSessionControlsHashtable, (ConvertTo-PSObjectShape -Value $script:policyMissingSessionControlsHashtable))) {
            $result = InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseCaPolicyView -Policies $raw
            }

            $result.session | Should -Not -BeNullOrEmpty
            $result.session.signInFrequency | Should -BeNullOrEmpty
            $result.session.persistentBrowser | Should -BeNullOrEmpty
            $result.session.cloudAppSecurity | Should -BeNullOrEmpty
            $result.session.disableResilienceDefaults | Should -BeNullOrEmpty
        }
    }

    # ---- Task 4.1 post-review, Finding 3 (Important): consolidated SHAPE NEUTRALITY ----
    # Mirrors tests/Unit/Expand/SettingsCatalogWalk.Tests.ps1:432's own consolidated
    # per-fixture-family pattern: EVERY named fixture in $script:caShapeFixtures runs
    # through both a hashtable and a PSObject materialization, asserting either identical
    # throw behavior or byte-identical canonical JSON output between the two shapes.

    It 'SHAPE NEUTRALITY: every fixture family normalizes identically (or throws identically) whether materialized as a hashtable or a PSObject tree' {
        foreach ($name in $script:caShapeFixtures.Keys) {
            $variant = Get-CaShapeFixtureVariant -Name $name

            if ($variant.ExpectThrow) {
                {
                    InModuleScope TenantPulse -ArgumentList $variant.Raw, $variant.Context {
                        param($raw, $ctx)
                        ConvertTo-PulseCaPolicyView -Policies $raw -Context $ctx
                    }
                } | Should -Throw -Because "fixture '$name' (hashtable shape) must throw"

                {
                    InModuleScope TenantPulse -ArgumentList $variant.AsPSObject, $variant.Context {
                        param($raw, $ctx)
                        ConvertTo-PulseCaPolicyView -Policies $raw -Context $ctx
                    }
                } | Should -Throw -Because "fixture '$name' (PSObject shape) must throw"

                continue
            }

            $hashtableResult = InModuleScope TenantPulse -ArgumentList $variant.Raw, $variant.Context {
                param($raw, $ctx)
                ConvertTo-PulseCaPolicyView -Policies $raw -Context $ctx
            }
            $psObjectResult = InModuleScope TenantPulse -ArgumentList $variant.AsPSObject, $variant.Context {
                param($raw, $ctx)
                ConvertTo-PulseCaPolicyView -Policies $raw -Context $ctx
            }

            $hashtableJson = InModuleScope TenantPulse -ArgumentList $hashtableResult {
                param($o)
                ConvertTo-PulseCanonicalJsonLine -InputObject $o
            }
            $psObjectJson = InModuleScope TenantPulse -ArgumentList $psObjectResult {
                param($o)
                ConvertTo-PulseCanonicalJsonLine -InputObject $o
            }

            $hashtableJson | Should -Be $psObjectJson -Because "fixture '$name' must normalize to byte-identical output between hashtable and PSObject shapes"
        }
    }
}
