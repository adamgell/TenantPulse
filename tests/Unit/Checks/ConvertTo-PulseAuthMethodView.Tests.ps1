BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function script:ConvertTo-PSObjectShape {
        param($Value)
        return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    }

    $script:rawFido2Hashtable = @{
        '@odata.type'            = '#microsoft.graph.fido2AuthenticationMethodConfiguration'
        id                       = 'Fido2'
        state                    = 'enabled'
        isAttestationEnforced    = $true
        isSelfServiceRegistrationAllowed = $true
        keyRestrictions          = @{ isEnforced = $false; enforcementType = 'block'; aaGuids = @() }
        includeTargets           = @(
            @{ id = 'all_users'; targetType = 'group'; isRegistrationRequired = $false }
        )
        excludeTargets           = @()
    }

    $script:rawSmsHashtable = @{
        '@odata.type'  = '#microsoft.graph.smsAuthenticationMethodConfiguration'
        id             = 'Sms'
        state          = 'enabled'
        includeTargets = @(
            @{ id = 'grp-1'; targetType = 'group'; isUsableForSignIn = $true }
            @{ id = 'grp-2'; targetType = 'group'; isUsableForSignIn = $false }
        )
    }

    # ---- Task 4.1 post-review: minimal/sparse fixture (Finding 1, self-caught sibling
    # defect - same array-unrolling trap ConvertTo-PulseCaPolicyView had) ----
    $script:minimalMethodHashtable = @{ id = 'Voice'; state = 'disabled' }

    # ---- Task 4.1 post-review, Finding 4 (Low): same settings, shuffled property order ----
    $script:rawFido2ShuffledHashtable = [ordered]@{
        excludeTargets                    = @()
        keyRestrictions                   = @{ isEnforced = $false; enforcementType = 'block'; aaGuids = @() }
        state                             = 'enabled'
        isSelfServiceRegistrationAllowed  = $true
        '@odata.type'                     = '#microsoft.graph.fido2AuthenticationMethodConfiguration'
        includeTargets                    = @(@{ id = 'all_users'; targetType = 'group'; isRegistrationRequired = $false })
        id                                = 'Fido2'
        isAttestationEnforced             = $true
    }

    # ---- Task 4.1 post-review: consolidated fixture registry (Finding 3 / Important) ----
    $script:authMethodShapeFixtures = [ordered]@{
        'fido2-full'          = @{ Raw = $script:rawFido2Hashtable }
        'fido2-shuffled-props' = @{ Raw = $script:rawFido2ShuffledHashtable }
        'sms-multi-target'    = @{ Raw = $script:rawSmsHashtable }
        'minimal-state-only'  = @{ Raw = $script:minimalMethodHashtable }
        'absent-state-throws' = @{ Raw = @{ id = 'Fido2' }; ExpectThrow = $true }
        'unrecognized-state-throws' = @{ Raw = @{ id = 'Fido2'; state = 'somethingElse' }; ExpectThrow = $true }
    }

    function script:Get-AuthMethodShapeFixtureVariant {
        param([string] $Name)
        $fixture = $script:authMethodShapeFixtures[$Name]
        return [pscustomobject]@{
            Raw         = $fixture.Raw
            AsPSObject  = (ConvertTo-PSObjectShape -Value $fixture.Raw)
            ExpectThrow = [bool] $fixture.ExpectThrow
        }
    }
}

Describe 'ConvertTo-PulseAuthMethodView' {
    It 'normalizes methodId and state (hashtable-shaped input)' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawFido2Hashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        $result.methodId | Should -Be 'Fido2'
        $result.state | Should -Be 'enabled'
    }

    It 'normalizes methodId and state (PSObject-shaped input)' {
        $pso = ConvertTo-PSObjectShape -Value $script:rawFido2Hashtable

        $result = InModuleScope TenantPulse -ArgumentList $pso {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        $result.methodId | Should -Be 'Fido2'
        $result.state | Should -Be 'enabled'
    }

    It 'throws when state is absent entirely (field-absence lens)' {
        $raw = @{ id = 'Fido2' }

        {
            InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseAuthMethodView -MethodConfigs $raw
            }
        } | Should -Throw
    }

    It 'throws on a state value that is neither enabled nor disabled' {
        $raw = $script:rawFido2Hashtable.Clone()
        $raw.state = 'somethingElse'

        {
            InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseAuthMethodView -MethodConfigs $raw
            }
        } | Should -Throw
    }

    It 'folds every non-well-known top-level property into -settings, keyed by its raw name' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawFido2Hashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        $result.settings['isAttestationEnforced'] | Should -BeTrue
        $result.settings['isSelfServiceRegistrationAllowed'] | Should -BeTrue
        $result.settings.Contains('id') | Should -BeFalse
        $result.settings.Contains('state') | Should -BeFalse
        $result.settings.Contains('includeTargets') | Should -BeFalse
        $result.settings.Contains('@odata.type') | Should -BeFalse
    }

    It 'normalizes includeTargets entries, preserving per-target isUsableForSignIn (TP.ENT.0009 shape)' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawSmsHashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        @($result.includeTargets).Count | Should -Be 2
        ($result.includeTargets | Where-Object { $_.id -eq 'grp-1' }).isUsableForSignIn | Should -BeTrue
        ($result.includeTargets | Where-Object { $_.id -eq 'grp-2' }).isUsableForSignIn | Should -BeFalse
    }

    It 'excludeTargets defaults to an empty array when absent, without throwing' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawSmsHashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        @($result.excludeTargets).Count | Should -Be 0
    }

    It 'accepts an array via pipeline and returns one view per method configuration' {
        $results = InModuleScope TenantPulse -ArgumentList (, @($script:rawFido2Hashtable, $script:rawSmsHashtable)) {
            param($raws)
            $raws | ConvertTo-PulseAuthMethodView
        }

        @($results).Count | Should -Be 2
        ($results | Where-Object { $_.methodId -eq 'Sms' }) | Should -Not -BeNullOrEmpty
    }

    # ---- Task 4.1 post-review, Finding 1 (Critical, self-caught sibling defect) ----
    # excludeTargets/includeTargets never collapse to $null (empty) or a bare scalar
    # (single element) - same ARRAY-RETURN UNROLLING TRAP ConvertTo-PulseCaPolicyView had.

    It 'a minimal method configuration (state only) normalizes includeTargets/excludeTargets as real, always-array, never-null fields' {
        foreach ($raw in @($script:minimalMethodHashtable, (ConvertTo-PSObjectShape -Value $script:minimalMethodHashtable))) {
            $result = InModuleScope TenantPulse -ArgumentList $raw {
                param($raw)
                ConvertTo-PulseAuthMethodView -MethodConfigs $raw
            }

            $result.state | Should -Be 'disabled'
            # .GetType() on a genuinely $null value throws - calling it here is itself part
            # of the assertion (a regression back to $null would fail this test with an
            # error, not a silent pass).
            $result.includeTargets.GetType().IsArray | Should -BeTrue -Because 'includeTargets must be a real (possibly empty) array, not $null'
            @($result.includeTargets).Count | Should -Be 0
            $result.excludeTargets.GetType().IsArray | Should -BeTrue -Because 'excludeTargets must be a real (possibly empty) array, not $null'
            @($result.excludeTargets).Count | Should -Be 0
        }
    }

    It 'a single-target includeTargets list stays a real one-element array, not a bare scalar' {
        $result = InModuleScope TenantPulse -ArgumentList $script:rawFido2Hashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        $result.includeTargets.GetType().IsArray | Should -BeTrue
        @($result.includeTargets).Count | Should -Be 1
    }

    # ---- Task 4.1 post-review, Finding 4 (Low): ordinal, response-order-independent
    # -settings insertion order ----

    It 'sorts -settings property names ordinally, independent of the raw response property order' {
        $orderedResult = InModuleScope TenantPulse -ArgumentList $script:rawFido2Hashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }
        $shuffledResult = InModuleScope TenantPulse -ArgumentList $script:rawFido2ShuffledHashtable {
            param($raw)
            ConvertTo-PulseAuthMethodView -MethodConfigs $raw
        }

        $expectedSortedKeys = @('isAttestationEnforced', 'isSelfServiceRegistrationAllowed', 'keyRestrictions')
        @($orderedResult.settings.Keys) | Should -Be $expectedSortedKeys
        @($shuffledResult.settings.Keys) | Should -Be $expectedSortedKeys

        $orderedJson = InModuleScope TenantPulse -ArgumentList $orderedResult {
            param($o) ConvertTo-PulseCanonicalJsonLine -InputObject $o
        }
        $shuffledJson = InModuleScope TenantPulse -ArgumentList $shuffledResult {
            param($o) ConvertTo-PulseCanonicalJsonLine -InputObject $o
        }
        $orderedJson | Should -Be $shuffledJson -Because 'shuffling the raw response property order must not change the serialized output'
    }

    # ---- Task 4.1 post-review, Finding 3 (Important): consolidated SHAPE NEUTRALITY ----

    It 'SHAPE NEUTRALITY: every fixture family normalizes identically (or throws identically) whether materialized as a hashtable or a PSObject tree' {
        foreach ($name in $script:authMethodShapeFixtures.Keys) {
            $variant = Get-AuthMethodShapeFixtureVariant -Name $name

            if ($variant.ExpectThrow) {
                {
                    InModuleScope TenantPulse -ArgumentList $variant.Raw {
                        param($raw)
                        ConvertTo-PulseAuthMethodView -MethodConfigs $raw
                    }
                } | Should -Throw -Because "fixture '$name' (hashtable shape) must throw"

                {
                    InModuleScope TenantPulse -ArgumentList $variant.AsPSObject {
                        param($raw)
                        ConvertTo-PulseAuthMethodView -MethodConfigs $raw
                    }
                } | Should -Throw -Because "fixture '$name' (PSObject shape) must throw"

                continue
            }

            $hashtableResult = InModuleScope TenantPulse -ArgumentList $variant.Raw {
                param($raw)
                ConvertTo-PulseAuthMethodView -MethodConfigs $raw
            }
            $psObjectResult = InModuleScope TenantPulse -ArgumentList $variant.AsPSObject {
                param($raw)
                ConvertTo-PulseAuthMethodView -MethodConfigs $raw
            }

            $hashtableJson = InModuleScope TenantPulse -ArgumentList $hashtableResult {
                param($o) ConvertTo-PulseCanonicalJsonLine -InputObject $o
            }
            $psObjectJson = InModuleScope TenantPulse -ArgumentList $psObjectResult {
                param($o) ConvertTo-PulseCanonicalJsonLine -InputObject $o
            }

            $hashtableJson | Should -Be $psObjectJson -Because "fixture '$name' must normalize to byte-identical output between hashtable and PSObject shapes"
        }
    }
}
