<#
    Dedicated unit tests for the C1 raw-dataset Sensitive-redaction pass (task-2.3-review
    round 2, finding 3) - Protect-PulseTypedPolicySensitivePayload.ps1's three functions,
    each exercised directly rather than only indirectly through
    TypedPolicySecretContract.Tests.ps1's own end-to-end capstone. Pins down the documented
    behaviors that file's own docstring promises: dataset/type pass-through boundaries,
    shape neutrality, and (round 2's own finding 1) fail-closed redaction of a wrong-shaped
    nested value.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:typedPolicyMaps = Import-PowerShellDataFile -LiteralPath (Join-Path $built.FullName 'Data/TypedPolicyMaps.psd1')
}

Describe 'Protect-PulseTypedPolicySensitivePayload' {
    It 'passes an UNMAPPED dataset name through completely unchanged (no known Sensitive classification exists for it)' {
        $plantedSecret = 'PLANTED-managedDevices-secret'
        $row = [pscustomobject]@{ id = 'd1'; serialNumber = $plantedSecret }

        $result = InModuleScope TenantPulse -ArgumentList $row, $script:typedPolicyMaps {
            param($row, $maps)
            Protect-PulseTypedPolicySensitivePayload -Data @($row) -DatasetName 'managedDevices' -TypedPolicyMaps $maps
        }

        $result.Count | Should -Be 1
        $result[0].serialNumber | Should -Be $plantedSecret
    }

    It 'passes a row with an UNMAPPED @odata.type through completely unchanged, even inside a MAPPED dataset' {
        $plantedSecret = 'PLANTED-legacy-android-secret'
        # A bare legacy compliance row with no @odata.type at all - the real shape observed
        # in Ivy24's own deviceCompliancePolicies dataset (see TypedPolicyMaps.psd1's own
        # docstring) - has no property map entry, so there is nothing to redact by.
        $row = [pscustomobject]@{ id = 'p1'; displayName = $plantedSecret }

        $result = InModuleScope TenantPulse -ArgumentList $row, $script:typedPolicyMaps {
            param($row, $maps)
            Protect-PulseTypedPolicySensitivePayload -Data @($row) -DatasetName 'deviceCompliancePolicies' -TypedPolicyMaps $maps
        }

        $result[0].displayName | Should -Be $plantedSecret
    }

    It 'a COMPLIANCE-family row (no Sensitive properties anywhere in that type''s map entry) round-trips every property unchanged' {
        # Pins the documented fact that none of the four measured compliance types carry
        # an actual Sensitive property (see TypedPolicyMaps.psd1's own docstring) - the
        # payload must still round-trip losslessly through this pass, not merely "not
        # crash".
        $row = [pscustomobject]@{
            '@odata.type'    = '#microsoft.graph.windows10CompliancePolicy'
            id               = 'c1'
            bitLockerEnabled = $true
            passwordRequired = $false
            osMinimumVersion = $null
        }

        $result = InModuleScope TenantPulse -ArgumentList $row, $script:typedPolicyMaps {
            param($row, $maps)
            Protect-PulseTypedPolicySensitivePayload -Data @($row) -DatasetName 'deviceCompliancePolicies' -TypedPolicyMaps $maps
        }

        $result[0].bitLockerEnabled | Should -BeTrue
        $result[0].passwordRequired | Should -BeFalse
        $result[0].osMinimumVersion | Should -BeNullOrEmpty
        $result[0].id | Should -Be 'c1'
    }

    It 'a MULTI-PROPERTY row redacts ONLY the Sensitive nested value, every sibling property (including ones this map does not even list) untouched' {
        $plantedSecret = 'PLANTED-multi-property-secret'
        $row = [pscustomobject]@{
            '@odata.type'       = '#microsoft.graph.windows10CustomConfiguration'
            id                  = 'c2'
            displayName         = 'Custom Profile'
            description         = 'not secret'
            someFuturePropertyThisMapDoesNotList = 'passthrough-value'
            omaSettings         = @(
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.omaSettingString'; omaUri = './x'; value = $plantedSecret }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $row, $script:typedPolicyMaps {
            param($row, $maps)
            Protect-PulseTypedPolicySensitivePayload -Data @($row) -DatasetName 'deviceConfigurations' -TypedPolicyMaps $maps
        }

        $result[0].id | Should -Be 'c2'
        $result[0].displayName | Should -Be 'Custom Profile'
        $result[0].description | Should -Be 'not secret'
        $result[0].someFuturePropertyThisMapDoesNotList | Should -Be 'passthrough-value'
        $result[0].omaSettings[0].value.redacted | Should -BeTrue
        $result[0].omaSettings[0].omaUri | Should -Be './x'
        ($result[0] | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'walks an IDICTIONARY-shaped row (AsHashtable, GraphKit''s real production shape) identically to a PSObject-shaped one' {
        $plantedSecret = 'PLANTED-hashtable-secret'
        $json = "{`"@odata.type`":`"#microsoft.graph.windows10CustomConfiguration`",`"id`":`"c3`",`"omaSettings`":[{`"@odata.type`":`"#microsoft.graph.omaSettingString`",`"omaUri`":`"./x`",`"value`":`"$plantedSecret`"}]}"
        $hashRow = $json | ConvertFrom-Json -AsHashtable

        $result = InModuleScope TenantPulse -ArgumentList $hashRow, $script:typedPolicyMaps {
            param($row, $maps)
            Protect-PulseTypedPolicySensitivePayload -Data @($row) -DatasetName 'deviceConfigurations' -TypedPolicyMaps $maps
        }

        $result[0].omaSettings[0].value.redacted | Should -BeTrue
        ($result[0] | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($plantedSecret))
    }
}

Describe 'Protect-PulseTypedPolicyRow' {
    It 'returns the ORIGINAL row object (same reference, not a clone) for an unmapped @odata.type - no unnecessary allocation' {
        $entry = $script:typedPolicyMaps.deviceConfiguration.'#microsoft.graph.windows10CustomConfiguration'
        $row = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.someFutureUnmappedType'; id = 'x1' }

        $isSameReference = InModuleScope TenantPulse -ArgumentList $row, $entry {
            param($row, $typeMap)
            $result = Protect-PulseTypedPolicyRow -Row $row -TypeMap @{ '#microsoft.graph.windows10CustomConfiguration' = $typeMap }
            [object]::ReferenceEquals($row, $result)
        }

        $isSameReference | Should -BeTrue
    }

    It 'redacts a top-level Sensitive property UNCONDITIONALLY - a compliance-shaped synthetic map entry proves the rule independent of any real map data' {
        # Direct, synthetic map entry (not TypedPolicyMaps.psd1's own real data) - proves
        # Protect-PulseTypedPolicyRow's OWN redaction rule for a top-level Sensitive flag,
        # decoupled from whether any REAL shipped type happens to have one.
        $syntheticTypeMap = @{
            '#microsoft.graph.syntheticType' = @{
                Properties = @(
                    @{ Name = 'secretField'; Sensitive = $true }
                    @{ Name = 'ordinaryField'; Sensitive = $false }
                )
            }
        }
        $row = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.syntheticType'; secretField = 'PLANTED'; ordinaryField = 'keep-me' }

        $result = InModuleScope TenantPulse -ArgumentList $row, $syntheticTypeMap {
            param($row, $typeMap)
            Protect-PulseTypedPolicyRow -Row $row -TypeMap $typeMap
        }

        $result.secretField.redacted | Should -BeTrue
        $result.ordinaryField | Should -Be 'keep-me'
    }
}

Describe 'Protect-PulseTypedPolicyNestedElement - FAIL CLOSED (task-2.3-review round 2, finding 1)' {
    It 'redacts a PSObject-shaped element normally (only the flagged property name)' {
        $element = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.omaSettingString'; omaUri = './x'; value = 'PLANTED' }

        $result = InModuleScope TenantPulse -ArgumentList $element {
            param($element)
            Protect-PulseTypedPolicyNestedElement -Element $element -SensitiveNames @('value')
        }

        $result.value.redacted | Should -BeTrue
        $result.omaUri | Should -Be './x'
    }

    It 'redacts an IDictionary-shaped element normally (only the flagged property name)' {
        $element = @{ '@odata.type' = '#microsoft.graph.omaSettingString'; omaUri = './x'; value = 'PLANTED' }

        $result = InModuleScope TenantPulse -ArgumentList $element {
            param($element)
            Protect-PulseTypedPolicyNestedElement -Element $element -SensitiveNames @('value')
        }

        $result.value.redacted | Should -BeTrue
        $result.omaUri | Should -Be './x'
    }

    It 'FAIL-OPEN REGRESSION: a bare SCALAR planted where an object was expected is redacted WHOLESALE, never passed through' {
        $plantedScalar = 'PLANTED-scalar-instead-of-object'

        $result = InModuleScope TenantPulse -ArgumentList $plantedScalar {
            param($scalar)
            Protect-PulseTypedPolicyNestedElement -Element $scalar -SensitiveNames @('value')
        }

        $result.redacted | Should -BeTrue
        ($result | ConvertTo-Json -Compress) | Should -Not -Match ([regex]::Escape($plantedScalar))
    }

    It 'FAIL-OPEN REGRESSION: an ARRAY planted where an object was expected is redacted WHOLESALE, never passed through' {
        $plantedArrayElement = 'PLANTED-array-instead-of-object'

        $result = InModuleScope TenantPulse -ArgumentList (, @($plantedArrayElement, 'other')) {
            param($arr)
            Protect-PulseTypedPolicyNestedElement -Element $arr -SensitiveNames @('value')
        }

        $result.redacted | Should -BeTrue
        ($result | ConvertTo-Json -Compress) | Should -Not -Match ([regex]::Escape($plantedArrayElement))
    }

    It 'FAIL-OPEN REGRESSION (end-to-end, via Protect-PulseTypedPolicySensitivePayload): a bare scalar sitting in the single-object Nested position (omaSettings NOT wrapped in an array) redacts wholesale' {
        # windows10CustomConfiguration's omaSettings is the one REAL Sensitive-nested
        # property in TypedPolicyMaps.psd1 today (installationSchedule's own Nested
        # properties are all Sensitive=$false, so it never even reaches the nested-redact
        # path at all - not a suitable fixture for this regression). A bare scalar sitting
        # where omaSettings is normally an array is exactly the "single-object Nested
        # position" branch this fix closes: pre-fix, this fell through to `return $Value`
        # unredacted.
        $plantedScalar = 'PLANTED-omaSettings-bare-scalar'
        $row = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
            id            = 'w1'
            omaSettings   = $plantedScalar
        }

        $result = InModuleScope TenantPulse -ArgumentList $row, $script:typedPolicyMaps {
            param($row, $maps)
            Protect-PulseTypedPolicySensitivePayload -Data @($row) -DatasetName 'deviceConfigurations' -TypedPolicyMaps $maps
        }

        $result[0].omaSettings.redacted | Should -BeTrue
        ($result[0] | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($plantedScalar))
    }

    It 'FAIL-OPEN REGRESSION (end-to-end): an omaSettings array containing a wrong-shaped scalar element alongside a normal object element redacts BOTH' {
        $plantedScalar = 'PLANTED-oma-scalar-element'
        $plantedObjectValue = 'PLANTED-oma-object-value'
        $row = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
            id            = 'c4'
            omaSettings   = @(
                $plantedScalar
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.omaSettingString'; omaUri = './x'; value = $plantedObjectValue }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $row, $script:typedPolicyMaps {
            param($row, $maps)
            Protect-PulseTypedPolicySensitivePayload -Data @($row) -DatasetName 'deviceConfigurations' -TypedPolicyMaps $maps
        }

        $result[0].omaSettings[0].redacted | Should -BeTrue
        $result[0].omaSettings[1].value.redacted | Should -BeTrue
        $serialized = $result[0] | ConvertTo-Json -Depth 10 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($plantedScalar))
        $serialized | Should -Not -Match ([regex]::Escape($plantedObjectValue))
    }
}
