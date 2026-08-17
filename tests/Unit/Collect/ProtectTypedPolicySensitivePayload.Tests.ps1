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

    # Part C, T3.4 (deeper-nesting map schema change): TypedPolicyMaps.psd1's own
    # windows10CustomConfiguration.omaSettings.value entry now ALSO carries a Nested
    # description of its real observed 2-level shape (a `redacted` marker property) -
    # this test proves that schema addition did not weaken this pass's own Sensitive-name
    # redaction (now recursive, see the T3.4 fix-round Describe below - but Sensitive still
    # wins BEFORE any such recursion is ever attempted, so this specific case is unaffected
    # either way): a raw `value` that is ALREADY an object (matching the real live-27
    # evidence, and also what an un-collected, genuinely secret Graph value would never
    # legitimately look like) still redacts wholesale to a single {redacted:true} marker,
    # not walked into or double-wrapped.
    It 'a raw omaSettings[].value that is ITSELF an object (matching the real live-confirmed deeper-nesting shape) still redacts wholesale via Sensitive-wins-first' {
        $plantedInnerField = 'PLANTED-already-object-shaped-value'
        $row = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
            id            = 'c5'
            omaSettings   = @(
                [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.omaSettingBoolean'
                    omaUri        = './x'
                    value         = [pscustomobject]@{ someInnerField = $plantedInnerField }
                }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $row, $script:typedPolicyMaps {
            param($row, $maps)
            Protect-PulseTypedPolicySensitivePayload -Data @($row) -DatasetName 'deviceConfigurations' -TypedPolicyMaps $maps
        }

        $result[0].omaSettings[0].value.redacted | Should -BeTrue
        # The wholesale marker replaces the ENTIRE object - no trace of its own inner shape
        # (someInnerField) survives, proving this pass did not try to walk into value's own
        # newly-added Nested description (it doesn't need to - Sensitive already redacted
        # the whole container before any such walk would matter).
        ($result[0].omaSettings[0].value.PSObject.Properties.Name) | Should -Be @('redacted')
        ($result[0] | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($plantedInnerField))
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

# T3.4 whole-task dual-review, fix round 1, MEDIUM finding (adversarial-proven live): this
# pass used to be capped at ONE level of Nested while ConvertTo-PulseTypedPolicyRows.ps1's
# row-emission walk had already grown genuine recursion in Part C - a depth-3 Sensitive
# leaf reached raw disk cleartext through THIS pass (inert with today's shipped map, but a
# real structural hole). RED-THEN-GREEN: this Describe's own Its were run against the
# PRE-fix (depth-1-only) Protect-PulseTypedPolicyRow/Protect-PulseTypedPolicyPropertyValue
# and failed (the depth-3 secret leaked into the cloned row) - see this task's own report
# for the failure transcript. Now green against the recursive
# Protect-PulseTypedPolicyValueBySpec/Protect-PulseTypedPolicyNestedContainer engine.
Describe 'Protect-PulseTypedPolicyRow - RECURSIVE Nested redaction (T3.4 fix round 1, MEDIUM)' {
    It 'a depth-3 Sensitive leaf (non-Sensitive -> non-Sensitive -> Sensitive) is redacted in the RAW dataset write, not just the row-emission walk' {
        $syntheticTypeMap = @{
            '#microsoft.graph.syntheticDepth3Type' = @{
                Properties = @(
                    @{
                        Name      = 'level1'
                        Sensitive = $false
                        Nested    = @{
                            Properties = @(
                                @{
                                    Name      = 'level2'
                                    Sensitive = $false
                                    Nested    = @{
                                        Properties = @(
                                            @{ Name = 'level3Secret'; Sensitive = $true }
                                            @{ Name = 'level3Plain'; Sensitive = $false }
                                        )
                                    }
                                }
                            )
                        }
                    }
                )
            }
        }
        $plantedSecret = 'PLANTED-raw-write-depth3-secret-zzz333'
        $row = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.syntheticDepth3Type'
            id            = 'depth3-1'
            level1        = [pscustomobject]@{
                level2 = [pscustomobject]@{
                    level3Secret = $plantedSecret
                    level3Plain  = 'plain-value-77'
                }
            }
        }

        $result = InModuleScope TenantPulse -ArgumentList $row, $syntheticTypeMap {
            param($row, $typeMap)
            Protect-PulseTypedPolicyRow -Row $row -TypeMap $typeMap
        }

        $result.level1.level2.level3Secret.redacted | Should -BeTrue
        $result.level1.level2.level3Plain | Should -Be 'plain-value-77'
        ($result | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'the same depth-3 shape redacts correctly through Protect-PulseTypedPolicySensitivePayload''s own public entry point (deviceConfigurations dataset), not just the internal Row helper' {
        $syntheticTypeMap = @{
            'deviceConfiguration' = @{
                '#microsoft.graph.syntheticDepth3Type' = @{
                    Properties = @(
                        @{
                            Name      = 'level1'
                            Sensitive = $false
                            Nested    = @{
                                Properties = @(
                                    @{
                                        Name      = 'level2'
                                        Sensitive = $false
                                        Nested    = @{
                                            Properties = @( @{ Name = 'level3Secret'; Sensitive = $true } )
                                        }
                                    }
                                )
                            }
                        }
                    )
                }
            }
        }
        $plantedSecret = 'PLANTED-public-entry-depth3-secret-zzz444'
        $row = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.syntheticDepth3Type'
            id            = 'depth3-2'
            level1        = [pscustomobject]@{ level2 = [pscustomobject]@{ level3Secret = $plantedSecret } }
        }

        $result = InModuleScope TenantPulse -ArgumentList $row, $syntheticTypeMap {
            param($row, $maps)
            Protect-PulseTypedPolicySensitivePayload -Data @($row) -DatasetName 'deviceConfigurations' -TypedPolicyMaps $maps
        }

        $result[0].level1.level2.level3Secret.redacted | Should -BeTrue
        ($result[0] | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($plantedSecret))
    }

    It 'a depth-3 chain with an ARRAY at level1 (per-element recursion) redacts every element''s own depth-3 secret independently' {
        $syntheticTypeMap = @{
            '#microsoft.graph.syntheticDepth3ArrayType' = @{
                Properties = @(
                    @{
                        Name      = 'items'
                        Sensitive = $false
                        Nested    = @{
                            Properties = @(
                                @{
                                    Name      = 'level2'
                                    Sensitive = $false
                                    Nested    = @{
                                        Properties = @( @{ Name = 'level3Secret'; Sensitive = $true } )
                                    }
                                }
                            )
                        }
                    }
                )
            }
        }
        $secretA = 'PLANTED-array-elem-a-secret'
        $secretB = 'PLANTED-array-elem-b-secret'
        $row = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.syntheticDepth3ArrayType'
            id            = 'depth3-array-1'
            items         = @(
                [pscustomobject]@{ level2 = [pscustomobject]@{ level3Secret = $secretA } }
                [pscustomobject]@{ level2 = [pscustomobject]@{ level3Secret = $secretB } }
            )
        }

        $result = InModuleScope TenantPulse -ArgumentList $row, $syntheticTypeMap {
            param($row, $typeMap)
            Protect-PulseTypedPolicyRow -Row $row -TypeMap $typeMap
        }

        $result.items[0].level2.level3Secret.redacted | Should -BeTrue
        $result.items[1].level2.level3Secret.redacted | Should -BeTrue
        $serialized = $result | ConvertTo-Json -Depth 10 -Compress
        $serialized | Should -Not -Match ([regex]::Escape($secretA))
        $serialized | Should -Not -Match ([regex]::Escape($secretB))
    }

    It 'a depth-3 chain with a hostile scalar sitting at level2 (where an object was expected) redacts WHOLESALE, fail-closed, at that depth' {
        $syntheticTypeMap = @{
            '#microsoft.graph.syntheticDepth3HostileType' = @{
                Properties = @(
                    @{
                        Name      = 'level1'
                        Sensitive = $false
                        Nested    = @{
                            Properties = @(
                                @{
                                    Name      = 'level2'
                                    Sensitive = $false
                                    Nested    = @{
                                        Properties = @( @{ Name = 'level3Secret'; Sensitive = $true } )
                                    }
                                }
                            )
                        }
                    }
                )
            }
        }
        $plantedScalar = 'PLANTED-hostile-scalar-at-level2'
        $row = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.syntheticDepth3HostileType'
            id            = 'depth3-hostile-1'
            # level2 is a bare scalar here, not the expected object - fail-closed must
            # redact the whole level2 value wholesale rather than pass it through.
            level1        = [pscustomobject]@{ level2 = $plantedScalar }
        }

        $result = InModuleScope TenantPulse -ArgumentList $row, $syntheticTypeMap {
            param($row, $typeMap)
            Protect-PulseTypedPolicyRow -Row $row -TypeMap $typeMap
        }

        $result.level1.level2.redacted | Should -BeTrue
        ($result | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match ([regex]::Escape($plantedScalar))
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
