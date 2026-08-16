BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    InModuleScope TenantPulse {
        function Get-GraphObject { param() }
    }
    Mock Get-GraphObject -ModuleName TenantPulse { throw 'Get-GraphObject must be mocked in this test.' }

    function New-TestDefinition {
        param(
            [string] $Id = 'device_vendor_msft_policy_config_example',
            [string] $Name = 'example',
            [string] $DisplayName = 'Example setting',
            [string] $RootDefinitionId = $null,
            [object[]] $Options = $null,
            [object] $Applicability = $null,
            [string] $ValueDefinitionODataType = $null
        )

        $definition = [ordered]@{
            id          = $Id
            name        = $Name
            displayName = $DisplayName
        }
        if ($RootDefinitionId) { $definition.rootDefinitionId = $RootDefinitionId }
        if ($Options) { $definition.options = $Options }
        if ($Applicability) { $definition.applicability = $Applicability }
        if ($ValueDefinitionODataType) {
            $definition.valueDefinition = [pscustomobject]@{ '@odata.type' = $ValueDefinitionODataType }
        }

        return [pscustomobject] $definition
    }
}

Describe 'Get-PulseSettingDefinitionIndex' {
    It 'returns an empty index for an empty corpus' {
        $index = InModuleScope TenantPulse {
            Get-PulseSettingDefinitionIndex -Data @()
        }

        $index.Count | Should -Be 0
    }

    It 'keys the index by definition id and holds only the six named fields' {
        $definition = New-TestDefinition -Id 'def-1' -Name 'setting_name' -DisplayName 'Setting Display'

        $index = InModuleScope TenantPulse -ArgumentList $definition {
            param($definition)
            Get-PulseSettingDefinitionIndex -Data @($definition)
        }

        $index.Contains('def-1') | Should -BeTrue
        $entry = $index['def-1']
        $entry.Keys.Count | Should -Be 6
        @($entry.Keys) | Sort-Object | Should -Be @('Applicability', 'DisplayName', 'IsSecretCapable', 'Name', 'OptionLabels', 'RootDefinitionId')

        $entry.Name | Should -Be 'setting_name'
        $entry.DisplayName | Should -Be 'Setting Display'
    }

    It 'never carries any field of the raw definition object besides the six named fields' {
        $definition = New-TestDefinition -Id 'def-2'
        Add-Member -InputObject $definition -NotePropertyName 'description' -NotePropertyValue 'a long description that must not appear in the index'
        Add-Member -InputObject $definition -NotePropertyName 'baseUri' -NotePropertyValue 'https://graph.microsoft.com/beta/deviceManagement/configurationSettings'
        Add-Member -InputObject $definition -NotePropertyName 'occurrence' -NotePropertyValue ([pscustomobject]@{ minDeviceCount = 0 })

        $index = InModuleScope TenantPulse -ArgumentList $definition {
            param($definition)
            Get-PulseSettingDefinitionIndex -Data @($definition)
        }

        $entry = $index['def-2']
        $entry.PSObject.Properties.Name -contains 'description' | Should -BeFalse
        ($entry.Keys -contains 'description') | Should -BeFalse
        ($entry.Keys -contains 'baseUri') | Should -BeFalse
        ($entry.Keys -contains 'occurrence') | Should -BeFalse
    }

    It 'populates RootDefinitionId when present on the raw definition' {
        $definition = New-TestDefinition -Id 'child-1' -RootDefinitionId 'root-1'

        $index = InModuleScope TenantPulse -ArgumentList $definition {
            param($definition)
            Get-PulseSettingDefinitionIndex -Data @($definition)
        }

        $index['child-1'].RootDefinitionId | Should -Be 'root-1'
    }

    It 'builds a compact optionId -> label map for a choice-shaped definition' {
        $options = @(
            [pscustomobject]@{ itemId = 'opt-1'; displayName = 'Option One' },
            [pscustomobject]@{ itemId = 'opt-2'; displayName = 'Option Two' }
        )
        $definition = New-TestDefinition -Id 'choice-1' -Options $options

        $index = InModuleScope TenantPulse -ArgumentList $definition {
            param($definition)
            Get-PulseSettingDefinitionIndex -Data @($definition)
        }

        $optionLabels = $index['choice-1'].OptionLabels
        $optionLabels.Count | Should -Be 2
        $optionLabels['opt-1'] | Should -Be 'Option One'
        $optionLabels['opt-2'] | Should -Be 'Option Two'
    }

    It 'defaults OptionLabels to an empty map for a non-choice definition' {
        $definition = New-TestDefinition -Id 'simple-1'

        $index = InModuleScope TenantPulse -ArgumentList $definition {
            param($definition)
            Get-PulseSettingDefinitionIndex -Data @($definition)
        }

        $index['simple-1'].OptionLabels.Count | Should -Be 0
    }

    It 'preserves the applicability object verbatim' {
        $applicability = [pscustomobject]@{ platform = 'windows10'; technologies = 'mdm' }
        $definition = New-TestDefinition -Id 'app-1' -Applicability $applicability

        $index = InModuleScope TenantPulse -ArgumentList $definition {
            param($definition)
            Get-PulseSettingDefinitionIndex -Data @($definition)
        }

        $index['app-1'].Applicability.platform | Should -Be 'windows10'
        $index['app-1'].Applicability.technologies | Should -Be 'mdm'
    }

    It 'flags IsSecretCapable true when valueDefinition.@odata.type names a SecretSettingValueDefinition subtype' {
        $definition = New-TestDefinition -Id 'secret-1' -ValueDefinitionODataType '#microsoft.graph.deviceManagementConfigurationSecretSettingValueDefinition'

        $index = InModuleScope TenantPulse -ArgumentList $definition {
            param($definition)
            Get-PulseSettingDefinitionIndex -Data @($definition)
        }

        $index['secret-1'].IsSecretCapable | Should -BeTrue
    }

    It 'flags IsSecretCapable false for an ordinary string-valued definition' {
        $definition = New-TestDefinition -Id 'string-1' -ValueDefinitionODataType '#microsoft.graph.deviceManagementConfigurationStringSettingValueDefinition'

        $index = InModuleScope TenantPulse -ArgumentList $definition {
            param($definition)
            Get-PulseSettingDefinitionIndex -Data @($definition)
        }

        $index['string-1'].IsSecretCapable | Should -BeFalse
    }

    It 'flags IsSecretCapable false when valueDefinition is entirely absent (a choice/group-shaped definition)' {
        $definition = New-TestDefinition -Id 'choice-shape-1'

        $index = InModuleScope TenantPulse -ArgumentList $definition {
            param($definition)
            Get-PulseSettingDefinitionIndex -Data @($definition)
        }

        $index['choice-shape-1'].IsSecretCapable | Should -BeFalse
    }

    It 'skips a row with no id rather than throwing' {
        $noIdRow = [pscustomobject]@{ name = 'no-id-here' }
        $goodRow = New-TestDefinition -Id 'has-id-1'

        $index = InModuleScope TenantPulse -ArgumentList $noIdRow, $goodRow {
            param($noIdRow, $goodRow)
            Get-PulseSettingDefinitionIndex -Data @($noIdRow, $goodRow)
        }

        $index.Count | Should -Be 1
        $index.Contains('has-id-1') | Should -BeTrue
    }

    It 'tolerates a null row inside the array' {
        $goodRow = New-TestDefinition -Id 'has-id-2'

        $index = InModuleScope TenantPulse -ArgumentList $goodRow {
            param($goodRow)
            Get-PulseSettingDefinitionIndex -Data @($null, $goodRow)
        }

        $index.Count | Should -Be 1
    }
}

Describe 'Save-PulseSettingDefinitionCorpus' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
        $script:context = [pscustomobject]@{ TenantId = 'tenant-guid-not-used-here' }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes reference/settingDefinitions.json atomically and records a Captured reference entry' {
        $rows = @(
            [pscustomobject]@{ id = 'def-a'; name = 'a'; displayName = 'A' }
            [pscustomobject]@{ id = 'def-b'; name = 'b'; displayName = 'B' }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' -and $Operation -eq 'ListBeta' } { $rows }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Save-PulseSettingDefinitionCorpus -Store $store -Context $context
        }

        $referenceFile = Join-Path $script:store.ReferencePath 'settingDefinitions.json'
        Test-Path -LiteralPath $referenceFile -PathType Leaf | Should -BeTrue

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.references.settingDefinitions.status | Should -Be 'Captured'
        $manifest.references.settingDefinitions.format | Should -Be 'json'
        $manifest.references.settingDefinitions.itemCount | Should -Be 2
        $manifest.references.settingDefinitions.sha256 | Should -Not -BeNullOrEmpty
        $manifest.references.settingDefinitions.retrievedUtc | Should -Not -BeNullOrEmpty
        $manifest.references.settingDefinitions.path | Should -Be 'reference/settingDefinitions.json'
    }

    It 'the sha256 recorded in the manifest matches the actual bytes written to disk' {
        $rows = @([pscustomobject]@{ id = 'def-a'; name = 'a'; displayName = 'A' })
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { $rows }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Save-PulseSettingDefinitionCorpus -Store $store -Context $context
        }

        $referenceFile = Join-Path $script:store.ReferencePath 'settingDefinitions.json'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes((Get-Content -LiteralPath $referenceFile -Raw))
        $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $actualSha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.references.settingDefinitions.sha256 | Should -Be $actualSha256
    }

    It 'returns only the compact index - never the raw corpus rows' {
        $rows = @(
            [pscustomobject]@{ id = 'def-a'; name = 'a'; displayName = 'A'; description = 'a long raw field' }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { $rows }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Save-PulseSettingDefinitionCorpus -Store $store -Context $context
        }

        $result.Contains('def-a') | Should -BeTrue
        $result['def-a'].Keys.Count | Should -Be 6
        ($result['def-a'].Keys -contains 'description') | Should -BeFalse
    }

    It 'strips GraphKit provenance stamps from the written reference file' {
        $rows = @(
            [pscustomobject]@{ id = 'def-a'; name = 'a'; _Tenant = 'ivy24'; _RetrievedUtc = '2026-01-01T00:00:00.000Z'; _GraphPath = '/x'; _ApiVersion = 'beta' }
        )
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { $rows }

        InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Save-PulseSettingDefinitionCorpus -Store $store -Context $context
        }

        $referenceFile = Join-Path $script:store.ReferencePath 'settingDefinitions.json'
        $written = Get-Content -LiteralPath $referenceFile -Raw
        $written | Should -Not -Match '_Tenant'
        $written | Should -Not -Match '_RetrievedUtc'
        $written | Should -Not -Match '_GraphPath'
        $written | Should -Not -Match '_ApiVersion'
    }

    It 'on capture failure, records a Failed reference entry with a reason and writes no reference file' {
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { throw "Get-GraphObject failed for 'ConfigurationSettingDefinition/ListBeta': 503 Service Unavailable." }

        $result = InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
            param($store, $context)
            Save-PulseSettingDefinitionCorpus -Store $store -Context $context
        }

        $result | Should -BeNullOrEmpty

        $referenceFile = Join-Path $script:store.ReferencePath 'settingDefinitions.json'
        Test-Path -LiteralPath $referenceFile -PathType Leaf | Should -BeFalse

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.references.settingDefinitions.status | Should -Be 'Failed'
        $manifest.references.settingDefinitions.reason | Should -Match 'capture-failed'
        $manifest.references.settingDefinitions.reason | Should -Match '503'
    }

    It 'does not throw when Get-GraphObject fails - the caller gets $null back, not an exception' {
        Mock Get-GraphObject -ModuleName TenantPulse -ParameterFilter { $Type -eq 'ConfigurationSettingDefinition' } { throw 'transport failure' }

        {
            InModuleScope TenantPulse -ArgumentList $script:store, $script:context {
                param($store, $context)
                Save-PulseSettingDefinitionCorpus -Store $store -Context $context
            }
        } | Should -Not -Throw
    }
}
