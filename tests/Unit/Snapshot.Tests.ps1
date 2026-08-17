BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $repoRoot = $script:repoRoot

    # Import the BUILT module (never dot-source source files: they would redefine module
    # classes and Add-Type types in test scope). Pester discovers tests per file, so each
    # file imports it.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force
}

Describe 'New-PulseSnapshotStore' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'creates datasets, reference and expanded directories plus a manifest skeleton' {
        $store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }

        $store.Root | Should -Be $script:storeRoot
        Test-Path -LiteralPath $store.DatasetsPath -PathType Container | Should -BeTrue
        Test-Path -LiteralPath $store.ReferencePath -PathType Container | Should -BeTrue
        Test-Path -LiteralPath $store.ExpandedPath -PathType Container | Should -BeTrue
        Test-Path -LiteralPath $store.ManifestPath -PathType Leaf | Should -BeTrue

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json

        $manifest.schemaVersion | Should -Not -BeNullOrEmpty
        $manifest.createdUtc | Should -Not -BeNullOrEmpty
        $manifest.PSObject.Properties.Name | Should -Contain 'tenant'
        $manifest.producer.PSObject.Properties.Name | Should -Contain 'tenantPulse'
        $manifest.producer.tenantPulse | Should -Not -BeNullOrEmpty
        $manifest.producer.PSObject.Properties.Name | Should -Contain 'graphKit'
        $manifest.producer.graphKit | Should -BeNullOrEmpty
        $manifest.collectionFailure | Should -BeNullOrEmpty
        $manifest.datasets.PSObject.Properties.Name.Count | Should -Be 0
    }

    It 'records the module''s own version as the tenantPulse producer version' {
        $store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }

        $moduleVersion = (Get-Module TenantPulse).Version.ToString()
        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.producer.tenantPulse | Should -Be $moduleVersion
    }

    # Item 26 (final fix wave): producer.graphKit was always null with no writer.
    It 'records -GraphKitVersion as the producer.graphKit field when supplied' {
        $store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot -GraphKitVersion '0.1.0'
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.producer.graphKit | Should -Be '0.1.0'
    }

    # Item 3 (final fix wave): store reuse must not leak a prior/foreign row.
    It 'clears a foreign file out of datasets/ when reusing an existing store path' {
        $firstStore = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }

        $foreignFile = Join-Path $firstStore.DatasetsPath 'managedDevices.json'
        Set-Content -LiteralPath $foreignFile -Value '[{"id":"leaked-from-a-prior-run"}]' -NoNewline -Encoding utf8
        Test-Path -LiteralPath $foreignFile -PathType Leaf | Should -BeTrue

        $secondStore = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }

        Test-Path -LiteralPath (Join-Path $secondStore.DatasetsPath 'managedDevices.json') -PathType Leaf | Should -BeFalse
        Test-Path -LiteralPath $secondStore.DatasetsPath -PathType Container | Should -BeTrue
    }
}

Describe 'Write-PulseDataset and Read-PulseDataset' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'round-trips written objects through Read-PulseDataset' {
        $data = @(
            [pscustomobject]@{ id = 'a'; value = 1 }
            [pscustomobject]@{ id = 'b'; value = 2 }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $data {
            param($store, $data)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected'
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'Sample'
        }

        $result.Count | Should -Be 2
        $result[0].id | Should -Be 'a'
        $result[0].value | Should -Be 1
        $result[1].id | Should -Be 'b'
        $result[1].value | Should -Be 2
    }

    # Task 1.11 review follow-up: GraphKit's Get-GraphObject stamps every row with
    # _Tenant/_RetrievedUtc/_GraphPath/_ApiVersion (see Remove-PulseGraphRowProvenance's
    # docstring). Write-PulseDataset now strips all four before serialization - this
    # pins that behavior directly against Write-PulseDataset, independent of the
    # Get-PulseTenantSnapshot end-to-end test that exercises the same thing via a real
    # collection run.
    It 'strips GraphKit''s per-row provenance stamps (_Tenant, _RetrievedUtc, _GraphPath, _ApiVersion) before serializing a dataset' {
        $data = @(
            [pscustomobject]@{
                id            = 'a'
                value         = 1
                _Tenant       = 'ivy24'
                _RetrievedUtc = [datetime]::UtcNow
                _GraphPath    = '/deviceManagement/managedDevices'
                _ApiVersion   = 'v1.0'
            }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $data {
            param($store, $data)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected'
        }

        $datasetFile = Join-Path $script:store.DatasetsPath 'Sample.json'
        $writtenJson = Get-Content -LiteralPath $datasetFile -Raw

        $writtenJson | Should -Not -Match '_Tenant'
        $writtenJson | Should -Not -Match '_RetrievedUtc'
        $writtenJson | Should -Not -Match '_GraphPath'
        $writtenJson | Should -Not -Match '_ApiVersion'
        $writtenJson | Should -Not -Match 'ivy24'

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'Sample'
        }
        $result[0].id | Should -Be 'a'
        $result[0].value | Should -Be 1
        $result[0].PSObject.Properties.Name | Should -Not -Contain '_Tenant'
    }

    It 'leaves a row with none of the four stamp properties unchanged (no-op when there is nothing to strip)' {
        $data = @([pscustomobject]@{ id = 'a'; value = 1 })

        InModuleScope TenantPulse -ArgumentList $script:store, $data {
            param($store, $data)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected'
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'Sample'
        }
        $result[0].id | Should -Be 'a'
        $result[0].value | Should -Be 1
    }

    It 'records status, apiVersion, sha256 and itemCount in the manifest entry for a Collected dataset' {
        $data = @(
            [pscustomobject]@{ id = 'a' }
            [pscustomobject]@{ id = 'b' }
            [pscustomobject]@{ id = 'c' }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $data {
            param($store, $data)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'beta' -Status 'Collected'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.datasets.Sample

        $entry.status | Should -Be 'Collected'
        $entry.apiVersion | Should -Be 'beta'
        $entry.sha256 | Should -Match '^[0-9a-f]{64}$'
        $entry.itemCount | Should -Be 3
        $entry.collectedUtc | Should -Not -BeNullOrEmpty
    }

    It 'throws naming the file when the on-disk dataset hash no longer matches the manifest' {
        $data = @([pscustomobject]@{ id = 'a' })

        InModuleScope TenantPulse -ArgumentList $script:store, $data {
            param($store, $data)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected'
        }

        $datasetFile = Join-Path $script:store.DatasetsPath 'Sample.json'
        Add-Content -LiteralPath $datasetFile -Value 'tampered'

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Read-PulseDataset -Store $store -Name 'Sample'
            }
        } | Should -Throw -ExpectedMessage '*Sample.json*'
    }

    # omp finding #2: a UTF-16 re-encode of the IDENTICAL decoded text must still fail the
    # hash check - the pre-fix code hashed a re-encoding of Get-Content-decoded text, not
    # the actual on-disk bytes, so this exact swap silently passed before this fix.
    It 'throws when the on-disk file is swapped for a UTF-16 re-encode of the identical text (omp finding #2)' {
        $data = @([pscustomobject]@{ id = 'a' })

        InModuleScope TenantPulse -ArgumentList $script:store, $data {
            param($store, $data)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected'
        }

        $datasetFile = Join-Path $script:store.DatasetsPath 'Sample.json'
        $originalText = Get-Content -LiteralPath $datasetFile -Raw
        # Re-save the IDENTICAL decoded text as UTF-16LE with a BOM - Get-Content -Raw
        # auto-detects the BOM and decodes back to the same string, but the actual on-disk
        # BYTES are completely different from what was hashed at write time.
        [System.IO.File]::WriteAllText($datasetFile, $originalText, [System.Text.Encoding]::Unicode)

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Read-PulseDataset -Store $store -Name 'Sample'
            }
        } | Should -Throw -ExpectedMessage '*Sample.json*'
    }

    It 'writes only a manifest entry, no dataset file, for a Failed status' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Write-PulseDataset -Store $store -Name 'Broken' -ApiVersion 'v1.0' -Status 'Failed' -Reason 'throttled'
        }

        $datasetFile = Join-Path $script:store.DatasetsPath 'Broken.json'
        Test-Path -LiteralPath $datasetFile | Should -BeFalse

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.datasets.Broken

        $entry.status | Should -Be 'Failed'
        $entry.reason | Should -Be 'throttled'
        $entry.sha256 | Should -BeNullOrEmpty
        $entry.itemCount | Should -BeNullOrEmpty
    }

    It 'writes only a manifest entry, no dataset file, for a Skipped status' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Write-PulseDataset -Store $store -Name 'NotNeeded' -ApiVersion 'v1.0' -Status 'Skipped' -Reason 'feature disabled'
        }

        $datasetFile = Join-Path $script:store.DatasetsPath 'NotNeeded.json'
        Test-Path -LiteralPath $datasetFile | Should -BeFalse

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.NotNeeded.status | Should -Be 'Skipped'
        $manifest.datasets.NotNeeded.reason | Should -Be 'feature disabled'
    }

    # Task 1.11 GraphKit 0.1.1 live-gate surprise (Ivy24 lab tenant): some Graph payloads
    # carry the raw tenant id as a genuine response FIELD, not a GraphKit provenance stamp -
    # Organization.id IS the tenant GUID, DirectoryRoleAssignment.principalOrganizationId is
    # also the tenant GUID. See Protect-PulseGraphRowTenantId's own docstring.
    It '-TenantId/-Pseudonym redact the raw tenant GUID out of row content, including a value equal to `id`' {
        $tenantId = '00000000-1111-2222-3333-444444444444'
        $data = @(
            [pscustomobject]@{ id = $tenantId; displayName = 'Contoso' }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $data, $tenantId {
            param($store, $data, $tenantId)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected' -TenantId $tenantId -Pseudonym 'tp-abc123'
        }

        $datasetFile = Join-Path $script:store.DatasetsPath 'Sample.json'
        $writtenJson = Get-Content -LiteralPath $datasetFile -Raw
        $writtenJson | Should -Not -Match ([regex]::Escape($tenantId))
        $writtenJson | Should -Match 'tp-abc123'

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'Sample'
        }
        $result[0].id | Should -Be 'tp-abc123'
        $result[0].displayName | Should -Be 'Contoso'
    }

    It 'redacts a nested tenant GUID (e.g. a DirectoryRoleAssignment-shaped principalOrganizationId) too' {
        $tenantId = '00000000-1111-2222-3333-444444444444'
        $data = @(
            [pscustomobject]@{
                id                     = 'assignment-1'
                principalOrganizationId = $tenantId
                principal              = [pscustomobject]@{ id = 'principal-1'; organizationId = $tenantId }
            }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $data, $tenantId {
            param($store, $data, $tenantId)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected' -TenantId $tenantId -Pseudonym 'tp-abc123'
        }

        $datasetFile = Join-Path $script:store.DatasetsPath 'Sample.json'
        $writtenJson = Get-Content -LiteralPath $datasetFile -Raw
        $writtenJson | Should -Not -Match ([regex]::Escape($tenantId))

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'Sample'
        }
        $result[0].principalOrganizationId | Should -Be 'tp-abc123'
        $result[0].principal.organizationId | Should -Be 'tp-abc123'
        $result[0].id | Should -Be 'assignment-1'
    }

    It 'omitting -TenantId/-Pseudonym leaves row content completely unredacted (pre-existing behavior for every other caller)' {
        $tenantId = '00000000-1111-2222-3333-444444444444'
        $data = @([pscustomobject]@{ id = $tenantId })

        InModuleScope TenantPulse -ArgumentList $script:store, $data {
            param($store, $data)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected'
        }

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'Sample'
        }
        $result[0].id | Should -Be $tenantId
    }

    It 'does NOT mutate the caller''s original -Data row objects (the collector reads the real id off these for IdFromDataset)' {
        $tenantId = '00000000-1111-2222-3333-444444444444'
        $originalRow = [pscustomobject]@{ id = $tenantId }
        $data = @($originalRow)

        InModuleScope TenantPulse -ArgumentList $script:store, $data, $tenantId {
            param($store, $data, $tenantId)
            Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected' -TenantId $tenantId -Pseudonym 'tp-abc123'
        }

        # The original object the caller still holds a reference to must be untouched -
        # only the CLONE written to disk is redacted.
        $originalRow.id | Should -Be $tenantId
    }

    # Task 1.11 live-gate finding (Ivy24, real ConditionalAccessPolicy rows): GraphKit
    # returns several nested Graph properties (conditions, grantControls, sessionControls)
    # as [System.Collections.Hashtable] / OrderedHashtable, not PSCustomObject. A Hashtable's
    # .PSObject.Properties surfaces its ADAPTER members (Keys, Values, Count, IsReadOnly,
    # SyncRoot, ...) rather than its dictionary entries - and a non-synchronized Hashtable's
    # SyncRoot property returns the SAME hashtable instance, so walking .PSObject.Properties
    # on a Hashtable is a self-reference the recursive redactor previously followed straight
    # into a call-depth overflow on every real policy row (reproduced live: ~4s burned per
    # row before falling back to the unredacted original - see Protect-PulseGraphRowTenantId).
    It 'redacts a tenant GUID nested inside a Hashtable-valued property (e.g. a real ConditionalAccessPolicy''s conditions/grantControls shape) without call-depth overflow' {
        $tenantId = '00000000-1111-2222-3333-444444444444'
        $data = @(
            [pscustomobject]@{
                id         = 'policy-1'
                conditions = [ordered] @{
                    applications = [ordered] @{ includeApplications = @('All') }
                    users        = [ordered] @{ excludeGuestsOrExternalUsers = [ordered] @{ externalTenants = [ordered] @{ membershipKind = 'all' } } }
                }
                grantControls = [ordered] @{ tenantOwnerId = $tenantId; operator = 'OR' }
            }
        )

        $writeDuration = Measure-Command {
            InModuleScope TenantPulse -ArgumentList $script:store, $data, $tenantId {
                param($store, $data, $tenantId)
                Write-PulseDataset -Store $store -Name 'Sample' -Data $data -ApiVersion 'v1.0' -Status 'Collected' -TenantId $tenantId -Pseudonym 'tp-abc123'
            }
        }

        # A regression to the old behavior burns whole seconds per row hunting for a call
        # depth it will never legitimately reach; a correct dictionary walk is near-instant.
        $writeDuration.TotalSeconds | Should -BeLessThan 2

        $datasetFile = Join-Path $script:store.DatasetsPath 'Sample.json'
        $writtenJson = Get-Content -LiteralPath $datasetFile -Raw
        $writtenJson | Should -Not -Match ([regex]::Escape($tenantId))

        $result = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Read-PulseDataset -Store $store -Name 'Sample'
        }
        $result[0].grantControls.tenantOwnerId | Should -Be 'tp-abc123'
        $result[0].conditions.users.excludeGuestsOrExternalUsers.externalTenants.membershipKind | Should -Be 'all'
    }
}

# Post-live-gate-review hardening (empirically probed: cyclic in-memory structures hang
# Protect-PulseGraphRowTenantId indefinitely - live Graph responses are bounded so no live
# field ever produces one, but the module hardens by construction rather than relying on
# that being true forever). Covers both halves of the fix: (1) a MaxDepth/CurrentDepth
# budget - matching ConvertTo-PulseCanonicalJson's own 64-level default, accounting for the
# root array level - that throws quickly, by name, instead of eventually blowing a native
# call stack; (2) FAIL CLOSED - any traversal error now propagates instead of being
# swallowed into "return the row unredacted", so a row that cannot be proven redacted is
# never written to disk.
Describe 'Protect-PulseGraphRowTenantId depth guard and fail-closed hardening' {
    BeforeEach {
        $script:tenantId = '00000000-1111-2222-3333-444444444444'
    }

    # Builds a chain of $Depth nested [pscustomobject] wrappers (outermost = depth 1, the
    # row itself) around a leaf object carrying $LeafValue - lets a test assert both "did
    # it throw" AND, for the succeeding case, "did it actually redact all the way down",
    # so a depth budget that silently truncated the walk instead of correctly completing
    # it would still be caught.
    function script:New-PulseDepthFixture {
        param([int] $Depth, [string] $LeafValue)

        $node = [pscustomobject] @{ leaf = $LeafValue }
        for ($d = 2; $d -le $Depth; $d++) {
            $node = [pscustomobject] @{ child = $node }
        }
        return $node
    }

    It 'a row nested to depth 63 (within the 64-level budget) succeeds and is fully redacted at the deepest level' {
        $row = New-PulseDepthFixture -Depth 63 -LeafValue $script:tenantId

        $result = InModuleScope TenantPulse -ArgumentList $row, $script:tenantId {
            param($row, $tenantId)
            Protect-PulseGraphRowTenantId -Data @($row) -TenantId $tenantId -Pseudonym 'tp-abc123'
        }

        $leaf = $result[0]
        for ($d = 2; $d -le 63; $d++) { $leaf = $leaf.child }
        $leaf.leaf | Should -Be 'tp-abc123'
    }

    It 'a row nested to depth 65 (beyond the 64-level budget) throws quickly, naming the exhausted depth' {
        $row = New-PulseDepthFixture -Depth 65 -LeafValue $script:tenantId

        $duration = Measure-Command {
            {
                InModuleScope TenantPulse -ArgumentList $row, $script:tenantId {
                    param($row, $tenantId)
                    Protect-PulseGraphRowTenantId -Data @($row) -TenantId $tenantId -Pseudonym 'tp-abc123'
                }
            } | Should -Throw -ExpectedMessage '*maximum redaction depth*64*'
        }
        $duration.TotalSeconds | Should -BeLessThan 2
    }

    It 'a self-referential (cyclic) Hashtable throws the depth error quickly instead of hanging' {
        $cyclic = @{ id = 'p1' }
        $cyclic['self'] = $cyclic
        $row = [pscustomobject] @{ id = $script:tenantId; nested = $cyclic }

        $duration = Measure-Command {
            {
                InModuleScope TenantPulse -ArgumentList $row, $script:tenantId {
                    param($row, $tenantId)
                    Protect-PulseGraphRowTenantId -Data @($row) -TenantId $tenantId -Pseudonym 'tp-abc123'
                }
            } | Should -Throw -ExpectedMessage '*maximum redaction depth*'
        }
        $duration.TotalSeconds | Should -BeLessThan 5
    }

    It 'a self-referential (cyclic) PSObject throws the depth error quickly instead of hanging' {
        $cyclic = [pscustomobject] @{ id = $script:tenantId }
        Add-Member -InputObject $cyclic -NotePropertyName 'self' -NotePropertyValue $cyclic

        $duration = Measure-Command {
            {
                InModuleScope TenantPulse -ArgumentList $cyclic, $script:tenantId {
                    param($row, $tenantId)
                    Protect-PulseGraphRowTenantId -Data @($row) -TenantId $tenantId -Pseudonym 'tp-abc123'
                }
            } | Should -Throw -ExpectedMessage '*maximum redaction depth*'
        }
        $duration.TotalSeconds | Should -BeLessThan 5
    }

    It 'a self-referential (cyclic) array/enumerable throws the depth error quickly instead of hanging' {
        $cyclicArray = [object[]]::new(1)
        $cyclicArray[0] = $cyclicArray
        $row = [pscustomobject] @{ id = $script:tenantId; items = $cyclicArray }

        $duration = Measure-Command {
            {
                InModuleScope TenantPulse -ArgumentList $row, $script:tenantId {
                    param($row, $tenantId)
                    Protect-PulseGraphRowTenantId -Data @($row) -TenantId $tenantId -Pseudonym 'tp-abc123'
                }
            } | Should -Throw -ExpectedMessage '*maximum redaction depth*'
        }
        $duration.TotalSeconds | Should -BeLessThan 5
    }
}

Describe 'Remove-PulseGraphRowProvenance' {
    It 'removes all four GraphKit stamp properties and leaves every other property untouched' {
        $row = [pscustomobject]@{
            id            = 'a'
            value         = 42
            _Tenant       = 'ivy24'
            _RetrievedUtc = [datetime]::UtcNow
            _GraphPath    = '/some/path'
            _ApiVersion   = 'v1.0'
        }

        $result = InModuleScope TenantPulse -ArgumentList (, @($row)) {
            param($data)
            Remove-PulseGraphRowProvenance -Data $data
        }

        $result.Count | Should -Be 1
        $result[0].id | Should -Be 'a'
        $result[0].value | Should -Be 42
        $result[0].PSObject.Properties.Name | Should -Not -Contain '_Tenant'
        $result[0].PSObject.Properties.Name | Should -Not -Contain '_RetrievedUtc'
        $result[0].PSObject.Properties.Name | Should -Not -Contain '_GraphPath'
        $result[0].PSObject.Properties.Name | Should -Not -Contain '_ApiVersion'
    }

    It 'is a no-op for a row that carries none of the four stamp names' {
        $row = [pscustomobject]@{ id = 'a'; value = 1 }

        $result = InModuleScope TenantPulse -ArgumentList (, @($row)) {
            param($data)
            Remove-PulseGraphRowProvenance -Data $data
        }

        $result[0].id | Should -Be 'a'
        $result[0].value | Should -Be 1
    }

    It 'handles an empty array without throwing' {
        {
            InModuleScope TenantPulse -ArgumentList (, [object[]] @()) {
                param($data)
                Remove-PulseGraphRowProvenance -Data $data
            }
        } | Should -Not -Throw
    }

    It 'skips a $null row rather than throwing' {
        $rows = [object[]] @($null, [pscustomobject]@{ id = 'a'; _Tenant = 'ivy24' })

        $result = InModuleScope TenantPulse -ArgumentList (, $rows) {
            param($data)
            Remove-PulseGraphRowProvenance -Data $data
        }

        $result.Count | Should -Be 2
        $result[0] | Should -BeNullOrEmpty
        $result[1].PSObject.Properties.Name | Should -Not -Contain '_Tenant'
    }

    It 'leaves a non-PSObject row (e.g. a hashtable) untouched rather than throwing' {
        $rows = [object[]] @(@{ id = 'a'; _Tenant = 'ivy24' })

        {
            InModuleScope TenantPulse -ArgumentList (, $rows) {
                param($data)
                Remove-PulseGraphRowProvenance -Data $data
            }
        } | Should -Not -Throw
    }
}

Describe 'Get-PulseSnapshotManifest' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'returns the parsed manifest with dataset statuses and reasons after writes' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Write-PulseDataset -Store $store -Name 'Ok' -Data @([pscustomobject]@{ id = 1 }) -ApiVersion 'v1.0' -Status 'Collected'
            Write-PulseDataset -Store $store -Name 'Bad' -ApiVersion 'v1.0' -Status 'Failed' -Reason 'timeout'
        }

        $manifest = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Get-PulseSnapshotManifest -Store $store
        }

        $manifest.datasets.Ok.status | Should -Be 'Collected'
        $manifest.datasets.Bad.status | Should -Be 'Failed'
        $manifest.datasets.Bad.reason | Should -Be 'timeout'
    }
}

# Part E, T3.4 (carried from the T3.3 review): manifest createdUtc culture-coercion fix.
# Get-PulseSnapshotManifest used to call plain `ConvertFrom-Json -AsHashtable`, and
# Get-PulseSnapshotStore used to call plain `ConvertFrom-Json` - both auto-parse any
# ISO-8601-looking JSON string into a real [datetime], which every downstream consumer
# then re-casts back to [string] (culture-sensitive, second-precision ToString()) instead
# of ever seeing the original text. These tests are RED against the pre-fix code (a plain
# ConvertFrom-Json/-AsHashtable read loses the 7-digit fraction and reformats with the
# thread's current culture) and GREEN against the fix (ConvertFrom-PulseJsonPreservingStrings
# keeps createdUtc as the exact source string all the way through).
Describe 'Manifest createdUtc culture-coercion fix (Part E, T3.4)' {
    BeforeEach {
        $script:culturePreservingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $script:culturePreservingRoot -ItemType Directory -Force | Out-Null
        $script:culturePreservingManifestPath = Join-Path $script:culturePreservingRoot 'manifest.json'
        # Hand-written manifest.json (same raw-write pattern the 'Get-PulseSnapshotStore'
        # Describe block above already uses), createdUtc carrying a 7-digit fraction - the
        # exact precision a real Microsoft Graph timestamp can carry, and the exact case
        # [datetime]::ToString()'s default 'fff' (millisecond) formatting truncates.
        $script:culturePreservingCreatedUtc = '2026-08-17T00:00:00.0000001Z'
        Set-Content -LiteralPath $script:culturePreservingManifestPath -Value (
            '{"schemaVersion":"1.0.0","createdUtc":"' + $script:culturePreservingCreatedUtc + '","tenant":"tp-abc123","producer":{},"datasets":{}}'
        ) -NoNewline
    }

    AfterEach {
        Remove-Item -LiteralPath $script:culturePreservingRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'Get-PulseSnapshotStore opens a manifest with a 7-digit-fraction createdUtc without throwing (validates and preserves it, never round-trips through [datetime])' {
        $opened = InModuleScope TenantPulse -ArgumentList $script:culturePreservingRoot {
            param($root)
            Get-PulseSnapshotStore -Path $root
        }

        $opened.ManifestPath | Should -Be $script:culturePreservingManifestPath
    }

    It 'Get-PulseSnapshotManifest returns createdUtc byte-identical to the source JSON text, exact character match, 7 fractional digits intact' {
        $store = InModuleScope TenantPulse -ArgumentList $script:culturePreservingRoot {
            param($root)
            Get-PulseSnapshotStore -Path $root
        }

        $manifest = InModuleScope TenantPulse -ArgumentList $store {
            param($store)
            Get-PulseSnapshotManifest -Store $store
        }

        $manifest.createdUtc | Should -BeOfType [string]
        $manifest.createdUtc | Should -Be $script:culturePreservingCreatedUtc
    }

    # CULTURE INDEPENDENCE (the actual regression this fix closes): forcing the CURRENT
    # THREAD CULTURE to a day-first locale (en-GB: dd/MM/yyyy) proves createdUtc is carried
    # through as a raw string, completely unaffected by thread culture, rather than being
    # coerced into a [datetime] and later re-stringified with ToString() (which DOES depend
    # on thread culture). The pre-fix code path would still "work" under en-GB for THIS
    # particular assertion by coincidence (dd/MM and MM/dd agree when day and month are both
    # single digits in some cases) - the decisive proof is the exact-string-match assertion
    # above, which the pre-fix [datetime]-coercing code fails outright (it drops the 7-digit
    # fraction and reformats to 'yyyy-MM-ddTHH:mm:ss' with no 'Z'/offset at all via a bare
    # ToString() cast) regardless of culture. This test additionally proves that switching
    # the thread culture around the read produces the identical result both times.
    It 'round-trips identically regardless of the current thread culture (invariant, day-first-locale-safe)' {
        $originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('en-GB')

            $store = InModuleScope TenantPulse -ArgumentList $script:culturePreservingRoot {
                param($root)
                Get-PulseSnapshotStore -Path $root
            }
            $manifestUnderDayFirstCulture = InModuleScope TenantPulse -ArgumentList $store {
                param($store)
                Get-PulseSnapshotManifest -Store $store
            }

            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

            $manifestUnderInvariantCulture = InModuleScope TenantPulse -ArgumentList $store {
                param($store)
                Get-PulseSnapshotManifest -Store $store
            }

            $manifestUnderDayFirstCulture.createdUtc | Should -Be $script:culturePreservingCreatedUtc
            $manifestUnderInvariantCulture.createdUtc | Should -Be $script:culturePreservingCreatedUtc
            $manifestUnderDayFirstCulture.createdUtc | Should -Be $manifestUnderInvariantCulture.createdUtc

            # Every real consumer (Test-PulseStaleDevices, Test-PulseApplePushCertificateValid,
            # Test-PulseCertificateConnectorsHealthy, ...) does exactly this: cast to
            # [string], then parse with InvariantCulture/AdjustToUniversal - proving that
            # round trip parses to the exact same instant regardless of what culture read
            # the manifest.
            $parsed = [datetime]::MinValue
            $parseSucceeded = [datetime]::TryParse(
                [string] $manifestUnderDayFirstCulture.createdUtc,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal,
                [ref] $parsed
            )
            $parseSucceeded | Should -BeTrue
            $parsed.Year | Should -Be 2026
            $parsed.Month | Should -Be 8
            $parsed.Day | Should -Be 17
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
        }
    }
}

Describe 'Set-PulseManifestEntry' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'updates a dataset entry without writing a dataset file' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Set-PulseManifestEntry -Store $store -Name 'Deferred' -Status 'Skipped' -Reason 'not licensed'
        }

        $datasetFile = Join-Path $script:store.DatasetsPath 'Deferred.json'
        Test-Path -LiteralPath $datasetFile | Should -BeFalse

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.datasets.Deferred.status | Should -Be 'Skipped'
        $manifest.datasets.Deferred.reason | Should -Be 'not licensed'
    }

    It 'sets the top-level collectionFailure field' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Set-PulseManifestEntry -Store $store -CollectionFailure 'auth token expired mid-run'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.collectionFailure | Should -Be 'auth token expired mid-run'
    }
}

Describe 'ConvertTo-PulseCanonicalJson' {
    It 'serializes the same object identically regardless of property insertion order' {
        $first = [ordered]@{
            zeta  = 1
            alpha = @{ b = 2; a = 1 }
            mid   = @('x', 'y', 'z')
        }

        $second = [ordered]@{
            alpha = @{ a = 1; b = 2 }
            mid   = @('x', 'y', 'z')
            zeta  = 1
        }

        $firstJson = InModuleScope TenantPulse -ArgumentList $first {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }

        $secondJson = InModuleScope TenantPulse -ArgumentList $second {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }

        $firstJson | Should -Be $secondJson
    }

    It 'produces output with no trailing whitespace on any line and LF line endings' {
        $obj = [ordered]@{ b = 'two'; a = @('one', 'three') }

        $json = InModuleScope TenantPulse -ArgumentList $obj {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }

        $json | Should -Not -Match "`r"
        foreach ($line in ($json -split "`n")) {
            $line | Should -Not -Match '[ \t]$'
        }
    }

    It 'sorts object keys alphabetically' {
        $obj = [ordered]@{ zeta = 1; alpha = 2; mid = 3 }

        $json = InModuleScope TenantPulse -ArgumentList $obj {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }

        $alphaIndex = $json.IndexOf('"alpha"')
        $midIndex = $json.IndexOf('"mid"')
        $zetaIndex = $json.IndexOf('"zeta"')

        $alphaIndex | Should -BeLessThan $midIndex
        $midIndex | Should -BeLessThan $zetaIndex
    }

    It 'serializing twice after shuffling property order remains byte-identical' {
        $obj = [ordered]@{
            one   = 1
            two   = 'two'
            three = @{ nested = $true; other = $null }
            four  = @(3, 1, 2)
        }

        $shuffled = [ordered]@{
            four  = @(3, 1, 2)
            three = @{ other = $null; nested = $true }
            two   = 'two'
            one   = 1
        }

        $jsonA = InModuleScope TenantPulse -ArgumentList $obj {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }
        $jsonB = InModuleScope TenantPulse -ArgumentList $shuffled {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }

        $bytesA = [System.Text.Encoding]::UTF8.GetBytes($jsonA)
        $bytesB = [System.Text.Encoding]::UTF8.GetBytes($jsonB)

        $bytesA | Should -Be $bytesB
    }

    It 'sorts case-distinct keys ordinally and byte-identically regardless of insertion order (C1)' {
        # A PowerShell hash literal (even [ordered]) rejects 'zebra' and 'Zebra' as
        # duplicate keys at parse time - its literal-syntax duplicate check is
        # case-insensitive. A case-sensitive .NET Dictionary sidesteps that so both
        # case variants of the same word can coexist as distinct keys, which is exactly
        # the scenario ordinal-vs-culture sorting disagrees on.
        $orderOne = [System.Collections.Generic.Dictionary[string, object]]::new()
        $orderOne['zebra'] = 1
        $orderOne['Zebra'] = 2
        $orderOne['apple'] = 3
        $orderOne['Apple'] = 4

        $orderTwo = [System.Collections.Generic.Dictionary[string, object]]::new()
        $orderTwo['Apple'] = 4
        $orderTwo['apple'] = 3
        $orderTwo['Zebra'] = 2
        $orderTwo['zebra'] = 1

        $jsonOne = InModuleScope TenantPulse -ArgumentList $orderOne {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }
        $jsonTwo = InModuleScope TenantPulse -ArgumentList $orderTwo {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }

        $bytesOne = [System.Text.Encoding]::UTF8.GetBytes($jsonOne)
        $bytesTwo = [System.Text.Encoding]::UTF8.GetBytes($jsonTwo)
        $bytesOne | Should -Be $bytesTwo

        # Ordinal order: all uppercase letters sort before all lowercase letters, so the
        # expected key order is Apple, Zebra, apple, zebra - not the case-insensitive
        # 'Apple, apple, Zebra, zebra' a culture-aware sort would (incorrectly) produce.
        $expected = @"
{
  "Apple": 4,
  "Zebra": 2,
  "apple": 3,
  "zebra": 1
}
"@ -replace "`r`n", "`n"

        $jsonOne | Should -Be $expected
    }

    It 'produces byte-identical golden output for a nested fixture (C1)' {
        $fixture = [ordered]@{
            zeta = [ordered]@{
                nested = @(3, 1, 2)
                flag   = $true
            }
            alpha = 'text with "quotes" and \backslash\'
            mid   = $null
        }

        $json = InModuleScope TenantPulse -ArgumentList $fixture {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }

        $expected = @"
{
  "alpha": "text with \"quotes\" and \\backslash\\",
  "mid": null,
  "zeta": {
    "flag": true,
    "nested": [
      3,
      1,
      2
    ]
  }
}
"@ -replace "`r`n", "`n"

        $json | Should -Be $expected
    }

    It 'produces byte-identical output regardless of the current thread culture (C1)' {
        $obj = [ordered]@{ zebra = 1.5; apple = @('B', 'a'); Count = 10 }

        $invariantJson = InModuleScope TenantPulse -ArgumentList $obj {
            param($obj)
            ConvertTo-PulseCanonicalJson -InputObject $obj
        }

        $originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('de-DE')

            $germanCultureJson = InModuleScope TenantPulse -ArgumentList $obj {
                param($obj)
                ConvertTo-PulseCanonicalJson -InputObject $obj
            }
        }
        finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
        }

        $invariantBytes = [System.Text.Encoding]::UTF8.GetBytes($invariantJson)
        $germanBytes = [System.Text.Encoding]::UTF8.GetBytes($germanCultureJson)

        $invariantBytes | Should -Be $germanBytes
    }

    It 'throws when two keys collide after string normalization (C1)' {
        $obj = @{}
        $obj[1] = 'int-one'
        $obj['1'] = 'string-one'

        {
            InModuleScope TenantPulse -ArgumentList $obj {
                param($obj)
                ConvertTo-PulseCanonicalJson -InputObject $obj
            }
        } | Should -Throw -ExpectedMessage '*duplicate*'
    }

    It 'formats a DateTimeOffset with an explicit invariant offset, not a lossy UTC Z (M1)' {
        # Built via AddTicks rather than the (..., millisecond, offset) constructor: that
        # overload only accepts 0-999 milliseconds, but the golden value needs all 7
        # fractional-second digits ('fffffff') that Graph timestamps can carry.
        $dt = [datetime]::new(2026, 8, 15, 21, 30, 41, 0, [System.DateTimeKind]::Unspecified).AddTicks(1234567)
        $dto = [datetimeoffset]::new($dt, [timespan]::FromHours(-4))

        $json = InModuleScope TenantPulse -ArgumentList $dto {
            param($value)
            ConvertTo-PulseCanonicalJson -InputObject $value
        }

        $json | Should -Be '"2026-08-15T21:30:41.1234567-04:00"'
    }

    # Item 9 (final fix wave): a Kind=Unspecified DateTime must be treated as already-UTC
    # (SpecifyKind), never passed through .ToUniversalTime() - which silently assumes the
    # value is LOCAL time and would shift it by the host's UTC offset.
    It 'treats a Kind=Unspecified DateTime as already-UTC, not local time (final fix wave, item 9)' {
        $unspecified = [datetime]::new(2026, 8, 15, 21, 30, 41, [System.DateTimeKind]::Unspecified)

        $json = InModuleScope TenantPulse -ArgumentList $unspecified {
            param($value)
            ConvertTo-PulseCanonicalJson -InputObject $value
        }

        $json | Should -Be '"2026-08-15T21:30:41.000Z"'
    }

    It 'leaves an already-Utc-kind DateTime unchanged (no shift applied)' {
        $utc = [datetime]::new(2026, 8, 15, 21, 30, 41, [System.DateTimeKind]::Utc)

        $json = InModuleScope TenantPulse -ArgumentList $utc {
            param($value)
            ConvertTo-PulseCanonicalJson -InputObject $value
        }

        $json | Should -Be '"2026-08-15T21:30:41.000Z"'
    }

    It 'throws on non-finite double values instead of emitting invalid JSON tokens (M2)' {
        {
            InModuleScope TenantPulse -ArgumentList ([double]::NaN) {
                param($value)
                ConvertTo-PulseCanonicalJson -InputObject $value
            }
        } | Should -Throw -ExpectedMessage '*non-finite*'

        {
            InModuleScope TenantPulse -ArgumentList ([double]::PositiveInfinity) {
                param($value)
                ConvertTo-PulseCanonicalJson -InputObject $value
            }
        } | Should -Throw -ExpectedMessage '*non-finite*'

        {
            InModuleScope TenantPulse -ArgumentList ([double]::NegativeInfinity) {
                param($value)
                ConvertTo-PulseCanonicalJson -InputObject $value
            }
        } | Should -Throw -ExpectedMessage '*non-finite*'
    }

    # REGRESSION (Phase 3 closing fix series, item 2b): the datetime formatting path
    # (see the docstring above 'if ($Value -is [datetime])' in
    # source/Private/Snapshot/ConvertTo-PulseCanonicalJson.ps1) explicitly formats with
    # [System.Globalization.CultureInfo]::InvariantCulture rather than the ambient thread
    # culture - this pins that behavior the same way the "Manifest createdUtc
    # culture-coercion fix (Part E, T3.4)" Describe block above pins
    # Get-PulseSnapshotManifest's. A day-first culture (en-GB, dd/MM/yyyy) run under a
    # non-UTC current-thread timezone (America/Los_Angeles-style negative offset, forced via
    # a Kind=Local DateTime constructed against a synthetic non-UTC TimeZoneInfo) is exactly
    # the combination most likely to leak either day/month transposition or a local-time
    # shift into the emitted ISO-8601 string. Without the fix, a culture-aware ToString()
    # call would either transpose day/month (en-GB reads dates day-first) or silently
    # reinterpret the instant through the host's local offset - either failure mode changes
    # the output string while this test's own DateTimeKind.Utc input is held fixed.
    It 'formats a DateTime identically regardless of current thread culture, even under a day-first (en-GB) locale (I3, datetime-containment regression)' {
        $originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            # 3 January 2026 - day (03) and month (01) both plausible as EITHER position,
            # so a day/month transposition bug would silently swap them without throwing;
            # only an exact-string assertion below catches it.
            $utcValue = [datetime]::new(2026, 1, 3, 9, 5, 41, [System.DateTimeKind]::Utc)

            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('en-GB')
            $jsonUnderDayFirstCulture = InModuleScope TenantPulse -ArgumentList $utcValue {
                param($value)
                ConvertTo-PulseCanonicalJson -InputObject $value
            }

            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
            $jsonUnderInvariantCulture = InModuleScope TenantPulse -ArgumentList $utcValue {
                param($value)
                ConvertTo-PulseCanonicalJson -InputObject $value
            }

            $jsonUnderDayFirstCulture | Should -Be '"2026-01-03T09:05:41.000Z"'
            $jsonUnderDayFirstCulture | Should -Be $jsonUnderInvariantCulture
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
        }
    }

    It 'formats a Kind=Unspecified DateTime identically regardless of current thread culture (I3, datetime-containment regression)' {
        $originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            $unspecifiedValue = [datetime]::new(2026, 1, 3, 9, 5, 41, [System.DateTimeKind]::Unspecified)

            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('en-GB')
            $jsonUnderDayFirstCulture = InModuleScope TenantPulse -ArgumentList $unspecifiedValue {
                param($value)
                ConvertTo-PulseCanonicalJson -InputObject $value
            }

            $jsonUnderDayFirstCulture | Should -Be '"2026-01-03T09:05:41.000Z"'
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
        }
    }
}

Describe 'Set-PulseManifestEntry atomicity and concurrency (I1)' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'never leaves manifest.json.tmp behind after a write' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Set-PulseManifestEntry -Store $store -Name 'One' -Status 'Collected' -ApiVersion 'v1.0'
        }

        $tmpPath = "$($script:store.ManifestPath).tmp"
        Test-Path -LiteralPath $tmpPath | Should -BeFalse
    }

    It 'loses no updates when two concurrent writers each write 20 distinct entries' {
        $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        $manifestPath = Join-Path $built.FullName 'TenantPulse.psd1'

        $scriptBlock = {
            param($ManifestPath, $Store, $Prefix, $Count)

            Import-Module $ManifestPath -Force
            $module = Get-Module -Name TenantPulse

            for ($i = 0; $i -lt $Count; $i++) {
                & $module {
                    param($Store, $Name)
                    Set-PulseManifestEntry -Store $Store -Name $Name -Status 'Collected' -ApiVersion 'v1.0'
                } $Store "$Prefix-$i"
            }
        }

        $runspaces = @()
        $handles = @()

        foreach ($prefix in @('RunA', 'RunB')) {
            $ps = [powershell]::Create()
            [void] $ps.AddScript($scriptBlock).AddArgument($manifestPath).AddArgument($script:store).AddArgument($prefix).AddArgument(20)
            $runspaces += $ps
            $handles += $ps.BeginInvoke()
        }

        for ($i = 0; $i -lt $runspaces.Count; $i++) {
            $runspaces[$i].EndInvoke($handles[$i])
            $runspaces[$i].Streams.Error | Should -BeNullOrEmpty
            $runspaces[$i].Dispose()
        }

        $manifest = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Get-PulseSnapshotManifest -Store $store
        }

        $manifest.datasets.Keys.Count | Should -Be 40
        for ($i = 0; $i -lt 20; $i++) {
            $manifest.datasets["RunA-$i"] | Should -Not -BeNullOrEmpty
            $manifest.datasets["RunB-$i"] | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Dataset name validation rejects path traversal (I2)' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'Write-PulseDataset throws naming the offending value for a traversal name' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Write-PulseDataset -Store $store -Name '..\manifest' -Data @() -ApiVersion 'v1.0' -Status 'Collected'
            }
        } | Should -Throw -ExpectedMessage '*..\manifest*'
    }

    It 'Read-PulseDataset throws naming the offending value for a traversal name' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Read-PulseDataset -Store $store -Name '../manifest'
            }
        } | Should -Throw -ExpectedMessage '*../manifest*'
    }

    It 'Set-PulseManifestEntry throws naming the offending value for a traversal name' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Set-PulseManifestEntry -Store $store -Name '..\..\manifest' -Status 'Collected' -ApiVersion 'v1.0'
            }
        } | Should -Throw -ExpectedMessage '*..\..\manifest*'
    }
}

Describe 'Get-PulseSnapshotStore' {
    BeforeEach {
        $script:openRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    }

    AfterEach {
        Remove-Item -LiteralPath $script:openRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'opens an existing snapshot store created by New-PulseSnapshotStore, without creating anything new' {
        $created = InModuleScope TenantPulse -ArgumentList $script:openRoot {
            param($openRoot)
            New-PulseSnapshotStore -Path $openRoot -Tenant 'tp-abc123'
        }

        $opened = InModuleScope TenantPulse -ArgumentList $script:openRoot {
            param($openRoot)
            Get-PulseSnapshotStore -Path $openRoot
        }

        $opened.Root | Should -Be $created.Root
        $opened.ManifestPath | Should -Be $created.ManifestPath
        $opened.DatasetsPath | Should -Be $created.DatasetsPath
        $opened.ReferencePath | Should -Be $created.ReferencePath
        $opened.ExpandedPath | Should -Be $created.ExpandedPath

        $manifest = Get-Content -LiteralPath $opened.ManifestPath -Raw | ConvertFrom-Json
        $manifest.tenant | Should -Be 'tp-abc123'
    }

    It 'throws for a path that does not exist' {
        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw
    }

    It 'throws for an existing directory with no manifest.json' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*manifest.json*'
    }

    It 'throws for a manifest.json with no schemaVersion' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"tenant":"tp-abc123"}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*schemaVersion*'
    }

    It 'throws for a manifest.json that is not valid JSON' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{ not json' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw
    }

    # Post-review regression coverage - reproduced case: an unsupported schemaVersion used
    # to open CLEANLY (only existence/non-empty was checked), silently producing a
    # confident-looking, entirely NotApplicable scored report with a null tenant/
    # generatedUtc downstream - the exact silent-gap failure this module forbids.
    It 'throws for a manifest.json declaring an unsupported schemaVersion (reproduced silent-gap case)' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"9999.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*schemaVersion*9999.0.0*'
    }

    It 'throws for a manifest.json missing createdUtc' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","tenant":"tp-abc123","producer":{},"datasets":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*createdUtc*'
    }

    It 'throws for a manifest.json missing producer' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","datasets":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*producer*'
    }

    It 'throws for a manifest.json missing datasets' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*datasets*'
    }

    It 'opens successfully for a well-formed manifest.json declaring the supported schemaVersion' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{}}' -NoNewline

        $opened = InModuleScope TenantPulse -ArgumentList $script:openRoot {
            param($openRoot)
            Get-PulseSnapshotStore -Path $openRoot
        }

        $opened.Root | Should -Not -BeNullOrEmpty
    }

    # Item 4 (final fix wave) - three reproduced holes: presence/non-empty checks alone let
    # a wrong-SHAPE value through, previously producing a confident-but-wrong evaluation or
    # a mid-run crash far from this function.

    It 'throws for a manifest.json with "datasets":null (reproduced: previously produced a confident all-NA report)' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":null}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*datasets*'
    }

    It 'throws for a manifest.json with "datasets":"x" - a bare string (reproduced: previously caused a mid-run crash)' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":"x"}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*datasets*'
    }

    It 'throws for a manifest.json with "createdUtc":"banana" (reproduced: previously produced garbage generatedUtc downstream)' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"banana","tenant":"tp-abc123","producer":{},"datasets":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*createdUtc*banana*'
    }

    It 'throws for a manifest.json with "producer":"x" - a bare string, not a non-null object' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":"x","datasets":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*producer*'
    }

    # Task 2.1: schema 1.1.0 round-trip and downgrade-acceptance behavior.

    It 'opens successfully for a well-formed manifest.json declaring schemaVersion 1.1.0 with references/expansions' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.1.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{},"references":{},"expansions":{}}' -NoNewline

        $opened = InModuleScope TenantPulse -ArgumentList $script:openRoot {
            param($openRoot)
            Get-PulseSnapshotStore -Path $openRoot
        }

        $opened.Root | Should -Not -BeNullOrEmpty
    }

    It 'still opens a 1.0.0 manifest with no references/expansions members at all (downgrade/back-compat)' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{}}' -NoNewline

        $opened = InModuleScope TenantPulse -ArgumentList $script:openRoot {
            param($openRoot)
            Get-PulseSnapshotStore -Path $openRoot
        }

        $opened.Root | Should -Not -BeNullOrEmpty

        $manifest = InModuleScope TenantPulse -ArgumentList $opened {
            param($opened)
            Get-PulseSnapshotManifest -Store $opened
        }
        $manifest.ContainsKey('references') | Should -BeFalse
        $manifest.ContainsKey('expansions') | Should -BeFalse
    }

    # omp finding #3: a 1.1.0 manifest REQUIRES references/expansions as non-null objects -
    # each of these is a reproduced acceptance (pre-fix, every one of these opened cleanly).

    It 'throws for a 1.1.0 manifest missing the references member entirely' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.1.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{},"expansions":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*references*'
    }

    It 'throws for a 1.1.0 manifest missing the expansions member entirely' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.1.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{},"references":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*expansions*'
    }

    It 'throws for a 1.1.0 manifest with "references":null (reproduced acceptance)' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.1.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{},"references":null,"expansions":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*references*'
    }

    It 'throws for a 1.1.0 manifest with "expansions":"x" - a bare string (reproduced acceptance)' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.1.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{},"references":{},"expansions":"x"}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*expansions*'
    }

    It 'throws for a 1.1.0 manifest with "references":[] - an array, not an object (reproduced acceptance)' {
        New-Item -Path $script:openRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:openRoot 'manifest.json') -Value '{"schemaVersion":"1.1.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{},"references":[],"expansions":{}}' -NoNewline

        {
            InModuleScope TenantPulse -ArgumentList $script:openRoot {
                param($openRoot)
                Get-PulseSnapshotStore -Path $openRoot
            }
        } | Should -Throw -ExpectedMessage '*references*'
    }
}

Describe 'New-PulseSnapshotStore schema 1.1.0 (Task 2.1)' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'writes schemaVersion 1.1.0' {
        $store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.schemaVersion | Should -Be '1.1.0'
    }

    It 'writes empty references and expansions objects' {
        $store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }

        $manifest = Get-Content -LiteralPath $store.ManifestPath -Raw | ConvertFrom-Json
        $manifest.PSObject.Properties.Name | Should -Contain 'references'
        $manifest.PSObject.Properties.Name | Should -Contain 'expansions'
        $manifest.references.PSObject.Properties.Name.Count | Should -Be 0
        $manifest.expansions.PSObject.Properties.Name.Count | Should -Be 0
    }
}

Describe 'Set-PulseReferenceEntry / Get-PulseReferenceData (Task 2.1)' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'records a Captured reference entry with the interface-specified fields' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured' `
                -Path 'reference/settingDefinitions.json' -SchemaVersion '1.0.0' -Sha256 'abc123' `
                -ItemCount 42 -RetrievedUtc '2026-08-16T12:00:00.000Z'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.references.settingDefinitions
        $entry.status | Should -Be 'Captured'
        $entry.path | Should -Be 'reference/settingDefinitions.json'
        $entry.format | Should -Be 'json'
        $entry.schemaVersion | Should -Be '1.0.0'
        $entry.sha256 | Should -Be 'abc123'
        $entry.itemCount | Should -Be 42
        # ConvertFrom-Json (without -AsHashtable) auto-casts an ISO-8601-shaped string to
        # [datetime] on read - not a manifest-writer bug, matching how this same file never
        # compares collectedUtc to a literal string either (see 'records status, apiVersion,
        # sha256 and itemCount...' above) - only presence is asserted here.
        $entry.retrievedUtc | Should -Not -BeNullOrEmpty
    }

    It 'records a Failed reference entry with only status and reason' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Failed' -Reason 'capture-failed: 503 Service Unavailable'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.references.settingDefinitions
        $entry.status | Should -Be 'Failed'
        $entry.reason | Should -Be 'capture-failed: 503 Service Unavailable'
        $entry.path | Should -BeNullOrEmpty
        $entry.sha256 | Should -BeNullOrEmpty
    }

    It 'round-trips through Get-PulseReferenceData when the sha256 matches the on-disk file' {
        $data = @([pscustomobject]@{ id = 'def-1'; name = 'one' }, [pscustomobject]@{ id = 'def-2'; name = 'two' })

        $roundTripped = InModuleScope TenantPulse -ArgumentList $script:store, $data {
            param($store, $data)

            $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $data
            $referencePath = Join-Path $store.ReferencePath 'settingDefinitions.json'
            Set-PulseAtomicFileContent -Path $referencePath -Value $canonicalJson

            $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
            $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
            $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured' `
                -Path 'reference/settingDefinitions.json' -SchemaVersion '1.0.0' -Sha256 $sha256 `
                -ItemCount 2 -RetrievedUtc '2026-08-16T12:00:00.000Z'

            Get-PulseReferenceData -Store $store -Name 'settingDefinitions'
        }

        @($roundTripped).Count | Should -Be 2
        $roundTripped[0].id | Should -Be 'def-1'
        $roundTripped[1].id | Should -Be 'def-2'
    }

    It 'throws naming the file when the on-disk reference file has been tampered with after capture' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)

            $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject @([pscustomobject]@{ id = 'def-1' })
            $referencePath = Join-Path $store.ReferencePath 'settingDefinitions.json'
            Set-PulseAtomicFileContent -Path $referencePath -Value $canonicalJson

            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured' `
                -Path 'reference/settingDefinitions.json' -SchemaVersion '1.0.0' -Sha256 'deliberately-wrong-hash' `
                -ItemCount 1 -RetrievedUtc '2026-08-16T12:00:00.000Z'
        }

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Get-PulseReferenceData -Store $store -Name 'settingDefinitions'
            }
        } | Should -Throw -ExpectedMessage '*settingDefinitions.json*'
    }

    # omp finding #2: same UTF-16 re-encode regression as Read-PulseDataset's own test above.
    It 'throws when the on-disk reference file is swapped for a UTF-16 re-encode of the identical text (omp finding #2)' {
        $roundTripSha256 = InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)

            $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject @([pscustomobject]@{ id = 'def-1' })
            $referencePath = Join-Path $store.ReferencePath 'settingDefinitions.json'
            Set-PulseAtomicFileContent -Path $referencePath -Value $canonicalJson

            $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
            $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
            $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured' `
                -Path 'reference/settingDefinitions.json' -SchemaVersion '1.0.0' -Sha256 $sha256 `
                -ItemCount 1 -RetrievedUtc '2026-08-16T12:00:00.000Z'

            $sha256
        }
        $roundTripSha256 | Should -Not -BeNullOrEmpty

        $referenceFile = Join-Path $script:store.ReferencePath 'settingDefinitions.json'
        $originalText = Get-Content -LiteralPath $referenceFile -Raw
        [System.IO.File]::WriteAllText($referenceFile, $originalText, [System.Text.Encoding]::Unicode)

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Get-PulseReferenceData -Store $store -Name 'settingDefinitions'
            }
        } | Should -Throw -ExpectedMessage '*settingDefinitions.json*'
    }

    It 'throws naming the reference name when no manifest entry exists for it' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Get-PulseReferenceData -Store $store -Name 'neverCaptured'
            }
        } | Should -Throw -ExpectedMessage '*neverCaptured*'
    }

    # omp finding #5 repro: a stale file left on disk from a prior run must NOT be returned
    # for a reference whose manifest entry says 'Failed' - the entry's status governs, not
    # merely "does a file happen to exist at that path".
    It 'throws naming the status, not silently returning stale on-disk data, for a Failed entry (repro)' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)

            # A stale file left over from some earlier, unrelated run - present on disk even
            # though THIS capture attempt failed.
            $referencePath = Join-Path $store.ReferencePath 'settingDefinitions.json'
            $staleJson = ConvertTo-PulseCanonicalJson -InputObject @([pscustomobject]@{ id = 'stale-from-a-prior-run' })
            Set-PulseAtomicFileContent -Path $referencePath -Value $staleJson

            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Failed' -Reason 'capture-failed: 503 Service Unavailable'
        }

        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Get-PulseReferenceData -Store $store -Name 'settingDefinitions'
            }
        } | Should -Throw -ExpectedMessage "*'Failed'*"
    }

    It 'throws naming the offending value for a path-traversal reference name' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Set-PulseReferenceEntry -Store $store -Name '..\manifest' -Status 'Captured' `
                    -Path 'reference/x.json' -SchemaVersion '1.0.0' -Sha256 'abc123' -ItemCount 1 -RetrievedUtc '2026-08-16T12:00:00.000Z'
            }
        } | Should -Throw -ExpectedMessage '*..\manifest*'
    }

    # omp finding #5: -Status 'Captured' requires the fields a reader needs to trust/locate
    # the data; -Status 'Failed' requires -Reason.

    It 'throws naming the missing fields when -Status Captured omits them' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured'
            }
        } | Should -Throw -ExpectedMessage '*Path*SchemaVersion*Sha256*ItemCount*RetrievedUtc*'
    }

    It 'throws when -Status Failed omits -Reason' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Failed'
            }
        } | Should -Throw -ExpectedMessage '*Reason*'
    }

    # omp finding #4: a schema 1.0.0 store must reject a reference write, not auto-vivify.

    It 'throws when writing a reference entry to a schema 1.0.0 store (no auto-vivify)' {
        $oldStoreRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $oldStoreRoot -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $oldStoreRoot 'reference') -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $oldStoreRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{}}' -NoNewline

        try {
            $oldStore = InModuleScope TenantPulse -ArgumentList $oldStoreRoot {
                param($oldStoreRoot)
                Get-PulseSnapshotStore -Path $oldStoreRoot
            }

            {
                InModuleScope TenantPulse -ArgumentList $oldStore {
                    param($oldStore)
                    Set-PulseReferenceEntry -Store $oldStore -Name 'settingDefinitions' -Status 'Captured' `
                        -Path 'reference/x.json' -SchemaVersion '1.0.0' -Sha256 'abc123' -ItemCount 1 -RetrievedUtc '2026-08-16T12:00:00.000Z'
                }
            } | Should -Throw -ExpectedMessage '*1.0.0*references*'

            $manifestAfter = Get-Content -LiteralPath (Join-Path $oldStoreRoot 'manifest.json') -Raw | ConvertFrom-Json
            $manifestAfter.PSObject.Properties.Name -contains 'references' | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $oldStoreRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Set-PulseExpansionEntry (Task 2.1)' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'records an Expanded entry with the interface-specified fields' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Set-PulseExpansionEntry -Store $store -Name 'settingsWalk' -Status 'Expanded' `
                -Path 'expanded/settingsWalk.jsonl' -SchemaVersion '1.0.0' -Sha256 'abc123' `
                -PolicyCount 781 -RowCount 4200 -UnresolvedNameCount 0 -RedactedSecretCount 3
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.expansions.settingsWalk
        $entry.status | Should -Be 'Expanded'
        $entry.path | Should -Be 'expanded/settingsWalk.jsonl'
        $entry.format | Should -Be 'jsonl'
        $entry.schemaVersion | Should -Be '1.0.0'
        $entry.sha256 | Should -Be 'abc123'
        $entry.policyCount | Should -Be 781
        $entry.rowCount | Should -Be 4200
        $entry.unresolvedNameCount | Should -Be 0
        $entry.redactedSecretCount | Should -Be 3
        @($entry.gaps).Count | Should -Be 0
    }

    It 'records a NotExpanded entry with reason "definitions corpus unavailable" and empty gaps' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            Set-PulseExpansionEntry -Store $store -Name 'settingsWalk' -Status 'NotExpanded' -Reason 'definitions corpus unavailable'
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.expansions.settingsWalk
        $entry.status | Should -Be 'NotExpanded'
        $entry.reason | Should -Be 'definitions corpus unavailable'
        @($entry.gaps).Count | Should -Be 0
    }

    It 'records a Partial entry carrying per-policy gaps' {
        $gaps = @(
            [ordered]@{ policyId = 'p1'; reason = 'settings fetch timed out' }
            [ordered]@{ policyId = 'p2'; reason = 'permission-denied' }
        )

        InModuleScope TenantPulse -ArgumentList $script:store, $gaps {
            param($store, $gaps)
            Set-PulseExpansionEntry -Store $store -Name 'settingsWalk' -Status 'Partial' `
                -Path 'expanded/settingsWalk.jsonl' -SchemaVersion '1.0.0' -Sha256 'def456' `
                -PolicyCount 781 -RowCount 4100 -Gaps $gaps
        }

        $manifest = Get-Content -LiteralPath $script:store.ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.expansions.settingsWalk
        $entry.status | Should -Be 'Partial'
        @($entry.gaps).Count | Should -Be 2
        $entry.gaps[0].policyId | Should -Be 'p1'
        $entry.gaps[0].reason | Should -Be 'settings fetch timed out'
        $entry.gaps[1].policyId | Should -Be 'p2'
    }

    It 'throws naming the offending value for a path-traversal expansion name' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Set-PulseExpansionEntry -Store $store -Name '../manifest' -Status 'Expanded' `
                    -Path 'expanded/x.jsonl' -SchemaVersion '1.0.0' -Sha256 'abc123' -PolicyCount 1 -RowCount 1
            }
        } | Should -Throw -ExpectedMessage '*../manifest*'
    }

    # omp finding #5: status-dependent field invariants, symmetric with Set-PulseReferenceEntry.

    It 'throws naming the missing fields when -Status Expanded omits them' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Set-PulseExpansionEntry -Store $store -Name 'settingsWalk' -Status 'Expanded'
            }
        } | Should -Throw -ExpectedMessage '*Path*SchemaVersion*Sha256*PolicyCount*RowCount*'
    }

    It 'throws when -Status Partial is written with empty -Gaps (contradiction)' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Set-PulseExpansionEntry -Store $store -Name 'settingsWalk' -Status 'Partial' `
                    -Path 'expanded/settingsWalk.jsonl' -SchemaVersion '1.0.0' -Sha256 'def456' `
                    -PolicyCount 781 -RowCount 4200
            }
        } | Should -Throw -ExpectedMessage '*Gaps*'
    }

    It 'throws when -Status NotExpanded omits -Reason' {
        {
            InModuleScope TenantPulse -ArgumentList $script:store {
                param($store)
                Set-PulseExpansionEntry -Store $store -Name 'settingsWalk' -Status 'NotExpanded'
            }
        } | Should -Throw -ExpectedMessage '*Reason*'
    }

    # omp finding #4: a schema 1.0.0 store must reject an expansion write, not auto-vivify.

    It 'throws when writing an expansion entry to a schema 1.0.0 store (no auto-vivify)' {
        $oldStoreRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -Path $oldStoreRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $oldStoreRoot 'manifest.json') -Value '{"schemaVersion":"1.0.0","createdUtc":"2026-01-01T00:00:00.000Z","tenant":"tp-abc123","producer":{},"datasets":{}}' -NoNewline

        try {
            $oldStore = InModuleScope TenantPulse -ArgumentList $oldStoreRoot {
                param($oldStoreRoot)
                Get-PulseSnapshotStore -Path $oldStoreRoot
            }

            {
                InModuleScope TenantPulse -ArgumentList $oldStore {
                    param($oldStore)
                    Set-PulseExpansionEntry -Store $oldStore -Name 'settingsWalk' -Status 'NotExpanded' -Reason 'definitions corpus unavailable'
                }
            } | Should -Throw -ExpectedMessage '*1.0.0*expansions*'
        } finally {
            Remove-Item -LiteralPath $oldStoreRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Set-PulseReferenceEntry atomic file-publish-then-manifest-update (Task 2.1, omp finding #1)' {
    BeforeEach {
        $script:storeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:store = InModuleScope TenantPulse -ArgumentList $script:storeRoot {
            param($storeRoot)
            New-PulseSnapshotStore -Path $storeRoot
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:storeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'renames the staged temp file to its final reference path and records the entry in one call' {
        InModuleScope TenantPulse -ArgumentList $script:store {
            param($store)
            $tempPath = Join-Path $store.ReferencePath 'settingDefinitions.deadbeef.tmp'
            Set-Content -LiteralPath $tempPath -Value '[{"id":"def-a"}]' -NoNewline -Encoding utf8NoBOM

            Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured' `
                -Path 'reference/settingDefinitions.json' -SchemaVersion '1.0.0' -Sha256 'abc123' `
                -ItemCount 1 -RetrievedUtc '2026-08-16T12:00:00.000Z' -PublishFromTempPath $tempPath
        }

        $finalPath = Join-Path $script:store.ReferencePath 'settingDefinitions.json'
        Test-Path -LiteralPath $finalPath -PathType Leaf | Should -BeTrue
        (Get-Content -LiteralPath $finalPath -Raw) | Should -Be '[{"id":"def-a"}]'

        $tempPathOnDisk = Join-Path $script:store.ReferencePath 'settingDefinitions.deadbeef.tmp'
        Test-Path -LiteralPath $tempPathOnDisk -PathType Leaf | Should -BeFalse
    }

    It 'two runspaces racing the same reference name never leave a manifest entry describing the wrong file (no split-brain)' {
        $storeRoot = $script:storeRoot

        # Resolve the built module path once on the main thread so each runspace can import
        # it independently (a runspace does not inherit the caller's already-imported module).
        $repoRoot = $script:repoRoot
        $built = Get-ChildItem (Join-Path $repoRoot 'output/module/TenantPulse') -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        $modulePath = Join-Path $built.FullName 'TenantPulse.psd1'

        $writer = {
            param($modulePath, $storeRoot, $payload)
            Import-Module $modulePath -Force
            $store = & (Get-Module TenantPulse) { param($storeRoot) Get-PulseSnapshotStore -Path $storeRoot } $storeRoot

            & (Get-Module TenantPulse) {
                param($store, $payload)

                $canonicalJson = ConvertTo-PulseCanonicalJson -InputObject $payload
                $tempPath = Join-Path $store.ReferencePath "settingDefinitions.$([guid]::NewGuid().ToString('N')).tmp"
                Set-Content -LiteralPath $tempPath -Value $canonicalJson -NoNewline -Encoding utf8NoBOM

                $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
                $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
                $sha256 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()

                for ($attempt = 0; $attempt -lt 50; $attempt++) {
                    try {
                        Set-PulseReferenceEntry -Store $store -Name 'settingDefinitions' -Status 'Captured' `
                            -Path 'reference/settingDefinitions.json' -SchemaVersion '1.0.0' -Sha256 $sha256 `
                            -ItemCount @($payload).Count -RetrievedUtc '2026-08-16T12:00:00.000Z' -PublishFromTempPath $tempPath
                        break
                    } catch {
                        Start-Sleep -Milliseconds 20
                    }
                }
            } $store $payload
        }

        $payloadA = @([pscustomobject]@{ id = 'writer-a-only' })
        $payloadB = @([pscustomobject]@{ id = 'writer-b-only-with-more-content-so-the-two-files-differ-in-length' })

        $runspaceA = [powershell]::Create()
        [void] $runspaceA.AddScript($writer).AddArgument($modulePath).AddArgument($storeRoot).AddArgument($payloadA)
        $runspaceB = [powershell]::Create()
        [void] $runspaceB.AddScript($writer).AddArgument($modulePath).AddArgument($storeRoot).AddArgument($payloadB)

        $handleA = $runspaceA.BeginInvoke()
        $handleB = $runspaceB.BeginInvoke()
        $runspaceA.EndInvoke($handleA)
        $runspaceB.EndInvoke($handleB)

        $errorsA = @($runspaceA.Streams.Error)
        $errorsB = @($runspaceB.Streams.Error)
        $runspaceA.Dispose()
        $runspaceB.Dispose()

        $errorsA | Should -BeNullOrEmpty
        $errorsB | Should -BeNullOrEmpty

        # THE PROPERTY: whichever writer's manifest entry ends up recorded, its sha256 MUST
        # match the ACTUAL bytes of the file on disk at that same moment - never the other
        # writer's file under this writer's hash (split-brain).
        $finalManifest = Get-Content -LiteralPath (Join-Path $storeRoot 'manifest.json') -Raw | ConvertFrom-Json
        $entry = $finalManifest.references.settingDefinitions
        $finalFile = Join-Path $storeRoot 'reference/settingDefinitions.json'
        $actualBytes = [System.IO.File]::ReadAllBytes($finalFile)
        $actualHashBytes = [System.Security.Cryptography.SHA256]::HashData($actualBytes)
        $actualSha256 = ([System.BitConverter]::ToString($actualHashBytes) -replace '-', '').ToLowerInvariant()

        $entry.sha256 | Should -Be $actualSha256

        # No orphaned temp files left behind by either writer.
        $leftoverTemps = @(Get-ChildItem -LiteralPath $script:store.ReferencePath -Filter '*.tmp' -ErrorAction SilentlyContinue)
        $leftoverTemps.Count | Should -Be 0
    }
}
