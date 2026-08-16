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
}
