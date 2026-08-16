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

Describe 'Get-PulseOperatorKey' {
    BeforeEach {
        $script:keyRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:keyPath = Join-Path $script:keyRoot 'operator.key'
    }

    AfterEach {
        Remove-Item -LiteralPath $script:keyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'auto-creates a 32-byte key on first call' {
        $key = InModuleScope TenantPulse -ArgumentList $script:keyPath {
            param($keyPath)
            Get-PulseOperatorKey -KeyPath $keyPath
        }

        Test-Path -LiteralPath $script:keyPath -PathType Leaf | Should -BeTrue
        # InModuleScope re-collects pipeline output, so a returned byte[] arrives here as
        # Object[] of boxed bytes - assert element type/range rather than array type.
        $key.Count | Should -Be 32
        $key | ForEach-Object { $_ | Should -BeOfType [byte] }
    }

    It 'reuses the same key bytes on a subsequent call' {
        $first = InModuleScope TenantPulse -ArgumentList $script:keyPath {
            param($keyPath)
            Get-PulseOperatorKey -KeyPath $keyPath
        }

        $second = InModuleScope TenantPulse -ArgumentList $script:keyPath {
            param($keyPath)
            Get-PulseOperatorKey -KeyPath $keyPath
        }

        [System.Convert]::ToBase64String($first) | Should -Be ([System.Convert]::ToBase64String($second))
    }

    It 'writes 0600-equivalent permissions on the key file on non-Windows platforms' {
        if ($IsWindows) {
            Set-ItResult -Skipped -Because 'POSIX permission bits do not apply on Windows'
            return
        }

        InModuleScope TenantPulse -ArgumentList $script:keyPath {
            param($keyPath)
            Get-PulseOperatorKey -KeyPath $keyPath
        }

        $mode = [System.IO.File]::GetUnixFileMode($script:keyPath)
        $mode | Should -Be ([System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite)
    }

    It 'writes 0700-equivalent permissions on the parent directory it creates, on non-Windows platforms' {
        if ($IsWindows) {
            Set-ItResult -Skipped -Because 'POSIX permission bits do not apply on Windows'
            return
        }

        InModuleScope TenantPulse -ArgumentList $script:keyPath {
            param($keyPath)
            Get-PulseOperatorKey -KeyPath $keyPath
        }

        $dirMode = [System.IO.File]::GetUnixFileMode($script:keyRoot)
        $dirMode | Should -Be (
            [System.IO.UnixFileMode]::UserRead -bor
            [System.IO.UnixFileMode]::UserWrite -bor
            [System.IO.UnixFileMode]::UserExecute)
    }

    It 'converges on identical key bytes when two processes race the first create' {
        $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        $manifestPath = Join-Path $built.FullName 'TenantPulse.psd1'

        $scriptBlock = {
            param($ManifestPath, $KeyPath)

            Import-Module $ManifestPath -Force
            $module = Get-Module -Name TenantPulse

            & $module {
                param($KeyPath)
                $key = Get-PulseOperatorKey -KeyPath $KeyPath
                [System.Convert]::ToBase64String($key)
            } $KeyPath
        }

        $runspaces = @()
        $handles = @()

        foreach ($i in 1..2) {
            $ps = [powershell]::Create()
            [void] $ps.AddScript($scriptBlock).AddArgument($manifestPath).AddArgument($script:keyPath)
            $runspaces += $ps
            $handles += $ps.BeginInvoke()
        }

        $results = @()
        for ($i = 0; $i -lt $runspaces.Count; $i++) {
            $output = $runspaces[$i].EndInvoke($handles[$i])
            $runspaces[$i].Streams.Error | Should -BeNullOrEmpty
            $results += ($output -join '')
            $runspaces[$i].Dispose()
        }

        $results.Count | Should -Be 2
        $results[0] | Should -Not -BeNullOrEmpty
        $results[0] | Should -Be $results[1]
    }

    It 'throws and never creates a key file when KeyPath points inside a snapshot root' {
        $snapshotRoot = Join-Path $script:keyRoot 'snapshot'
        New-Item -Path $snapshotRoot -ItemType Directory -Force | Out-Null
        $manifestPath = Join-Path $snapshotRoot 'manifest.json'
        Set-Content -LiteralPath $manifestPath -Value '{"schemaVersion":"1.0.0"}' -NoNewline -Encoding utf8NoBOM

        $badKeyPath = Join-Path $snapshotRoot 'operator.key'

        {
            InModuleScope TenantPulse -ArgumentList $badKeyPath {
                param($keyPath)
                Get-PulseOperatorKey -KeyPath $keyPath
            }
        } | Should -Throw -ExpectedMessage '*snapshot*'

        Test-Path -LiteralPath $badKeyPath | Should -BeFalse
    }

    It 'throws and never creates a key file when KeyPath is nested under a snapshot root' {
        $snapshotRoot = Join-Path $script:keyRoot 'snapshot2'
        $nested = Join-Path $snapshotRoot 'nested/deeper'
        New-Item -Path $nested -ItemType Directory -Force | Out-Null
        $manifestPath = Join-Path $snapshotRoot 'manifest.json'
        Set-Content -LiteralPath $manifestPath -Value '{"schemaVersion":"1.0.0"}' -NoNewline -Encoding utf8NoBOM

        $badKeyPath = Join-Path $nested 'operator.key'

        {
            InModuleScope TenantPulse -ArgumentList $badKeyPath {
                param($keyPath)
                Get-PulseOperatorKey -KeyPath $keyPath
            }
        } | Should -Throw -ExpectedMessage '*snapshot*'

        Test-Path -LiteralPath $badKeyPath | Should -BeFalse
    }

    It 'throws instead of reading a pre-existing key file that lives inside a snapshot root' {
        $snapshotRoot = Join-Path $script:keyRoot 'snapshot3'
        New-Item -Path $snapshotRoot -ItemType Directory -Force | Out-Null
        $manifestPath = Join-Path $snapshotRoot 'manifest.json'
        Set-Content -LiteralPath $manifestPath -Value '{"schemaVersion":"1.0.0"}' -NoNewline -Encoding utf8NoBOM

        $preExistingKeyPath = Join-Path $snapshotRoot 'operator.key'
        [System.IO.File]::WriteAllBytes($preExistingKeyPath, [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))

        {
            InModuleScope TenantPulse -ArgumentList $preExistingKeyPath {
                param($keyPath)
                Get-PulseOperatorKey -KeyPath $keyPath
            }
        } | Should -Throw -ExpectedMessage '*snapshot*'
    }

    It 'throws a clear corrupt-key error instead of returning a truncated key' {
        New-Item -Path $script:keyRoot -ItemType Directory -Force | Out-Null
        [System.IO.File]::WriteAllBytes($script:keyPath, [byte[]] (0..15))

        {
            InModuleScope TenantPulse -ArgumentList $script:keyPath {
                param($keyPath)
                Get-PulseOperatorKey -KeyPath $keyPath
            }
        } | Should -Throw -ExpectedMessage '*corrupt*16 bytes, expected 32*'
    }
}

Describe 'Get-PulsePseudonym' {
    It 'matches a pinned known-answer vector (HMAC-SHA256, key bytes 0..31, value "contoso-tenant-id")' {
        # Expected digest computed independently (Python hmac/hashlib and openssl dgst
        # -mac hmac, both agreeing) outside this module, then hardcoded here, so this
        # test catches encoding/casing/algorithm drift that a self-referential
        # "compute it the same way and compare" test could never catch.
        $key = [byte[]] (0..31)

        $pseudonym = InModuleScope TenantPulse -ArgumentList 'contoso-tenant-id', $key {
            param($value, $key)
            Get-PulsePseudonym -Value $value -Key $key
        }

        $pseudonym | Should -Be 'tp-f6417c6f751acdc537bd9df382e599d2c2d666384072866eba462bbd212f95c6'
    }

    It 'matches the tp- prefixed 64-hex-digit format' {
        $key = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)

        $pseudonym = InModuleScope TenantPulse -ArgumentList 'contoso-tenant-id', $key {
            param($value, $key)
            Get-PulsePseudonym -Value $value -Key $key
        }

        $pseudonym | Should -Match '^tp-[0-9a-f]{64}$'
    }

    It 'is stable across repeated calls for the same value and key' {
        $key = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)

        $first = InModuleScope TenantPulse -ArgumentList 'contoso-tenant-id', $key {
            param($value, $key)
            Get-PulsePseudonym -Value $value -Key $key
        }

        $second = InModuleScope TenantPulse -ArgumentList 'contoso-tenant-id', $key {
            param($value, $key)
            Get-PulsePseudonym -Value $value -Key $key
        }

        $first | Should -Be $second
    }

    It 'differs across different keys for the same value' {
        $keyOne = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        $keyTwo = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)

        $first = InModuleScope TenantPulse -ArgumentList 'contoso-tenant-id', $keyOne {
            param($value, $key)
            Get-PulsePseudonym -Value $value -Key $key
        }

        $second = InModuleScope TenantPulse -ArgumentList 'contoso-tenant-id', $keyTwo {
            param($value, $key)
            Get-PulsePseudonym -Value $value -Key $key
        }

        $first | Should -Not -Be $second
    }

    It 'differs across different values for the same key' {
        $key = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)

        $first = InModuleScope TenantPulse -ArgumentList 'contoso-tenant-id', $key {
            param($value, $key)
            Get-PulsePseudonym -Value $value -Key $key
        }

        $second = InModuleScope TenantPulse -ArgumentList 'fabrikam-tenant-id', $key {
            param($value, $key)
            Get-PulsePseudonym -Value $value -Key $key
        }

        $first | Should -Not -Be $second
    }
}
