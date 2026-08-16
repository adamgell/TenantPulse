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
}

Describe 'Get-PulsePseudonym' {
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
