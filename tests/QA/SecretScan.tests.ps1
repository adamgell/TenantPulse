<#
    QA gate: repo-local, offline secret/PII scan. Complements (does not replace) gitleaks
    running in CI (see .github/workflows/ci.yml) - this file exists so the same checks run
    on every developer machine via `./build.ps1 -Tasks test`, with no network access and no
    third-party binary required.

    Scans source/ and tests/ for:
        1. a GUID-looking id sitting near a real-looking (non-Microsoft/GitHub) domain -
           the classic "leaked real tenant id + tenant domain" shape.
        2. a bearer-token-shaped JWT ('eyJ...' header/payload pair).
        3. a PEM private-key or certificate header.
        4. connection-string patterns (Azure Storage AccountKey=/SharedAccessSignature=,
           SQL-style Server=...Password=..., or a URL with embedded userinfo credentials).
    Plus, scoped to source/ only:
        5. a raw NUL or other C0 control byte - the exact class of mistake Task 1.8
           introduced and then fixed (a literal NUL byte typed into a .ps1 comment instead
           of the [char]0 spelling); this is a permanent regression guard for it.

    Get-PulseSecretScanViolations and Get-PulseControlByteViolations are unit-tested first
    against small synthetic strings/byte arrays (proving each pattern actually fires, and
    that the allowlist actually suppresses a known-safe GUID) before being run once more
    against the real repo tree - the same two-phase shape FixtureProvenance.tests.ps1 and
    ReadOnly.tests.ps1 use.

    tests/QA/ itself is excluded from the real-repo scan below: this file (and its sibling
    QA gates) necessarily contains the detection patterns as literal text - matching
    against itself would be a self-inflicted false positive, not a real finding. QA code is
    reviewed by hand, not by this scanner.
#>

BeforeAll {
    $projectPath = "$($PSScriptRoot)\..\.." | Convert-Path
    $script:sourcePath = Join-Path -Path $projectPath -ChildPath 'source'
    $script:testsPath = Join-Path -Path $projectPath -ChildPath 'tests'
    $script:qaPath = Join-Path -Path $projectPath -ChildPath 'tests/QA'

    <#
        Well-known Microsoft PUBLIC constant GUIDs that legitimately appear in TenantPulse
        source (built-in Entra role TEMPLATE ids, documented and identical across every
        tenant - see Test-PulseAdminMfaEnforced.ps1's own docstring) or in this module's own
        manifest (a module GUID, not a tenant identifier). None of these are secrets; they
        are allowlisted here, by value, with a comment naming what each one is, so the scan
        can still flag an actual unknown GUID-near-domain pair without ever flagging these.
    #>
    $script:allowedGuids = @(
        # Entra built-in role TEMPLATE ids (public, tenant-stable, documented by Microsoft -
        # see source/Private/Checks/Test-PulseAdminMfaEnforced.ps1's own docstring/table).
        '62e90394-69f5-4237-9190-012177145e10' # Global Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' # Application Administrator
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' # Authentication Administrator
        'b0f54661-2d74-4c50-afa3-1ec803f12efe' # Billing Administrator
        '158c047a-c907-4556-b7ef-446551a6b5f7' # Cloud Application Administrator
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' # Conditional Access Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de' # Exchange Administrator
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' # Helpdesk Administrator
        '966707d0-3269-4727-9be2-8c3a10f19b9d' # Password Administrator
        # TenantPulse's own module manifest GUID (source/TenantPulse.psd1) - a public
        # package identifier, never a tenant id.
        'a2f6d0f0-6d0c-4a6b-9f7e-9c9e6f6c7c2f' # TenantPulse module GUID
    )

    # Reference/documentation domains that appear throughout Consulting.PortalLinks and
    # References.Authorities in check descriptors - Microsoft's own official doc/portal
    # hosts and GitHub. These are never "a real tenant's domain" no matter what GUID sits
    # near them, so they never trip the GUID-near-domain check.
    $script:safeDomainSuffixes = @(
        'microsoft.com'
        'github.com'
    )

    <#
        Scans one file's text CONTENT for the four PII/secret-shaped patterns described in
        this file's own docstring (everything except the raw-control-byte check, which
        needs raw bytes, not decoded text - see Get-PulseControlByteViolations). Returns
        every violation as a string; empty array means clean.
    #>
    function Get-PulseSecretScanViolations {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string] $Content,

            [Parameter(Mandatory)]
            [string] $RelativePath,

            [string[]] $AllowedGuid = @(),

            [string[]] $SafeDomainSuffix = @()
        )

        $violations = [System.Collections.Generic.List[string]]::new()

        if ([string]::IsNullOrEmpty($Content)) {
            return $violations.ToArray()
        }

        $allowedGuidLookup = [System.Collections.Generic.HashSet[string]]::new(
            [string[]] @($AllowedGuid | ForEach-Object { $_.ToLowerInvariant() }),
            [System.StringComparer]::Ordinal
        )

        # 1. GUID-looking id within 200 characters of a real-looking (non-allowlisted)
        # domain - the "leaked real tenant id + tenant domain" shape.
        #
        # The domain match additionally requires its final label to be a recognized TLD
        # (below) - without that, this dotted-identifier-heavy codebase (check ids like
        # 'TP.ENT.0003', property paths like '$Datasets.organizationMdmAuthority') produces
        # constant false "domains" out of ordinary PowerShell/naming syntax that merely
        # happens to contain dots and letters.
        $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        $domainPattern = '\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        $knownTlds = [System.Collections.Generic.HashSet[string]]::new(
            [string[]] @(
                'com', 'net', 'org', 'io', 'co', 'gov', 'edu', 'mil', 'info', 'biz', 'name',
                'pro', 'app', 'dev', 'ai', 'cloud', 'me', 'tv', 'us', 'uk', 'ca', 'de', 'fr',
                'nl', 'au', 'nz', 'jp', 'in', 'br', 'es', 'it', 'ch', 'se', 'no', 'dk', 'fi',
                'pl', 'ru', 'cn', 'onmicrosoft'
            ),
            [System.StringComparer]::OrdinalIgnoreCase
        )

        foreach ($guidMatch in [regex]::Matches($Content, $guidPattern)) {
            $guid = $guidMatch.Value.ToLowerInvariant()
            if ($allowedGuidLookup.Contains($guid)) {
                continue
            }

            $windowStart = [Math]::Max(0, $guidMatch.Index - 200)
            $windowEnd = [Math]::Min($Content.Length, $guidMatch.Index + $guidMatch.Length + 200)
            $window = $Content.Substring($windowStart, $windowEnd - $windowStart)

            foreach ($domainMatch in [regex]::Matches($window, $domainPattern)) {
                $domain = $domainMatch.Value.ToLowerInvariant()
                $finalLabel = $domain.Substring($domain.LastIndexOf('.') + 1)

                if (-not $knownTlds.Contains($finalLabel)) {
                    continue
                }

                $isSafe = $false
                foreach ($suffix in $SafeDomainSuffix) {
                    if ($domain -eq $suffix -or $domain.EndsWith(".$suffix")) {
                        $isSafe = $true
                        break
                    }
                }

                if (-not $isSafe) {
                    $violations.Add("$RelativePath : GUID '$guid' appears within 200 characters of non-allowlisted domain '$domain' - looks like a real tenant id/domain pair, not a synthetic placeholder or a known-public constant.")
                    break
                }
            }
        }

        # 2. Bearer-token-shaped JWT: base64url header, dot, base64url payload.
        if ([regex]::IsMatch($Content, 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')) {
            $violations.Add("$RelativePath : bearer-token-shaped (JWT) string found.")
        }

        # 3. PEM private key / certificate header.
        if ($Content -cmatch '-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----') {
            $violations.Add("$RelativePath : PEM header found (private key or certificate material).")
        }

        # 4. Connection-string patterns.
        if ($Content -match '(?i)\b(AccountKey|SharedAccessSignature)\s*=') {
            $violations.Add("$RelativePath : Azure Storage connection-string pattern found (AccountKey=/SharedAccessSignature=).")
        }
        if ($Content -match '(?i)\b(Server|Data Source)\s*=[^;\r\n]+;[^\r\n]*Password\s*=') {
            $violations.Add("$RelativePath : SQL-style connection-string pattern found (...Password=...).")
        }
        if ($Content -match '://[^/\s:@]+:[^/\s@]+@') {
            $violations.Add("$RelativePath : URL with embedded userinfo credentials found.")
        }

        return $violations.ToArray()
    }

    <#
        Scans raw file BYTES for a NUL byte or any other C0 control byte outside tab/LF/CR
        - the regression class from Task 1.8 (a literal NUL byte typed into a .ps1 comment).
        Returns every violation as a string; empty array means clean.
    #>
    function Get-PulseControlByteViolations {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [byte[]] $Bytes,

            [Parameter(Mandatory)]
            [string] $RelativePath
        )

        $violations = [System.Collections.Generic.List[string]]::new()
        $allowedControlBytes = [System.Collections.Generic.HashSet[byte]]::new([byte[]] @(0x09, 0x0A, 0x0D))

        for ($i = 0; $i -lt $Bytes.Length; $i++) {
            $b = $Bytes[$i]
            if ($b -lt 0x20 -and -not $allowedControlBytes.Contains($b)) {
                $violations.Add("$RelativePath : raw control byte 0x$($b.ToString('X2')) at offset $i - source files must never contain a literal control byte (use the `$([char]<n>)` spelling instead).")
                break
            }
        }

        return $violations.ToArray()
    }
}

Describe 'Secret/PII scan gate logic' -Tag 'QA', 'SecretScan' {

    Context 'Get-PulseSecretScanViolations (unit-tested against synthetic inputs, proving each pattern fires)' {
        It 'reports zero violations for clean, ordinary source text' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content "function Get-Foo { param([string] `$Bar) }" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid $script:allowedGuids `
                -SafeDomainSuffix $script:safeDomainSuffixes)

            $violations | Should -BeNullOrEmpty
        }

        It 'flags a GUID sitting near a non-allowlisted domain' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content "tenantId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479' for contoso-prod.example.com" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid $script:allowedGuids `
                -SafeDomainSuffix $script:safeDomainSuffixes)

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'looks like a real tenant id/domain pair'
        }

        It 'does NOT flag an allowlisted GUID even when a real-looking domain sits nearby' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content "role '62e90394-69f5-4237-9190-012177145e10' at contoso-prod.example.com" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid $script:allowedGuids `
                -SafeDomainSuffix $script:safeDomainSuffixes)

            $violations | Should -BeNullOrEmpty
        }

        It 'does NOT flag a GUID near a dotted PowerShell identifier that merely looks domain-shaped (no real TLD)' {
            # The exact false-positive class this codebase would otherwise trip constantly:
            # check ids like 'TP.ENT.0003' and property paths like
            # '$Datasets.organizationMdmAuthority' are dotted, letters-and-dots text but
            # never a real domain - neither 'ent' nor 'organizationmdmauthority' is a
            # recognized TLD.
            $violations = @(Get-PulseSecretScanViolations `
                -Content "TP.ENT.0003 references f47ac10b-58cc-4372-a567-0e02b2c3d479 via `$Datasets.organizationMdmAuthority" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes)

            $violations | Should -BeNullOrEmpty
        }

        It 'does NOT flag a GUID near only Microsoft/GitHub reference domains' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content "See f47ac10b-58cc-4372-a567-0e02b2c3d479 at https://learn.microsoft.com/entra and https://github.com/example" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid $script:allowedGuids `
                -SafeDomainSuffix $script:safeDomainSuffixes)

            $violations | Should -BeNullOrEmpty
        }

        It 'flags a bearer-token-shaped JWT' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'bearer-token-shaped'
        }

        It 'flags a PEM private key header' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content "-----BEGIN RSA PRIVATE KEY-----`nMIIEow...`n-----END RSA PRIVATE KEY-----" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'PEM header'
        }

        It 'flags a PEM certificate header' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content "-----BEGIN CERTIFICATE-----`nMIIDdz...`n-----END CERTIFICATE-----" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'PEM header'
        }

        It 'flags an Azure Storage connection string' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content 'DefaultEndpointsProtocol=https;AccountName=fake;AccountKey=abcd1234==;EndpointSuffix=core.windows.net' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'Azure Storage connection-string pattern'
        }

        It 'flags a SQL-style connection string with an embedded password' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content 'Server=tcp:fake.database.windows.net;Database=fake;User Id=fake;Password=hunter2;' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'SQL-style connection-string pattern'
        }

        It 'flags a URL with embedded userinfo credentials' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content 'curl https://svcuser:hunter2@example.com/api' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'embedded userinfo credentials'
        }

        It 'reports every violation in one pass rather than stopping at the first' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content ("-----BEGIN CERTIFICATE-----`n" + 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0') `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 2
        }
    }

    Context 'Get-PulseControlByteViolations (unit-tested against synthetic byte arrays)' {
        It 'reports zero violations for ordinary printable/whitespace bytes' {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("function Foo`t{`r`n    'ok'`n}")
            $violations = @(Get-PulseControlByteViolations -Bytes $bytes -RelativePath 'source/Fake.ps1')

            $violations | Should -BeNullOrEmpty
        }

        It 'flags a raw NUL byte - the exact Task 1.8 regression class' {
            $bytes = [byte[]] @(0x23, 0x20, 0x00, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74) # "# \0comment"
            $violations = @(Get-PulseControlByteViolations -Bytes $bytes -RelativePath 'source/Fake.ps1')

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match '0x00'
        }

        It 'flags a raw non-NUL control byte (e.g. 0x01)' {
            $bytes = [byte[]] @(0x61, 0x01, 0x62)
            $violations = @(Get-PulseControlByteViolations -Bytes $bytes -RelativePath 'source/Fake.ps1')

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match '0x01'
        }
    }
}

Describe 'Secret/PII scan gate' -Tag 'QA', 'SecretScan' {

    BeforeDiscovery {
        $projectPath = "$($PSScriptRoot)\..\.." | Convert-Path
        $textExtensions = @('.ps1', '.psm1', '.psd1', '.md', '.txt')

        $scanFiles = @(
            Get-ChildItem -Path (Join-Path $projectPath 'source'), (Join-Path $projectPath 'tests') -Recurse -File |
                Where-Object {
                    $textExtensions -contains $_.Extension -and
                    ($_.FullName -replace '\\', '/') -notmatch '/tests/QA/'
                }
        )

        $secretScanCases = @($scanFiles | ForEach-Object {
            @{ FullPath = $_.FullName; RelativePath = (($_.FullName.Substring($projectPath.Length + 1)) -replace '\\', '/') }
        })

        $sourceFiles = @(Get-ChildItem -Path (Join-Path $projectPath 'source') -Recurse -File)

        $controlByteCases = @($sourceFiles | ForEach-Object {
            @{ FullPath = $_.FullName; RelativePath = (($_.FullName.Substring($projectPath.Length + 1)) -replace '\\', '/') }
        })

        # Discovery-time guard, not a runtime It: if either list is empty, test-case
        # generation for the -ForEach blocks below silently produces zero leaf tests - the
        # exact "gate stays green because it is testing nothing" failure mode
        # Assert-GateResult.ps1's NotRun accounting exists to catch across the whole suite.
        # Failing loudly here, at discovery, is the more direct version of that guarantee
        # for this one file.
        if ($secretScanCases.Count -eq 0) {
            throw 'Secret/PII scan gate: discovered zero files under source/ or tests/ to scan - the file discovery itself is broken.'
        }
        if ($controlByteCases.Count -eq 0) {
            throw 'Secret/PII scan gate: discovered zero files under source/ to control-byte-scan - the file discovery itself is broken.'
        }
    }

    It "'<RelativePath>' has no secret/PII-shaped content" -ForEach $secretScanCases {
        $content = Get-Content -LiteralPath $FullPath -Raw -ErrorAction Stop
        $violations = @(Get-PulseSecretScanViolations -Content $content -RelativePath $RelativePath -AllowedGuid $script:allowedGuids -SafeDomainSuffix $script:safeDomainSuffixes)

        $violations | Should -BeNullOrEmpty -Because ($violations -join "`n")
    }

    It "'<RelativePath>' contains no raw NUL/control bytes" -ForEach $controlByteCases {
        $bytes = [System.IO.File]::ReadAllBytes($FullPath)
        $violations = @(Get-PulseControlByteViolations -Bytes $bytes -RelativePath $RelativePath)

        $violations | Should -BeNullOrEmpty -Because ($violations -join "`n")
    }
}
