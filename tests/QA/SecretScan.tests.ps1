<#
    QA gate: repo-local, offline secret/PII scan. Complements (does not replace) gitleaks
    running in CI (see .github/workflows/ci.yml) - this file exists so the same checks run
    on every developer machine via `./build.ps1 -Tasks test`, with no network access and no
    third-party binary required.

    Scans source/ and tests/ (text-shaped files: .ps1/.psm1/.psd1/.psc1/.pssc/.md/.txt/
    .json/.csv/.xml) for:
        1. a GUID-looking id sitting near a real-looking (non-Microsoft/GitHub) domain -
           the classic "leaked real tenant id + tenant domain" shape.
        2. a bearer-token-shaped JWT ('eyJ...' header/payload pair).
        3. a PEM private-key or certificate header.
        4. connection-string patterns (Azure Storage AccountKey=/SharedAccessSignature=,
           SQL-style Server=/Data Source=...Password=... in EITHER key order, or a URL
           with embedded userinfo credentials).
        5. a Shared Access Signature (SAS) token query parameter ([?&]sig=/[?&]se=...).
    Plus, scoped to BOTH source/ and tests/:
        6. a raw NUL or other C0 control byte - the exact class of mistake Task 1.8
           introduced and then fixed (a literal NUL byte typed into a .ps1 comment instead
           of the [char]0 spelling); this is a permanent regression guard for it. Scanning
           tests/ too is safe: every legitimate use of an actual NUL character in this
           repo (e.g. Invoke-PulseEvaluation.ps1's evidence-uniqueness tuple separator)
           already goes through the `[char]0` spelling, never a literal byte, in test
           files exactly as in source.

    Get-PulseSecretScanViolations and Get-PulseControlByteViolations are unit-tested first
    against small synthetic strings/byte arrays (proving each pattern actually fires, and
    that the allowlist actually suppresses a known-safe GUID) before being run once more
    against the real repo tree - the same two-phase shape FixtureProvenance.tests.ps1 and
    ReadOnly.tests.ps1 use.

    tests/QA/ itself is excluded from the real-repo scan below: this file (and its sibling
    QA gates) necessarily contains the detection patterns as literal text - matching
    against itself would be a self-inflicted false positive, not a real finding. QA code is
    reviewed by hand, not by this scanner.

    ACCEPTED RESIDUALS - this is a repo-local, offline, regex-shaped gate, not a general
    secret scanner; gitleaks (wired into CI, see .github/workflows/ci.yml) is the real
    defense-in-depth backstop for everything below:
        - Non-canonical JWTs: the bearer-token check requires the literal 'eyJ' header
          prefix (the base64url encoding of '{"'); a JWT with an atypical header, or one
          re-encoded/wrapped in a way that breaks that literal prefix, is not caught here.
        - Homoglyph/punycode domains: the GUID-near-domain check matches ASCII
          letters/digits/hyphens only - a domain using Unicode confusables or raw punycode
          ('xn--...') is not caught here.
        - Split or encoded tokens: any secret broken across a line boundary, string
          concatenation, or a non-base64/hex encoding (e.g. wrapped in an extra layer of
          encoding) will not match these single-line, single-encoding regexes. Entropy-
          based detection (gitleaks' real strength) is the only backstop for this class.
        - Self-allowlist-editing: every allowlist/deny-list here (allowedGuids,
          safeDomainSuffixes, denyListedDomains) lives in this same repo, editable by
          whoever can edit this file - a repo-local gate cannot stop a bad actor with
          write access from allowlisting their own leak. This is an inherent property of
          any repo-local gate, not specific to this one; PR review and gitleaks (a
          separately-maintained, non-repo-local rule set) are the actual backstops.
        - onmicrosoft.com is deliberately IN the safe-domain-suffix opposite - i.e. it is
          NOT added to $safeDomainSuffixes and is left to over-detect: a real
          '<tenant>.onmicrosoft.com' next to a real GUID is exactly the "leaked real
          tenant" shape this check exists to catch, so it fails loud (a false positive
          costs a moment's review; a false negative here would defeat the check's entire
          purpose) rather than being suppressed for convenience.
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

    # Domain-shaped EXACT PATTERNS that are never a real domain no matter what the whole
    # matched token is - the complement of $safeDomainSuffixes for cases where the fixed
    # part is the front, not the back, of the match. 'microsoft.graph.<Identifier>' is the
    # literal namespace prefix every Microsoft Graph OData type-discriminator VALUE uses
    # (e.g. '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance', matched
    # here without its leading '#', which is not a domain-pattern character) - these values
    # appear throughout tests/Fixtures/SettingsCatalog/*.json right next to real (remapped)
    # settingInstanceTemplateId/settingValueTemplateId GUIDs, and the task that produced
    # those fixtures requires @odata.type values to be kept VERBATIM (public schema), so
    # they cannot be scrubbed to dodge this check. A suffix-only allowlist cannot reach
    # this shape (the "domain" here is the whole 'microsoft.graph.<PascalCaseTypeName>'
    # run, not something ending in a known TLD).
    #
    # DELIBERATELY a full-token '^...$' regex, NOT a StartsWith/prefix check: a bare
    # StartsWith('microsoft.graph.') would also admit a genuinely malicious domain that
    # merely BEGINS with the same text, e.g. 'microsoft.graph.attacker-exfil.io' (a domain
    # an attacker fully controls, registered specifically to slip past a naive prefix
    # check) - the domain-matching regex's own greedy '(?:label\.)+label' shape means that
    # whole string is captured as ONE token, and a prefix check has no way to tell "ends
    # after the type name" apart from "has more attacker-controlled labels tacked on
    # after it". Anchoring the WHOLE token to
    # 'microsoft\.graph\.[A-Za-z0-9]+' with no further dots permitted closes that hole:
    # every real @odata.type value is exactly 'microsoft.graph.<PascalCaseIdentifier>'
    # with no additional dotted labels, so a legitimate value still matches while
    # 'microsoft.graph.attacker-exfil.io' (three additional labels after 'graph') does not.
    $script:safeDomainExactPatterns = @(
        '^microsoft\.graph\.[A-Za-z0-9]+$'
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

            [string[]] $SafeDomainSuffix = @(),

            [string[]] $SafeDomainExactPattern = @()
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
        # The domain match is deliberately GENERAL - any dotted run of labels ending in a
        # 2+ letter final label - rather than gated by a fixed TLD allowlist. A TLD
        # allowlist cannot scale (contoso.technology, contoso.agency, contoso.ltd, and
        # every other new gTLD would silently slip through undetected); a small,
        # BY-VALUE deny-list of the specific code-shaped strings that actually false-
        # positive is the inverted, maintainable version of the same idea. Because the
        # domain check only ever runs inside a 200-character window around an actual
        # (non-allowlisted) GUID match - not against the whole file - the practical
        # false-positive surface turns out to be tiny: running this general pattern
        # against the real repo (every text file under source/ and tests/, excluding
        # tests/QA/) surfaced exactly one class of false positive, seeded below.
        $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        $domainPattern = '\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

        # Deny-list of specific, lowercase, code-shaped "domains" the general pattern
        # above matches but which are never a real domain - each seeded by actually
        # running the general (un-gated) pattern over the whole repo and confirming what
        # fired near a real GUID.
        $denyListedDomains = [System.Collections.Generic.HashSet[string]]::new(
            [string[]] @(
                # TenantPulse's own check-id family prefixes (e.g. 'TP.ENT.0003',
                # 'TP.INT.0001') - two-letter-ish dotted labels that are structurally
                # domain-shaped but are check ids, never a domain. Fires in
                # TP.ENT.0003.Tests.ps1 next to its synthetic break-glass placeholder
                # GUIDs (11111111-.../22222222-...).
                'tp.ent'
                'tp.int'
                # The literal JSON property key '@odata.type' (Microsoft Graph's
                # OData type-discriminator field) - domain-shaped ('odata' + '.' +
                # 'type', a 2+ letter final label) but a schema property name, never a
                # domain. Fires throughout tests/Fixtures/SettingsCatalog/*.json, where
                # every sanitized Settings Catalog payload has real (remapped)
                # settingInstanceTemplateId/settingValueTemplateId GUIDs sitting a few
                # lines from a "@odata.type": "#microsoft.graph...Instance" key.
                'odata.type'
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
                # A match immediately preceded by '$' is a PowerShell variable-rooted
                # property-access chain ('$Datasets.organizationMdmAuthority',
                # '$check.category', ...), never a domain - this is the general,
                # structural counterpart to the by-value deny-list above, covering the
                # unbounded space of property/method names without having to enumerate
                # each one.
                $precedingChar = if ($domainMatch.Index -gt 0) { $window.Substring($domainMatch.Index - 1, 1) } else { '' }
                if ($precedingChar -eq '$') {
                    continue
                }

                $domain = $domainMatch.Value.ToLowerInvariant()

                if ($denyListedDomains.Contains($domain)) {
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
                    # -cmatch, not -match: $domain is already ToLowerInvariant()'d above and
                    # every pattern in $SafeDomainExactPattern is written lowercase, so an
                    # ordinal/case-sensitive match is both correct and marginally cheaper -
                    # a case-INSENSITIVE match here would add no coverage (the domain can
                    # never contain uppercase at this point) while being one more implicit
                    # behavior to reason about.
                    foreach ($pattern in $SafeDomainExactPattern) {
                        if ($domain -cmatch $pattern) {
                            $isSafe = $true
                            break
                        }
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
        # SQL-style Server=/Data Source=...Password=... - checked BOTH orderings, since a
        # connection string is a semicolon-delimited bag of key=value pairs with no fixed
        # key order (Password=...;Server=... is exactly as real as Server=...;Password=...).
        if ($Content -match '(?i)\b(Server|Data Source)\s*=[^;\r\n]+;[^\r\n]*Password\s*=') {
            $violations.Add("$RelativePath : SQL-style connection-string pattern found (...Password=...).")
        }
        if ($Content -match '(?i)\bPassword\s*=[^;\r\n]+;[^\r\n]*(Server|Data Source)\s*=') {
            $violations.Add("$RelativePath : SQL-style connection-string pattern found (Password=...;...Server=/Data Source=...).")
        }
        if ($Content -match '://[^/\s:@]+:[^/\s@]+@') {
            $violations.Add("$RelativePath : URL with embedded userinfo credentials found.")
        }
        # 5. Shared Access Signature (SAS) token query parameters - '?sig=...' / '&se=...'
        # followed by a long base64url-ish run, the shape Azure Storage/Service Bus SAS
        # URLs use regardless of which resource they were minted for.
        if ($Content -match '(?i)[?&](sig|se)=[A-Za-z0-9%._~+/=-]{16,}') {
            $violations.Add("$RelativePath : SAS-token-shaped query parameter found ([?&]sig=/[?&]se=...).")
        }

        return $violations.ToArray()
    }

    <#
        Scans raw file BYTES for a NUL byte or any other C0 control byte outside tab/LF/CR
        - the regression class from Task 1.8 (a literal NUL byte typed into a .ps1 comment).
        Item 6 in this file's own docstring. Returns every violation as a string; empty
        array means clean.
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

        It 'catches a GUID near a small-gTLD real-looking domain a fixed TLD allowlist would have missed' {
            # The exact hole this deny-list inversion exists to close: '.technology' is a
            # real, registrable gTLD that a small fixed TLD allowlist would never contain -
            # a fixed-allowlist detector lets contoso.technology (or .agency, .ltd, and
            # every other newer gTLD) through undetected.
            $violations = @(Get-PulseSecretScanViolations `
                -Content "tenantId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479' for contoso.technology" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes)

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'looks like a real tenant id/domain pair'
        }

        It 'does NOT flag a GUID near the TP.ENT/TP.INT check-id family prefix (deny-listed, not TLD-gated)' {
            # The false-positive class this codebase would otherwise trip constantly: check
            # ids like 'TP.ENT.0003' are dotted, letters-and-dots text that the now-general
            # (un-gated) domain pattern DOES match - 'tp.ent' - but it is deny-listed by
            # value because it is never a real domain, not because it lacks a "real" TLD.
            $violations = @(Get-PulseSecretScanViolations `
                -Content "TP.ENT.0003 references f47ac10b-58cc-4372-a567-0e02b2c3d479 in the same file as TP.INT.0001" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes)

            $violations | Should -BeNullOrEmpty
        }

        It 'does NOT flag a GUID near a "#microsoft.graph.<Type>" @odata.type VALUE (safe-domain-exact-pattern, not suffix-gated)' {
            # Companion to the deny-listed '@odata.type' KEY case below: the @odata.type
            # VALUE itself ('#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance')
            # is also domain-shaped once its leading '#' is stripped by the domain pattern -
            # 'microsoft.graph.devicemanagementconfigurationchoicesettinginstance' is one
            # dotted run ending in a 2+ letter label. A suffix allowlist cannot reach this
            # (it never ends in a known TLD), so this needs the full-token-regex counterpart.
            $violations = @(Get-PulseSecretScanViolations `
                -Content '"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance", "settingInstanceTemplateId": "04a00609-ef59-430d-b7b7-a8238b93d84f"' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes `
                -SafeDomainExactPattern $script:safeDomainExactPatterns)

            $violations | Should -BeNullOrEmpty
        }

        It 'still flags a GUID near a real-looking domain that merely MENTIONS "microsoft.graph" mid-string' {
            # Proves the check is a genuine full-token match, not an accidental "contains" -
            # a domain that merely has 'microsoft.graph' somewhere other than its start
            # must still be flagged.
            $violations = @(Get-PulseSecretScanViolations `
                -Content "tenantId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479' for evil-microsoft.graph.contoso-prod.example.com" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes `
                -SafeDomainExactPattern $script:safeDomainExactPatterns)

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'looks like a real tenant id/domain pair'
        }

        It 'still flags a GUID near "microsoft.graph.attacker-exfil.io" - the exact StartsWith-bypass mutation from code review' {
            # The precise hole a naive StartsWith('microsoft.graph.') check would have left
            # open: 'microsoft.graph.attacker-exfil.io' STARTS WITH the safe prefix but is a
            # domain an attacker fully controls (registered specifically to look like a
            # Graph OData type value at a glance). The full-token regex
            # '^microsoft\.graph\.[A-Za-z0-9]+$' rejects it because real @odata.type values
            # never have additional dotted labels after the type name - this one has three
            # ('attacker-exfil' + '.' + 'io', on top of 'graph').
            $violations = @(Get-PulseSecretScanViolations `
                -Content "tenantId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479' for microsoft.graph.attacker-exfil.io" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes `
                -SafeDomainExactPattern $script:safeDomainExactPatterns)

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'looks like a real tenant id/domain pair'
            $violations[0] | Should -Match ([regex]::Escape('microsoft.graph.attacker-exfil.io'))
        }

        It 'does NOT flag a GUID near the literal "@odata.type" JSON property key (deny-listed, not TLD-gated)' {
            # The Settings Catalog fixture class: every sanitized policy/settings JSON
            # payload under tests/Fixtures/SettingsCatalog/ has a real settingInstanceTemplateId
            # or settingValueTemplateId GUID sitting a few lines from a literal
            # '"@odata.type": "#microsoft.graph...Instance"' key - domain-shaped
            # ('odata.type') but a schema property name, never a domain.
            $violations = @(Get-PulseSecretScanViolations `
                -Content '"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance", "settingInstanceTemplateId": "04a00609-ef59-430d-b7b7-a8238b93d84f"' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes `
                -SafeDomainExactPattern $script:safeDomainExactPatterns)

            $violations | Should -BeNullOrEmpty
        }

        It 'does NOT flag a GUID near an ordinary dotted PowerShell property-path expression' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content "id = f47ac10b-58cc-4372-a567-0e02b2c3d479; see `$Datasets.organizationMdmAuthority.foo" `
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

        It 'flags a SQL-style connection string with Server= before Password=' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content 'Server=tcp:fake.database.windows.net;Database=fake;User Id=fake;Password=hunter2;' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'SQL-style connection-string pattern'
        }

        It 'flags a SQL-style connection string with Password= BEFORE Server= (key order independence)' {
            # Connection strings are an unordered semicolon-delimited bag of key=value
            # pairs - Password=...;Server=... is exactly as real a shape as
            # Server=...;Password=..., and a detector that only checks one ordering has a
            # hole a rearranged (or hand-written) connection string walks straight through.
            $violations = @(Get-PulseSecretScanViolations `
                -Content 'Password=hunter2;Database=fake;User Id=fake;Server=tcp:fake.database.windows.net;' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'SQL-style connection-string pattern'
        }

        It 'flags a SAS-token-shaped query parameter' {
            $violations = @(Get-PulseSecretScanViolations `
                -Content 'https://fake.blob.core.windows.net/container/blob?sv=2023-01-01&se=2026-12-31T00%3A00%3A00Z&sig=AbCdEf1234567890%2FGhIjKl%3D' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'SAS-token-shaped'
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
        $textExtensions = @('.ps1', '.psm1', '.psd1', '.psc1', '.pssc', '.md', '.txt', '.json', '.csv', '.xml', '.yml', '.yaml')

        # ROOTS (post-review fix, item 28): previously only source/ and tests/ were
        # scanned - scripts/ (the publish script, which handles an API key end to end) and
        # the repo-root build/CI/doc surface (build.ps1, build.yaml, README.md,
        # CHANGELOG.md, .github/workflows/ci.yml) were never scanned at all, even though
        # every one of them is exactly the kind of file a secret or PII value could land in
        # by accident (a pasted example token in a doc, a hardcoded value in a workflow
        # file). Extended to cover all of them, while still excluding output/ (build
        # artifacts, never hand-authored) and tests/QA/ (this scanner's own code, reviewed
        # by hand - see the exclusion note elsewhere in this file).
        $recurseRoots = @(
            (Join-Path $projectPath 'source')
            (Join-Path $projectPath 'tests')
            (Join-Path $projectPath 'scripts')
        ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }

        $explicitRootFiles = @(
            (Join-Path $projectPath 'build.ps1')
            (Join-Path $projectPath 'build.yaml')
            (Join-Path $projectPath 'README.md')
            (Join-Path $projectPath 'CHANGELOG.md')
            (Join-Path $projectPath '.github/workflows/ci.yml')
        ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | ForEach-Object { Get-Item -LiteralPath $_ }

        $scanFiles = @(
            (Get-ChildItem -Path $recurseRoots -Recurse -File |
                Where-Object {
                    $textExtensions -contains $_.Extension -and
                    ($_.FullName -replace '\\', '/') -notmatch '/tests/QA/' -and
                    ($_.FullName -replace '\\', '/') -notmatch '(^|/)output/'
                }) + $explicitRootFiles
        )

        $secretScanCases = @($scanFiles | ForEach-Object {
            @{ FullPath = $_.FullName; RelativePath = (($_.FullName.Substring($projectPath.Length + 1)) -replace '\\', '/') }
        })

        # Control-byte scan covers the exact same root set as the secret scan above -
        # excluding tests/QA/ and output/ for the same reasons: this file's own
        # control-byte unit test fixtures below construct literal control bytes in-memory
        # as [byte[]] arrays, never on disk, so there is nothing to exclude there in
        # practice, but the exclusion keeps the same "QA/build-artifact content is
        # reviewed by hand or generated, not scanned" rule consistent across both scans.
        $controlByteFiles = @(
            (Get-ChildItem -Path $recurseRoots -Recurse -File |
                Where-Object {
                    ($_.FullName -replace '\\', '/') -notmatch '/tests/QA/' -and
                    ($_.FullName -replace '\\', '/') -notmatch '(^|/)output/'
                }) + $explicitRootFiles
        )

        $controlByteCases = @($controlByteFiles | ForEach-Object {
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
            throw 'Secret/PII scan gate: discovered zero files under source/ or tests/ to control-byte-scan - the file discovery itself is broken.'
        }
    }

    It "'<RelativePath>' has no secret/PII-shaped content" -ForEach $secretScanCases {
        $content = Get-Content -LiteralPath $FullPath -Raw -ErrorAction Stop
        $violations = @(Get-PulseSecretScanViolations -Content $content -RelativePath $RelativePath -AllowedGuid $script:allowedGuids -SafeDomainSuffix $script:safeDomainSuffixes -SafeDomainExactPattern $script:safeDomainExactPatterns)

        $violations | Should -BeNullOrEmpty -Because ($violations -join "`n")
    }

    It "'<RelativePath>' contains no raw NUL/control bytes" -ForEach $controlByteCases {
        $bytes = [System.IO.File]::ReadAllBytes($FullPath)
        $violations = @(Get-PulseControlByteViolations -Bytes $bytes -RelativePath $RelativePath)

        $violations | Should -BeNullOrEmpty -Because ($violations -join "`n")
    }
}
