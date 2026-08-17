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
        7. a DIGEST-BASED banned-identifier check: the Ivy24 lab tenant's real Entra tenant
           GUID (leaked into tests/Unit/Snapshot.Tests.ps1 and
           tests/Unit/Get-PulseTenantSnapshot.Tests.ps1 by Task 1.11's live-gate work,
           scrubbed to a synthetic placeholder in the same task that added this check) is
           banned by comparing a SHA-256 DIGEST of every candidate token against a table of
           known-banned digests, never a literal or reversibly-encoded copy of the value
           itself. Bare-value, zero-heuristic on WHERE it can appear: item 1's
           GUID-near-domain check is deliberately narrow (requires a real-looking domain
           nearby) and a lone tenant GUID sitting in a PowerShell test variable with no
           domain nearby - exactly the shape that leaked - walks straight through it. This
           one specific known-real value gets an unconditional "never again, anywhere, in
           any context" rule instead.

           DIGEST, NOT REVERSAL (hygiene-rule rework, post-review): an EARLIER version of
           this check stored the real GUID as its own character-reversal (imagine
           'edcba-4321' reversing back to '1234-abcde' at scan time - the real entry used
           the actual banned GUID) so this tracked file never contained the value as ONE
           literal, greppable string. That was a genuine defect, not a mitigation: character reversal is a
           trivially invertible transform any reader of this PUBLIC repo can undo by eye -
           the reversed string, sitting at HEAD in a tracked file, WAS the disclosure, in a
           form immune to any later history rewrite (the value is recoverable from the
           CURRENT tree, not just from history). A cryptographic digest has no such
           inverse: SHA-256 is a one-way function, so this table can be read by anyone with
           repository access without recovering the banned value from it. See
           Get-PulseBannedIdentifierDigests/Get-PulseTokenDigest below for the mechanism,
           and this file's own mutation-test Describe block for proof the real value
           (recovered at TEST-RUN TIME from git history, never typed into any tracked file)
           still trips this check.
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
        # Entra built-in DIRECTORY ROLE ids (public, tenant-stable, documented by
        # Microsoft's authorizationPolicy.guestUserRoleId reference) - Task 4.2,
        # source/Private/Checks/Test-PulseAuthorizationPolicyDefaults.ps1 (EIDSCA.AP07).
        '2af84b1e-32c8-42b7-82bc-daa82404023b' # Restricted Guest User role (recommended)
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' # Guest User role (Microsoft's permissive default)
        # TenantPulse's own module manifest GUID (source/TenantPulse.psd1) - a public
        # package identifier, never a tenant id.
        'a2f6d0f0-6d0c-4a6b-9f7e-9c9e6f6c7c2f' # TenantPulse module GUID
        # Task 2.3 typed-policy fixture synthetic ids (tests/Fixtures/TypedPolicy/*.json,
        # scripted-sanitized-real captures off Ivy24's own deviceCompliancePolicies/
        # deviceConfigurations - see tests/Fixtures/PROVENANCE.md). Deliberately
        # allowlisted BY VALUE here, the same stable mechanism every other constant GUID
        # above uses, rather than relying on the domain-denylist/safe-pattern heuristics
        # below - those fixtures' own "#microsoft.graph.<TypeName>" OData type-
        # discriminator VALUES (public schema, kept verbatim, cannot be scrubbed) sit
        # within the 200-character window of these ids in a short file, and an exact-
        # value allowlist entry is immune to how that general heuristic's own matching
        # happens to behave for any given input, unlike a by-value domain-text deny-list
        # entry which is brittle to exactly which substring the general regex captures.
        '11111111-0000-4000-8000-000000000001' # TypedPolicy fixture: compliance-windows10
        '11111111-0000-4000-8000-000000000002' # TypedPolicy fixture: compliance-androidWorkProfile
        '11111111-0000-4000-8000-000000000003' # TypedPolicy fixture: compliance-macOS
        '11111111-0000-4000-8000-000000000004' # TypedPolicy fixture: compliance-ios
        '22222222-0000-4000-8000-000000000001' # TypedPolicy fixture: deviceConfiguration-windows10Custom
        '22222222-0000-4000-8000-000000000002' # TypedPolicy fixture: deviceConfiguration-windowsUpdateForBusiness
        '22222222-0000-4000-8000-000000000003' # TypedPolicy fixture: deviceConfiguration-sharedPC
        # Task 4.4 - built-in Microsoft authentication STRENGTH policy ids (public,
        # tenant-stable, documented at learn.microsoft.com/entra/identity/authentication/
        # concept-authentication-strengths) - see
        # source/Private/Checks/Test-PulsePrivilegedRolesPhishingResistantMfa.ps1's own
        # docstring for both id variants.
        '00000000-0000-0000-0000-000000000004' # built-in "Phishing-resistant MFA" strength
        '00000000-0000-0000-0000-000000000005' # built-in phishing-resistant strength variant (cert-based auth)
        # Task 4.4 - synthetic test-fixture principal ids (repeated-digit pattern, never a
        # real tenant identifier), same by-value convention as the TypedPolicy fixture ids
        # above - each sits within 200 characters of a dotted PowerShell property-path
        # token (e.g. 'conditions.clientApplications', 'detail.exempt') the domain-shaped
        # heuristic cannot distinguish from a real domain.
        '22222222-2222-2222-2222-222222222222' # ConvertTo-PulseCaPolicyView.Tests.ps1 synthetic excludeApplications id
        '33333333-3333-3333-3333-333333333333' # TP.ENT.0022.Tests.ps1 synthetic ServiceAccounts principal id
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
    #
    # BARE 'microsoft.graph' ALSO safe, no trailing type name required (task-2.3-review
    # fix, reproduced against a real fixture): the shared $domainPattern's own final label
    # is letters-ONLY ('[a-zA-Z]{2,}', no digits) - a real @odata.type whose type name
    # itself starts with a digit-bearing token, e.g.
    # '#microsoft.graph.windows10CustomConfiguration' (TypedPolicyMaps.psd1 covers several:
    # windows10CustomConfiguration, windows10CompliancePolicy, windows10GeneralConfiguration,
    # windows10EndpointProtectionConfiguration - 'windows10' is not letters-only), can NEVER
    # be captured as one whole 'microsoft.graph.<TypeName>' domain match at all: the regex
    # engine stops the match at the last all-letters label it can find, which is just
    # 'graph' - producing a BARE two-label 'microsoft.graph' match, distinct from (and not
    # covered by) the three-label pattern above. This is not a window-truncation artifact
    # (see Get-PulseSecretScanViolations' own item-1 comment for that separate, already-
    # fixed bug) - it is the domain regex's OWN tokenization boundary, reproducible against
    # the full, untruncated content. 'microsoft.graph' alone is exactly as safe as
    # 'microsoft.graph.<TypeName>' - it is the fixed, well-known Graph OData namespace root,
    # never a real registrable domain ('.graph' is not a TLD) - so the optional trailing
    # '(\.[A-Za-z0-9]+)?' group admits both shapes under the same StartsWith-bypass-proof
    # full-token anchoring as before.
    $script:safeDomainExactPatterns = @(
        '^microsoft\.graph(\.[A-Za-z0-9]+)?$'
    )

    <#
        DIGEST TABLE for the item-7 banned-identifier check (hygiene-rule rework - see
        this file's own DIGEST, NOT REVERSAL docstring section for why a reversible
        transform of a real secret, sitting in a tracked file in a public repo, is itself
        the disclosure it claims to prevent). Each entry maps a lowercase, 32-hex-character
        digest -> a human-readable LABEL - never the banned value. The digest is computed
        by Get-PulseTokenDigest below (SHA-256 of the lowercased candidate token, first 32
        hex characters / 16 bytes) - the SAME function both the production check and this
        file's own tests use, so there is exactly one place the computation is defined.

        Findings report the LABEL, never the value that matched (this table's own values
        are never echoed back into a violation string) - see Get-PulseSecretScanViolations'
        item-7 block below.

        '6ca05670c4afd49e806f7cddbab83b00' = the Ivy24 lab tenant's real Entra tenant GUID.
        This digest was computed OFFLINE, once, from the real value recovered from git
        history (commit 477ce2d, before it was scrubbed) - the real GUID itself is not, and
        must never be, written into this file.
    #>
    $script:PulseBannedIdentifierDigests = @{
        '6ca05670c4afd49e806f7cddbab83b00' = 'lab tenant id'
    }

    <#
        Computes the banned-identifier digest for one candidate token: SHA-256 of the
        lowercase-invariant token text, truncated to its first 32 hex characters (16
        bytes) - a deliberate truncation (not the full 64-char digest) since this is a
        deny-list membership check, not a content-integrity hash; 128 bits of collision
        resistance is far more than this closed, small table needs, and a shorter digest
        keeps $script:PulseBannedIdentifierDigests's own entries compact and readable.
    #>
    function Get-PulseTokenDigest {
        [CmdletBinding()]
        [OutputType([string])]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string] $Token
        )

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Token.ToLowerInvariant())
        $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $hex = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
        return $hex.Substring(0, 32)
    }

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
                # The '#microsoft.graph.<TypeName>' OData type-discriminator VALUE
                # itself (not just the '@odata.type' key above) - domain-shaped
                # ('microsoft' + '.' + 'graph', a 2+ letter final label) but Microsoft
                # Graph's own public type-discriminator prefix, never a domain, and
                # identical across every tenant. Fires in
                # tests/Fixtures/TypedPolicy/deviceConfiguration-windows10Custom.json,
                # a short sanitized fixture where the whole file sits inside the
                # 200-character window around its own synthetic 'id' GUID, so BOTH the
                # top-level "#microsoft.graph.windows10CustomConfiguration" type and the
                # nested omaSettings[0] "#microsoft.graph.omaSettingBoolean" type land in
                # that window - two related domain-shaped matches from the SAME harmless
                # prefix, not two independent findings.
                'ft.graph'
                'microsoft.graph.omasettingboolean'
            ),
            [System.StringComparer]::OrdinalIgnoreCase
        )

        # Domain matches are computed ONCE against the FULL, untruncated $Content - never a
        # windowed substring (bug found while extending this file's own golden-fixture
        # coverage, task-2.3-review C1/I1 round: a real 'omaSettings' fixture placed
        # '"@odata.type": "#microsoft.graph.windows10CustomConfiguration"' close enough to
        # the fixture's own remapped `id` GUID that the OLD per-GUID `$Content.Substring(...)`
        # window sliced the 200-char boundary mid-token, truncating the safe, allowlisted
        # 'microsoft.graph.windows10CustomConfiguration' token down to a mangled 'ft.graph'
        # - which no longer matched $SafeDomainExactPattern's 'microsoft\.graph\....' prefix
        # and false-positived as a real tenant-id/domain pair. Matching against the whole,
        # never-truncated file up front and then testing each match's SPAN for overlap with
        # the per-GUID window (below) gets the identical "only look near this GUID" behavior
        # with no risk of ever slicing a token in half.
        $allDomainMatches = [regex]::Matches($Content, $domainPattern)

        foreach ($guidMatch in [regex]::Matches($Content, $guidPattern)) {
            $guid = $guidMatch.Value.ToLowerInvariant()
            if ($allowedGuidLookup.Contains($guid)) {
                continue
            }

            $windowStart = [Math]::Max(0, $guidMatch.Index - 200)
            $windowEnd = [Math]::Min($Content.Length, $guidMatch.Index + $guidMatch.Length + 200)

            foreach ($domainMatch in $allDomainMatches) {
                # Overlap test against the (untruncated-token) window, not containment of a
                # substring - a domain match that starts before the window but still ends
                # inside it (or vice versa) is still "near" the GUID in the sense this check
                # cares about.
                if ($domainMatch.Index + $domainMatch.Length -le $windowStart -or $domainMatch.Index -ge $windowEnd) {
                    continue
                }

                # A match immediately preceded by '$' is a PowerShell variable-rooted
                # property-access chain ('$Datasets.organizationMdmAuthority',
                # '$check.category', ...), never a domain - this is the general,
                # structural counterpart to the by-value deny-list above, covering the
                # unbounded space of property/method names without having to enumerate
                # each one. Checked against $Content directly now (matches are full-content
                # matches, not window-relative ones).
                $precedingChar = if ($domainMatch.Index -gt 0) { $Content.Substring($domainMatch.Index - 1, 1) } else { '' }
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

        # 7. DIGEST-BASED banned identifier (hygiene-rule rework - see this file's own
        # DIGEST, NOT REVERSAL docstring section for why an earlier exact-match-on-
        # reversed-string version of this check was itself a disclosure, not a
        # mitigation). Deliberately zero-heuristic on WHERE a match can appear - item 1's
        # GUID-near-domain check requires a real-looking domain within 200 characters, and
        # the real value this rule exists to catch leaked in a shape with NO domain nearby
        # (a bare GUID assigned to a PowerShell test variable, e.g. `$tenantId = '<guid>'`),
        # which evades that heuristic by design.
        #
        # TOKENIZE, DIGEST, COMPARE: every substring matching the candidate-token pattern
        # (an alnum start, 3+ more alnum-or-hyphen characters - broad enough to catch a
        # bare GUID, a hyphenated slug, or any other "word" shape a banned identifier might
        # take) is hashed via Get-PulseTokenDigest and checked against
        # $script:PulseBannedIdentifierDigests. SHA-256 is one-way: this table (and this
        # whole check) can be read by anyone with repo access without recovering the
        # banned value from it - unlike the character-reversal this replaces, which was
        # trivially invertible by eye. A match is deduplicated by LABEL within one file (at
        # most one violation per banned identifier per file) and the violation message
        # names ONLY the label, never the matched token text - so even the FINDING itself
        # (which could land in a public CI log) never echoes the value back.
        $foundLabels = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($tokenMatch in [regex]::Matches($Content, '[A-Za-z0-9][A-Za-z0-9-]{3,}')) {
            $digest = Get-PulseTokenDigest -Token $tokenMatch.Value
            if ($script:PulseBannedIdentifierDigests.ContainsKey($digest)) {
                $label = $script:PulseBannedIdentifierDigests[$digest]
                if ($foundLabels.Add($label)) {
                    $violations.Add("$RelativePath : banned identifier found (label: '$label') - this value must never appear in a tracked file in any context; see Get-PulseSecretScanViolations' own item-7 comment for the digest-based mechanism.")
                }
            }
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

        It 'does NOT flag a GUID near a digit-bearing @odata.type value ("#microsoft.graph.windows10CustomConfiguration") - the domain regex''s own letters-only-final-label boundary reproduced' {
            # Reproduced against a real fixture (tests/Fixtures/TypedPolicy/
            # deviceConfiguration-windows10Custom.json, task-2.3-review C1/I1 round): the
            # shared $domainPattern's own final label is letters-ONLY - a type name whose
            # own text contains a digit ('windows10...') can never be captured as one whole
            # 'microsoft.graph.<TypeName>' three-label match at all; the regex engine stops
            # at the last all-letters label it finds, producing a BARE two-label
            # 'microsoft.graph' match instead - a DIFFERENT shape than the three-label
            # pattern the pre-fix $safeDomainExactPatterns only covered, and therefore
            # falsely flagged. Not the window-truncation bug (see the item-1 comment for
            # that separate fix) - reproducible here against a short, un-windowed string.
            $violations = @(Get-PulseSecretScanViolations `
                -Content '"@odata.type": "#microsoft.graph.windows10CustomConfiguration", "id": "11111111-2222-4333-8444-555555555555"' `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes `
                -SafeDomainExactPattern $script:safeDomainExactPatterns)

            $violations | Should -BeNullOrEmpty
        }

        It 'still flags a GUID near a BARE "microsoft.graph" that is genuinely part of a longer, attacker-controlled domain (bare-form does not reopen the StartsWith-bypass hole)' {
            # The bare-form allowlist entry ('^microsoft\.graph(\.[A-Za-z0-9]+)?$') must
            # stay just as StartsWith-bypass-proof as the three-label form - a domain that
            # merely STARTS with 'microsoft.graph' but has MORE dotted labels after it
            # (attacker-controlled) is still rejected, whether or not the "type name"
            # portion happens to contain a digit.
            $violations = @(Get-PulseSecretScanViolations `
                -Content "tenantId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479' for microsoft.graph.attacker-exfil2.io" `
                -RelativePath 'source/Fake.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes `
                -SafeDomainExactPattern $script:safeDomainExactPatterns)

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match 'looks like a real tenant id/domain pair'
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

        It 'Get-PulseTokenDigest is deterministic and matches an independently-computed SHA-256[0:32] for a non-secret example token' {
            # Not a secret - any known string works to prove the MECHANISM
            # (tokenize -> lowercase -> SHA-256 -> first-32-hex) is wired correctly. The
            # expected digest below was computed independently (Python hashlib), not
            # copied from the production code path under test.
            (Get-PulseTokenDigest -Token 'hello-world') | Should -Be 'afa27b44d43b02a9fea41d13cedc2e40'
            # Case-insensitive input (lowercased before hashing).
            (Get-PulseTokenDigest -Token 'HELLO-WORLD') | Should -Be 'afa27b44d43b02a9fea41d13cedc2e40'
        }

        It 'does NOT flag an ordinary synthetic placeholder GUID as a banned identifier' {
            # Mutation-test direction 1/2: a value that is NOT in
            # $script:PulseBannedIdentifierDigests must never fire, however GUID-shaped it
            # is - proves the digest comparison is a real membership test, not an
            # accidental always-match.
            $violations = @(Get-PulseSecretScanViolations `
                -Content "`$tenantId = '00000000-1111-2222-3333-444444444444'" `
                -RelativePath 'tests/Fake.Tests.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations | Should -BeNullOrEmpty
        }

        It 'flags the REAL Ivy24 lab tenant GUID via digest match, recovered from git history at TEST-RUN TIME - reports only the LABEL, never the value' {
            # Mutation-test direction 2/2 (the "plant the real value, assert red" half).
            # The real GUID is recovered from git history HERE, in memory, at test-run
            # time - it is NEVER typed into this or any other tracked file (that would be
            # exactly the disclosure item 7 exists to prevent). Commit 477ce2d is the
            # last revision (before the Task 2.3-review scrub) whose tracked
            # tests/Unit/Snapshot.Tests.ps1 still carried the real value.
            $historicalContent = git -C $projectPath show '477ce2d:tests/Unit/Snapshot.Tests.ps1' 2>$null
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($historicalContent)) {
                throw 'Could not recover the historical fixture content from git history (477ce2d:tests/Unit/Snapshot.Tests.ps1) - this repo must have full git history for this mutation test to run; a shallow clone would silently skip real coverage here, so this fails loudly instead.'
            }
            $recoveredGuid = [regex]::Match($historicalContent, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}').Value
            $recoveredGuid | Should -Not -BeNullOrEmpty -Because 'the historical revision is expected to contain a GUID-shaped literal to recover'
            (Get-PulseTokenDigest -Token $recoveredGuid) | Should -Be '6ca05670c4afd49e806f7cddbab83b00' -Because 'the recovered value must be the SAME real GUID the digest table was built from, or this test proves nothing'

            # Fed to the scan function directly (-Content), never written to any file on
            # disk (gitignored temp path or otherwise) - Get-PulseSecretScanViolations
            # takes content by value, so this exercises the identical production code
            # path a real tracked-file scan would, with no extra I/O needed to prove it.
            $violations = @(Get-PulseSecretScanViolations `
                -Content "`$tenantId = '$recoveredGuid'" `
                -RelativePath 'tests/Fake.Tests.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix @())

            $violations.Count | Should -Be 1
            $violations[0] | Should -Match "label: 'lab tenant id'"
            # The finding itself must never echo the matched value back (public-CI-log
            # safety, per the hygiene-rule rework) - even though THIS test file now holds
            # the real value in a variable, transiently, at run time, the violation
            # STRING this production function returns must not.
            $violations[0] | Should -Not -Match ([regex]::Escape($recoveredGuid))
        }

        It 'item 1''s GUID-near-domain check does NOT truncate a safe "microsoft.graph.<Type>" token at its 200-character window boundary (reproduced false positive, task-2.3-review fix)' {
            # Reproduces the exact shape tests/Fixtures/TypedPolicy/deviceConfiguration-
            # windows10Custom.json tripped: a safe, allowlisted-by-pattern
            # '#microsoft.graph.<Type>' @odata.type value sitting close enough to a
            # DIFFERENT (non-allowlisted) GUID that the OLD per-GUID windowing sliced the
            # token mid-word ('ft.graph' instead of 'microsoft.graph.windows10CustomConfiguration'),
            # which no longer matched $SafeDomainExactPattern and false-positived.
            $filler = '.' * 180
            $content = "`"@odata.type`": `"#microsoft.graph.windows10CustomConfiguration`",$filler`"id`": `"11111111-2222-4333-8444-555555555555`""

            $violations = @(Get-PulseSecretScanViolations `
                -Content $content `
                -RelativePath 'tests/Fake.Tests.ps1' `
                -AllowedGuid @() `
                -SafeDomainSuffix $script:safeDomainSuffixes `
                -SafeDomainExactPattern $script:safeDomainExactPatterns)

            $violations | Should -BeNullOrEmpty -Because ($violations -join "`n")
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
