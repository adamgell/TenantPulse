<#
    Scripted, exhaustive scrub for a committed live-tenant gate artifact (docs/gates/*.json).

    BACKGROUND (why this script exists): the first cut of docs/gates/phase4-ivy24-findings.
    redacted.json leaked real live-tenant PII - device names including person-derived ones
    (personal-device naming patterns, e.g. the shape "<Name>'s <device type>"; other real
    device names shaped like usernames or serial numbers), real serial/asset-tag-shaped
    device names, and real Conditional Access policy display names - because the original
    scrub only targeted dash-formatted GUIDs, not every free-text value a live Graph read can
    carry. None of the actual leaked values are reproduced here, deliberately - see this
    repo's docs/gates/README.md "Incident note" for the same reasoning. This script
    replaces that approach with an EXHAUSTIVE walk: every finding's `evidence[].detail`
    object (the one place per-row, tenant-derived free text lives in a TenantPulse findings
    document - confirmed by inspecting every check's evidence shape in this run: displayName,
    mfaMechanism, roleDisplayName, servicePrincipalName, principalId, roleDefinitionId,
    usableForSignInTargetIds, source, setting, expected/value, credentialType, lifetimeDays,
    maxAllowedDays, approximateLastSignInDateTime) has EVERY string leaf value replaced with a
    stable pseudonym, no exceptions, no per-field-name allowlist. This is deliberately more
    aggressive than distinguishing "this field looks structural" from "this field looks like a
    name" - a per-field allowlist is exactly the failure mode that let the original leak
    through unnoticed (a field the author did not anticipate as identity-bearing). Numbers,
    booleans, and $null are left as-is (a lifetimeDays: 365 or severity: 'High' is not a
    tenant-identity leak); every [string] leaf inside `detail` is not - literally EVERY one,
    including a timestamp-shaped string (see -DateKind String below for why that requires its
    own fix, not just a docstring claim).

    DATE-COERCION BUG, FOUND AND FIXED (remediation round 2): the first version of this
    script read the document with a plain `ConvertFrom-Json` call, which - by PowerShell's
    own default behavior - silently parses any ISO-8601-looking JSON string into a real
    [datetime] object, not a [string]. `approximateLastSignInDateTime` values therefore never
    reached the `-is [string]` branch below at all; they fell through to the generic
    pass-through path UNTOUCHED, survived re-serialization as raw ISO-8601 text, and shipped
    in the committed artifact in full - a real "every string leaf, no exceptions" claim that
    was not true in effect, on the exact class of field ("when did this device last sign in")
    that IS tenant-derived and identity-adjacent. `-DateKind String` on `ConvertFrom-Json`
    keeps every JSON string a [string] exactly as read (the same fix
    `Export-PulseReport.ps1`/`Export-PulseJsonReport.ps1` already use for a different byte-
    identity reason - see those files' own docstrings) - which makes the existing `-is
    [string]` branch see (and pseudonymize) a timestamp exactly like every other string leaf,
    with no special-casing needed. There is no longer a "timestamps are a documented
    exception" carve-out anywhere in this pipeline: they are pseudonymized like everything
    else, matching this docstring's own "every string leaf, no exceptions" claim for real.

    WEAK-HASH BUG, FOUND AND FIXED (merge-review remediation): the first version of this
    script pseudonymized every `detail` leaf with a PLAIN, UNSALTED SHA-256 of the raw
    string. That is not sound for this input class: the values being hashed (device
    display names, "<Name>'s <device type>" personal-device patterns, CA policy titles) are
    LOW-ENTROPY and identity-shaped - exactly the kind of input an offline dictionary/
    rainbow-table attack (enumerate plausible device names, hash each, compare against the
    committed digests) can reverse, and the hash CONSTRUCTION itself is public in this same
    repository (this file, at HEAD, forever) - an attacker does not even need to guess the
    algorithm. Fixed by switching to HMAC-SHA256 (`Get-PulsePseudonym`, the SAME primitive
    `Invoke-PulseAssessment -Redact` already uses for its own evidence-identity
    pseudonymization - see that function's own file, dot-sourced below rather than
    reimplemented, so this script uses the one already-reviewed HMAC construction in the
    repo instead of a second hand-rolled one) keyed with a CRYPTOGRAPHICALLY RANDOM,
    PER-RUN key:
      - Generated fresh every time this script runs
        (`[System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)`), never
        derived from anything about the document, the tenant, or a prior run.
      - NEVER written to disk, NEVER logged, NEVER embedded in the artifact itself, and
        held only in a local PowerShell variable for the lifetime of this script's process
        - it goes out of scope (and is garbage-collected) the moment the script exits. It
        is not the same key `Invoke-PulseAssessment -Redact`'s own operator key uses
        (`~/.tenantpulse/operator.key`) and is never written to that path or any other -
        this artifact is a one-off, throwaway scrub of an already-collected report copy,
        not a reversible-with-the-right-key pseudonym a downstream consumer is meant to
        correlate against a live tenant, so there is no reason for its key to outlive the
        process that used it.
      - Consequence, STATED DELIBERATELY: pseudonyms in THIS committed artifact are
        internally consistent (same raw value -> same pseudonym, EVERYWHERE within a single
        run of this script, so the artifact stays diffable/verifiable - the same device
        still recurs under the same token everywhere it appears in one file) but are NOT
        stable across separate runs of this script, and are NOT correlatable with any
        pseudonym `Invoke-PulseAssessment -Redact` itself produced for the same tenant
        (that uses the persistent operator key; this uses a discarded one). Regenerating
        this artifact from a fresh live run and re-scrubbing it produces a DIFFERENT set of
        pseudonym tokens for the same underlying values - this is intentional, not a defect:
        cross-run linkability is exactly the property an offline dictionary attack against a
        low-entropy input space would need, and this design denies it by construction (there
        is no persisted key anywhere for an attacker to find, and a fresh key each run means
        even the SAME device name pseudonymizes to a DIFFERENT token next time).

    MANUAL-REVIEW CARVE-OUT REMOVED (merge-review remediation): the first version of this
    script scrubbed ONLY `evidence[].detail` and left every other field (`reason`, `title`,
    `consulting`, `references`, `origin`, ...) untouched on the strength of "checked by hand
    across this run's 28 findings, found nothing" - a one-time human assurance, not a
    mechanical guarantee, and exactly the kind of carve-out this whole remediation exists to
    close. This script now also WALKS the entire document (every field) and ASSERTS, on
    every run, that no string matches a leak-shaped pattern (possessive-name-shaped text, a
    dash-formatted GUID, an email address) - see Assert-PulseArtifactNoLeakedFreeText below
    - with ONE exception, not a human-judgment one: `consulting`/`references`/`origin` are
    excluded from this walk because they are STRUCTURALLY incapable of carrying live-tenant
    data - they are sourced from the check-descriptor .psd1 catalog files at catalog-LOAD
    time, not from any Graph read, so they are byte-identical regardless of which tenant was
    assessed. This was proven empirically, not assumed: an earlier, unscoped version of this
    assertion threw on real catalog prose ("Security Defaults is Microsoft's free,
    all-or-nothing baseline identity policy" - TP.ENT.0001's own `consulting.whatItMeans`),
    which is legitimate authored text, not a leak - this repo's own remediation/consulting
    text is full of similar possessive proper nouns (Microsoft's, CIS's, ScuBA's, Entra's).
    `reason`/`title`/`category`/`severity`/`status`/`effort`/`impact`/`coverage`/`scores`/
    `notices`/`producer`/`schemaVersion`/`tenant` ARE all walked now, mechanically, every
    run - this is deliberately an ASSERTION (throws and refuses to write the file if it
    fires), not a silent replacement, since pseudonymizing them would destroy the artifact's
    entire purpose (a human-readable transcription source for docs/STATUS.md - see this
    repo's own docs/gates/README.md). The mechanical check now stands in permanently for
    what used to be a one-time manual read of `reason` specifically - if a future live run's
    `reason` text ever DOES interpolate a raw tenant value (a check-authoring bug, not
    something this script should paper over), this script fails loudly instead of silently
    shipping it.

    PSEUDONYM SCHEME: `tp-<HMAC-SHA256 hex, keyed with the ephemeral per-run key above>` -
    see the WEAK-HASH BUG section above for why this replaced a plain unsalted SHA-256.

    USAGE:
        pwsh -File scripts/Protect-PulseGateArtifact.ps1 -Path docs/gates/phase4-ivy24-findings.redacted.json

    Rewrites the file in place. NOT idempotent across separate invocations by design (see
    the ephemeral-key consequence above: re-running this script on an already-scrubbed file
    re-hashes every existing `tp-...` token under a FRESH random key, producing a different
    but equally safe set of tokens) - safe to re-run any number of times, just don't expect
    byte-identical output between runs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'

# Reuses the repo's own already-reviewed HMAC-SHA256 pseudonym construction rather than
# hand-rolling a second one - see this file's own WEAK-HASH BUG docstring section. Dot-
# sourced directly (this is a standalone maintenance script, not part of the built module,
# and Get-PulsePseudonym.ps1 is self-contained - no other module dependencies) rather than
# importing the whole module, so this script has no build-output dependency.
. (Join-Path $PSScriptRoot '../source/Private/Identity/Get-PulsePseudonym.ps1')

# Cryptographically random, per-run, NEVER-persisted key - see this file's own WEAK-HASH BUG
# docstring section for the full rationale (why HMAC over plain hash, why ephemeral over
# persisted, what "cross-run linkability is intentionally lost" means in practice).
$script:EphemeralArtifactKey = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)

function ConvertTo-PulseArtifactPseudonym {
    param([string] $Value)

    # Empty-string special case: Get-PulsePseudonym declares -Value as Mandatory, and
    # PowerShell's own mandatory-parameter binding rejects an empty [string] outright
    # (distinct from $null, which a mandatory [string] parameter would also reject, but
    # AllowNull()/string-typed params here mean an empty string is the actual shape a
    # real live finding can carry, e.g. a Graph field returned as ""). Rather than loosen
    # Get-PulsePseudonym's own contract (a shared, already-reviewed primitive other
    # callers rely on) to accommodate this one script's edge case, the identical HMAC
    # construction is applied directly here for empty input only - same key, same
    # algorithm, same "tp-<hex>" output shape, just not routed through a function whose
    # signature does not accept it.
    if ([string]::IsNullOrEmpty($Value)) {
        $hmac = [System.Security.Cryptography.HMACSHA256]::new($script:EphemeralArtifactKey)
        try {
            $hashBytes = $hmac.ComputeHash([byte[]] @())
        } finally {
            $hmac.Dispose()
        }
        return "tp-$([System.Convert]::ToHexString($hashBytes).ToLowerInvariant())"
    }

    return Get-PulsePseudonym -Value $Value -Key $script:EphemeralArtifactKey
}

# Recursively scrubs every [string] leaf found anywhere inside $Node (object, array, or
# scalar) - deliberately shape-agnostic (no per-field-name special-casing) so a `detail`
# shape this script's author never anticipated is scrubbed exactly as thoroughly as one that
# was. Numbers/booleans/$null pass through unchanged; nested objects/arrays are walked, not
# skipped.
function Protect-PulseDetailValue {
    param([Parameter(Mandatory)][AllowNull()] $Node)

    if ($null -eq $Node) { return $null }

    if ($Node -is [string]) {
        return ConvertTo-PulseArtifactPseudonym -Value $Node
    }

    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        return @(foreach ($item in $Node) { Protect-PulseDetailValue -Node $item })
    }

    if ($Node -is [pscustomobject]) {
        $result = [ordered]@{}
        foreach ($prop in $Node.PSObject.Properties) {
            $result[$prop.Name] = Protect-PulseDetailValue -Node $prop.Value
        }
        return [pscustomobject] $result
    }

    # Numbers, booleans, and anything else pass through unchanged.
    return $Node
}

# Property names this assertion does NOT recurse into, at any depth - see this file's own
# STATIC-CONTENT EXCLUSION docstring section. Every one of these is check-DESCRIPTOR
# content, sourced from the .psd1 catalog files at catalog-LOAD time, not from a live Graph
# read - identical byte-for-byte regardless of which tenant was assessed or when. Proven
# empirically, not assumed: a first cut of this assertion (with no exclusions) threw on
# real, harmless catalog prose like "Security Defaults is Microsoft's free, all-or-nothing
# baseline identity policy" (TP.ENT.0001's own consulting.whatItMeans) - "Microsoft's" is a
# legitimate possessive proper noun, not a leak, and this repo's authored text is full of
# them (CIS's, ScuBA's, Entra's, GraphKit's, ...). Excluding these subtrees is NOT the
# "manually-reviewed-only carve-out" this whole fix removes - that carve-out relied on a
# human having read 28 findings once; this exclusion relies on WHERE the data comes from
# structurally (the catalog files, never a live tenant read), which cannot change from run
# to run the way a human's one-time read could go stale.
$script:PulseArtifactStaticContentProperties = [System.Collections.Generic.HashSet[string]]::new(
    [string[]] @('consulting', 'references', 'origin'),
    [System.StringComparer]::OrdinalIgnoreCase
)

# BY-VALUE allowlist of known organization/product proper nouns this catalog's OWN
# authored text legitimately uses possessively, even in a dynamic field like `reason`
# (e.g. TP.ENT.0005's real reason text: "All 9 of Microsoft's minimum admin roles are
# covered..." - "Microsoft's" is baked into the check's own Reason-building code, not
# tenant-derived, and appears even though `reason` itself is walked - unlike `consulting`/
# `references`/`origin`, `reason` genuinely can carry live-tenant-derived text too, so it
# cannot be excluded wholesale the way those structurally-static fields are). Seeded the
# same way tests/QA/SecretScan.tests.ps1's own `denyListedDomains` allowlist was: by
# actually running the unscoped check against a real live-run artifact and recording every
# genuine false positive it produced - not a guess at what might appear. A name NOT on
# this list still fails the assertion, so this narrows false positives without widening
# what counts as a genuine leak.
$script:PulseArtifactKnownSafePossessiveNames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]] @(
        'Microsoft', 'CIS', 'CISA', 'ScuBA', 'Entra', 'GraphKit', 'TenantPulse', 'Maester',
        'Azure', 'PowerShell', 'Windows', 'EIDSCA'
    ),
    [System.StringComparer]::Ordinal
)

# Recursively walks EVERY string leaf anywhere in $Node (the whole document, or any
# sub-tree of it) EXCEPT the static-catalog-content subtrees named above, and throws the
# first time one matches a leak-shaped pattern. Replaces the "checked by hand" carve-out
# the first version of this script relied on for everything outside evidence[].detail -
# see this file's own MANUAL-REVIEW CARVE-OUT REMOVED docstring section: `reason`, `title`,
# `category`, `severity`, `status`, `effort`, `impact`, `coverage`, `scores`, `notices`,
# `producer`, `schemaVersion`, and `tenant` are all mechanically walked now, every run, not
# assumed safe from a one-time read. Deliberately NARROW patterns (mirroring
# tests/QA/SecretScan.tests.ps1's own items 1 and 8) rather than a blanket "flag every
# capitalized word" scan - the goal is a mechanical backstop for the SAME leak class this
# whole remediation is about, not a general-purpose PII classifier.
function Assert-PulseArtifactNoLeakedFreeText {
    param(
        [Parameter(Mandatory)][AllowNull()] $Node,
        [Parameter(Mandatory)][string] $PathLabel
    )

    if ($null -eq $Node) { return }

    if ($Node -is [string]) {
        # Possessive-name-shaped text - "<Name>'s <thing>", straight or curly apostrophe -
        # the exact shape that leaked from evidence[].detail originally. Outside `detail`
        # (and outside the static-content subtrees excluded above) this text is
        # TenantPulse's own authored prose, which never legitimately takes this shape
        # (check titles/reason text are written in third person, not as "someone's
        # device").
        #
        # -cmatch, NOT -match (found and fixed empirically during this same round):
        # PowerShell's -match operator is CASE-INSENSITIVE by default, so `[A-Z]` in an
        # -match pattern does NOT actually require an uppercase letter - it matches any
        # letter, upper or lower. That silently turned "capitalized proper noun" into "any
        # word", and a real live finding's reason text ("...the tenant's primary
        # access-control layer...") tripped this assertion on the entirely ordinary,
        # lowercase word "tenant's" - not a leak, a false positive from operator choice,
        # not pattern design. Case-sensitive matching (.NET regex's default; PowerShell's
        # own -match/-cmatch distinction does not apply to [regex]::Matches) means `[A-Z]`
        # means what it says here.
        #
        # Every match's captured name is checked against the by-value organization-name
        # allowlist above BEFORE throwing - a real live run's `reason` text legitimately
        # says things like "All 9 of Microsoft's minimum admin roles..." (TP.ENT.0005's own
        # Reason-building code, not tenant-derived), so a bare "did this pattern match at
        # all" boolean check is too broad for a field (unlike `consulting`/`references`/
        # `origin`) that genuinely CAN carry live-tenant text too and therefore cannot be
        # excluded wholesale.
        foreach ($nameMatch in [regex]::Matches($Node, "([A-Z][a-zA-Z]+)['\x27’]s\b")) {
            $capturedName = $nameMatch.Groups[1].Value
            if (-not $script:PulseArtifactKnownSafePossessiveNames.Contains($capturedName)) {
                throw "Assert-PulseArtifactNoLeakedFreeText: possessive-name-shaped text ($capturedName's) found outside evidence[].detail at '$PathLabel' - refusing to write the artifact. This field is supposed to be TenantPulse's own authored content, never tenant-derived free text; if a check's Reason-building logic now interpolates a raw value, fix it at the source rather than scrubbing this artifact around it. If '$capturedName' is a legitimate organization/product name TenantPulse's own text uses possessively, add it to `$script:PulseArtifactKnownSafePossessiveNames` above."
            }
        }
        # A dash-formatted GUID anywhere outside detail - every legitimate GUID-shaped
        # value in this document already lives inside evidence[].detail (already fully
        # pseudonymized above); one outside it is unexpected and worth failing loudly on.
        if ($Node -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') {
            throw "Assert-PulseArtifactNoLeakedFreeText: GUID-shaped text found outside evidence[].detail at '$PathLabel' - refusing to write the artifact."
        }
        # An email address anywhere outside detail.
        if ($Node -match '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}') {
            throw "Assert-PulseArtifactNoLeakedFreeText: email-shaped text found outside evidence[].detail at '$PathLabel' - refusing to write the artifact."
        }
        return
    }

    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        $i = 0
        foreach ($item in $Node) {
            Assert-PulseArtifactNoLeakedFreeText -Node $item -PathLabel "$PathLabel[$i]"
            $i++
        }
        return
    }

    if ($Node -is [pscustomobject]) {
        foreach ($prop in $Node.PSObject.Properties) {
            if ($script:PulseArtifactStaticContentProperties.Contains($prop.Name)) {
                continue
            }
            Assert-PulseArtifactNoLeakedFreeText -Node $prop.Value -PathLabel "$PathLabel.$($prop.Name)"
        }
    }
}

# -DateKind String (remediation round 2 fix - see this file's own DATE-COERCION BUG
# docstring section): without this, ConvertFrom-Json silently coerces any ISO-8601-looking
# string (e.g. approximateLastSignInDateTime) into a [datetime], which the -is [string]
# check in Protect-PulseDetailValue below then never sees - the exact gap that let ~70
# raw timestamps survive an earlier version of this scrub untouched.
$resolvedPath = (Resolve-Path -LiteralPath $Path).ProviderPath
$document = Get-Content -LiteralPath $resolvedPath -Raw | ConvertFrom-Json -Depth 64 -DateKind String

$scrubbedDetailCount = 0
foreach ($finding in @($document.findings)) {
    foreach ($item in @($finding.evidence)) {
        if ($null -ne $item.detail) {
            $item.detail = Protect-PulseDetailValue -Node $item.detail
            $scrubbedDetailCount++
        }
    }
}

# Whole-document mechanical assertion - see MANUAL-REVIEW CARVE-OUT REMOVED above. Runs
# AFTER the detail scrub, over the WHOLE document (including the now-scrubbed detail
# objects, harmlessly - a tp-<hex> token never matches any of the leak patterns), so this
# is a genuine belt-and-braces pass, not a redundant no-op.
Assert-PulseArtifactNoLeakedFreeText -Node $document -PathLabel '$document'

# ConvertTo-Json's default depth (2) silently truncates a nested document this deep -
# matches this repo's own convention (ConvertTo-PulseCanonicalJson, Export-PulseReport) of
# always passing an explicit -Depth well above anything this schema nests.
$document | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $resolvedPath -NoNewline

Write-Host "Protect-PulseGateArtifact: scrubbed $scrubbedDetailCount evidence detail object(s) in '$resolvedPath' (HMAC-SHA256, ephemeral per-run key, discarded on exit); whole-document leak-pattern assertion passed."
