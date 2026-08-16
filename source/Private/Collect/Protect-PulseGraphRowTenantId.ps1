<#
    Private: redact the raw tenant GUID out of Graph row CONTENT before it is written to a
    dataset file.

    GraphKit 0.1.1 migration live gate (Ivy24 lab tenant, Task 1.11) surprise: two of the
    six newly-live datasets carry the raw tenant id as part of their actual PAYLOAD, not
    merely as a GraphKit provenance stamp (Remove-PulseGraphRowProvenance already strips
    those) - Organization.id IS the tenant GUID by definition, and every
    DirectoryRoleAssignment row's principalOrganizationId is also the tenant GUID. Neither
    is a provenance stamp GraphKit added; both are genuine Graph API response fields whose
    VALUE happens to equal the tenant identifier for this tenant. Every dataset collected
    before this task only ever returned object/device/policy ids, never the tenant's own
    id, so this class of leak had no prior datasets.json to appear in.

    Applied at the same collector call sites that already have both a raw $TenantId and the
    run's $Pseudonym in scope (mirroring Protect-PulseReason, which redacts the same pair
    out of reason strings) - immediately before Write-PulseDataset for a Collected outcome,
    so every dataset file this module writes from here forward is covered, not just the two
    that surfaced the gap.

    Walks EVERY string value in the row tree - not just a fixed list of known-risky
    property names - and replaces an exact case-insensitive match of -TenantId with
    -Pseudonym. A fixed-field-name approach would need updating every time a new dataset
    happens to surface the tenant id under a different property name (there is no
    Graph-wide guarantee it will always be called principalOrganizationId or id); a
    value-based scan catches it regardless of which field carries it, including inside a
    nested object or an array element. Recurses into nested PSCustomObject/Hashtable
    property values and every element of an array/collection value; leaves every
    non-string, non-container value (numbers, booleans, $null, DateTime) untouched.

    DELIBERATELY NOT in-place, unlike Remove-PulseGraphRowProvenance: this function returns
    brand-new cloned row objects rather than mutating -Data's own elements. Invoke-PulseCollection
    keeps a reference to the SAME row objects it passes to Write-PulseDataset in
    $collectedRows, for a later IdFromDataset entry to read a dependency's `id` off of - and
    for the organization dataset specifically, `id` IS the raw tenant GUID this function
    exists to redact. Remove-PulseGraphRowProvenance's own docstring is explicit that its
    in-place mutation is safe only because the four stamp names it strips are never `id`;
    that safety argument does not hold here, so this function clones instead of mutating,
    and Write-PulseDataset (its only caller) uses the clone for serialization only, leaving
    the original row objects - and therefore $collectedRows - carrying the real, unredacted
    id a dependent Graph call actually needs.

    -MaxDepth (post-live-gate-review hardening; default 64, matching
    ConvertTo-PulseCanonicalJson's own -Depth default): every recursive descent checks
    -CurrentDepth against -MaxDepth BEFORE doing any work, and throws immediately - never
    just "eventually" via a native call-depth overflow - once the budget is exhausted. This
    is what actually closes the bug class the Hashtable/SyncRoot self-reference fix (see
    the IDictionary branch below) exposed: a Hashtable was ONE concrete cycle GraphKit's
    real responses happen to produce, but the underlying risk is any cyclic or
    pathologically deep in-memory structure reaching this function, GraphKit-shaped or
    not - a native PowerShell call-depth overflow is slow (each frame costs real CPU before
    the CLR gives up) and, more importantly, was being SWALLOWED by the old catch-and-
    fall-back-to-unredacted behavior (see FAIL CLOSED below), silently shipping whatever
    the cycle happened to reach before overflowing. An explicit, cheap, first-thing-in-the-
    function depth check turns an eventual slow crash into an immediate, named, catchable
    error. -CurrentDepth starts at 1, not 0, for each row passed to the internal walker -
    accounting for the root array level ConvertTo-PulseCanonicalJson's own -Depth budget
    counts (Write-PulseDataset serializes the WHOLE redacted array as one document, and
    that array is depth 0 in the serializer's own accounting; each row inside it is
    already one level in), so a row that would trip the canonical serializer's own depth
    gate on write is refused here first, at redaction time, with a clearer, redaction-
    specific error rather than surfacing only much later as a serialization failure.

    FAIL CLOSED (post-live-gate-review hardening - this replaces this function's own prior
    behavior, and is the important correction): a traversal error of ANY kind - a depth-
    budget exhaustion, or literally any other exception the recursive walk could raise -
    now PROPAGATES OUT of this function instead of being caught here and silently
    downgraded to "return the original, UNREDACTED row". That prior behavior was a
    fail-OPEN on this function's entire reason for existing: a row this function cannot
    prove it redacted was, before this fix, written to disk anyway, unredacted, with only a
    Write-Verbose line (which most operators never see) marking the failure. A caller that
    cannot confirm redaction succeeded must not silently ship the unredacted alternative -
    it must fail loudly instead. Invoke-PulseCollection's per-dataset try/catch (the same
    one wrapping Get-GraphObject) already exists to turn exactly this kind of exception
    into a Failed dataset with a redacted reason and NO dataset file written (Write-
    PulseDataset never reaches its own file-write step - the throw happens during
    redaction, before serialization starts) - this function now uses that existing
    machinery instead of quietly defeating it.
#>

function Protect-PulseGraphRowTenantId {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Data,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $TenantId,

        [Parameter(Mandatory)]
        [string] $Pseudonym,

        # Matches ConvertTo-PulseCanonicalJson's own -Depth default (see this function's
        # own docstring for why 64, and why -CurrentDepth below starts at 1 rather than 0).
        [ValidateRange(1, [int]::MaxValue)]
        [int] $MaxDepth = 64
    )

    if ([string]::IsNullOrEmpty($TenantId)) {
        return , $Data
    }

    # Builds a NEW value tree (never mutates -Value in place) with every exact,
    # case-insensitive occurrence of $TenantId inside a string value replaced by
    # $Pseudonym. Non-string, non-container values (numbers, booleans, DateTime, $null)
    # are returned as-is - the same reference is fine there since they are immutable/
    # value-shaped in PowerShell.
    #
    # -CurrentDepth/-MaxDepth: checked FIRST, before any other work at this level -
    # including before dereferencing $Value's members - so a cyclic or pathologically deep
    # structure is refused quickly (one cheap integer comparison per level) rather than
    # walked until a native call-depth overflow eventually (and slowly) stops it. The
    # thrown message names the exhausted depth, per this function's own docstring.
    function Protect-PulseGraphValue {
        param($Value, [string] $TenantId, [string] $Pseudonym, [int] $CurrentDepth, [int] $MaxDepth)

        if ($CurrentDepth -gt $MaxDepth) {
            throw "Protect-PulseGraphRowTenantId: row content exceeds the maximum redaction depth of $MaxDepth (reached depth $CurrentDepth) - refusing to continue, which would otherwise risk an unbounded or cyclic traversal."
        }

        if ($null -eq $Value) { return $Value }

        if ($Value -is [string]) {
            if ($Value.IndexOf($TenantId, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return [regex]::Replace($Value, [regex]::Escape($TenantId), { param($m) $Pseudonym }, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            return $Value
        }

        # IDictionary (Hashtable/OrderedHashtable - GraphKit returns several nested Graph
        # properties this way, e.g. a ConditionalAccessPolicy's conditions/grantControls)
        # MUST be checked, and walked via its own dictionary entries, BEFORE the generic
        # PSObject branch below - never via .PSObject.Properties. A Hashtable's
        # .PSObject.Properties surfaces its ADAPTER members (Keys, Values, Count,
        # IsReadOnly, IsFixedSize, IsSynchronized, SyncRoot, ...), not its dictionary
        # entries - and a non-synchronized Hashtable's own SyncRoot property returns the
        # SAME hashtable instance. Walking .PSObject.Properties on a Hashtable therefore
        # recurses into itself via SyncRoot (reproduced live against Ivy24 - see this
        # function's own docstring and the regression tests in Snapshot.Tests.ps1); the
        # -MaxDepth guard above is this function's general-purpose backstop against that
        # WHOLE class of self-reference, GraphKit-shaped or not, but walking dictionary
        # entries correctly here means a real Graph row never gets anywhere near it.
        if ($Value -is [System.Collections.IDictionary]) {
            $clone = [ordered] @{}
            foreach ($key in @($Value.Keys)) {
                $clone[$key] = Protect-PulseGraphValue -Value $Value[$key] -TenantId $TenantId -Pseudonym $Pseudonym -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
            }
            return $clone
        }

        if ($Value -is [System.Management.Automation.PSObject]) {
            $clone = [pscustomobject]@{}
            foreach ($property in @($Value.PSObject.Properties)) {
                $redactedValue = Protect-PulseGraphValue -Value $property.Value -TenantId $TenantId -Pseudonym $Pseudonym -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
                Add-Member -InputObject $clone -NotePropertyName $property.Name -NotePropertyValue $redactedValue
            }
            return $clone
        }

        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            $items = @($Value)
            $clonedItems = [object[]]::new($items.Count)
            for ($i = 0; $i -lt $items.Count; $i++) {
                $clonedItems[$i] = Protect-PulseGraphValue -Value $items[$i] -TenantId $TenantId -Pseudonym $Pseudonym -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
            }
            return , $clonedItems
        }

        return $Value
    }

    $clonedRows = [object[]]::new($Data.Count)
    for ($i = 0; $i -lt $Data.Count; $i++) {
        $row = $Data[$i]
        if ($null -eq $row -or $row -isnot [System.Management.Automation.PSObject]) {
            $clonedRows[$i] = $row
            continue
        }

        # FAIL CLOSED (see this function's own docstring): no try/catch here anymore. A
        # row this function cannot prove it redacted - whatever the reason - must not be
        # silently shipped unredacted; the exception propagates to Write-PulseDataset and
        # then to Invoke-PulseCollection's own per-dataset catch, which classifies the
        # WHOLE dataset Failed (with a redacted reason) and writes no dataset file at all,
        # rather than this function quietly downgrading one bad row to "unredacted but
        # present".
        $clonedRows[$i] = Protect-PulseGraphValue -Value $row -TenantId $TenantId -Pseudonym $Pseudonym -CurrentDepth 1 -MaxDepth $MaxDepth
    }

    return , $clonedRows
}
