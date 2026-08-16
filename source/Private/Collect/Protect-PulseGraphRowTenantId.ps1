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

    TOTAL by construction, exactly like the collector's other per-dataset helpers: a $null
    or empty -TenantId (the pre-context total-failure path, or any caller that has no
    tenant id to redact) returns -Data completely unchanged (no cloning at all - nothing to
    redact means nothing to protect against downstream mutation either), never a throw, and
    a malformed/unexpected row shape is walked defensively (AllowNull row elements
    tolerated, exactly like Remove-PulseGraphRowProvenance) rather than aborting collection
    over a single odd row.
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
        [string] $Pseudonym
    )

    if ([string]::IsNullOrEmpty($TenantId)) {
        return , $Data
    }

    # Builds a NEW value tree (never mutates -Value in place) with every exact,
    # case-insensitive occurrence of $TenantId inside a string value replaced by
    # $Pseudonym. Non-string, non-container values (numbers, booleans, DateTime, $null)
    # are returned as-is - the same reference is fine there since they are immutable/
    # value-shaped in PowerShell.
    function Protect-PulseGraphValue {
        param($Value, [string] $TenantId, [string] $Pseudonym)

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
        # recurses into itself via SyncRoot and blows PowerShell's call depth on every real
        # Graph row that has one (reproduced live against Ivy24 - see this function's own
        # docstring and the regression test in Snapshot.Tests.ps1).
        if ($Value -is [System.Collections.IDictionary]) {
            $clone = [ordered] @{}
            foreach ($key in @($Value.Keys)) {
                $clone[$key] = Protect-PulseGraphValue -Value $Value[$key] -TenantId $TenantId -Pseudonym $Pseudonym
            }
            return $clone
        }

        if ($Value -is [System.Management.Automation.PSObject]) {
            $clone = [pscustomobject]@{}
            foreach ($property in @($Value.PSObject.Properties)) {
                $redactedValue = Protect-PulseGraphValue -Value $property.Value -TenantId $TenantId -Pseudonym $Pseudonym
                Add-Member -InputObject $clone -NotePropertyName $property.Name -NotePropertyValue $redactedValue
            }
            return $clone
        }

        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            $items = @($Value)
            $clonedItems = [object[]]::new($items.Count)
            for ($i = 0; $i -lt $items.Count; $i++) {
                $clonedItems[$i] = Protect-PulseGraphValue -Value $items[$i] -TenantId $TenantId -Pseudonym $Pseudonym
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

        try {
            $clonedRows[$i] = Protect-PulseGraphValue -Value $row -TenantId $TenantId -Pseudonym $Pseudonym
        } catch {
            # Total: a single unreadable/unclonable row must never abort collection - fall
            # back to the original row (unredacted, but at least present) rather than
            # propagate or silently drop it.
            Write-Verbose "Protect-PulseGraphRowTenantId: could not redact row $($i): $($_.Exception.Message)"
            $clonedRows[$i] = $row
        }
    }

    return , $clonedRows
}
