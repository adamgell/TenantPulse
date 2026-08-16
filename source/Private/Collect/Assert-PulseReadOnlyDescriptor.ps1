<#
    Private: enforce the read-only predicate against a resolved GraphKit descriptor.

    TenantPulse is read-only by design (see the spec's global constraint) - it must never
    collect through a GraphKit descriptor capable of a write, and it must never collect
    through a descriptor whose replay semantics could mask a write-shaped side effect (a
    POST-shaped report export, for instance). The predicate is exactly:

        ThrottleClass -eq 'Read' -and ReplayPolicy -eq 'Safe'

    This same predicate, applied identically, backs two different enforcement points: this
    function is the RUNTIME assertion the collector (Invoke-PulseCollection) calls before
    ever attempting to read a dataset, and Task 1.10's STATIC gate walks every entry in
    DatasetMap.psd1 offline (no live tenant, no token) calling this same function so a
    read-only violation is caught at CI time, not discovered mid-collection against a real
    tenant. A violation of this predicate is always FATAL - it throws and aborts the whole
    collection run, because it is a module-authoring bug (a dataset map entry pointing at
    a write-shaped or unsafe-to-replay descriptor), never a per-dataset runtime outcome.

    Resolves the descriptor itself via GraphKit's Get-GraphOperation (metadata lookup
    only - this never makes a network call, so the static gate can call it with no Graph
    context at all) rather than accepting an already-resolved descriptor object, so both
    call sites share the exact same resolution path.

    -ApiVersion (optional): when supplied, also compares it against the resolved
    descriptor's own ApiVersion. Unlike the read-only predicate above, an ApiVersion
    mismatch is NOT fatal to the whole run - DatasetMap.psd1 simply drifted out of sync
    with a GraphKit release (an operational/configuration problem, not a read-only
    violation) - so this still throws (this function's contract is "assert or throw"), but
    the thrown message is prefixed 'descriptor-version-drift:' specifically so the
    collector's caller can distinguish it from the fatal read-only violation above and
    downgrade it to a per-dataset Failed outcome instead of aborting the run. See
    Invoke-PulseCollection's own catch around this call for that distinction.
#>

function Assert-PulseReadOnlyDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Type,

        [Parameter(Mandatory)]
        [string] $Operation,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ApiVersion
    )

    $descriptor = Get-GraphOperation -Type $Type -Operation $Operation -ErrorAction Stop

    if ($null -eq $descriptor) {
        throw "Assert-PulseReadOnlyDescriptor: no GraphKit operation descriptor was found for '$Type/$Operation'."
    }

    $throttleClass = [string] $descriptor.ThrottleClass
    $replayPolicy = [string] $descriptor.ReplayPolicy

    if ($throttleClass -ne 'Read' -or $replayPolicy -ne 'Safe') {
        throw "Assert-PulseReadOnlyDescriptor: '$Type/$Operation' is not a read-only descriptor (ThrottleClass='$throttleClass', ReplayPolicy='$replayPolicy'). TenantPulse only ever collects through descriptors where ThrottleClass is 'Read' and ReplayPolicy is 'Safe'."
    }

    if (-not [string]::IsNullOrEmpty($ApiVersion)) {
        $resolvedApiVersion = [string] $descriptor.ApiVersion
        if ($resolvedApiVersion -ne $ApiVersion) {
            throw "Assert-PulseReadOnlyDescriptor: descriptor-version-drift: DatasetMap.psd1 declares ApiVersion '$ApiVersion' for '$Type/$Operation' but the resolved GraphKit descriptor is '$resolvedApiVersion'. Update DatasetMap.psd1 to match."
        }
    }
}
