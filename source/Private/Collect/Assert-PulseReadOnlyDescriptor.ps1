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
    tenant.

    Resolves the descriptor itself via GraphKit's Get-GraphOperation (metadata lookup
    only - this never makes a network call, so the static gate can call it with no Graph
    context at all) rather than accepting an already-resolved descriptor object, so both
    call sites share the exact same resolution path.
#>

function Assert-PulseReadOnlyDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Type,

        [Parameter(Mandatory)]
        [string] $Operation
    )

    $descriptor = Get-GraphOperation -Type $Type -Operation $Operation

    if ($null -eq $descriptor) {
        throw "Assert-PulseReadOnlyDescriptor: no GraphKit operation descriptor was found for '$Type/$Operation'."
    }

    $throttleClass = [string] $descriptor.ThrottleClass
    $replayPolicy = [string] $descriptor.ReplayPolicy

    if ($throttleClass -ne 'Read' -or $replayPolicy -ne 'Safe') {
        throw "Assert-PulseReadOnlyDescriptor: '$Type/$Operation' is not a read-only descriptor (ThrottleClass='$throttleClass', ReplayPolicy='$replayPolicy'). TenantPulse only ever collects through descriptors where ThrottleClass is 'Read' and ReplayPolicy is 'Safe'."
    }
}
