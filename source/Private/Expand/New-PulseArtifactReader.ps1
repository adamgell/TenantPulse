<#
    Private: builds the READ-ONLY artifact accessor a Function rule receives as
    $Context.ArtifactReader (Task 3.1 review-fix round - replaces the original design's raw
    $Context.Store handoff, which a reviewer correctly rejected as too broad: a live $Store
    pscustomobject exposes every property/path the whole snapshot-store surface has, handing
    a rule far more reach than "read the conflicts artifact" ever needed).

    NO STORE HANDLE, NO SETTABLE PROPERTIES: the object this function returns carries
    exactly two members, ScriptMethods GetConflictArtifact() and (Part A, T3.4 addition)
    GetSettingPresenceIndex() - no NoteProperty a caller could reassign, no reference back
    to the live $Store object a caller could reach through. -Store's Root/ManifestPath are
    read ONCE here, into ordinary local [string] variables (`$frozenRoot`/`$frozenManifestPath`)
    that the returned methods close over via GetNewClosure() - .NET strings are themselves
    immutable, so once captured there is no operation a rule (or anything downstream) can
    perform on those two local copies that would reach back into, or change, the real
    $Store object or any later check's view of it. Each method body reconstructs only the
    minimal {Root;ManifestPath} shape Get-PulseConflictArtifact/Get-PulseSettingPresenceIndex/
    Get-PulseSnapshotManifest actually read, from those frozen copies - never from the
    original -Store parameter, which is not captured by either closure at all.

    FUNCTION-RULE-ONLY, BY CONSTRUCTION OF WHO CALLS THIS: only
    Invoke-PulseCheckEvaluation's Function-rule branch ever builds one of these (see that
    function's own docstring for why the Expression-sandbox path never receives one at
    all, even via $Context - it is stripped before the sandboxed runspace's Context clone
    is built). A rule function that receives $Context.ArtifactReader may only ever call the
    read operations exposed here - there is no write path, no arbitrary-path read, no way
    to reach the manifest.datasets tree or any other file under the store root this object
    does not explicitly expose a method for. GROWING THIS SURFACE (Part A, T3.4, is the
    second artifact type this docstring's own original wording anticipated - "a second
    artifact type, say") means adding a second named ScriptMethod here, deliberately, not
    widening what the existing one can reach - GetSettingPresenceIndex() below is built the
    identical way GetConflictArtifact() already was: its own frozen closure, its own
    already-resolved CommandInfo, no new surface shared between the two methods beyond the
    same two frozen strings both were already closing over.
#>

function New-PulseArtifactReader {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store
    )

    # FROZEN COPIES - plain [string] locals, captured by value (strings are immutable in
    # .NET), never the live $Store object itself. See this file's own top-level docstring.
    $frozenRoot = [string] $Store.Root
    $frozenManifestPath = [string] $Store.ManifestPath

    # Resolved to a CommandInfo HERE, inside the module's own scope, rather than calling
    # 'Get-PulseConflictArtifact' by bare name from inside the closure below: a
    # ScriptMethod's body executes in the CALLER's scope (a rule function's scope, not
    # this module's), and .GetNewClosure() only captures VARIABLES, not command
    # resolution - a bare name lookup from inside the closure at invocation time cannot
    # find this module's own private (unexported) function. Capturing the already-resolved
    # CommandInfo now and invoking it via `& $conflictArtifactCommand` below sidesteps that
    # entirely, since `&` on a CommandInfo runs it in ITS OWN bound module context
    # regardless of where the closure is later invoked from.
    $conflictArtifactCommand = Get-Command -Name 'Get-PulseConflictArtifact'
    # Part A, T3.4 addition - resolved here for the identical reason
    # $conflictArtifactCommand is: a bare name lookup from inside a ScriptMethod closure
    # cannot find this module's own private function at the caller's (rule's) scope.
    $settingPresenceIndexCommand = Get-Command -Name 'Get-PulseSettingPresenceIndex'

    $getConflictArtifact = {
        # Reconstructed from the FROZEN strings captured at New-PulseArtifactReader
        # construction time - never a reference to the original, live $Store this reader
        # was built from. Get-PulseConflictArtifact/Get-PulseSnapshotManifest only ever
        # read .Root/.ManifestPath, so this minimal shape is sufficient and nothing more
        # of the real store surface is reachable through it.
        $frozenStoreShape = [pscustomobject]@{ Root = $frozenRoot; ManifestPath = $frozenManifestPath }
        return & $conflictArtifactCommand -Store $frozenStoreShape
    }.GetNewClosure()

    $getSettingPresenceIndex = {
        # Same frozen-shape reconstruction as $getConflictArtifact above -
        # Get-PulseSettingPresenceIndex/Get-PulseSnapshotManifest only ever read
        # .Root/.ManifestPath too.
        $frozenStoreShape = [pscustomobject]@{ Root = $frozenRoot; ManifestPath = $frozenManifestPath }
        return & $settingPresenceIndexCommand -Store $frozenStoreShape
    }.GetNewClosure()

    $reader = [pscustomobject]@{ PSTypeName = 'TenantPulse.ArtifactReader' }
    Add-Member -InputObject $reader -MemberType ScriptMethod -Name 'GetConflictArtifact' -Value $getConflictArtifact
    Add-Member -InputObject $reader -MemberType ScriptMethod -Name 'GetSettingPresenceIndex' -Value $getSettingPresenceIndex

    return $reader
}
