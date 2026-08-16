<#
    Private: recover the real HTTP status code for a Get-GraphObject failure the collector
    just caught.

    THE SURPRISE (Task 1.11 live gate, confirmed against the Ivy24 lab tenant): GraphKit
    0.1.0's Get-GraphObject discards the status code on failure. Its own final step throws
    a fixed-shape message - "Get-GraphObject failed for '<Type>/<Operation>': Outcome
    '<Outcome>', Certainty '<Certainty>'." - built from nothing but the two enum values,
    with no Response/StatusCode property on the exception and no '403'/'forbidden' text in
    the message. Get-PulseFailureClass's structured-property and message-text signals were
    both written against an assumed shape (unit tests mocked "403 Forbidden" into the
    thrown message); the real Get-GraphObject throw carries neither, so every 403 a live
    tenant returns falls through Get-PulseFailureClass to the generic 'Failed' branch
    instead of 'PermissionDenied' - a real ConditionalAccessPolicy/List 403 against Ivy24
    (no Policy.Read.All grant on the lab app) landed as dataset status Failed, not the
    Skipped-with-permission-reason honest-degradation contract the design promises.

    GraphKit DOES still know the status code - it just never puts it in what
    Get-GraphObject throws. Invoke-GraphOperation (also a GraphKit command; still "read
    exclusively through GraphKit's read-class descriptors", never Connect-MgGraph or a raw
    URI) resolves the SAME descriptor and returns the full GraphKit.OperationResult
    envelope WITHOUT throwing on a non-Succeeded outcome, and its .Telemetry is an ordered
    list of one record per HTTP attempt, each carrying its own .StatusCode. This function
    re-issues that same read (same Type/Operation/Parameters/Context Get-GraphObject just
    attempted) through Invoke-GraphOperation, purely to recover the status code its sibling
    call already discarded, and returns the LAST attempt's StatusCode - the one the retry
    loop actually stopped on. It never returns rows and its result is used for
    classification only.

    Called ONLY from the collector's catch block, i.e. only after a read has already
    failed - so this adds one extra read-only Graph call per failed dataset, never per
    successful one. All descriptors Assert-PulseReadOnlyDescriptor accepts are List/Get
    reads, so a same-shaped repeat call is idempotent and side-effect-free.

    TOTAL by construction, exactly like Get-PulseFailureClass: this function must never
    itself throw. A malformed Telemetry shape, a second failure from the supplemental
    call, or Invoke-GraphOperation not being available must all fall back to $null (no
    signal recovered) rather than take down dataset classification.
#>

function Get-PulseGraphFailureStatusCode {
    [CmdletBinding()]
    [OutputType([System.Nullable[int]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Context,

        [Parameter(Mandatory)]
        [string] $Type,

        [Parameter(Mandatory)]
        [string] $Operation,

        [Parameter()]
        [hashtable] $Parameters
    )

    try {
        $invokeParams = @{
            Context     = $Context
            Type        = $Type
            Operation   = $Operation
            ErrorAction = 'Stop'
        }
        if ($null -ne $Parameters -and $Parameters.Count -gt 0) {
            $invokeParams.Parameters = $Parameters
        }

        $result = Invoke-GraphOperation @invokeParams

        if ($null -eq $result) { return $null }

        $telemetryProperty = $result.PSObject.Properties['Telemetry']
        if ($null -eq $telemetryProperty -or $null -eq $telemetryProperty.Value) { return $null }

        $attempts = @($telemetryProperty.Value)
        if ($attempts.Count -eq 0) { return $null }

        $lastAttempt = $attempts[$attempts.Count - 1]
        $statusProperty = $lastAttempt.PSObject.Properties['StatusCode']
        if ($null -eq $statusProperty -or $null -eq $statusProperty.Value) { return $null }

        $statusValue = $statusProperty.Value

        # Enum-typed StatusCode (post-review fix, e.g. [System.Net.HttpStatusCode]::Forbidden)
        # must be cast to [int] directly - [string] on an enum value renders its NAME
        # ('Forbidden'), not its underlying numeric value ('403'), so the TryParse below
        # would simply fail and this function would silently recover no signal at all.
        if ($statusValue -is [System.Enum]) { return [int] $statusValue }

        $parsed = 0
        if ([int]::TryParse([string] $statusValue, [ref] $parsed)) {
            return $parsed
        }

        return $null
    } catch {
        # Total: recovering a classification signal must never itself become a second,
        # unhandled failure - the caller falls back to whatever Get-PulseFailureClass can
        # still infer from the original ErrorRecord. Write-Warning (post-review fix, not
        # Write-Verbose only): a supplemental recovery failure is an operationally
        # interesting event - it means the collector's status classification for this
        # dataset is running on a WEAKER signal than usual - and Write-Verbose is silent by
        # default in every normal run, which buried this from an operator who never passes
        # -Verbose. Write-Warning surfaces by default; the caller (Invoke-PulseCollection)
        # also appends '(status unknown)' to the dataset's own Failed reason for the same
        # reason - visible in the artifact itself, not just the console.
        Write-Warning "Get-PulseGraphFailureStatusCode: supplemental Invoke-GraphOperation for '$Type/$Operation' did not recover a status code: $($_.Exception.Message)"
        return $null
    }
}
