<#
    Private: redact identifying values out of a manifest reason string.

    Every dataset reason and the top-level collectionFailure both come, at least in part,
    from a caught GraphKit exception's message - and a real failure message can carry the
    raw profile id verbatim (an MSAL AADSTS error embeds it, "profile 'x' not found" names
    it directly) or the raw tenant GUID once a context has resolved one. Writing that
    straight into the manifest would violate the module-wide "tenant id is always
    pseudonymized in artifacts" rule just as surely as writing the raw id into the
    `tenant` field would - a reason string is still part of the snapshot artifact.

    Every occurrence of -ProfileId (and, when supplied and non-empty, -TenantId) is
    replaced with -Pseudonym before the result is capped at 500 characters - long enough
    to keep a reason legible, short enough that a verbose stack-trace-shaped exception
    message can never balloon the manifest or smuggle out unredacted context via sheer
    length. Every reason written anywhere in Get-PulseTenantSnapshot and
    Invoke-PulseCollection is routed through this function, including reasons built from
    fixed, non-exception text - the routing is unconditional so no future reason source
    can be added without the redaction path being obvious to bypass.
#>

function Protect-PulseReason {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Message,

        # AllowEmptyString (post-review, Task 1.6): the docstring below already documents
        # "-ProfileId alone is redacted whenever this is omitted or empty" - the evaluator
        # (Invoke-PulseEvaluation) has no raw profile id to redact by the time it runs (the
        # manifest's own `tenant` field is already a pseudonym), so it deliberately calls
        # this with -ProfileId '' to get the 500-character cap with no substring
        # replacement. Without this attribute a Mandatory [string] parameter rejects an
        # empty string outright, which contradicted that documented behavior.
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [string] $Pseudonym,

        # Optional: the raw tenant id (a GUID, once a context has resolved one), if the
        # caller has one available. -ProfileId alone is redacted whenever this is omitted
        # or empty - the two are independent identifying values that can each show up in
        # an error message on their own.
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $TenantId
    )

    $redacted = $Message

    if (-not [string]::IsNullOrEmpty($redacted)) {
        if (-not [string]::IsNullOrEmpty($ProfileId)) {
            $redacted = $redacted.Replace($ProfileId, $Pseudonym)
        }

        if (-not [string]::IsNullOrEmpty($TenantId)) {
            $redacted = $redacted.Replace($TenantId, $Pseudonym)
        }

        if ($redacted.Length -gt 500) {
            $redacted = $redacted.Substring(0, 500)
        }
    }

    return $redacted
}
