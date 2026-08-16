<#
    Private: classify a Graph read failure as PermissionDenied, AuthFailure or Failed.

    Permission handling is attempt-and-classify (see Invoke-PulseCollection): GraphKit has
    no per-operation "can this context read this now" pre-flight, so the collector always
    attempts the read and inspects whatever it catches. A 403 outcome means "not
    permitted, not necessarily broken" and classifies the dataset Skipped with a
    permission-denied reason. An auth failure (401, or an MSAL/AADSTS-shaped error) means
    no read in this run can possibly succeed - GraphKit's Get-GraphContext performs zero
    network calls and never acquires a token (see its own docstring), so a real
    authentication failure is only ever discovered here, at the FIRST dataset attempt, not
    at context-acquisition time. Anything else means the attempt genuinely failed and
    classifies the dataset Failed.

    TOTAL by construction: this function must never itself throw. It runs inside the
    collector's per-dataset catch block - a classifier that throws would take down the
    whole collection run over a single malformed or unexpected error shape, exactly the
    kind of silent-gap failure this module exists to prevent. Every status-code read goes
    through a TryParse-based conversion (never a bare [int] cast, which throws on a
    non-numeric StatusCode such as the string "403 Forbidden"), and the entire body is
    wrapped in a last-resort try/catch that falls back to 'Failed' - the most conservative
    classification - rather than propagating.

    Isolated on purpose: this is the one place that has to guess at GraphKit's error
    shape, so it is kept small, directly unit-testable against a synthetic ErrorRecord (or
    even $null), and easy to swap once Task 1.11's live gate confirms the real shape
    against an actual tenant. Signals are checked most-authoritative first:

        1. Exception.Response.StatusCode / Exception.StatusCode - the shape a
           System.Net.Http.HttpRequestException (or similar) carries when GraphKit's
           transport surfaces the raw HTTP response. 403 -> PermissionDenied, 401 ->
           AuthFailure, anything else numeric -> Failed.
        2. The rendered exception message, pattern-matched (case-insensitively) for an
           AADSTS error code, "token acquisition" or "unauthorized" -> AuthFailure; '403',
           'forbidden' or 'accessdenied' -> PermissionDenied - the last-resort fallback for
           a plain `throw "<text>"` that carries no structured status at all (exactly the
           shape Get-GraphObject's own "Outcome/Certainty" failure message has today - see
           its docstring).

    TODO(Task 1.11): once GraphKit's live error shapes are confirmed against a real
    tenant, tighten this to the authoritative property and drop (or narrow) the
    message-text fallback.
#>

function Get-PulseFailureClass {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    # Never throws: a TryParse-based, exception-swallowing conversion from an arbitrary
    # (possibly string, possibly garbage-typed) StatusCode-shaped value to a nullable int.
    function ConvertTo-PulseNullableStatusCode {
        param($Value)

        if ($null -eq $Value) { return $null }

        try {
            if ($Value -is [int]) { return $Value }

            $parsed = 0
            if ([int]::TryParse([string] $Value, [ref] $parsed)) {
                return $parsed
            }
        } catch {
            # Fall through to $null below - stringifying or parsing a genuinely hostile
            # value must never itself throw out of the classifier. Write-Verbose only
            # (never Write-Error/throw): this is an expected, silent-by-design path for
            # any StatusCode-shaped value that isn't cleanly parseable.
            Write-Verbose "Get-PulseFailureClass: could not parse a status code from '$Value': $($_.Exception.Message)"
        }

        return $null
    }

    try {
        if ($null -eq $ErrorRecord) {
            return 'Failed'
        }

        $statusCode = $null
        $exception = $ErrorRecord.Exception

        if ($null -ne $exception) {
            $responseProperty = $exception.PSObject.Properties['Response']
            if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
                $statusProperty = $responseProperty.Value.PSObject.Properties['StatusCode']
                if ($null -ne $statusProperty) {
                    $statusCode = ConvertTo-PulseNullableStatusCode -Value $statusProperty.Value
                }
            }

            if ($null -eq $statusCode) {
                $directStatusProperty = $exception.PSObject.Properties['StatusCode']
                if ($null -ne $directStatusProperty) {
                    $statusCode = ConvertTo-PulseNullableStatusCode -Value $directStatusProperty.Value
                }
            }
        }

        if ($statusCode -eq 403) {
            return 'PermissionDenied'
        }

        if ($statusCode -eq 401) {
            return 'AuthFailure'
        }

        if ($null -ne $statusCode) {
            return 'Failed'
        }

        $message = ''
        if ($null -ne $exception -and $null -ne $exception.Message) {
            $message = [string] $exception.Message
        }

        if ($message -match 'AADSTS\d+' -or $message -match '(?i)token acquisition' -or $message -match '(?i)\bunauthorized\b') {
            return 'AuthFailure'
        }

        if ($message -match '\b403\b' -or $message -match '(?i)forbidden' -or $message -match '(?i)accessdenied') {
            return 'PermissionDenied'
        }

        return 'Failed'
    } catch {
        # Last resort: this classifier must be TOTAL. Whatever went wrong above, it must
        # never propagate out and take down the collector's per-dataset catch - fail safe
        # to the most conservative classification instead.
        return 'Failed'
    }
}
