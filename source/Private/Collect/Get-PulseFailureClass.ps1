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

    GraphKit 0.1.1 (Task 1.11 GraphKit 0.1.1 migration): Get-GraphObject no longer throws a
    bare, structure-free string. Its failure is now an ErrorRecord built by GraphKit's own
    New-GraphOperationFailureRecord, which carries THREE structured signals a consumer can
    branch on without a second, out-of-band Graph call:

        1. $_.CategoryInfo.Category - mapped by GraphKit from the HTTP status of the last
           attempt: AuthenticationError for 401, PermissionDenied for 403 (also
           ObjectNotFound/404, LimitsExceeded/429, ResourceUnavailable/5xx, none of which
           this classifier maps to AuthFailure/PermissionDenied - they fall through to the
           signals below). This is checked FIRST and is authoritative: GraphKit computed
           it directly from the status code, no parsing required on this side.
        2. $_.TargetObject.Telemetry - the whole GraphKit.OperationResult envelope is the
           ErrorRecord's TargetObject, so @($_.TargetObject.Telemetry)[-1].StatusCode (the
           attempt the retry loop actually stopped on) is available whenever signal (1)
           didn't already decide the classification (e.g. a category this function doesn't
           map, or a caller that built an ErrorRecord with CategoryInfo.Category left at
           its default NotSpecified). Same enum-aware 403/401/other-numeric mapping as
           before: an [System.Net.HttpStatusCode]-typed StatusCode must be cast to [int]
           directly, never stringified first ([string] on an enum renders its NAME, not
           its numeric value, which would make a TryParse-based conversion fail silently).
        3. The rendered exception message, pattern-matched (case-insensitively) for an
           AADSTS error code, "token acquisition" or "unauthorized" -> AuthFailure; '403',
           'forbidden' or 'accessdenied' -> PermissionDenied - a last-resort fallback for
           anything upstream of Get-GraphObject (e.g. Get-GraphContext's own auth
           failures) that throws a plain string with no structured shape at all.

    No out-of-band recovery call is needed anymore: GraphKit 0.1.1's own ErrorRecord is the
    complete signal, so the Get-PulseGraphFailureStatusCode supplemental-probe workaround
    (one extra read-only Graph call per failed dataset, purely to recover a status code
    Get-GraphObject 0.1.0 discarded) has been deleted along with its call site and its
    -SupplementalStatusCode parameter here. Invoke-PulseCollection's '(status unknown)'
    suffix on a generic Failed reason now means signals (1)-(3) above ALL came up empty -
    an ErrorRecord that carries no CategoryInfo.Category this function maps, no Telemetry
    this function can read a status code from, and no message text either signal matches -
    genuinely weaker signal, not (as before) "the supplemental probe itself failed".
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

            # Enum-typed values (e.g. [System.Net.HttpStatusCode]::Forbidden) must be cast
            # to [int] directly, BEFORE falling through to the TryParse path below -
            # [string] on an enum value renders its NAME ('Forbidden'), not its underlying
            # numeric value ('403'), so [int]::TryParse against that string would simply
            # fail and this classifier would silently lose the status code signal.
            if ($Value -is [System.Enum]) { return [int] $Value }

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

        # Signal (1): GraphKit's own CategoryInfo.Category, mapped directly from the HTTP
        # status of the last attempt. Checked first because GraphKit already did the
        # status-to-category mapping - nothing to parse or infer on this side.
        $category = $null
        $categoryInfoProperty = $ErrorRecord.PSObject.Properties['CategoryInfo']
        if ($null -ne $categoryInfoProperty -and $null -ne $categoryInfoProperty.Value) {
            $categoryProperty = $categoryInfoProperty.Value.PSObject.Properties['Category']
            if ($null -ne $categoryProperty) {
                $category = [string] $categoryProperty.Value
            }
        }

        if ($category -eq 'PermissionDenied') {
            return 'PermissionDenied'
        }

        if ($category -eq 'AuthenticationError') {
            return 'AuthFailure'
        }

        # Signal (2): the last Telemetry attempt's StatusCode, read off TargetObject (the
        # whole GraphKit.OperationResult envelope GraphKit's New-GraphOperationFailureRecord
        # attaches to the ErrorRecord it throws). Only consulted when signal (1) didn't
        # already decide the classification - a category this function doesn't map (404,
        # 429, 5xx, NotSpecified) falls through to here rather than short-circuiting.
        $statusCode = $null
        $targetObjectProperty = $ErrorRecord.PSObject.Properties['TargetObject']
        if ($null -ne $targetObjectProperty -and $null -ne $targetObjectProperty.Value) {
            $telemetryProperty = $targetObjectProperty.Value.PSObject.Properties['Telemetry']
            if ($null -ne $telemetryProperty -and $null -ne $telemetryProperty.Value) {
                $attempts = @($telemetryProperty.Value)
                if ($attempts.Count -gt 0) {
                    $lastAttempt = $attempts[$attempts.Count - 1]
                    $statusProperty = $lastAttempt.PSObject.Properties['StatusCode']
                    if ($null -ne $statusProperty) {
                        $statusCode = ConvertTo-PulseNullableStatusCode -Value $statusProperty.Value
                    }
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

        # Signal (3): the rendered exception message - a last-resort fallback for anything
        # upstream of Get-GraphObject (e.g. Get-GraphContext's own auth failures) that
        # throws a plain string with no structured CategoryInfo/Telemetry shape at all.
        $message = ''
        $exception = $ErrorRecord.Exception
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
