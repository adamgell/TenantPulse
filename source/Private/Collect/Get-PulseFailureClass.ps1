<#
    Private: classify a Graph read failure as PermissionDenied or Failed.

    Permission handling is attempt-and-classify (see Invoke-PulseCollection): GraphKit has
    no per-operation "can this context read this now" pre-flight, so the collector always
    attempts the read and inspects whatever it catches. A 403 outcome means "not
    permitted, not necessarily broken" and classifies the dataset Skipped with a
    permission-denied reason; anything else means the attempt genuinely failed and
    classifies the dataset Failed.

    Isolated on purpose: this is the one place that has to guess at GraphKit's error
    shape, so it is kept small, directly unit-testable against a synthetic ErrorRecord,
    and easy to swap once Task 1.11's live gate confirms the real shape against an actual
    tenant. Three signals are checked, most-authoritative first, and the function stops at
    the first one that resolves a status code:

        1. Exception.Response.StatusCode - the shape a System.Net.Http.HttpRequestException
           (or similar) carries when GraphKit's transport surfaces the raw HTTP response.
        2. Exception.StatusCode - a flatter shape some wrapped exceptions expose directly.
        3. The rendered exception message, pattern-matched for '403', 'forbidden' or
           'accessdenied' - the last-resort fallback for a plain `throw "<text>"` that
           carries no structured status at all (exactly the shape Get-GraphObject's own
           "Outcome/Certainty" failure message has today - see its docstring).

    TODO(Task 1.11): once GraphKit's live 403 shape is confirmed against a real tenant,
    tighten this to the authoritative property and drop (or narrow) the message-text
    fallback.
#>

function Get-PulseFailureClass {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    $statusCode = $null
    $exception = $ErrorRecord.Exception

    if ($null -ne $exception) {
        $responseProperty = $exception.PSObject.Properties['Response']
        if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
            $statusProperty = $responseProperty.Value.PSObject.Properties['StatusCode']
            if ($null -ne $statusProperty -and $null -ne $statusProperty.Value) {
                $statusCode = [int] $statusProperty.Value
            }
        }

        if ($null -eq $statusCode) {
            $directStatusProperty = $exception.PSObject.Properties['StatusCode']
            if ($null -ne $directStatusProperty -and $null -ne $directStatusProperty.Value) {
                $statusCode = [int] $directStatusProperty.Value
            }
        }
    }

    if ($statusCode -eq 403) {
        return 'PermissionDenied'
    }

    if ($null -ne $statusCode) {
        return 'Failed'
    }

    $message = [string] $ErrorRecord.Exception.Message
    if ($message -match '\b403\b' -or $message -match '(?i)forbidden' -or $message -match '(?i)accessdenied') {
        return 'PermissionDenied'
    }

    return 'Failed'
}
