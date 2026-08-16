<#
    Private: resolve a check's declared license/feature gate to a status.

    Phase 1 staging: this is a stub gate registry. No live license/feature detection exists
    yet - that arrives once later tasks start collecting the datasets a real gate check
    would need (e.g. a subscribedSkus read for 'EntraP1'). Every gate name, unconditionally,
    resolves to Status 'Unknown' for now.

    Returns a small {Status; Detail} object rather than a bare string so a later task's real
    detection has somewhere to put a human-readable reason ('Unavailable' because of what,
    specifically) without changing the return SHAPE the evaluator already consumes - only
    this function's body needs to change.

    'Unknown' is a load-bearing contract, not just a placeholder value: Invoke-PulseEvaluation
    treats it (and 'Available') as "the check runs" - it never degrades a check to
    NotApplicable. Only 'Unavailable' does that, and only 'Unavailable' is wired to a
    NotApplicable reason quoting -Detail ("gate '<name>' unavailable: <detail>"). This
    function never returns 'Unavailable' yet, so that path is exercised in tests via a
    mocked/overridden Get-PulseGateStatus, not by this stub - the evaluator's wiring is real
    and tested even though this implementation cannot yet trigger it.
#>

function Get-PulseGateStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Gate,

        [Parameter(Mandatory)]
        [hashtable] $Manifest
    )

    # -Gate/-Manifest are the declared interface every call site already passes (see
    # Invoke-PulseCheckEvaluation) - referenced here only via Write-Verbose so a future
    # implementation has somewhere obvious to plug real detection in, and so static
    # analysis does not flag them as unused on what is, for now, a deliberate stub.
    Write-Verbose "Get-PulseGateStatus: gate '$Gate' resolves to 'Unknown' (Phase 1 stub - no live detection yet; manifest has $($Manifest.Keys.Count) top-level keys)."

    return [pscustomobject]@{
        Status = 'Unknown'
        Detail = $null
    }
}
