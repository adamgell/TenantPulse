<#
    Private: resolve a check's declared license/feature gate to a status.

    Phase 1 staging: this is a stub gate registry. No live license/feature detection exists
    yet - that arrives once later tasks start collecting the datasets a real gate check
    would need (e.g. a subscribedSkus read for 'EntraP1'). Every gate name, unconditionally,
    resolves to 'Unknown' for now.

    'Unknown' is a load-bearing contract, not just a placeholder value: Invoke-PulseEvaluation
    treats it as "the engine cannot yet tell whether this gate is satisfied, so let the check
    run anyway" - it never degrades a check to NotApplicable. Only a genuinely missing/
    Failed/Skipped dataset does that. When a later task teaches this function real detection
    (returning e.g. 'Available'/'Unavailable'), only this one function needs to change - the
    evaluator already calls it per declared gate.
#>

function Get-PulseGateStatus {
    [CmdletBinding()]
    [OutputType([string])]
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

    return 'Unknown'
}
