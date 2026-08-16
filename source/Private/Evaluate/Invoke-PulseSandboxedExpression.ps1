<#
    Private: evaluate an Expression-type check rule's text in an isolated runspace.

    SECURITY FIX (C1, post-review): the original implementation ran a check descriptor's
    Rule.Expression text via ScriptBlock.InvokeWithContext inside Invoke-PulseCheckEvaluation
    itself - a scriptblock created with [scriptblock]::Create() and invoked via the call
    operator/InvokeWithContext runs in FullLanguage with a live scope chain up through its
    caller. Proven exploitable: expression text could read $operatorKey (raw HMAC bytes) and
    other caller-scope variables, write parent/global scope, mutate the shared dataset cache
    by reference, and reach TenantPulse's own private functions - none of which a check
    descriptor (data, not code the module authors fully trust) should ever be able to do.

    Fix: every Expression rule now runs in a BRAND NEW [powershell] instance bound to a
    freshly created Runspace with its own InitialSessionState, disposed immediately after.
    Specifically:
      - A new Runspace has its own SessionState - no scope chain to Invoke-PulseCheckEvaluation
        or anything above it. $operatorKey, $Store, $Manifest, $DatasetCache, the redaction
        map, and every TenantPulse private function are simply not there to find, by
        construction - not because they are hidden, but because this is a different
        .NET object graph entirely.
      - LanguageMode is set to ConstrainedLanguage before the runspace opens, which blocks
        arbitrary .NET type conversions/casts, calling non-approved static methods, COM
        interop, and Add-Type - the class of "escape the sandbox via raw .NET" techniques.
      - The InitialSessionState is CreateDefault2() (Microsoft.PowerShell.Core cmdlets only -
        Get-Variable, Where-Object, ForEach-Object, etc. - not the broader
        Management/Utility module surface CreateDefault() would pull in), so ordinary
        expression syntax (property access, comparison operators, simple pipelines) keeps
        working, while the module's own functions and any file-system-touching cmdlets from
        Utility/Management are simply not loaded.
      - The ONLY data handed in is a per-check hashtable already deep-cloned via the
        ConvertTo-PulseCanonicalJson -> ConvertFrom-Json round-trip (see
        Invoke-PulseEvaluation's ConvertTo-PulseClonedDatasets) - a live reference is never
        shared, so an expression that mutates $Datasets in place can never affect the shared
        dataset cache or any other check's view of the data.
      - Non-terminating errors raised inside the sandboxed script (e.g. a command that does
        not resolve there) are read from the PowerShell instance's own Streams.Error after
        Invoke() and turned into an engine Error result - they never propagate as a live
        ErrorRecord carrying anything about the host process.

    HONEST RESIDUAL (document, do not oversell): ConstrainedLanguage plus a bare runspace is
    a real barrier against ACCIDENTAL scope/reference leakage and against the specific
    exploitation techniques above, but it is NOT a hardened sandbox against a dedicated
    adversary who controls a check descriptor's Rule.Expression text - PowerShell's own
    ConstrainedLanguage documentation is explicit that mode alone is not a complete security
    boundary, and side channels (timing, resource exhaustion, whatever ConstrainedLanguage's
    approved-type allow-list still permits) are not addressed here. The trust story for
    Phase 1 is "we author and review every shipped check descriptor" - descriptors ARE code.
    A trust boundary that has to hold against a community-contributed, unreviewed descriptor
    is explicitly future work, not something this function claims to solve.

    Returns @{ Status = 'Pass'|'Fail'|'Error'; Reason = <string, or $null for Pass/Fail> } -
    the same per-check result hashtable shape Invoke-PulseCheckEvaluation already uses, minus
    Evidence (an Expression rule never produces any).
#>

function Invoke-PulseSandboxedExpression {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string] $Expression,

        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $initialSessionState.LanguageMode = [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage

    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($initialSessionState)
    $shell = $null

    try {
        $runspace.Open()

        # SessionStateProxy.SetVariable is a host-side API call, not user script code - it
        # is unaffected by the runspace's LanguageMode. This is the ONLY thing handed into
        # the sandbox.
        $runspace.SessionStateProxy.SetVariable('Datasets', $Datasets)

        $shell = [System.Management.Automation.PowerShell]::Create()
        $shell.Runspace = $runspace
        [void] $shell.AddScript($Expression)

        $outputs = @($shell.Invoke())

        if ($shell.HadErrors -and $shell.Streams.Error.Count -gt 0) {
            return @{
                Status = 'Error'
                Reason = "expression rule raised an error: $($shell.Streams.Error[0].Exception.Message)"
            }
        }

        if ($outputs.Count -ne 1) {
            return @{
                Status = 'Error'
                Reason = "expression rule produced $($outputs.Count) output(s), expected exactly 1."
            }
        }

        $value = $outputs[0]

        if ($value -isnot [bool]) {
            $typeName = if ($null -eq $value) { 'null' } else { $value.GetType().Name }
            return @{
                Status = 'Error'
                Reason = "expression rule did not evaluate to a boolean (got $typeName)."
            }
        }

        return @{
            Status = if ($value) { 'Pass' } else { 'Fail' }
            Reason = $null
        }
    } catch {
        # A terminating error from Invoke() itself (e.g. a parse error the runspace could
        # not even start executing) lands here rather than in Streams.Error.
        return @{
            Status = 'Error'
            Reason = "expression rule failed to execute: $($_.Exception.Message)"
        }
    } finally {
        if ($shell) {
            $shell.Dispose()
        }
        $runspace.Close()
        $runspace.Dispose()
    }
}
