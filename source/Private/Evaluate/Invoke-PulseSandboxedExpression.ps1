<#
    Private: evaluate an Expression-type check rule's text in an isolated runspace.

    SECURITY FIX (C1, post-review, round 2): round 1 used
    InitialSessionState.CreateDefault2(), documented (wrongly) as "Core cmdlets only".
    A re-review proved that claim false: CreateDefault2() actually loads
    Microsoft.PowerShell.Management AND Microsoft.PowerShell.Utility, not just Core - from
    inside that "sandbox", New-Item, Get-Content, Set-Content, Remove-Item,
    Invoke-WebRequest and Invoke-RestMethod all executed successfully. Runspace/scope/
    module isolation (round 1's actual contribution) held throughout - ConstrainedLanguage
    restricts .NET TYPES, it does not restrict which CMDLETS are loaded into the session.
    The cmdlet surface was the hole, and it is a serious one: a check descriptor's
    Expression text could read/write the host filesystem or make outbound network calls.

    Round 2 fix: the InitialSessionState is now built from
    [InitialSessionState]::Create() - genuinely empty, no default snap-ins, no
    Microsoft.PowerShell.Core/Management/Utility - with an explicit ALLOWLIST of exactly
    five cmdlets added back one at a time via SessionStateCmdletEntry against their real
    implementing types: Where-Object, ForEach-Object, Select-Object, Measure-Object,
    Sort-Object. These are the only pipeline verbs a boolean property-assertion expression
    over $Datasets genuinely needs (property/member access, comparison and arithmetic
    operators, indexing, and the pipeline operator itself are PARSER/ENGINE features, not
    cmdlets - they work with zero cmdlets loaded at all). No file-system cmdlet
    (Get-Content, Set-Content, New-Item, Remove-Item, ...), no network cmdlet
    (Invoke-WebRequest, Invoke-RestMethod, ...), no Get-Variable/Set-Variable, no
    Get-Module/Import-Module, and nothing else from Management or Utility is reachable -
    they are simply never added to this session's command table, the same "not hidden,
    not there" guarantee round 1 already established for variables and functions.
    LanguageMode stays ConstrainedLanguage on top, for the same reason as round 1: it
    blocks arbitrary .NET type conversions/casts, non-approved static method calls, COM
    interop and Add-Type - a defense the cmdlet allowlist does not provide on its own.

    Empirically verified (not just asserted) before landing this: with the five-cmdlet
    allowlist, `$Datasets.a.Count -gt 0`, `$Datasets.a | Where-Object {...}`,
    `| ForEach-Object {...}`, `| Select-Object -First 1` and `| Measure-Object` all still
    work; New-Item/Get-Content/Set-Content/Remove-Item/Invoke-WebRequest/
    Invoke-RestMethod/Get-Variable/Get-Module all fail with "term ... is not recognized"
    (CommandNotFoundException, captured as a non-terminating error - see below) and leave
    no trace on the host (no file written, no request made). One caveat surfaced during
    that verification: `Sort-Object -Property <name>` over the hashtable-shaped records
    ConvertTo-PulseClonedDatasets hands in can throw under ConstrainedLanguage
    ("Hashtable-to-Object conversion is not supported in restricted language mode") -
    ConstrainedLanguage blocks the implicit Hashtable->PSObject conversion Sort-Object's
    property-extraction machinery needs internally for a hashtable-typed pipeline object.
    Sort-Object stays allowlisted (it is still useful for value-only sorts, e.g.
    `$Datasets.a | Sort-Object` over a plain string array), but a descriptor author
    relying on `Sort-Object -Property` over hashtable records should expect that specific
    combination to surface as an engine Error, not a silent misbehavior - the error message
    names exactly what happened.

    Returns @{ Status = 'Pass'|'Fail'|'Error'; Reason = <string, or $null for Pass/Fail> } -
    the same per-check result hashtable shape Invoke-PulseCheckEvaluation already uses, minus
    Evidence (an Expression rule never produces any).

    HONEST RESIDUAL (updated for round 2 - what is and is not actually true now): the
    sandbox is a genuinely empty runspace plus a five-cmdlet allowlist
    (Where-Object/ForEach-Object/Select-Object/Measure-Object/Sort-Object) plus
    ConstrainedLanguage. What that combination demonstrably stops, because it was tested
    against exactly these techniques: reading/writing the host filesystem, making network
    calls, reaching the caller's variables (operator key, store, manifest, redaction map),
    reaching TenantPulse's own private functions, and arbitrary .NET type
    conversion/method-call escapes. What it does NOT claim to stop: timing side channels,
    resource exhaustion (an expression can still busy-loop or allocate memory inside its
    own runspace), and anything expressible using only the five allowlisted cmdlets plus
    ConstrainedLanguage-approved operators/types (which is intentionally a very small
    surface, but "very small" is not "zero"). This is still not a hardened sandbox against
    a dedicated adversary - PowerShell's own ConstrainedLanguage documentation says so
    explicitly. The Phase 1 trust story remains "we author and review every shipped check
    descriptor" - descriptors are code, and this sandbox exists to contain an authoring
    MISTAKE or a reviewed-but-imperfect descriptor, not to hold against a
    community-contributed, unreviewed one - that trust boundary is explicit future work.
#>

function Invoke-PulseSandboxedExpression {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string] $Expression,

        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        # Task 1.8: optional evaluation context (e.g. BreakGlassAccounts/ServiceAccounts
        # from an -AssessmentProfile), exposed to the expression as $Context. Defaults to
        # an empty hashtable - since this runspace is fresh and isolated per call, an
        # always-present empty $Context is harmless and needs no opt-in gating the way the
        # Function-rule path does (see Invoke-PulseEvaluation's own docstring for why that
        # path DOES need to gate on the target function's declared parameters).
        [Parameter()]
        [hashtable] $Context = @{}
    )

    $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::Create()
    $initialSessionState.LanguageMode = [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage

    # The ONLY cmdlets a boolean property-assertion expression over $Datasets genuinely
    # needs - added one at a time against their real implementing type, never via
    # ImportPSModule/snap-in (which would pull in every other cmdlet that module ships).
    # See this function's own docstring for the round-2 fix rationale and what was
    # empirically verified against this exact allowlist.
    $allowedCmdlets = @(
        @{ Name = 'Where-Object'; Type = [Microsoft.PowerShell.Commands.WhereObjectCommand] }
        @{ Name = 'ForEach-Object'; Type = [Microsoft.PowerShell.Commands.ForEachObjectCommand] }
        @{ Name = 'Select-Object'; Type = [Microsoft.PowerShell.Commands.SelectObjectCommand] }
        @{ Name = 'Measure-Object'; Type = [Microsoft.PowerShell.Commands.MeasureObjectCommand] }
        @{ Name = 'Sort-Object'; Type = [Microsoft.PowerShell.Commands.SortObjectCommand] }
    )
    foreach ($cmdlet in $allowedCmdlets) {
        $entry = [System.Management.Automation.Runspaces.SessionStateCmdletEntry]::new($cmdlet.Name, $cmdlet.Type, $null)
        $initialSessionState.Commands.Add($entry)
    }

    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($initialSessionState)
    $shell = $null

    try {
        $runspace.Open()

        # SessionStateProxy.SetVariable is a host-side API call, not user script code - it
        # is unaffected by the runspace's LanguageMode or its cmdlet allowlist. This is the
        # ONLY thing handed into the sandbox.
        $runspace.SessionStateProxy.SetVariable('Datasets', $Datasets)
        $runspace.SessionStateProxy.SetVariable('Context', $Context)

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
