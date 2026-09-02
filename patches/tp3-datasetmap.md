# TP3 DatasetMap proposals (C0 = Proposed only)

Do not apply these rows until owner approval. This worktree does not edit
`source/Data/DatasetMap.psd1` or `source/Public/Get-PulseTenantSnapshot.ps1`.

## dataProcessorServiceForWindowsFeaturesOnboarding (TP.INT.0009)

Replace the synthetic GraphKit `Get` placeholder. Runtime already sends no
request and returns `Skipped` / `PlatformUnavailable` with a recheck trigger.
Provenance must stay `Provider = TenantPulse`, empty `Operations`, no descriptor
fallback.

```powershell
# Proposed: keep Pending as a static placeholder only. Collection is owned by
# Invoke-PulseWindowsDataProcessorPlan (RequiresNetwork = false). Do not name a
# GraphKit Type/Operation that is never invoked.
dataProcessorServiceForWindowsFeaturesOnboarding = @{
    Provider = 'TenantPulse'
    Pending = $true
    ExpectedThrottleClass = 'Read'
    ExpectedReplayPolicy = 'Safe'
}
```

## Administrative Template expansion (not check-driven collection)

Declare the three released GraphKit 0.3.0 primitives so the static Read/Safe
gate covers the expansion walker. Do not add them to ordinary
`Invoke-PulseCollection` — they are per-policy and require `-Requested` or a
selected check that declares `administrativeTemplates`.

```powershell
groupPolicyConfigurations = @{ Type = 'GroupPolicyConfiguration'; Operation = 'ListBeta'; ApiVersion = 'beta' }
groupPolicyDefinitionValues = @{ Type = 'GroupPolicyDefinitionValue'; Operation = 'ListBeta'; ApiVersion = 'beta' }
groupPolicyPresentationValues = @{ Type = 'GroupPolicyPresentationValue'; Operation = 'ListBeta'; ApiVersion = 'beta' }
```

## Get-PulseTenantSnapshot wiring (do not apply here)

After the existing `-ExpandSettings` block, and never as a default-on path:

```powershell
$expansionSelection = Resolve-PulseRequestedExpansions -SelectedChecks $selectedChecks -ExpandSettings:$ExpandSettings
if ($ExpandSettings -or (@($expansionSelection.Requested) -contains 'administrativeTemplates')) {
    $null = Invoke-PulseAdministrativeTemplateExpansion -Store $store -Context $context `
        -Requested -SelectedChecks $selectedChecks `
        -ProfileId $ProfileId -Pseudonym $tenantPseudonym -TenantId $contextTenantId `
        -NetworkAbortState $networkAbortState
}
if ($ExpandSettings -or (@($expansionSelection.Requested) -contains 'expansionSummary')) {
    $null = Invoke-PulseExpansionSummary -Store $store -Requested -SelectedChecks $selectedChecks `
        -ProfileId $ProfileId -Pseudonym $tenantPseudonym -TenantId $contextTenantId
}
```

Explicit `-ExpandSettings:$false` keeps `Resolve-PulseRequestedExpansions`
opted out (`DependencyUnavailable`). Checks that declare `Data.Expansions`
already map missing artifacts to `NotApplicable`.

## Known-artifact registry (Test-PulseCheckDescriptor.ps1)

Proposed additions: `administrativeTemplates`, `expansionSummary`. Not applied
in this worktree.
