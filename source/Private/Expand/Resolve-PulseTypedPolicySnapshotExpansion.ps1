<#
    Private: -FromSnapshot decision wiring for Task 2.3's compliance + legacy typed-policy
    expansion - the exact sibling of Resolve-PulseSettingsCatalogSnapshotExpansion (T2.2's
    own P1-11 fix), covering the two NEW artifacts (`compliance`, `deviceConfiguration`)
    that function knows nothing about. Called once, right after a -FromSnapshot store is
    opened, alongside that function - see Invoke-PulseAssessment's own wiring.

    Runs INDEPENDENTLY per family (mirrors Invoke-PulseTypedPolicyExpansionPipeline's own
    per-family independence): a `deviceCompliancePolicies` dataset that was never collected
    (or a `compliance` expansion that cannot be verified or re-derived) must never block
    the `deviceConfiguration` family's own decision, and vice versa.

    DECISION, per family, in order:
      1. The family's raw policy dataset (`deviceCompliancePolicies`/`deviceConfigurations`)
         is not `Collected` in the manifest -> skip this family entirely. A snapshot whose
         collection never reached (or failed) this dataset has nothing for this function to
         verify or re-derive - inventing a typed-policy expansion here would fabricate data
         collection itself never produced.
      2. manifest.expansions.<name> exists with status 'Expanded' or 'Partial' AND its
         recorded file re-hashes to the recorded sha256 -> VERIFIED, already usable as
         written; nothing to do. Any other status, a missing/renamed file, or a hash
         mismatch all fall through to step 3 (T2.2's own "absent or invalid treated
         identically" rule - a corrupted artifact is never silently trusted).
      3. Re-expand via -FromCapturedPayloads: NEVER Graph. Reads the policy list back from
         the raw dataset (Read-PulseDataset) and re-derives - assignment data comes back
         from the PER-POLICY assignment datasets Invoke-PulseTypedPolicyExpansion's own
         live run already persisted (see that file's own RAW ASSIGNMENT PERSISTENCE
         docstring section); a policy whose own assignment payload was never captured (or
         is unreadable) gaps that one policy, exactly like a live fetch failure would - it
         does not abort the whole family's re-derivation.

    TypedPolicyMaps.psd1 is loaded once here (module-relative 'Data/TypedPolicyMaps.psd1',
    the same path Invoke-PulseTypedPolicyExpansionPipeline resolves) - a load failure is a
    module-authoring bug (a missing/malformed shipped file), not a per-tenant runtime
    outcome, so it propagates rather than being swallowed - matching that pipeline's own
    rule for the identical load.

    BEST-EFFORT PER FAMILY, NEVER ABORTS THE ASSESSMENT (mirrors T2.2's own sibling): any
    unexpected failure verifying/re-deriving ONE family is caught and swallowed for that
    family only - Invoke-PulseAssessment's own evaluation/scoring/render pipeline does not
    depend on either typed-policy expansion, so a failure here must never abort an
    otherwise-successful re-evaluation of an existing snapshot.
#>

function Resolve-PulseTypedPolicySnapshotExpansion {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store
    )

    $moduleBase = if ($MyInvocation.MyCommand.Module) { $MyInvocation.MyCommand.Module.ModuleBase } else { $PSScriptRoot }
    $typedPolicyMapPath = Join-Path $moduleBase 'Data/TypedPolicyMaps.psd1'
    $typedPolicyMaps = Import-PowerShellDataFile -LiteralPath $typedPolicyMapPath -ErrorAction Stop

    $families = @(
        [pscustomobject]@{ ExpansionName = 'compliance'; DatasetName = 'deviceCompliancePolicies'; PolicyType = 'compliance'; AssignmentType = 'DeviceCompliancePolicyAssignment'; TypeMap = $typedPolicyMaps.compliance }
        [pscustomobject]@{ ExpansionName = 'deviceConfiguration'; DatasetName = 'deviceConfigurations'; PolicyType = 'deviceConfiguration'; AssignmentType = 'DeviceConfigurationAssignment'; TypeMap = $typedPolicyMaps.deviceConfiguration }
    )

    foreach ($family in $families) {
        try {
            $manifest = Get-PulseSnapshotManifest -Store $Store

            if (-not $manifest.datasets -or -not $manifest.datasets.ContainsKey($family.DatasetName)) { continue }
            if ($manifest.datasets[$family.DatasetName].status -ne 'Collected') { continue }

            if ($manifest.expansions -and $manifest.expansions.ContainsKey($family.ExpansionName)) {
                $entry = $manifest.expansions[$family.ExpansionName]
                if ($entry.status -eq 'Expanded' -or $entry.status -eq 'Partial') {
                    $filePath = Join-Path $Store.Root $entry.path
                    if (Test-Path -LiteralPath $filePath -PathType Leaf) {
                        $actualSha256 = Get-PulseFileSha256 -Path $filePath
                        if ($actualSha256 -eq $entry.sha256) {
                            # VERIFIED - already usable as written. Nothing to do.
                            continue
                        }
                    }
                }
            }

            # ABSENT OR INVALID - re-expand from captured payloads, never Graph.
            $policies = Read-PulseDataset -Store $Store -Name $family.DatasetName

            $null = Invoke-PulseTypedPolicyExpansion -Store $Store -Context $null -Policies $policies `
                -PolicyType $family.PolicyType -TypeMap $family.TypeMap -AssignmentType $family.AssignmentType `
                -Name $family.ExpansionName -FromCapturedPayloads $true
        } catch {
            Write-Verbose "Resolve-PulseTypedPolicySnapshotExpansion: could not verify or re-derive '$($family.ExpansionName)' for '$($Store.Root)': $($_.Exception.Message)"
        }
    }
}
