@{
    Id         = 'TP.INT.0006'
    Title      = 'Conflicting security-setting values across policies'
    Category   = 'Intune.SettingsCatalog'
    Severity   = 'Medium'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('configurationPolicies')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseConflictingPolicySettings'
    }
    Consulting = @{
        WhatItMeans  = 'Two or more Settings Catalog / typed configuration policies assign different concrete values to the SAME underlying setting definition, to device or user scopes that overlap or cannot be proven disjoint. This is built entirely from the settings-expansion index (expanded/conflicts.json) - a single pass over every resolved setting row across every collected policy family, never a pairwise policy-to-policy comparison - and reports each conflicting definitionId with all of its competing values, the policies that set them, and a four-state assignment-overlap classification (proven / possible / none / unknown) rather than a collapsed yes/no. On Ivy24, the archetype behind this check is not a hypothetical: Windows Autopatch update-ring policies and a separate set of update/quality settings authored through OneIT Baseline (OIB)-style policies both target overlapping device groups and disagree on deferral/deadline values for the same CSPs. The live Ivy24 gate indexed 165 total conflicts this way - assignmentOverlap none=8, possible=34, unknown=123 (recorded verbatim in docs/STATUS.md''s Phase 2 live-gate section) - so the 34-conflict Fail-driving figure this check is built to surface is a real, previously-recorded measurement, not an illustrative estimate.'
        WhyItMatters = 'Per Microsoft''s own guidance (Avoid policy conflicts, Intune documentation): "Devices and users targeted with the same setting from different policies cause conflicts. When conflicts occur, Intune generates an error and doesn''t apply either setting." This is NOT a last-writer-wins outcome where one policy silently wins - it is an ENFORCEMENT GAP: for every setting caught in a proven or possible conflict, NEITHER policy''s intended value reaches the device, while both policies may otherwise still show as broadly "assigned". The failure is only visible by proactively checking Devices > Monitor > Configuration policy assignment failure (or Reports > Settings error in Intune for Education) per policy - nothing prompts an admin to look there, and nothing in either policy''s own overview page flags that it is in conflict with another. A conflict marked overlap "none" is not currently colliding on any device, but is still a maintenance hazard - the moment either policy''s assignment changes, it becomes a live conflict with no change-control step to catch it.'
        Remediation  = @(
            'For every conflict with overlap "proven" or "possible" (this finding''s evidence), open Devices > Monitor > Configuration policy assignment failure and check whether the named policies are reporting an assignment failure for the affected devices - the setting is not applied at all until the conflict is resolved, not merely uncertain which value is in effect.'
            'Consolidate the conflicting setting into a single authoritative policy per target population, or make assignment scopes provably disjoint (distinct, non-overlapping security groups with no shared members, and no "All devices"/"All users" targets or dynamic-membership filters on either side) - a proven-disjoint pair is a durable fix, a hoped-for-disjoint one is not.'
            'Where the archetype applies (Autopatch rings vs. a separate baseline/OIB-style update policy), pick ONE mechanism to own Windows Update deferral/deadline settings for a given device population and retire or narrow the other - do not run both against the same devices.'
            'Conflicts reported with overlap "none" are lower urgency but not free - track them; revisit this check after any assignment change to either policy named in the evidence, since a "none" today can become "proven" tomorrow with no other signal.'
            'Conflicts reported with overlap "unknown" mean TenantPulse could not yet resolve assignment-scope overlap for that pair (deferred pending a GraphKit release) - treat them with the same caution as "possible" until a later snapshot resolves them one way or the other.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/PoliciesMenu', 'https://intune.microsoft.com/#view/Microsoft_Intune_Enrollment/UpdateRingsMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0006--conflicting-security-setting-values-across-policies'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/solutions/education/tutorial-school-deployment/policy-conflicts'
            'https://github.com/Micke-K/IntuneManagement'
        )
    }
    Origin     = $null
}
