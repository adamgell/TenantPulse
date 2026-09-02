# TP5A DatasetMap proposal

Do not apply this file in the TP5A worktree. The integration controller lands
`source/Data/DatasetMap.psd1` (and public-surface registries) from this proposal.

GraphKit primitives used here are public 0.3.0 only. No GraphKit.Auth. No ARM.
No fake Graph descriptors.

## New composite dataset

```powershell
# Bounded, cycle-safe group membership closure. TenantPulse-owned Walk over
# GraphKit GroupMember.List (v1.0). Optional seed discovery uses
# ConditionalAccessPolicy.List (beta) and DirectoryRoleAssignment.List (v1.0).
# Caps (MaxDepth/MaxGroups/MaxMembersPerGroup/MaxTotalMembers/MemberPageCap)
# are visible on the collection Detail and every row. Sampled/truncated
# outcomes are Partial (or Failed with no usable rows) and must never be
# Collected. Resolve-PulseProviderPlanRegistry already routes `groupClosure`
# to Invoke-PulseGroupClosurePlan.
groupClosure = @{
    Type                    = 'GroupClosureWalk'
    Operation               = 'Walk'
    ApiVersion              = 'v1.0'
    Pending                 = $true
    ExpectedThrottleClass   = 'Read'
    ExpectedReplayPolicy    = 'Safe'
}
```

Checks that consume closure rows today look for `-Datasets.groupMembers` (dictionary
or closure-row array). After this map lands, either:

1. Alias `groupMembers` to the same Walk entry, or
2. Rename check/helper consumption to `groupClosure` in a follow-up controller commit.

Recommended alias so existing helper contracts stay stable:

```powershell
groupMembers = @{
    Type                    = 'GroupClosureWalk'
    Operation               = 'Walk'
    ApiVersion              = 'v1.0'
    Pending                 = $true
    ExpectedThrottleClass   = 'Read'
    ExpectedReplayPolicy    = 'Safe'
}
```

If both names are published, they must resolve to the same plan command.

## Descriptor dataset additions after the map lands

These cannot ship in TP5A because `Test-PulseCheckDescriptor` cross-checks
`Data.Datasets` against DatasetMap keys.

| Check | Add to Data.Datasets | Why |
|---|---|---|
| TP.ENT.0003 | `groupMembers` (or `groupClosure`) | Per-policy excludeGroups membership |
| TP.ENT.0021 | `groupMembers` (or `groupClosure`) | Effective privileged assignment count |
| TP.ENT.0022 | `groupMembers` (or `groupClosure`) | Permanent-active group expansion |

TP.ENT.0022 **removed** unused `roleEligibilityScheduleInstances` in this
worktree so a skipped eligibility dataset cannot suppress the check.

## Already-mapped assignment primitives (no new Graph types)

Endpoint security composites now also call `ConfigurationPolicyAssignment.ListBeta`
(already in DatasetMap as `configurationPolicyAssignments`). No DatasetMap row
change is required for that child call; the static read-only gate already covers
the Type/Operation pair.

`deviceCompliancePolicyAssignments` and `deviceConfigurationAssignments` remain
per-policy `{id}` Lists. Ordinary `IdFromDataset` collection cannot feed TP.INT.0002
or TP.INT.0004. Those checks now fail closed unless assignment objects are present
on the policy row (include intent). A later composite/expansion train should stamp
those assignments; do not add Application.List or ARM rows here.

## Caps (plan defaults)

| Name | Default |
|---|---|
| MaxDepth | 8 |
| MaxGroups | 256 |
| MaxMembersPerGroup | 2000 |
| MaxTotalMembers | 20000 |
| MemberPageCap | 20 |

Override via ManifestEntry properties of the same names.
