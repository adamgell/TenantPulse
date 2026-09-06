# Audit report data contract v1

## Purpose and boundary

`Get-PulseTenantSnapshot -ReportData Reports` and the equivalent fresh-collection
`Invoke-PulseAssessment` path publish six neutral, hash-verified JSONL expansions. Five are projected
from ordinary snapshot datasets; Apple enrollment profiles use one GraphKit-owned child collection
per stored DEP token:

| IHA report | Successor artifact | Authoritative source datasets |
|---|---|---|
| AppleEnrollmentProfiles | `apple-enrollment-profiles` | `depOnboardingSettings` plus `AppleEnrollmentProfile.ListByToken` |
| CompliancePolicyAssignments | `compliance-policy-assignments` | `deviceCompliancePolicies` |
| ConditionalAccessPolicies | `conditional-access-policies` | `conditionalAccessPolicies` |
| ConnectorsAndTokensReport | `connectors-and-tokens` | `ndesConnectors`, `domainConnectors`, `depOnboardingSettings`, `vppTokens` |
| DirectoryRoles | `directory-role-summary` | `directoryRoleDefinitions`, `directoryRoleAssignments`, `roleAssignmentScheduleInstances`, `roleEligibilityScheduleInstances` |
| Groups | `groups-inventory` | `groups` |

`-ReportData All` selects `Applications`, `Devices`, `Inventory`, and `Reports`; overlapping roots
are collected once through the ordinary manifest. The five snapshot-only projections read completed
datasets through their recorded hashes. The Apple producer validates its read/safe beta descriptor,
participates in the same one-time permission preflight and authentication-abort state, and sends no
request when the token dataset, descriptor, or permission decision is unavailable.

The Apple child route requires exact GraphKit `0.3.1`. Its catalog, paging route, and result-shape
contract are deterministic package evidence; live Graph permission/response proof and PSGallery
publication remain separate.

TenantPulse ends at machine data. It does not render DOCX/XLSX, carry CDW or customer branding,
judge whether work is approved, or overwrite customer-maintained response, owner, date,
prerequisite, or approval fields.

## Common artifact rules

Every row carries `schemaVersion = "1"` and `sourceColumns`, which preserves the complete source
object in stable property order. Before publication, the current tenant id is recursively replaced
with the snapshot pseudonym. Artifacts use canonical JSONL, ordinal artifact-specific sort keys,
the complete canonical row as a final tie-breaker, content-addressed filenames, and SHA-256 values
in `manifest.expansions`.

`Expanded` means all required sources and usable rows were complete. `Partial` means usable rows
exist with bounded gaps for malformed rows or partial/unavailable sibling sources. `NotExpanded`
means no authoritative artifact could be produced. An unavailable source is never converted to an
authoritative empty result.

The projections preserve service values. They do not compute severity, approval, current-clock
status, days to expiration, fuzzy matches, or comma-joined display cells. A future Office builder
may derive presentation values if it records the derivation inputs and run cutoff.

## `compliance-policy-assignments`

Rows promote `policyId`, `policyName`, `policyType`, `platform`, `assignmentCount`, `assignments`,
`passcodeRequired`, `minimumPasscodeLength`, and `encryptionRequired`. Assignments remain structured
objects; presentation code may turn their targets into display text without losing ids or filters.
The platform is derived only from the policy's Graph type discriminator.

This replaces IHA's policy, platform, target/count, passcode, and encryption input columns. It does
not interpret a missing setting as disabled or compliant.

## `conditional-access-policies`

Rows reuse TenantPulse's shared Conditional Access normalizer and promote policy identity, the
three-state normalized state, access type, included/excluded users, groups, and applications,
client-app types, platforms, locations, grant/session controls, and created/modified timestamps.
Unknown or absent Graph state is invalid provider data and creates a gap; it is not labeled
disabled. Structured condition/control objects are retained rather than flattened.

This supersedes IHA's nine-column overview while adding exclusions and exact control structures
needed by the existing Conditional Access report designs.

## `connectors-and-tokens`

The artifact is a tagged union. Every row has `sourceDataset`, `recordType`, `recordId`, `name`,
service state, version, installation/communication/expiration timestamps, Apple identifier,
machine/domain name, and `sourceColumns`. One unavailable connector/token family makes the union
`Partial`; all four unavailable makes it `NotExpanded`.

IHA's computed status and `DaysUntilExpiration` are presentation behavior. The successor preserves
the underlying service state and timestamp so a report builder can calculate a documented value at
a declared UTC cutoff.

## `directory-role-summary`

Rows are keyed by `roleDefinitionId` and promote template id, name, description, built-in and
privileged flags, permanent/active/eligible assignment counts, permanent principal ids, and the
complete structured records for each assignment family. Missing assignment families remain gaps.

This intentionally replaces the older activated-role/member-name table with the richer unified
RBAC/PIM evidence available from GraphKit 0.3.0. Principal display names and email addresses are
not invented: the stable dependency does not collect authoritative principal objects for this
report. An Office builder should display ids plus an explicit unresolved-name state until a later
version adds a verified principal-resolution operation.

## `groups-inventory`

Rows promote the legacy inventory surface: group id, display name, description, group types, mail,
mail-enabled, mail nickname, security-enabled, visibility, membership rule and processing state,
and created, renewed, and expiration timestamps. A row without an id is excluded with an explicit
gap. The complete source object remains in `sourceColumns`.

## `apple-enrollment-profiles`

Rows promote token/profile ids and names, the polymorphic Graph type, platform, enrollment modes,
authentication and Company Portal requirements, default/mandatory/location/restore flags, support
contacts, pairing mode, structured management certificates, allowed iOS enrollment types,
created/modified timestamps, and role-scope tags. `sourceColumns` and `tokenSourceColumns` preserve
the complete returned objects. Missing token/profile identities, unnamed profiles, partial child
pages, and failed siblings remain gaps.

IHA's fuzzy group-name matching is intentionally replaced with
`groupAssociationState = "NotEvaluated"`. Name similarity is not an Apple enrollment-profile
assignment relationship and is never presented as collected tenant fact. The deterministic GraphKit
descriptor and TenantPulse projection are complete; live service permission/shape proof and release
of the paired GraphKit package remain separate gates documented in
`iha-migration-and-recovery-v1.md`.
