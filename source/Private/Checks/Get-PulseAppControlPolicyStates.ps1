<#
    Private: classify every App Control for Business policy visible in
    Part A's settingPresenceIndex, for TP.INT.0017 (enforce + active control)
    and TP.INT.0018 (that same bar AND Managed Installer enabled).

    SAME-POLICY AND, not a tenant-wide union: Maester MT.1179/MT.1180 Pass only
    when enforce + active control (+ Managed Installer for 0018) land on ONE
    policy. A tenant that audits on policy A and uploads empty XML on policy B
    must Fail. Get-PulseSettingPresenceMatchingPolicies supplies the per-value
    policyIds the presence index now keeps; this function intersects them.

    CORPUS-VERIFIED definitionIds / option itemIds (live capture
    scratch/live-27/snapshot/reference/settingDefinitions.json, 18,227
    definitions). Maester's own source keys two STRINGS THAT DO NOT EXIST
    in that capture:
      - XML payload: Maester `...applicationcontrolv2_policy` - LIVE id is
        `...applicationcontrolv2_xmlupload`
      - upload choice: Maester `*upload_policy_selected` - LIVE itemId is
        `...buildoptions_upload_xml_selected`
    Ported against the live ids, not the dead Maester literals. Built-in
    controls (`...buildoptions_built_in_controls_selected`) and audit-mode
    (`...auditmode_disabled` = Enforce, `...auditmode_enabled` = Audit)
    match Maester and the corpus.

    visibility:"template" on these definitions is live-confirmed in that
    same capture. Microsoft's published Graph schema docs still omit the
    property. Implementation keys the live ids, not the unpublished field.

    ASSIGNMENT: Settings Catalog rows still carry assignments:null (G-gate).
    Matching Maester, existence of the policy is enough - this classifier
    uses policyIds, not assignedPolicyIds. An unassigned App Control
    policy still Passes the same way Maester's template-family fetch does.

    XML emptiness: a non-empty string is active control for an upload
    policy. A redacted XML value on an upload policy is NOT treated as
    present (fail-closed) - the caller Warns instead of Pass.

    FAMILY: settingsCatalog only. These definitions are template-surface
    App Control settings, not compliance/deviceConfiguration CSPs.
#>

function Get-PulseAppControlOrdinalIdSet {
    param([object[]] $Ids)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($id in @($Ids)) {
        if (-not [string]::IsNullOrEmpty([string] $id)) {
            [void] $set.Add([string] $id)
        }
    }
    return , $set
}

function Get-PulseAppControlPolicyStates {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Artifact
    )

    $buildOptionsId = 'device_vendor_msft_policy_config_applicationcontrolv2_buildoptions'
    $auditModeId = 'device_vendor_msft_policy_config_applicationcontrolv2_auditmode'
    $xmlUploadId = 'device_vendor_msft_policy_config_applicationcontrolv2_xmlupload'
    $managedInstallerId = 'device_vendor_msft_policy_config_applicationcontrolv2_trustappsfrommanagedinstaller'

    $builtInItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_buildoptions_built_in_controls_selected'
    $uploadItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_buildoptions_upload_xml_selected'
    $auditEnabledItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_auditmode_enabled'
    $auditDisabledItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_auditmode_disabled'
    $miEnabledItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_trustappsfrommanagedinstaller_enabled'
    $miDisabledItemId = 'device_vendor_msft_policy_config_applicationcontrolv2_trustappsfrommanagedinstaller_disabled'

    $eq = {
        param($expected)
        return {
            param($value)
            return [string] $value -eq $expected
        }.GetNewClosure()
    }

    $xmlNonEmpty = {
        param($value)
        return -not [string]::IsNullOrWhiteSpace([string] $value)
    }

    $family = 'settingsCatalog'
    $builtIn = Get-PulseSettingPresenceMatchingPolicies -Artifact $Artifact -Family $family -DefinitionId $buildOptionsId -IsSatisfyingValue (& $eq $builtInItemId)
    $upload = Get-PulseSettingPresenceMatchingPolicies -Artifact $Artifact -Family $family -DefinitionId $buildOptionsId -IsSatisfyingValue (& $eq $uploadItemId)
    $enforcing = Get-PulseSettingPresenceMatchingPolicies -Artifact $Artifact -Family $family -DefinitionId $auditModeId -IsSatisfyingValue (& $eq $auditDisabledItemId)
    $auditOnly = Get-PulseSettingPresenceMatchingPolicies -Artifact $Artifact -Family $family -DefinitionId $auditModeId -IsSatisfyingValue (& $eq $auditEnabledItemId)
    $xmlPresent = Get-PulseSettingPresenceMatchingPolicies -Artifact $Artifact -Family $family -DefinitionId $xmlUploadId -IsSatisfyingValue $xmlNonEmpty
    $miEnabled = Get-PulseSettingPresenceMatchingPolicies -Artifact $Artifact -Family $family -DefinitionId $managedInstallerId -IsSatisfyingValue (& $eq $miEnabledItemId)
    $miDisabled = Get-PulseSettingPresenceMatchingPolicies -Artifact $Artifact -Family $family -DefinitionId $managedInstallerId -IsSatisfyingValue (& $eq $miDisabledItemId)

    $anyUnknownAssignment = [bool] $builtIn.AnyUnknownAssignment -or
        [bool] $upload.AnyUnknownAssignment -or
        [bool] $enforcing.AnyUnknownAssignment -or
        [bool] $auditOnly.AnyUnknownAssignment -or
        [bool] $xmlPresent.AnyUnknownAssignment -or
        [bool] $miEnabled.AnyUnknownAssignment -or
        [bool] $miDisabled.AnyUnknownAssignment

    $allIds = Get-PulseAppControlOrdinalIdSet @(
        $builtIn.MatchingPolicyIds + $upload.MatchingPolicyIds +
        $enforcing.MatchingPolicyIds + $auditOnly.MatchingPolicyIds +
        $xmlPresent.MatchingPolicyIds + $xmlPresent.RedactedPolicyIds +
        $miEnabled.MatchingPolicyIds + $miDisabled.MatchingPolicyIds +
        $builtIn.RedactedPolicyIds + $upload.RedactedPolicyIds +
        $enforcing.RedactedPolicyIds + $auditOnly.RedactedPolicyIds +
        $miEnabled.RedactedPolicyIds + $miDisabled.RedactedPolicyIds
    )

    $builtInSet = Get-PulseAppControlOrdinalIdSet $builtIn.MatchingPolicyIds
    $uploadSet = Get-PulseAppControlOrdinalIdSet $upload.MatchingPolicyIds
    $enforcingSet = Get-PulseAppControlOrdinalIdSet $enforcing.MatchingPolicyIds
    $auditOnlySet = Get-PulseAppControlOrdinalIdSet $auditOnly.MatchingPolicyIds
    $xmlPresentSet = Get-PulseAppControlOrdinalIdSet $xmlPresent.MatchingPolicyIds
    $xmlRedactedSet = Get-PulseAppControlOrdinalIdSet $xmlPresent.RedactedPolicyIds
    $miEnabledSet = Get-PulseAppControlOrdinalIdSet $miEnabled.MatchingPolicyIds
    $miDisabledSet = Get-PulseAppControlOrdinalIdSet $miDisabled.MatchingPolicyIds
    $buildRedactedSet = Get-PulseAppControlOrdinalIdSet (@($builtIn.RedactedPolicyIds) + @($upload.RedactedPolicyIds))
    $auditRedactedSet = Get-PulseAppControlOrdinalIdSet (@($enforcing.RedactedPolicyIds) + @($auditOnly.RedactedPolicyIds))
    $miRedactedSet = Get-PulseAppControlOrdinalIdSet (@($miEnabled.RedactedPolicyIds) + @($miDisabled.RedactedPolicyIds))

    $sortedIds = @($allIds)
    [System.Array]::Sort($sortedIds, [System.StringComparer]::Ordinal)

    $policies = foreach ($policyId in $sortedIds) {
        $isBuiltIn = $builtInSet.Contains($policyId)
        $isUpload = $uploadSet.Contains($policyId)
        $xmlKnownPresent = $xmlPresentSet.Contains($policyId)
        $xmlRedacted = $xmlRedactedSet.Contains($policyId)
        $hasActiveControl = $isBuiltIn -or ($isUpload -and $xmlKnownPresent)
        $activeControlUnknown = (-not $hasActiveControl) -and (
            $buildRedactedSet.Contains($policyId) -or
            ($isUpload -and $xmlRedacted)
        )

        $buildOptions = if ($isBuiltIn) { 'built-in' } elseif ($isUpload) { 'xml-upload' } elseif ($buildRedactedSet.Contains($policyId)) { 'redacted' } else { 'not-configured' }
        $auditMode = if ($enforcingSet.Contains($policyId)) { 'enforce' } elseif ($auditOnlySet.Contains($policyId)) { 'audit' } elseif ($auditRedactedSet.Contains($policyId)) { 'redacted' } else { 'not-configured' }
        $managedInstaller = if ($miEnabledSet.Contains($policyId)) { 'enabled' } elseif ($miDisabledSet.Contains($policyId)) { 'disabled' } elseif ($miRedactedSet.Contains($policyId)) { 'redacted' } else { 'not-configured' }

        [pscustomobject]@{
            PolicyId                 = $policyId
            BuildOptions             = $buildOptions
            AuditMode                = $auditMode
            ManagedInstaller         = $managedInstaller
            Enforcing                = $enforcingSet.Contains($policyId)
            HasActiveControl         = $hasActiveControl
            ActiveControlUnknown     = $activeControlUnknown
            XmlPresent               = $xmlKnownPresent
            XmlRedacted              = $xmlRedacted
            AuditRedacted            = $auditRedactedSet.Contains($policyId)
            BuildRedacted            = $buildRedactedSet.Contains($policyId)
            ManagedInstallerRedacted = $miRedactedSet.Contains($policyId)
        }
    }

    return [pscustomobject]@{
        Policies             = @($policies)
        AnyUnknownAssignment = $anyUnknownAssignment
        AnyAppControlPresent = $builtIn.Present -or $upload.Present -or $enforcing.Present -or $auditOnly.Present -or $xmlPresent.Present -or $miEnabled.Present -or $miDisabled.Present
    }
}
