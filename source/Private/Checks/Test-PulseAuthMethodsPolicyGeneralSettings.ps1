<#
    Private: TP.ENT.0007 rule function - authentication methods policy general settings
    (EIDSCA.AG01-AG03 port; see docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md).
    New check, T4.3 wave 2 (not part of T4.2's wave-1 EIDSCA port).

    Consumes $Datasets.authenticationMethodsPolicy directly - the RAW top-level policy
    object, NOT ConvertTo-PulseAuthMethodView (that converter normalizes entries inside the
    policy's own `authenticationMethodConfigurations` array, e.g. Fido2/Sms/Voice - a
    different, per-method slice of this same dataset. AG01-AG03 read TOP-LEVEL properties of
    the policy object itself, one Graph object backing three findings, same fan-in pattern
    Test-PulseAuthorizationPolicyDefaults.ps1 established for TP.ENT.0012).

    ABSENT PROPERTY -> ERROR (field-absence lens, matching TP.ENT.0012's own convention):
    authenticationMethodsPolicy is a real singleton resource Graph always returns fully
    populated on a modern tenant (this dataset already backs TP.ENT.0006/0008, live/not
    Pending, unlike the directorySettings dataset TP.ENT.0013/0015/0016 read) - a missing
    top-level property is an unrecognized/regressed shape, not a legitimate absent-setting
    state. Throws, same as Test-PulseAuthorizationPolicyDefaults.ps1's own
    Get-PulseRequiredProperty.

    Property mapping - verified directly against the EIDSCA config source at implementation
    time (https://raw.githubusercontent.com/Cloud-Architekt/AzureAD-Attack-Defense/AADSCAv4/config/EidscaConfig.json,
    each control's own `CurrentValue` field, which encodes the exact nested Graph property
    path - not just the `Name` field, which is a flattened pseudo-name):
        AG01 policyMigrationState                        -> want in ('migrationComplete', '') (default 'premigration'), Informational
        AG02 reportSuspiciousActivitySettings.state       -> want 'enabled' (default 'default'), Medium
        AG03 reportSuspiciousActivitySettings.includeTarget.id -> want 'all_users' (default 'all_users'), High

    GATING: AG02 (Medium) and AG03 (High) gate Status - both are meaningful security controls
    per EIDSCA's own tags. AG01 is Informational per EIDSCA's own tag (a migration-status
    signal, not itself an exploitable gap) and is evidence-only, matching TP.ENT.0012's own
    AP14 precedent for an Informational-tagged property that does not gate.
#>

function Test-PulseAuthMethodsPolicyGeneralSettings {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    $rows = @($Datasets.authenticationMethodsPolicy)
    if ($rows.Count -eq 0) {
        return New-PulseFinding -Status Fail -Reason 'No authenticationMethodsPolicy row was collected - cannot evaluate the authentication methods policy general settings.'
    }
    $policy = $rows[0]

    function Get-PulseRequiredAuthPolicyProperty {
        param($Node, [string] $PropertyName)
        $has = if ($Node -is [System.Collections.IDictionary]) { $Node.Contains($PropertyName) } else { $null -ne $Node.PSObject.Properties[$PropertyName] }
        if (-not $has) {
            throw "Test-PulseAuthMethodsPolicyGeneralSettings: authenticationMethodsPolicy has no '$PropertyName' property - cannot evaluate an unrecognized/absent-field shape."
        }
        return Get-PulseSettingsCatalogValueProperty -Node $Node -PropertyName $PropertyName
    }

    $policyMigrationState = [string] (Get-PulseRequiredAuthPolicyProperty -Node $policy -PropertyName 'policyMigrationState')

    $reportSuspiciousActivitySettings = Get-PulseRequiredAuthPolicyProperty -Node $policy -PropertyName 'reportSuspiciousActivitySettings'
    $reportState = [string] (Get-PulseRequiredAuthPolicyProperty -Node $reportSuspiciousActivitySettings -PropertyName 'state')
    $includeTarget = Get-PulseRequiredAuthPolicyProperty -Node $reportSuspiciousActivitySettings -PropertyName 'includeTarget'
    $includeTargetId = [string] (Get-PulseRequiredAuthPolicyProperty -Node $includeTarget -PropertyName 'id')

    $ag01Ok = $policyMigrationState -in @('migrationComplete', '')
    $ag02Ok = [string]::Equals($reportState, 'enabled', [System.StringComparison]::Ordinal)
    $ag03Ok = [string]::Equals($includeTargetId, 'all_users', [System.StringComparison]::Ordinal)

    $evidence = @(
        @{ Identity = 'EIDSCA.AG01'; Detail = @{ setting = 'policyMigrationState'; value = $policyMigrationState; expected = @('migrationComplete', ''); severity = 'Informational'; ok = $ag01Ok } }
        @{ Identity = 'EIDSCA.AG02'; Detail = @{ setting = 'reportSuspiciousActivitySettings.state'; value = $reportState; expected = 'enabled'; severity = 'Medium'; ok = $ag02Ok } }
        @{ Identity = 'EIDSCA.AG03'; Detail = @{ setting = 'reportSuspiciousActivitySettings.includeTarget.id'; value = $includeTargetId; expected = 'all_users'; severity = 'High'; ok = $ag03Ok } }
    )

    $gapReasons = [System.Collections.Generic.List[string]]::new()
    if (-not $ag02Ok) {
        $gapReasons.Add("Suspicious sign-in-attempt reporting from the Authenticator app/voice calls is not enabled (reportSuspiciousActivitySettings.state = '$reportState', not 'enabled', EIDSCA.AG02).")
    }
    if (-not $ag03Ok) {
        $gapReasons.Add("Suspicious-activity reporting is scoped to '$includeTargetId', not all users (EIDSCA.AG03).")
    }

    if ($gapReasons.Count -gt 0) {
        return New-PulseFinding -Status Fail -Reason ($gapReasons -join ' ') -Evidence $evidence
    }

    return New-PulseFinding -Status Pass -Reason "Suspicious sign-in-attempt reporting is enabled and scoped to all users (EIDSCA.AG02/AG03); migration state is $(if ($ag01Ok) { 'complete or never customized' } else { "'$policyMigrationState'" }) (EIDSCA.AG01, informational)." -Evidence $evidence
}
