<#
    Private: TP.ENT.0019 rule function - application/service-principal credential hygiene
    (ScuBA MS.AAD.5.6v1: password credential lifetime SHOULD be <=180 days; MS.AAD.5.7v1:
    certificate credential lifetime SHOULD be <=365 days). See
    docs/research/iha-v2/2026-08-16-phase4-entra-check-entries.md#tpent0019.

    SCOPE, HONEST AND NARROWER THAN THE RESEARCH ENTRY (not silently dropped - see this
    check's own descriptor Consulting text and DatasetMap.psd1's own servicePrincipals
    entry docstring): the research entry's Data section names BOTH
    v1.0/applications and v1.0/servicePrincipals. GraphKit 0.1.1's installed catalog has no
    'Application' Type at all (confirmed via Get-GraphOperation -List at implementation
    time) - only ServicePrincipal.List exists. This check therefore evaluates SERVICE
    PRINCIPAL credentials only; app-REGISTRATION credential hygiene rides as a descriptor
    need for a future GraphKit release (see the T4.4 report). A tenant's app registrations
    with long-lived secrets are NOT visible to this check yet - that gap is named in
    Consulting.WhatItMeans, not hidden behind an apparently-complete Pass.

    SCALABILITY GUARDRAIL (omp HIGH, plan's own Task 4.4 note): the credential dataset can
    be large on real tenants with heavy service-principal sprawl. This evaluator NEVER
    materializes an unbounded per-credential evidence array - evidence is CAPPED to the
    $script:EvidenceCap worst offenders (longest-overdue lifetime, descending), with the
    total offending-credential count and total-evaluated-credential count always stated in
    Reason regardless of how many rows evidence actually carries. The collector's own
    servicePrincipals dataset itself still pages/collects normally (GraphKit's List
    operation handles paging) - only the EVALUATOR'S evidence projection is capped.

    THRESHOLDS: a passwordCredential is offending when its lifetime (endDateTime -
    startDateTime) exceeds 180 days; a keyCredential (certificate) is offending when its
    lifetime exceeds 365 days. A credential missing EITHER startDateTime or endDateTime
    cannot have its lifetime computed - flagged separately as "unparseable", never silently
    skipped and never counted as offending (a genuinely unmeasurable lifetime is not the
    same claim as "measured and found compliant"). SHOULD-tier severity (High per this
    check's own descriptor, but explicitly SHOULD not SHALL, per the research entry's own
    Notes) - reflected in Consulting tone, not in a lower Severity, since a leaked long-lived
    app-only secret is a genuinely serious, durable exposure even though ScuBA itself does
    not mandate it.
#>

function Test-PulseAppCredentialHygiene {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets
    )

    # Default cap on evidence rows - stated in this check's own descriptor
    # (TP.ENT.0019.psd1's Consulting.WhatItMeans) and in every Reason this function
    # produces, per the plan's own scalability-guardrail requirement.
    $evidenceCap = 50
    $passwordMaxDays = 180
    $certMaxDays = 365

    $servicePrincipals = @($Datasets.servicePrincipals)

    function Get-PulseCredentialLifetimeDays {
        param($Credential)
        $start = Get-PulseSettingsCatalogValueProperty -Node $Credential -PropertyName 'startDateTime'
        $end = Get-PulseSettingsCatalogValueProperty -Node $Credential -PropertyName 'endDateTime'
        if ([string]::IsNullOrEmpty([string] $start) -or [string]::IsNullOrEmpty([string] $end)) {
            return $null
        }
        try {
            $startDate = [datetimeoffset]::Parse([string] $start, [System.Globalization.CultureInfo]::InvariantCulture)
            $endDate = [datetimeoffset]::Parse([string] $end, [System.Globalization.CultureInfo]::InvariantCulture)
        } catch {
            return $null
        }
        return [math]::Round(($endDate - $startDate).TotalDays, 1)
    }

    $offenders = [System.Collections.Generic.List[pscustomobject]]::new()
    $unparseable = [System.Collections.Generic.List[pscustomobject]]::new()
    $totalCredentials = 0

    foreach ($sp in $servicePrincipals) {
        $spId = [string] (Get-PulseSettingsCatalogValueProperty -Node $sp -PropertyName 'id')
        $spName = [string] (Get-PulseSettingsCatalogValueProperty -Node $sp -PropertyName 'displayName')

        # BARE ASSIGNMENT, NO OUTER @() WRAP (reproduced live, see this file's own test
        # coverage): Get-PulseSettingsCatalogValueProperty already comma-protects an
        # array-typed return as ONE pipeline object (see that function's own ARRAY-RETURN
        # UNROLLING TRAP docstring) - wrapping the call site itself in @() re-collects that
        # single already-array-shaped pipeline object into a ONE-ELEMENT array WHOSE SOLE
        # ELEMENT is the original array (double-nesting), not the flat array a caller
        # expects. A bare assignment captures the single pipeline object (the array) as-is;
        # @() is applied separately to normalize a genuinely absent ($null) property into
        # an empty array, matching ConvertTo-PulseCaPolicyView's own ConvertTo-StringArray
        # convention.
        $passwordCredsRaw = Get-PulseSettingsCatalogValueProperty -Node $sp -PropertyName 'passwordCredentials'
        $passwordCreds = if ($null -eq $passwordCredsRaw) { @() } else { $passwordCredsRaw }
        foreach ($cred in $passwordCreds) {
            if ($null -eq $cred) { continue }
            $totalCredentials++
            $lifetimeDays = Get-PulseCredentialLifetimeDays -Credential $cred
            $keyId = [string] (Get-PulseSettingsCatalogValueProperty -Node $cred -PropertyName 'keyId')
            if ($null -eq $lifetimeDays) {
                $unparseable.Add([pscustomobject]@{ ServicePrincipalId = $spId; ServicePrincipalName = $spName; KeyId = $keyId; CredentialType = 'password' })
                continue
            }
            if ($lifetimeDays -gt $passwordMaxDays) {
                $offenders.Add([pscustomobject]@{
                    ServicePrincipalId   = $spId
                    ServicePrincipalName = $spName
                    KeyId                = $keyId
                    CredentialType       = 'password'
                    LifetimeDays         = $lifetimeDays
                    MaxAllowedDays       = $passwordMaxDays
                })
            }
        }

        $keyCredsRaw = Get-PulseSettingsCatalogValueProperty -Node $sp -PropertyName 'keyCredentials'
        $keyCreds = if ($null -eq $keyCredsRaw) { @() } else { $keyCredsRaw }
        foreach ($cred in $keyCreds) {
            if ($null -eq $cred) { continue }
            $totalCredentials++
            $lifetimeDays = Get-PulseCredentialLifetimeDays -Credential $cred
            $keyId = [string] (Get-PulseSettingsCatalogValueProperty -Node $cred -PropertyName 'keyId')
            if ($null -eq $lifetimeDays) {
                $unparseable.Add([pscustomobject]@{ ServicePrincipalId = $spId; ServicePrincipalName = $spName; KeyId = $keyId; CredentialType = 'certificate' })
                continue
            }
            if ($lifetimeDays -gt $certMaxDays) {
                $offenders.Add([pscustomobject]@{
                    ServicePrincipalId   = $spId
                    ServicePrincipalName = $spName
                    KeyId                = $keyId
                    CredentialType       = 'certificate'
                    LifetimeDays         = $lifetimeDays
                    MaxAllowedDays       = $certMaxDays
                })
            }
        }
    }

    $sortedOffenders = @($offenders | Sort-Object -Property @{ Expression = { $_.LifetimeDays - $_.MaxAllowedDays } } -Descending)
    $cappedOffenders = @($sortedOffenders | Select-Object -First $evidenceCap)

    $totalOffenders = $sortedOffenders.Count
    $totalUnparseable = $unparseable.Count

    $capNote = if ($totalOffenders -gt $evidenceCap) { " (evidence capped to the $evidenceCap worst offenders by degree-over-threshold; $($totalOffenders - $evidenceCap) additional offending credential(s) not itemized)" } else { '' }

    if ($totalOffenders -eq 0) {
        $reason = "No service principal credential exceeds ScuBA's lifetime guidance (password <=$passwordMaxDays days, certificate <=$certMaxDays days) across $totalCredentials credential(s) on $($servicePrincipals.Count) service principal(s) evaluated."
        if ($totalUnparseable -gt 0) {
            $reason += " $totalUnparseable credential(s) had an unparseable start/end date and could not be evaluated."
        }
        return New-PulseFinding -Status Pass -Reason $reason
    }

    $evidence = @($cappedOffenders | ForEach-Object {
        @{
            Identity = "$($_.ServicePrincipalId):$($_.KeyId)"
            Detail   = @{
                servicePrincipalName = $_.ServicePrincipalName
                credentialType       = $_.CredentialType
                lifetimeDays         = $_.LifetimeDays
                maxAllowedDays       = $_.MaxAllowedDays
            }
        }
    })

    $reason = "$totalOffenders of $totalCredentials evaluated service principal credential(s) exceed ScuBA's lifetime guidance (password <=$passwordMaxDays days, certificate <=$certMaxDays days)$capNote."
    if ($totalUnparseable -gt 0) {
        $reason += " $totalUnparseable additional credential(s) had an unparseable start/end date and could not be evaluated."
    }

    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
}
