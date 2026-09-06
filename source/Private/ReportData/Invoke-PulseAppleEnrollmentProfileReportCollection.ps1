<#
    Graph-backed Apple Automated Device Enrollment profile report collection.

    The parent DEP-token collection is already a hash-verified snapshot dataset. Graph
    exposes the profiles only as a beta child collection below each token, so this producer
    reads the stored token evidence and performs one GraphKit-owned, read-only operation per
    valid token. The output is neutral schema-v1 JSONL for later Office rendering.

    IHA's fuzzy comparison between profile names and group names is intentionally not
    reproduced. It was a presentation inference, not an assignment relationship. This
    artifact preserves the service-returned profile and token fields and records
    groupAssociationState = NotEvaluated so a renderer cannot mistake a name similarity for
    tenant configuration.
#>

$script:PulseAppleEnrollmentProfileReportOperations = @(
    [pscustomobject]@{
        Type = 'AppleEnrollmentProfile'; Operation = 'ListByToken'; ApiVersion = 'beta'
        PagingStrategy = 'NextLink'
    }
)

function Get-PulseAppleEnrollmentProfileReportOperations {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return @($script:PulseAppleEnrollmentProfileReportOperations | ForEach-Object {
            [pscustomobject]@{
                Type = $_.Type; Operation = $_.Operation; ApiVersion = $_.ApiVersion
                PagingStrategy = $_.PagingStrategy
            }
        })
}

function Get-PulseAppleEnrollmentProfilePlatform {
    param([AllowNull()] $Profile)

    $platform = Get-PulseReportValue -InputObject $Profile -Name @('platform')
    if (-not [string]::IsNullOrWhiteSpace([string] $platform)) { return $platform }

    $profileType = ConvertTo-PulseTargetType -Value (Get-PulseReportValue -InputObject $Profile -Name @('@odata.type'))
    switch -Regex ($profileType) {
        '(?i)macos' { return 'macOS' }
        '(?i)tvos' { return 'tvOS' }
        '(?i)ios' { return 'iOS' }
        default { return $null }
    }
}

function New-PulseAppleEnrollmentProfileRow {
    param(
        [Parameter(Mandatory)] $Token,
        [Parameter(Mandatory)] $Profile
    )

    $managementCertificates = @(Get-PulseReportValue -InputObject $Profile -Name @('managementCertificates'))
    return [pscustomobject][ordered]@{
        schemaVersion                                = '1'
        tokenId                                      = Get-PulseReportValue -InputObject $Token -Name @('id')
        tokenName                                    = Get-PulseReportValue -InputObject $Token -Name @('tokenName', 'displayName')
        profileId                                    = Get-PulseReportValue -InputObject $Profile -Name @('id')
        profileName                                  = Get-PulseReportValue -InputObject $Profile -Name @('displayName')
        description                                  = Get-PulseReportValue -InputObject $Profile -Name @('description')
        profileType                                  = ConvertTo-PulseTargetType -Value (Get-PulseReportValue -InputObject $Profile -Name @('@odata.type'))
        platform                                     = Get-PulseAppleEnrollmentProfilePlatform -Profile $Profile
        enrollmentType                               = Get-PulseReportValue -InputObject $Profile -Name @('enrollmentType')
        defaultIosUserEnrollmentType                 = Get-PulseReportValue -InputObject $Profile -Name @('defaultIosUserEnrollmentType')
        requiresUserAuthentication                   = Get-PulseReportValue -InputObject $Profile -Name @('requiresUserAuthentication')
        requireCompanyPortalOnSetupAssistant         = Get-PulseReportValue -InputObject $Profile -Name @(
            'requireCompanyPortalOnSetupAssistant',
            'requireCompanyPortalOnSetupAssistantEnrolledDevices',
            'enableAuthenticationViaCompanyPortal'
        )
        isDefault                                    = Get-PulseReportValue -InputObject $Profile -Name @('isDefault')
        isMandatory                                  = Get-PulseReportValue -InputObject $Profile -Name @('isMandatory')
        locationDisabled                             = Get-PulseReportValue -InputObject $Profile -Name @('locationDisabled')
        supportPhoneNumber                           = Get-PulseReportValue -InputObject $Profile -Name @('supportPhoneNumber')
        supportEmailAddress                          = Get-PulseReportValue -InputObject $Profile -Name @('supportEmailAddress')
        iTunesPairingMode                            = Get-PulseReportValue -InputObject $Profile -Name @('iTunesPairingMode')
        managementCertificates                       = @($managementCertificates | ForEach-Object { ConvertTo-PulseReportSourceMap -InputObject $_ })
        managementCertificateCount                  = $managementCertificates.Count
        restoreBlocked                               = Get-PulseReportValue -InputObject $Profile -Name @('restoreBlocked')
        iOSUserEnrollmentTypesAllowed                = @(Get-PulseReportValue -InputObject $Profile -Name @('iOSUserEnrollmentTypesAllowed'))
        createdDateTime                              = Get-PulseReportValue -InputObject $Profile -Name @('createdDateTime')
        lastModifiedDateTime                         = Get-PulseReportValue -InputObject $Profile -Name @('lastModifiedDateTime')
        roleScopeTagIds                              = @(Get-PulseReportValue -InputObject $Profile -Name @('roleScopeTagIds'))
        groupAssociationState                        = 'NotEvaluated'
        sourceColumns                                = ConvertTo-PulseReportSourceMap -InputObject $Profile
        tokenSourceColumns                           = ConvertTo-PulseReportSourceMap -InputObject $Token
    }
}

function Set-PulseAppleEnrollmentProfileReportUnavailable {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Store,
        [Parameter(Mandatory)] [string] $ReasonCode,
        [Parameter(Mandatory)] [string] $ProfileId,
        [Parameter(Mandatory)] [string] $Pseudonym,
        [AllowNull()] [string] $TenantId
    )

    $reason = Protect-PulseReason -Message "apple-enrollment-profiles: $ReasonCode" `
        -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $TenantId
    Set-PulseExpansionEntry -Store $Store -Name 'apple-enrollment-profiles' -Status NotExpanded -Reason $reason
    return [pscustomobject]@{ Status = 'NotExpanded'; RowCount = 0; Gaps = @() }
}

function Invoke-PulseAppleEnrollmentProfileReportCollection {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Store,
        [Parameter(Mandatory)] [pscustomobject] $Context,
        [Parameter(Mandatory)] $AuthorizationDecision,
        [Parameter(Mandatory)] [pscustomobject] $NetworkAbortState,
        [Parameter(Mandatory)] [string] $ProfileId,
        [Parameter(Mandatory)] [string] $Pseudonym
    )

    $tenantId = if ($Context.PSObject.Properties['TenantId']) { [string] $Context.TenantId } else { $null }
    $manifest = Get-PulseSnapshotManifest -Store $Store
    $tokenSource = Get-PulseAuditReportDatasetState -Store $Store -Manifest $manifest -Name 'depOnboardingSettings'
    if (-not $tokenSource.Available) {
        return Set-PulseAppleEnrollmentProfileReportUnavailable -Store $Store -ReasonCode "source-$($tokenSource.ReasonCode)" `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
    }

    $operations = @(Get-PulseAppleEnrollmentProfileReportOperations)
    $spec = $operations[0]
    try {
        $descriptor = Assert-PulseReadOnlyDescriptor -Type $spec.Type -Operation $spec.Operation `
            -ApiVersion $spec.ApiVersion -PassThru
        if ($null -eq $descriptor -or [string] $descriptor.PagingStrategy -ne $spec.PagingStrategy) {
            return Set-PulseAppleEnrollmentProfileReportUnavailable -Store $Store -ReasonCode 'descriptor-paging-drift' `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        }
    } catch {
        return Set-PulseAppleEnrollmentProfileReportUnavailable -Store $Store -ReasonCode 'descriptor-unavailable' `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
    }

    $authorization = Get-PulseReportAuthorization -AuthorizationDecision $AuthorizationDecision -Operations $operations
    if ($NetworkAbortState.AuthenticationAborted -or $authorization.Decision -ne 'Granted') {
        $reasonCode = if ($NetworkAbortState.AuthenticationAborted) { 'authentication-failed' } else { [string] $authorization.ReasonCode }
        return Set-PulseAppleEnrollmentProfileReportUnavailable -Store $Store -ReasonCode "permission-$reasonCode" `
            -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
    }

    $tokens = @($tokenSource.Rows)
    $rows = [System.Collections.Generic.List[object]]::new()
    $gaps = [System.Collections.Generic.List[object]]::new()
    if ($tokenSource.Status -eq 'Partial') {
        $gaps.Add((New-PulseReportGap -Scope 'depOnboardingSettings' -ReasonCode 'source-dataset-partial' -Operation 'AppleEnrollmentProfile.ListByToken')) | Out-Null
    }

    $tokenIndex = 0
    foreach ($token in $tokens) {
        $tokenIndex++
        $tokenId = [string] (Get-PulseReportValue -InputObject $token -Name @('id'))
        if ([string]::IsNullOrWhiteSpace($tokenId)) {
            $gaps.Add((New-PulseReportGap -Scope "dep-token-$tokenIndex" -ReasonCode 'invalid-provider-data' -Operation 'AppleEnrollmentProfile.ListByToken')) | Out-Null
            continue
        }
        if ($NetworkAbortState.AuthenticationAborted) {
            $gaps.Add((New-PulseReportGap -Scope $tokenId -ReasonCode 'authentication-failed' -Operation 'AppleEnrollmentProfile.ListByToken')) | Out-Null
            continue
        }

        $outcome = Invoke-PulseReportGraphOperation -Context $Context -Spec $spec `
            -Dataset 'apple-enrollment-profiles' -Parameters @{ depOnboardingSettingId = $tokenId }
        if ($outcome.FailureClass -eq 'AuthenticationFailed') {
            Set-PulseReportAuthenticationAbort -Store $Store -NetworkAbortState $NetworkAbortState `
                -ProfileId $ProfileId -Pseudonym $Pseudonym -TenantId $tenantId
        }
        if ($outcome.Status -eq 'Failed') {
            $gaps.Add((New-PulseReportGap -Scope $tokenId -ReasonCode $outcome.ReasonCode -Operation 'AppleEnrollmentProfile.ListByToken')) | Out-Null
            continue
        }
        if ($outcome.Status -eq 'Partial') {
            $gaps.Add((New-PulseReportGap -Scope $tokenId -ReasonCode $outcome.ReasonCode -Operation 'AppleEnrollmentProfile.ListByToken')) | Out-Null
        }

        $profileIndex = 0
        foreach ($profile in @($outcome.Rows)) {
            $profileIndex++
            $currentProfileId = [string] (Get-PulseReportValue -InputObject $profile -Name @('id'))
            if ([string]::IsNullOrWhiteSpace($currentProfileId)) {
                $gaps.Add((New-PulseReportGap -Scope "$tokenId/profile-$profileIndex" -ReasonCode 'invalid-provider-data' -Operation 'AppleEnrollmentProfile.ListByToken')) | Out-Null
                continue
            }
            if ([string]::IsNullOrWhiteSpace([string] (Get-PulseReportValue -InputObject $profile -Name @('displayName')))) {
                $gaps.Add((New-PulseReportGap -Scope "$tokenId/$currentProfileId" -ReasonCode 'profile-name-missing' -Operation 'AppleEnrollmentProfile.ListByToken')) | Out-Null
            }
            $rows.Add((New-PulseAppleEnrollmentProfileRow -Token $token -Profile $profile)) | Out-Null
        }
    }

    try {
        return Publish-PulseAuditReportRows -Store $Store -Name 'apple-enrollment-profiles' `
            -Rows $rows.ToArray() -Gaps $gaps.ToArray() -SourceCount $tokens.Count `
            -SortProperties @('tokenId', 'profileId', 'profileName') -ProfileId $ProfileId `
            -Pseudonym $Pseudonym -TenantId $tenantId
    } catch {
        $reason = Protect-PulseReason -Message 'artifact-publication-failed' -ProfileId $ProfileId `
            -Pseudonym $Pseudonym -TenantId $tenantId
        Set-PulseExpansionEntry -Store $Store -Name 'apple-enrollment-profiles' -Status Failed -Reason $reason
        return [pscustomobject]@{ Status = 'Failed'; RowCount = 0; Gaps = @() }
    }
}
