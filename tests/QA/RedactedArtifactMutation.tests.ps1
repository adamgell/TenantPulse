<#
    QA gate: mutation canaries for TenantPulse 1.0 classified artifacts (TP9A).

    Inserts identity-shaped, secret-shaped, policy-label, path, markup, and safe
    technical values into every 1.0 privacy class and tenant-derived field. Asserts
    both protection (identity/secret never leak) and retained remediation value
    (labels, counts, reviewed text survive). Synthetic keys live only under the test
    temp root. No live tenant, vault, or configured-key operations.
#>

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    $script:CanaryIdentity = 'canary.user@tenantpulse.test'
    $script:CanarySecret = 'eyJhbGciOiJub25lIn0.eyJjYW5hcnkiOiIxIn0.x'
    $script:CanaryPolicyLabel = 'Require MFA for all users'
    $script:CanaryPath = 'C:\Users\canary\AppData\Local\TenantPulse\snapshot'
    $script:CanaryMarkup = '<script>alert("canary")</script>'
    $script:CanaryRelativePath = 'expanded/settingsCatalog.json'
    $script:KeyBytes = [byte[]] (1 .. 32)
}

Describe 'privacy class mutation matrix' {
    BeforeAll {
        $script:classes = InModuleScope TenantPulse { Get-PulsePrivacyClasses }
        $script:canaries = @{
            IdentityShaped = $script:CanaryIdentity
            SecretShaped   = $script:CanarySecret
            PolicyLabel    = $script:CanaryPolicyLabel
            UnsafePath     = $script:CanaryPath
            Markup         = $script:CanaryMarkup
            SafeCount      = 7
            RelativePath   = $script:CanaryRelativePath
        }
    }

    It 'rejects identity, secret, path, and markup canaries in SafeTechnical and SafeOperatorLabel' {
        $identity = $script:CanaryIdentity
        $secret = $script:CanarySecret
        $path = $script:CanaryPath
        $markup = $script:CanaryMarkup
        InModuleScope TenantPulse -ArgumentList $identity, $secret, $path, $markup {
            param($Identity, $Secret, $PathValue, $Markup)
            foreach ($className in @('SafeTechnical', 'SafeOperatorLabel')) {
                foreach ($value in @($Identity, $Secret, $PathValue, $Markup)) {
                    { New-PulseClassifiedValue -Class $className -Value $value } |
                        Should -Throw -ExpectedMessage '*not valid for privacy class*'
                }
            }
        }
    }

    It 'rejects identity and secret canaries in BoundedReviewedText' {
        $identity = $script:CanaryIdentity
        $secret = $script:CanarySecret
        InModuleScope TenantPulse -ArgumentList $identity, $secret {
            param($Identity, $Secret)
            { New-PulseClassifiedValue -Class 'BoundedReviewedText' -Value $Identity } |
                Should -Throw -ExpectedMessage '*not valid for privacy class*'
            { New-PulseClassifiedValue -Class 'BoundedReviewedText' -Value $Secret } |
                Should -Throw -ExpectedMessage '*not valid for privacy class*'
        }
    }

    It 'protects identity and secret canaries when they are classified correctly' {
        $identity = $script:CanaryIdentity
        $secret = $script:CanarySecret
        $key = $script:KeyBytes
        $result = InModuleScope TenantPulse -ArgumentList $identity, $secret, $key {
            param($Identity, $Secret, $Key)
            [pscustomobject]@{
                Identity = New-PulseClassifiedValue -Class 'Identity' -Value $Identity -OperatorKey $Key
                Secret   = New-PulseClassifiedValue -Class 'SecretSensitive' -Value $Secret
            }
        }

        $result.Identity.Value | Should -Not -Be $identity
        $result.Identity.Value | Should -Match '^tp-[a-f0-9]{64}$'
        $result.Secret.Value.redacted | Should -BeTrue
    }

    It 'retains policy-label, relative path, count, and reviewed markup under their classes' {
        $label = $script:CanaryPolicyLabel
        $relative = $script:CanaryRelativePath
        $markup = $script:CanaryMarkup
        $result = InModuleScope TenantPulse -ArgumentList $label, $relative, $markup {
            param($Label, $Relative, $Markup)
            [pscustomobject]@{
                Label    = New-PulseClassifiedValue -Class 'SafeOperatorLabel' -Value $Label
                Path     = New-PulseClassifiedValue -Class 'SafeTechnical' -Value $Relative
                Count    = New-PulseClassifiedValue -Class 'SafeTechnical' -Value 7
                Reviewed = New-PulseClassifiedValue -Class 'BoundedReviewedText' -Value $Markup
                Html     = ConvertTo-PulseHtmlEncodedText -Text $Markup
            }
        }

        $result.Label.Value | Should -Be $label
        $result.Path.Value | Should -Be $relative
        $result.Count.Value | Should -Be 7
        $result.Reviewed.Value | Should -Be $markup
        $result.Html | Should -Not -Match '<script>'
    }
}

Describe 'finding / gap / error / sort-key / JSON mutation' {
    It 'fails closed when any planted unclassified canary reaches safe-share JSON' {
        $identity = $script:CanaryIdentity
        $key = $script:KeyBytes
        {
            InModuleScope TenantPulse -ArgumentList $identity, $key {
                param($Identity, $Key)
                $document = [pscustomobject]@{
                    schemaVersion = '1.0'
                    findings      = @(
                        [pscustomobject]@{
                            id         = 'TP.ENT.0004'
                            reason     = 'legacy auth is not blocked'
                            reasonCode = 'legacy-auth-unblocked'
                            evidence   = @(
                                [pscustomobject]@{
                                    identity     = 'policy-1'
                                    sortKey      = 'policy-1'
                                    detail       = [pscustomobject]@{ guest = $Identity }
                                    fieldClasses = @{
                                        identity = 'Identity'
                                        sortKey  = 'Identity'
                                    }
                                }
                            )
                        }
                    )
                }
                ConvertTo-PulseSafeShareDocument -Document $document -OperatorKey $Key | Out-Null
            }
        } | Should -Throw -ExpectedMessage '*unclassified*'
    }

    It 'keeps remediation value in classified JSON after identity and secret canaries are planted' {
        $identity = $script:CanaryIdentity
        $secret = $script:CanarySecret
        $label = $script:CanaryPolicyLabel
        $relative = $script:CanaryRelativePath
        $markup = $script:CanaryMarkup
        $key = $script:KeyBytes
        $json = InModuleScope TenantPulse -ArgumentList $identity, $secret, $label, $relative, $markup, $key {
            param($Identity, $Secret, $Label, $Relative, $Markup, $Key)
            $document = [pscustomobject]@{
                schemaVersion = '1.0'
                findings      = @(
                    [pscustomobject]@{
                        id         = 'TP.INT.0005'
                        title      = 'Stale devices are removed'
                        category   = 'Intune.Devices'
                        reason     = '3 stale devices need review'
                        reasonCode = 'stale-device-count'
                        evidence   = @(
                            [pscustomobject]@{
                                identity     = $Identity
                                sortKey      = $Identity
                                detail       = [pscustomobject]@{
                                    upn        = $Identity
                                    secret     = $Secret
                                    policyName = $Label
                                    artifact   = $Relative
                                    count      = 3
                                    guidance   = $Markup
                                }
                                fieldClasses = @{
                                    identity   = 'Identity'
                                    sortKey    = 'Identity'
                                    upn        = 'Identity'
                                    secret     = 'SecretSensitive'
                                    policyName = 'SafeOperatorLabel'
                                    artifact   = 'SafeTechnical'
                                    count      = 'SafeTechnical'
                                    guidance   = 'BoundedReviewedText'
                                }
                            }
                        )
                    }
                )
            }
            $shared = ConvertTo-PulseSafeShareDocument -Document $document -OperatorKey $Key
            ConvertTo-PulseCanonicalJson -InputObject $shared
        }

        $json | Should -Not -Match ([regex]::Escape($identity))
        $json | Should -Not -Match 'eyJ'
        $json | Should -Not -Match ([regex]::Escape($script:CanaryPath))
        $json | Should -Match ([regex]::Escape($label))
        $json | Should -Match ([regex]::Escape($relative))
        $json | Should -Match 'stale-device-count'
        $json | Should -Match '3 stale devices need review'
        $json | Should -Match '"count": 3'
        $json | Should -Match '"boundary": "classified"'
        $hex = [System.BitConverter]::ToString($script:KeyBytes) -replace '-', ''
        $json | Should -Not -Match $hex
        $json | Should -Not -Match 'operator\.key'
        $json | Should -Not -Match 'vault'
    }

    It 'classifies collection-gap detail fail-closed when RequireClassification is set' {
        $identity = $script:CanaryIdentity
        {
            InModuleScope TenantPulse -ArgumentList $identity {
                param($Identity)
                New-PulseCollectionGap -Scope 'policy-1' -FailureClass 'ProviderFailed' `
                    -ReasonCode 'setting-read-failed' -Operation 'ConfigurationPolicySetting.ListBeta' `
                    -ApiVersion 'beta' -Detail @{ upn = $Identity } -RequireClassification
            }
        } | Should -Throw -ExpectedMessage '*unclassified*'
    }

    It 'accepts a classified collection-gap detail map' {
        $gap = InModuleScope TenantPulse {
            New-PulseCollectionGap -Scope 'policy-1' -FailureClass 'PermissionDenied' `
                -ReasonCode 'permission-denied' -Operation 'ConfigurationPolicySetting.ListBeta' `
                -ApiVersion 'beta' -Detail @{ missingCount = 2 } `
                -FieldClasses @{ missingCount = 'SafeTechnical' } -RequireClassification
        }

        $gap.ReasonCode | Should -Be 'permission-denied'
        $gap.Detail.missingCount | Should -Be 2
    }

    It 'does not mutate the source document while producing classified JSON' {
        $identity = $script:CanaryIdentity
        $key = $script:KeyBytes
        $result = InModuleScope TenantPulse -ArgumentList $identity, $key {
            param($Identity, $Key)
            $document = [pscustomobject]@{
                schemaVersion = '1.0'
                findings      = @(
                    [pscustomobject]@{
                        id         = 'TP.ENT.0001'
                        reason     = 'baseline missing'
                        reasonCode = 'baseline-missing'
                        evidence   = @(
                            [pscustomobject]@{
                                identity     = $Identity
                                sortKey      = $Identity
                                detail       = $null
                                fieldClasses = @{ identity = 'Identity'; sortKey = 'Identity' }
                            }
                        )
                    }
                )
            }
            $shared = ConvertTo-PulseSafeShareDocument -Document $document -OperatorKey $Key
            [pscustomobject]@{
                SourceIdentity = $document.findings[0].evidence[0].identity
                SharedIdentity = $shared.findings[0].evidence[0].identity
            }
        }

        $result.SourceIdentity | Should -Be $identity
        $result.SharedIdentity | Should -Match '^tp-[a-f0-9]{64}$'
        $result.SharedIdentity | Should -Not -Be $identity
    }
}

Describe 'HTML encoding mutation for 1.0 consumers' {
    It 'encodes planted markup so an HTML renderer cannot emit a raw script node' {
        $markup = $script:CanaryMarkup
        $encoded = InModuleScope TenantPulse -ArgumentList $markup {
            param($Value)
            ConvertTo-PulseHtmlEncodedText -Text $Value
        }

        $encoded | Should -Not -Match '<script>'
        $encoded | Should -Not -Match '</script>'
        $encoded | Should -Match 'canary'
        $encoded | Should -Match '&lt;'
        $encoded | Should -Match '&gt;'
    }
}
