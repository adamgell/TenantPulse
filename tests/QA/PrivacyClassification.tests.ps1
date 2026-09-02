<#
    QA gate: TenantPulse 1.0 privacy classification (TP9A / AC-25).

    Proves construction-time fail-closed behavior, the five privacy classes, reason-code
    migration, the RedactDetailKeys compatibility layer, and deterministic two-key
    pseudonym rotation. Synthetic canaries and synthetic keys live only in this QA file
    and test temp roots. No real credential, vault, or configured-key operations.
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
    $script:CanaryTechnicalCount = 42
    $script:KeyGen1 = [byte[]] (1 .. 32)
    $script:KeyGen2 = [byte[]] (32 .. 1)
}

Describe 'Get-PulsePrivacyClasses' {
    It 'returns exactly the five 1.0 privacy classes' {
        $classes = InModuleScope TenantPulse { Get-PulsePrivacyClasses }
        $classes | Should -Be @('Identity', 'SecretSensitive', 'SafeTechnical', 'SafeOperatorLabel', 'BoundedReviewedText')
    }
}

Describe 'New-PulseClassifiedValue fail-closed construction' {
    It 'throws when Class is missing or unknown' {
        {
            InModuleScope TenantPulse {
                New-PulseClassifiedValue -Class 'Unclassified' -Value 'x'
            }
        } | Should -Throw -ExpectedMessage '*privacy class*'
    }

    It 'throws when an identity-shaped value is claimed as SafeTechnical' {
        $identity = $script:CanaryIdentity
        {
            InModuleScope TenantPulse -ArgumentList $identity {
                param($Value)
                New-PulseClassifiedValue -Class 'SafeTechnical' -Value $Value
            }
        } | Should -Throw -ExpectedMessage '*not valid for privacy class*'
    }

    It 'throws when a secret-shaped value is claimed as SafeOperatorLabel' {
        $secret = $script:CanarySecret
        {
            InModuleScope TenantPulse -ArgumentList $secret {
                param($Value)
                New-PulseClassifiedValue -Class 'SafeOperatorLabel' -Value $Value
            }
        } | Should -Throw -ExpectedMessage '*not valid for privacy class*'
    }

    It 'throws when an unsafe path is claimed as SafeTechnical' {
        $path = $script:CanaryPath
        {
            InModuleScope TenantPulse -ArgumentList $path {
                param($Value)
                New-PulseClassifiedValue -Class 'SafeTechnical' -Value $Value
            }
        } | Should -Throw -ExpectedMessage '*not valid for privacy class*'
    }

    It 'throws when markup is claimed as SafeTechnical' {
        $markup = $script:CanaryMarkup
        {
            InModuleScope TenantPulse -ArgumentList $markup {
                param($Value)
                New-PulseClassifiedValue -Class 'SafeTechnical' -Value $Value
            }
        } | Should -Throw -ExpectedMessage '*not valid for privacy class*'
    }

    It 'throws when Identity is constructed without an operator key and without deferral' {
        $identity = $script:CanaryIdentity
        {
            InModuleScope TenantPulse -ArgumentList $identity {
                param($Value)
                New-PulseClassifiedValue -Class 'Identity' -Value $Value
            }
        } | Should -Throw -ExpectedMessage '*OperatorKey*'
    }
}

Describe 'classified value protection' {
    It 'pseudonymizes an identity canary and drops the raw value' {
        $identity = $script:CanaryIdentity
        $key = $script:KeyGen1
        $classified = InModuleScope TenantPulse -ArgumentList $identity, $key {
            param($Value, $Key)
            New-PulseClassifiedValue -Class 'Identity' -Value $Value -OperatorKey $Key
        }

        $classified.Class | Should -Be 'Identity'
        $classified.Protected | Should -BeTrue
        $classified.Value | Should -Match '^tp-[a-f0-9]{64}$'
        $classified.Value | Should -Not -Be $identity
        [string] $classified.Value | Should -Not -Match 'canary\.user'
    }

    It 'redacts a secret canary irreversibly' {
        $secret = $script:CanarySecret
        $classified = InModuleScope TenantPulse -ArgumentList $secret {
            param($Value)
            New-PulseClassifiedValue -Class 'SecretSensitive' -Value $Value
        }

        $classified.Class | Should -Be 'SecretSensitive'
        $classified.Protected | Should -BeTrue
        $classified.Value.redacted | Should -BeTrue
        ($classified | ConvertTo-Json -Compress) | Should -Not -Match 'eyJ'
        ($classified | ConvertTo-Json -Compress) | Should -Not -Match ([regex]::Escape($secret))
    }

    It 'retains a policy-label canary as SafeOperatorLabel' {
        $label = $script:CanaryPolicyLabel
        $classified = InModuleScope TenantPulse -ArgumentList $label {
            param($Value)
            New-PulseClassifiedValue -Class 'SafeOperatorLabel' -Value $Value
        }

        $classified.Value | Should -Be $label
        $classified.Protected | Should -BeTrue
    }

    It 'retains a safe technical count' {
        $count = $script:CanaryTechnicalCount
        $classified = InModuleScope TenantPulse -ArgumentList $count {
            param($Value)
            New-PulseClassifiedValue -Class 'SafeTechnical' -Value $Value
        }

        $classified.Value | Should -Be 42
    }

    It 'retains bounded reviewed text and HTML-encodes markup for HTML consumers' {
        $markup = $script:CanaryMarkup
        $result = InModuleScope TenantPulse -ArgumentList $markup {
            param($Value)
            $classified = New-PulseClassifiedValue -Class 'BoundedReviewedText' -Value $Value
            [pscustomobject]@{
                JsonValue = $classified.Value
                HtmlValue = ConvertTo-PulseHtmlEncodedText -Text $classified.Value
            }
        }

        $result.JsonValue | Should -Be $markup
        $result.HtmlValue | Should -Not -Match '<script>'
        $result.HtmlValue | Should -Match '&lt;script&gt;'
    }

    It 'accepts a snapshot-relative path as SafeTechnical' {
        $classified = InModuleScope TenantPulse {
            New-PulseClassifiedValue -Class 'SafeTechnical' -Value 'expanded/conflicts.json'
        }
        $classified.Value | Should -Be 'expanded/conflicts.json'
    }
}

Describe 'ConvertTo-PulseClassifiedReason' {
    It 'accepts a reason code plus classified arguments' {
        $count = $script:CanaryTechnicalCount
        $reason = InModuleScope TenantPulse -ArgumentList $count {
            param($Count)
            ConvertTo-PulseClassifiedReason -ReasonCode 'stale-device-count' -Text '3 stale devices need review' -Arguments @(
                (New-PulseClassifiedValue -Class 'SafeTechnical' -Value $Count)
            )
        }

        $reason.ReasonCode | Should -Be 'stale-device-count'
        $reason.Class | Should -Be 'BoundedReviewedText'
        $reason.Arguments.Count | Should -Be 1
    }

    It 'rejects a free-text reason argument that is not classified' {
        {
            InModuleScope TenantPulse {
                ConvertTo-PulseClassifiedReason -ReasonCode 'gap' -Arguments @('alice@contoso.example')
            }
        } | Should -Throw -ExpectedMessage '*classified value*'
    }

    It 'rejects identity-shaped reason text' {
        $identity = $script:CanaryIdentity
        {
            InModuleScope TenantPulse -ArgumentList $identity {
                param($Value)
                ConvertTo-PulseClassifiedReason -ReasonCode 'gap' -Text $Value
            }
        } | Should -Throw -ExpectedMessage '*BoundedReviewedText*'
    }
}

Describe 'New-PulseFinding classification contract' {
    It 'labels a free-text reason plus unmarked detail as local-only compatibility output' {
        $result = InModuleScope TenantPulse {
            New-PulseFinding -Status Warn -Reason 'alice@contoso.example is excluded' -Evidence @(
                @{
                    Identity         = 'admin@contoso.example'
                    Detail           = @{ upn = 'alice@contoso.example'; count = 1 }
                    RedactDetailKeys = @('upn')
                }
            )
        }

        $result.PrivacyComplete | Should -BeFalse
        $result.ReasonCode | Should -BeNullOrEmpty
        $result.Evidence[0].FieldClasses['upn'] | Should -Be 'Identity'
    }

    It 'is complete when reason code and field classes cover every tenant-derived field' {
        $result = InModuleScope TenantPulse {
            New-PulseFinding -Status Fail -ReasonCode 'stale-device-count' -Reason '3 stale devices need review' -Evidence @(
                @{
                    Identity    = 'managed:device-1'
                    Detail      = @{ source = 'managedDevices'; lastSyncDateTime = '2026-01-01T00:00:00Z' }
                    FieldClasses = @{
                        Identity         = 'Identity'
                        SortKey          = 'Identity'
                        source           = 'SafeTechnical'
                        lastSyncDateTime = 'SafeTechnical'
                    }
                }
            )
        }

        $result.PrivacyComplete | Should -BeTrue
        $result.ReasonCode | Should -Be 'stale-device-count'
    }

    It 'throws from the classified construction path when fields are unclassified' {
        {
            InModuleScope TenantPulse {
                New-PulseFinding -Status Fail -Reason 'free text' -RequireClassification -Evidence @(
                    @{ Identity = 'obj-1'; Detail = @{ upn = 'alice@contoso.example' } }
                )
            }
        } | Should -Throw -ExpectedMessage '*unclassified*'
    }
}

Describe 'Assert-PulsePrivacyClassification' {
    It 'throws on an unclassified scalar' {
        {
            InModuleScope TenantPulse {
                Assert-PulsePrivacyClassification -InputObject 'alice@contoso.example' -Path 'reason'
            }
        } | Should -Throw -ExpectedMessage '*unclassified*'
    }

    It 'accepts a protected identity value' {
        $identity = $script:CanaryIdentity
        $key = $script:KeyGen1
        InModuleScope TenantPulse -ArgumentList $identity, $key {
            param($Value, $Key)
            $classified = New-PulseClassifiedValue -Class 'Identity' -Value $Value -OperatorKey $Key
            Assert-PulsePrivacyClassification -InputObject $classified -Path 'evidence.identity'
        }
    }
}

Describe 'ConvertTo-PulseSafeShareDocument' {
    It 'fails closed when evidence detail is unclassified' {
        $key = $script:KeyGen1
        {
            InModuleScope TenantPulse -ArgumentList $key {
                param($Key)
                $document = [pscustomobject]@{
                    schemaVersion = '1.0'
                    findings      = @(
                        [pscustomobject]@{
                            id         = 'TP.ENT.0001'
                            reason     = 'ok'
                            reasonCode = 'ok'
                            evidence   = @(
                                [pscustomobject]@{
                                    identity = 'obj-1'
                                    sortKey  = 'obj-1'
                                    detail   = [pscustomobject]@{ upn = 'canary.user@tenantpulse.test' }
                                }
                            )
                        }
                    )
                }
                ConvertTo-PulseSafeShareDocument -Document $document -OperatorKey $Key | Out-Null
            }
        } | Should -Throw -ExpectedMessage '*unclassified*'
    }

    It 'protects identity and secret canaries while retaining remediation value' {
        $identity = $script:CanaryIdentity
        $secret = $script:CanarySecret
        $label = $script:CanaryPolicyLabel
        $markup = $script:CanaryMarkup
        $key = $script:KeyGen1
        $shared = InModuleScope TenantPulse -ArgumentList $identity, $secret, $label, $markup, $key {
            param($Identity, $Secret, $Label, $Markup, $Key)
            $document = [pscustomobject]@{
                schemaVersion = '1.0'
                findings      = @(
                    [pscustomobject]@{
                        id         = 'TP.INT.0005'
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
                                    count      = 3
                                    guidance   = $Markup
                                }
                                fieldClasses = @{
                                    identity   = 'Identity'
                                    sortKey    = 'Identity'
                                    upn        = 'Identity'
                                    secret     = 'SecretSensitive'
                                    policyName = 'SafeOperatorLabel'
                                    count      = 'SafeTechnical'
                                    guidance   = 'BoundedReviewedText'
                                }
                            }
                        )
                    }
                )
            }
            ConvertTo-PulseSafeShareDocument -Document $document -OperatorKey $Key
        }

        $json = $shared | ConvertTo-Json -Depth 8 -Compress
        $json | Should -Not -Match ([regex]::Escape($identity))
        $json | Should -Not -Match 'eyJ'
        $json | Should -Match ([regex]::Escape($label))
        $json | Should -Match '"count":3'
        $json | Should -Match 'stale-device-count'
        $shared.privacy.complete | Should -BeTrue
        $shared.privacy.boundary | Should -Be 'classified'
        $shared.findings[0].evidence[0].identity | Should -Match '^tp-[a-f0-9]{64}$'
        $shared.findings[0].evidence[0].detail.secret.redacted | Should -BeTrue
        $shared.findings[0].evidence[0].detail.guidance | Should -Be $markup
    }
}

Describe 'check descriptor privacy validation' {
    It 'rejects an unknown Privacy.EvidenceFields class' {
        $errors = InModuleScope TenantPulse {
            Test-PulseCheckDescriptor -Label 'TP.ENT.0001' -Descriptor @{
                Id         = 'TP.ENT.0001'
                Title      = 'Security Defaults state is appropriate'
                Category   = 'Entra.Identity'
                Severity   = 'High'
                Effort     = 'Low'
                Impact     = 'High'
                Data       = @{ Datasets = @('securityDefaultsPolicy'); Gates = @() }
                Rule       = @{ Type = 'Expression'; Expression = '$true' }
                Consulting = @{
                    WhatItMeans  = 'Author reviewed.'
                    WhyItMatters = 'Author reviewed.'
                    Remediation  = @('Do the thing.')
                    PortalLinks  = @('https://learn.microsoft.com/entra')
                }
                References = @{
                    Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#x'
                    Authorities = @('https://learn.microsoft.com/entra')
                }
                Privacy    = @{
                    EvidenceFields = @{ upn = 'NotAClass' }
                }
            }
        }

        ($errors -join "`n") | Should -Match 'Privacy\.EvidenceFields'
        ($errors -join "`n") | Should -Match 'NotAClass'
    }

    It 'accepts a valid Privacy.EvidenceFields map and treats catalog consulting as BoundedReviewedText' {
        $errors = InModuleScope TenantPulse {
            Test-PulseCheckDescriptor -Label 'TP.ENT.0001' -Descriptor @{
                Id         = 'TP.ENT.0001'
                Title      = 'Security Defaults state is appropriate'
                Category   = 'Entra.Identity'
                Severity   = 'High'
                Effort     = 'Low'
                Impact     = 'High'
                Data       = @{ Datasets = @('securityDefaultsPolicy'); Gates = @() }
                Rule       = @{ Type = 'Expression'; Expression = '$true' }
                Consulting = @{
                    WhatItMeans  = 'Author reviewed.'
                    WhyItMatters = 'Author reviewed.'
                    Remediation  = @('Do the thing.')
                    PortalLinks  = @('https://learn.microsoft.com/entra')
                }
                References = @{
                    Research    = 'docs/research/iha-v2/2026-08-15-microsoft-official-guidance.md#x'
                    Authorities = @('https://learn.microsoft.com/entra')
                }
                Privacy    = @{
                    EvidenceFields = @{
                        upn   = 'Identity'
                        count = 'SafeTechnical'
                    }
                    CatalogFields  = @{
                        Title      = 'SafeOperatorLabel'
                        Consulting = 'BoundedReviewedText'
                    }
                }
            }
        }

        @($errors).Count | Should -Be 0
    }
}

Describe 'deterministic two-key fixture' {
    It 'keeps the same identity stable within one key generation and changes after replacement' {
        $identity = $script:CanaryIdentity
        $key1 = $script:KeyGen1
        $key2 = $script:KeyGen2
        $result = InModuleScope TenantPulse -ArgumentList $identity, $key1, $key2 {
            param($Value, $First, $Second)
            $a = New-PulseClassifiedValue -Class 'Identity' -Value $Value -OperatorKey $First
            $b = New-PulseClassifiedValue -Class 'Identity' -Value $Value -OperatorKey $First
            $c = New-PulseClassifiedValue -Class 'Identity' -Value $Value -OperatorKey $Second
            [pscustomobject]@{
                First       = $a.Value
                FirstAgain  = $b.Value
                Second      = $c.Value
            }
        }

        $result.First | Should -Be $result.FirstAgain
        $result.First | Should -Not -Be $result.Second
        $result.First | Should -Match '^tp-[a-f0-9]{64}$'
        $result.Second | Should -Match '^tp-[a-f0-9]{64}$'
    }

    It 'never emits raw key bytes, vault references, or reversible surrogates' {
        $identity = $script:CanaryIdentity
        $key1 = $script:KeyGen1
        $payload = InModuleScope TenantPulse -ArgumentList $identity, $key1 {
            param($Value, $Key)
            $classified = New-PulseClassifiedValue -Class 'Identity' -Value $Value -OperatorKey $Key
            $lifecycle = Get-PulseOperatorKeyLifecycleText
            ($classified | ConvertTo-Json -Compress) + "`n" + $lifecycle
        }

        $hex = [System.BitConverter]::ToString($script:KeyGen1) -replace '-', ''
        $base64 = [System.Convert]::ToBase64String($script:KeyGen1)
        $payload | Should -Not -Match $hex
        $payload | Should -Not -Match ([regex]::Escape($base64))
        $payload | Should -Not -Match 'vault:'
        $payload | Should -Not -Match 'SecretManagement'
        $payload | Should -Not -Match $identity
        $payload | Should -Match 'Join-break'
        $payload | Should -Match 'Backup'
        $payload | Should -Match 'Replacement'
        $payload | Should -Match 'no public rotate cmdlet'
        $payload | Should -Not -Match 'Rotate-Pulse'
        $payload | Should -Not -Match 'New-PulseOperatorKey'
    }

    It 'documents that synthetic keys stay in test temp roots' {
        $text = InModuleScope TenantPulse { Get-PulseOperatorKeyLifecycleText }
        $text | Should -Match 'test temp roots'
        $text | Should -Match 'approval-gated'
    }
}

Describe 'Protect-PulseReason compatibility layer' {
    It 'still caps and substitutes and is labeled as the non-safe path' {
        $redacted = InModuleScope TenantPulse {
            Protect-PulseReason -Message ('profile-id-canary ' + ('x' * 600)) -ProfileId 'profile-id-canary' -Pseudonym 'tp-deadbeef'
        }

        $redacted | Should -Match 'tp-deadbeef'
        $redacted | Should -Not -Match 'profile-id-canary'
        $redacted.Length | Should -Be 500

        $label = InModuleScope TenantPulse { ConvertTo-PulseCompatPrivacyLabel }
        $label.complete | Should -BeFalse
        $label.boundary | Should -Be 'local-only'
        $label.compatLayer | Should -BeTrue
    }
}
