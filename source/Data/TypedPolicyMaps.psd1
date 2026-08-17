<#
    Task 2.3: the compliance + legacy typed-policy property maps.

    Consumed by Invoke-PulseTypedPolicyExpansion / ConvertTo-PulseTypedPolicyRows. Unlike
    the Settings Catalog (T2.2), `deviceCompliancePolicies` and `deviceConfigurations` are
    polymorphic, HAND-TYPED Graph resources - each `@odata.type` is its own fixed C#-style
    class with its own property set, not a generic definitionId tree a corpus can describe.
    There is no Graph-side settings-definition catalog to walk for these two families, so
    this map IS the schema: every type this module knows how to setting-expand is listed
    here, by its own EXACT, fully-qualified `@odata.type` string, with the flat property
    list T2.3 extracts one row per property from.

    SCHEMA (frozen for T2.3):
        @{
            <policyType> = @{      # 'compliance' | 'deviceConfiguration' - matches the
                                    # frozen row schema v1 policyType values this task emits
                '#microsoft.graph.<odataType>' = @{
                    Properties = @(
                        @{ Name = '<propertyName>'; Sensitive = $true|$false }
                        @{ Name = '<propertyName>'; Sensitive = $false; Nested = @{
                               Properties = @( @{ Name = '<subPropertyName>'; Sensitive = $true|$false } )
                           } }
                        ...
                    )
                }
            }
        }
    `Nested` supports RECURSIVE depth (Part C/T3.4 extension - was "exactly ONE level" until
    this task; a Nested.Properties entry MAY now itself carry a further `Nested` key,
    walked by ConvertTo-PulseTypedPolicyRows/Protect-PulseTypedPolicySensitivePayload
    exactly like a top-level property - see those files' own docstrings for the full walk
    rule). A `Nested` property whose raw value is an ARRAY is walked per-element (matches
    windows10CustomConfiguration.omaSettings, an array of polymorphic omaSetting objects);
    a `Nested` property whose raw value is a single OBJECT is walked once, directly.

    SENSITIVE ALWAYS WINS, AT EVERY DEPTH (the discipline that makes unbounded depth safe
    to allow): a property spec with Sensitive=$true redacts wholesale the INSTANT it is
    reached, regardless of whether it ALSO carries its own `Nested` key describing what is
    inside it - that Nested description, if present on a Sensitive property, is schema-
    legal but is documentation only, never walked. This is why windows10CustomConfiguration's
    `omaSettings.value` below can now carry a `Nested` description of its own real,
    live-confirmed 2-level shape (see that entry's own comment) WITHOUT weakening its
    existing unconditional redaction in the slightest - proven by a dedicated regression
    test (TypedPolicyWalk.Tests.ps1), not merely asserted here.

    EXACT-MATCH DISPATCH (T2.2's hard lesson, carried forward unconditionally): a policy's
    own `@odata.type` is looked up in the relevant policyType sub-map as an EXACT,
    case-insensitive, fully-qualified string - never by suffix/contains. A type with no
    entry here (including a bare legacy row with NO `@odata.type` at all - observed for
    real in Ivy24's own deviceCompliancePolicies dataset, see below) is NEVER
    setting-expanded; the driver records, per policy, 'collected, not setting-expanded: no
    property map for <type>' and moves on - the policy's own raw dataset row (already
    collected by the ordinary check-driven flow) is untouched and still fully available to
    every check that reads deviceCompliancePolicies/deviceConfigurations directly.

    SENSITIVE PROPERTIES redact exactly like a Settings Catalog secret (T2.3 requirement):
    {redacted:true}, value **never** persisted to any artifact (raw dataset write, jsonl
    row, or gap/reason text) - proven by a planted-value regression test. None of the four
    compliance types measured against Ivy24's own deviceCompliancePolicies dataset
    (windows10CompliancePolicy, androidWorkProfileCompliancePolicy, macOSCompliancePolicy,
    iosCompliancePolicy - property lists below are the REAL, exhaustive property sets
    observed in that dataset, not guessed) carry an actual credential-bearing property -
    every property they expose is a policy TOGGLE/THRESHOLD (bitLockerEnabled,
    passwordMinimumLength, ...), never a secret VALUE.

    ADJUDICATED DESIGN NOTE (post-review): `Sensitive` here redacts by direct map-flag
    lookup in ConvertTo-PulseTypedPolicyRows, NOT by calling
    Resolve-PulseSettingsCatalogValueClassification - that classifier is reserved for
    discriminating an ANONYMOUS node's shape (an `{@odata.type;value;valueState}`-wrapped
    Settings Catalog value with no author-declared intent, where "is this secret" must be
    inferred structurally); a typed-map property already carries an explicit, author-
    declared `Sensitive` flag here, so there is nothing left to discriminate - reusing the
    classifier would mean asking it to re-derive an answer this map already states.

    windows10CustomConfiguration is
    different: `omaSettings` is an ARBITRARY, unstructured OMA-URI/CSP push channel real
    tenants use to deliver credential-bearing CSPs (WiFi pre-shared keys, VPN secrets,
    enrollment certificates) - Graph's own polymorphic omaSetting subtypes (omaSettingString,
    omaSettingBase64, ...) give NO structural signal distinguishing "this OMA-URI happens to
    carry a secret" from "this one doesn't". Per the fail-closed principle this whole
    module applies to every other unclassifiable value shape (see
    Resolve-PulseSettingsCatalogValueClassification's own docstring), every omaSettings
    element's own `value` is flagged Sensitive here - the one concrete "wiFi preSharedKey
    class field" instance in this initial map list.

    LEGACY @odata.type INVENTORY (T2.3 task instruction): docs/spike and the T1.11/live
    snapshots are not in-repo for this worktree. The instruction's own named list is used
    verbatim - windows10CustomConfiguration, windows10GeneralConfiguration,
    windowsUpdateForBusinessConfiguration, windows10EndpointProtectionConfiguration,
    macOSGeneralDeviceConfiguration, iosGeneralDeviceConfiguration,
    androidWorkProfileGeneralDeviceConfiguration - PLUS one more found as in-repo evidence
    while implementing this task: `scratch/live-011/snapshot/datasets/deviceConfigurations.json`
    (an Ivy24 live snapshot artifact already checked into this repo) shows the REAL set
    actually present on Ivy24 at capture time was only THREE types: sharedPCConfiguration,
    windows10CustomConfiguration, windowsUpdateForBusinessConfiguration.
    sharedPCConfiguration is therefore added below too (its property list is the REAL,
    exhaustive set from that same file), since real field evidence beats a guessed-absent
    type. windows10GeneralConfiguration, windows10EndpointProtectionConfiguration,
    macOSGeneralDeviceConfiguration, iosGeneralDeviceConfiguration and
    androidWorkProfileGeneralDeviceConfiguration were NOT observed in that snapshot; their
    property lists below are drawn from Microsoft Graph's published schema (well-known,
    stable property names), not a live capture, and are marked as such. RECORD THE REAL
    IVY24 INVENTORY AT T2.7 (the live gate) - re-run the same enumeration against a current
    Ivy24 snapshot and true up this map (add missing types, correct any property drift)
    before Phase 2 closes; scratch/live-011 is a point-in-time capture, not a contract.
    windowsUpdateForBusinessConfiguration's property list below IS a real, exhaustive
    capture from that same in-repo file (41 properties, verified) since the instruction
    names it explicitly and evidence was available.
#>
@{
    compliance = @{
        '#microsoft.graph.windows10CompliancePolicy' = @{
            Properties = @(
                @{ Name = 'bitLockerEnabled'; Sensitive = $false }
                @{ Name = 'codeIntegrityEnabled'; Sensitive = $false }
                @{ Name = 'earlyLaunchAntiMalwareDriverEnabled'; Sensitive = $false }
                @{ Name = 'mobileOsMaximumVersion'; Sensitive = $false }
                @{ Name = 'mobileOsMinimumVersion'; Sensitive = $false }
                @{ Name = 'osMaximumVersion'; Sensitive = $false }
                @{ Name = 'osMinimumVersion'; Sensitive = $false }
                @{ Name = 'passwordBlockSimple'; Sensitive = $false }
                @{ Name = 'passwordExpirationDays'; Sensitive = $false }
                @{ Name = 'passwordMinimumCharacterSetCount'; Sensitive = $false }
                @{ Name = 'passwordMinimumLength'; Sensitive = $false }
                @{ Name = 'passwordMinutesOfInactivityBeforeLock'; Sensitive = $false }
                @{ Name = 'passwordPreviousPasswordBlockCount'; Sensitive = $false }
                @{ Name = 'passwordRequired'; Sensitive = $false }
                @{ Name = 'passwordRequiredToUnlockFromIdle'; Sensitive = $false }
                @{ Name = 'passwordRequiredType'; Sensitive = $false }
                @{ Name = 'requireHealthyDeviceReport'; Sensitive = $false }
                @{ Name = 'secureBootEnabled'; Sensitive = $false }
                @{ Name = 'storageRequireEncryption'; Sensitive = $false }
            )
        }
        '#microsoft.graph.androidWorkProfileCompliancePolicy' = @{
            Properties = @(
                @{ Name = 'deviceThreatProtectionEnabled'; Sensitive = $false }
                @{ Name = 'deviceThreatProtectionRequiredSecurityLevel'; Sensitive = $false }
                @{ Name = 'minAndroidSecurityPatchLevel'; Sensitive = $false }
                @{ Name = 'osMaximumVersion'; Sensitive = $false }
                @{ Name = 'osMinimumVersion'; Sensitive = $false }
                @{ Name = 'passwordExpirationDays'; Sensitive = $false }
                @{ Name = 'passwordMinimumLength'; Sensitive = $false }
                @{ Name = 'passwordMinutesOfInactivityBeforeLock'; Sensitive = $false }
                @{ Name = 'passwordPreviousPasswordBlockCount'; Sensitive = $false }
                @{ Name = 'passwordRequired'; Sensitive = $false }
                @{ Name = 'passwordRequiredType'; Sensitive = $false }
                @{ Name = 'securityBlockJailbrokenDevices'; Sensitive = $false }
                @{ Name = 'securityDisableUsbDebugging'; Sensitive = $false }
                @{ Name = 'securityPreventInstallAppsFromUnknownSources'; Sensitive = $false }
                @{ Name = 'securityRequireCompanyPortalAppIntegrity'; Sensitive = $false }
                @{ Name = 'securityRequireGooglePlayServices'; Sensitive = $false }
                @{ Name = 'securityRequireSafetyNetAttestationBasicIntegrity'; Sensitive = $false }
                @{ Name = 'securityRequireSafetyNetAttestationCertifiedDevice'; Sensitive = $false }
                @{ Name = 'securityRequireUpToDateSecurityProviders'; Sensitive = $false }
                @{ Name = 'securityRequireVerifyApps'; Sensitive = $false }
                @{ Name = 'storageRequireEncryption'; Sensitive = $false }
            )
        }
        # Not observed in the Ivy24 snapshot this task had in-repo evidence for, but the
        # sibling of androidWorkProfileCompliancePolicy Intune also ships (Android
        # Enterprise fully-managed/device-owner) - same property shape family. Flagged for
        # T2.7 live-gate confirmation alongside the rest of this map.
        '#microsoft.graph.androidDeviceOwnerCompliancePolicy' = @{
            Properties = @(
                @{ Name = 'deviceThreatProtectionEnabled'; Sensitive = $false }
                @{ Name = 'deviceThreatProtectionRequiredSecurityLevel'; Sensitive = $false }
                @{ Name = 'minAndroidSecurityPatchLevel'; Sensitive = $false }
                @{ Name = 'osMaximumVersion'; Sensitive = $false }
                @{ Name = 'osMinimumVersion'; Sensitive = $false }
                @{ Name = 'passwordExpirationDays'; Sensitive = $false }
                @{ Name = 'passwordMinimumLength'; Sensitive = $false }
                @{ Name = 'passwordMinutesOfInactivityBeforeLock'; Sensitive = $false }
                @{ Name = 'passwordRequired'; Sensitive = $false }
                @{ Name = 'passwordRequiredType'; Sensitive = $false }
                @{ Name = 'storageRequireEncryption'; Sensitive = $false }
            )
        }
        '#microsoft.graph.macOSCompliancePolicy' = @{
            Properties = @(
                @{ Name = 'deviceThreatProtectionEnabled'; Sensitive = $false }
                @{ Name = 'deviceThreatProtectionRequiredSecurityLevel'; Sensitive = $false }
                @{ Name = 'firewallBlockAllIncoming'; Sensitive = $false }
                @{ Name = 'firewallEnableStealthMode'; Sensitive = $false }
                @{ Name = 'firewallEnabled'; Sensitive = $false }
                @{ Name = 'osMaximumVersion'; Sensitive = $false }
                @{ Name = 'osMinimumVersion'; Sensitive = $false }
                @{ Name = 'passwordBlockSimple'; Sensitive = $false }
                @{ Name = 'passwordExpirationDays'; Sensitive = $false }
                @{ Name = 'passwordMinimumCharacterSetCount'; Sensitive = $false }
                @{ Name = 'passwordMinimumLength'; Sensitive = $false }
                @{ Name = 'passwordMinutesOfInactivityBeforeLock'; Sensitive = $false }
                @{ Name = 'passwordPreviousPasswordBlockCount'; Sensitive = $false }
                @{ Name = 'passwordRequired'; Sensitive = $false }
                @{ Name = 'passwordRequiredType'; Sensitive = $false }
                @{ Name = 'storageRequireEncryption'; Sensitive = $false }
                @{ Name = 'systemIntegrityProtectionEnabled'; Sensitive = $false }
            )
        }
        '#microsoft.graph.iosCompliancePolicy' = @{
            Properties = @(
                @{ Name = 'deviceThreatProtectionEnabled'; Sensitive = $false }
                @{ Name = 'deviceThreatProtectionRequiredSecurityLevel'; Sensitive = $false }
                @{ Name = 'managedEmailProfileRequired'; Sensitive = $false }
                @{ Name = 'osMaximumVersion'; Sensitive = $false }
                @{ Name = 'osMinimumVersion'; Sensitive = $false }
                @{ Name = 'passcodeBlockSimple'; Sensitive = $false }
                @{ Name = 'passcodeExpirationDays'; Sensitive = $false }
                @{ Name = 'passcodeMinimumCharacterSetCount'; Sensitive = $false }
                @{ Name = 'passcodeMinimumLength'; Sensitive = $false }
                @{ Name = 'passcodeMinutesOfInactivityBeforeLock'; Sensitive = $false }
                @{ Name = 'passcodePreviousPasscodeBlockCount'; Sensitive = $false }
                @{ Name = 'passcodeRequired'; Sensitive = $false }
                @{ Name = 'passcodeRequiredType'; Sensitive = $false }
                @{ Name = 'securityBlockJailbrokenDevices'; Sensitive = $false }
            )
        }
    }

    deviceConfiguration = @{
        # REAL, exhaustive capture (scratch/live-011/snapshot/datasets/deviceConfigurations.json).
        # omaSettings is arbitrary/unstructured - see this file's top docstring for why its
        # own `value` is flagged Sensitive fail-closed.
        #
        # DEEPER-NESTING GAP (deferred F3, T2.7 live gate, docs/STATUS.md) - RESOLVED T3.4:
        # the T2.7 live gate against Ivy24 confirmed all 8 real windows10CustomConfiguration
        # policies present at capture time each carry exactly one omaSettings element whose
        # `value` is itself an OBJECT, one level past what this map's Nested schema could
        # describe at the time (scratch/live-27/snapshot/datasets/deviceConfigurations.json,
        # still in-repo, is the exact evidentiary artifact - all 8 windows10CustomConfiguration
        # policies in that capture, 8/8). Root cause, confirmed by reading the collection
        # path: this is NOT a Graph-native shape variance - it is this module's OWN
        # collection-time redaction marker (Protect-PulseTypedPolicySensitivePayload,
        # Invoke-PulseCollection.ps1, called BEFORE Write-PulseDataset ever persists this
        # dataset) replacing `value` with `{ redacted: true }` because `value` is declared
        # Sensitive below - i.e. the "deeper nesting" observed live is this module's own
        # safe output shape for a value it already correctly protected, not an unclassified
        # secret leaking through. `value` keeps Sensitive=$true here, completely UNCHANGED -
        # the fail-closed redaction behavior for a real, live secret (a WiFi PSK/VPN secret/
        # certificate an admin actually configured) is not touched by this resolution at
        # all. What changes: the schema can now DESCRIBE that real 2-level shape (Nested
        # added below, `redacted` marked non-Sensitive since it is this module's own boolean
        # marker literal, never Graph-sourced secret content - declared by architecture
        # knowledge, never by name-pattern matching), and ConvertTo-PulseTypedPolicyRows/
        # Protect-PulseTypedPolicySensitivePayload can now walk to that depth in general -
        # but per the "Sensitive always wins" rule (this file's own top docstring), `value`
        # being Sensitive means this Nested description is schema-legal documentation of the
        # real observed shape, never actually walked - proven, not merely asserted, by
        # TypedPolicyWalk.Tests.ps1's dedicated regression test against a fixture sanitized
        # from that exact live-27 evidence.
        '#microsoft.graph.windows10CustomConfiguration' = @{
            Properties = @(
                @{
                    Name      = 'omaSettings'
                    Sensitive = $false
                    Nested    = @{
                        Properties = @(
                            @{
                                Name      = 'value'
                                Sensitive = $true
                                Nested    = @{
                                    Properties = @(
                                        @{ Name = 'redacted'; Sensitive = $false }
                                    )
                                }
                            }
                        )
                    }
                }
            )
        }
        # REAL, exhaustive capture, 41 properties (scratch/live-011, see this file's own
        # docstring) - none are credential-bearing; every one is a scheduling/deferral
        # toggle or threshold.
        '#microsoft.graph.windowsUpdateForBusinessConfiguration' = @{
            Properties = @(
                @{ Name = 'allowWindows11Upgrade'; Sensitive = $false }
                @{ Name = 'autoRestartNotificationDismissal'; Sensitive = $false }
                @{ Name = 'automaticUpdateMode'; Sensitive = $false }
                @{ Name = 'businessReadyUpdatesOnly'; Sensitive = $false }
                @{ Name = 'deadlineForFeatureUpdatesInDays'; Sensitive = $false }
                @{ Name = 'deadlineForQualityUpdatesInDays'; Sensitive = $false }
                @{ Name = 'deadlineGracePeriodInDays'; Sensitive = $false }
                @{ Name = 'deliveryOptimizationMode'; Sensitive = $false }
                @{ Name = 'driversExcluded'; Sensitive = $false }
                @{ Name = 'engagedRestartDeadlineInDays'; Sensitive = $false }
                @{ Name = 'engagedRestartSnoozeScheduleInDays'; Sensitive = $false }
                @{ Name = 'engagedRestartTransitionScheduleInDays'; Sensitive = $false }
                @{ Name = 'featureUpdatesDeferralPeriodInDays'; Sensitive = $false }
                @{ Name = 'featureUpdatesPauseExpiryDateTime'; Sensitive = $false }
                @{ Name = 'featureUpdatesPauseStartDate'; Sensitive = $false }
                @{ Name = 'featureUpdatesPaused'; Sensitive = $false }
                @{ Name = 'featureUpdatesRollbackStartDateTime'; Sensitive = $false }
                @{ Name = 'featureUpdatesRollbackWindowInDays'; Sensitive = $false }
                @{ Name = 'featureUpdatesWillBeRolledBack'; Sensitive = $false }
                @{
                    Name      = 'installationSchedule'
                    Sensitive = $false
                    Nested    = @{
                        Properties = @(
                            @{ Name = 'scheduledInstallDay'; Sensitive = $false }
                            @{ Name = 'scheduledInstallTime'; Sensitive = $false }
                            @{ Name = 'activeHoursStart'; Sensitive = $false }
                            @{ Name = 'activeHoursEnd'; Sensitive = $false }
                        )
                    }
                }
                @{ Name = 'microsoftUpdateServiceAllowed'; Sensitive = $false }
                @{ Name = 'postponeRebootUntilAfterDeadline'; Sensitive = $false }
                @{ Name = 'prereleaseFeatures'; Sensitive = $false }
                @{ Name = 'qualityUpdatesDeferralPeriodInDays'; Sensitive = $false }
                @{ Name = 'qualityUpdatesPauseExpiryDateTime'; Sensitive = $false }
                @{ Name = 'qualityUpdatesPauseStartDate'; Sensitive = $false }
                @{ Name = 'qualityUpdatesPaused'; Sensitive = $false }
                @{ Name = 'qualityUpdatesRollbackStartDateTime'; Sensitive = $false }
                @{ Name = 'qualityUpdatesWillBeRolledBack'; Sensitive = $false }
                @{ Name = 'scheduleImminentRestartWarningInMinutes'; Sensitive = $false }
                @{ Name = 'scheduleRestartWarningInHours'; Sensitive = $false }
                @{ Name = 'skipChecksBeforeRestart'; Sensitive = $false }
                @{ Name = 'updateNotificationLevel'; Sensitive = $false }
                @{ Name = 'updateWeeks'; Sensitive = $false }
                @{ Name = 'userPauseAccess'; Sensitive = $false }
                @{ Name = 'userWindowsUpdateScanAccess'; Sensitive = $false }
            )
        }
        # REAL, exhaustive capture (scratch/live-011) - found as in-repo evidence, added
        # beyond the task instruction's own named list (see this file's top docstring).
        '#microsoft.graph.sharedPCConfiguration' = @{
            Properties = @(
                @{ Name = 'accountManagerPolicy'; Sensitive = $false }
                @{ Name = 'allowLocalStorage'; Sensitive = $false }
                @{ Name = 'allowedAccounts'; Sensitive = $false }
                @{ Name = 'disableAccountManager'; Sensitive = $false }
                @{ Name = 'disableEduPolicies'; Sensitive = $false }
                @{ Name = 'disablePowerPolicies'; Sensitive = $false }
                @{ Name = 'disableSignInOnResume'; Sensitive = $false }
                @{ Name = 'enabled'; Sensitive = $false }
                @{ Name = 'idleTimeBeforeSleepInSeconds'; Sensitive = $false }
                @{ Name = 'kioskAppDisplayName'; Sensitive = $false }
                @{ Name = 'kioskAppUserModelId'; Sensitive = $false }
                @{ Name = 'maintenanceStartTime'; Sensitive = $false }
            )
        }
        # NOT observed in the in-repo Ivy24 evidence - property lists drawn from Microsoft
        # Graph's published (well-known/stable) schema, not a live capture. T2.7 live gate
        # must confirm/true these up (see this file's top docstring).
        '#microsoft.graph.windows10GeneralConfiguration' = @{
            Properties = @(
                @{ Name = 'accountsBlockAddingNonMicrosoftAccountEmail'; Sensitive = $false }
                @{ Name = 'antiTheftModeBlocked'; Sensitive = $false }
                @{ Name = 'bluetoothBlocked'; Sensitive = $false }
                @{ Name = 'cameraBlocked'; Sensitive = $false }
                @{ Name = 'defenderBlockEndUserAccess'; Sensitive = $false }
                @{ Name = 'diskEncryptionEnableBitLocker'; Sensitive = $false }
                @{ Name = 'passwordBlockSimple'; Sensitive = $false }
                @{ Name = 'passwordExpirationDays'; Sensitive = $false }
                @{ Name = 'passwordMinimumLength'; Sensitive = $false }
                @{ Name = 'passwordRequired'; Sensitive = $false }
                @{ Name = 'passwordRequiredType'; Sensitive = $false }
                @{ Name = 'smartScreenBlockPromptOverride'; Sensitive = $false }
                @{ Name = 'smartScreenEnableAppInstallControl'; Sensitive = $false }
                @{ Name = 'usbBlocked'; Sensitive = $false }
                @{ Name = 'wifiBlocked'; Sensitive = $false }
            )
        }
        '#microsoft.graph.windows10EndpointProtectionConfiguration' = @{
            Properties = @(
                @{ Name = 'bitLockerDisableWarningForOtherDiskEncryption'; Sensitive = $false }
                @{ Name = 'bitLockerEnableStorageCardEncryptionComparedToOSDrive'; Sensitive = $false }
                @{ Name = 'bitLockerRecoveryPasswordRotation'; Sensitive = $false }
                @{ Name = 'defenderRequireRealTimeMonitoring'; Sensitive = $false }
                @{ Name = 'defenderScanRemovableDrivesDuringFullScan'; Sensitive = $false }
                @{ Name = 'firewallBlockStatefulFTP'; Sensitive = $false }
                @{ Name = 'firewallProfileDomain'; Sensitive = $false }
                @{ Name = 'smartScreenBlockOverrideForFiles'; Sensitive = $false }
                @{ Name = 'smartScreenEnableInShell'; Sensitive = $false }
                @{ Name = 'userRightsAccessCredentialManagerAsTrustedCaller'; Sensitive = $false }
                @{ Name = 'xboxServicesEnableXboxGameSaveTask'; Sensitive = $false }
            )
        }
        '#microsoft.graph.macOSGeneralDeviceConfiguration' = @{
            Properties = @(
                @{ Name = 'appsSingleAppModeList'; Sensitive = $false }
                @{ Name = 'compliantAppListType'; Sensitive = $false }
                @{ Name = 'emailInDomainSuffixes'; Sensitive = $false }
                @{ Name = 'firewallBlockAllIncoming'; Sensitive = $false }
                @{ Name = 'firewallEnabled'; Sensitive = $false }
                @{ Name = 'passwordBlockSimple'; Sensitive = $false }
                @{ Name = 'passwordMinimumLength'; Sensitive = $false }
                @{ Name = 'passwordRequired'; Sensitive = $false }
                @{ Name = 'passwordRequiredType'; Sensitive = $false }
                @{ Name = 'screenLockDisableImmediate'; Sensitive = $false }
            )
        }
        '#microsoft.graph.iosGeneralDeviceConfiguration' = @{
            Properties = @(
                @{ Name = 'appsSingleAppModeList'; Sensitive = $false }
                @{ Name = 'appsVisibilityListType'; Sensitive = $false }
                @{ Name = 'cameraBlocked'; Sensitive = $false }
                @{ Name = 'iCloudBlockBackup'; Sensitive = $false }
                @{ Name = 'passcodeBlockSimple'; Sensitive = $false }
                @{ Name = 'passcodeMinimumLength'; Sensitive = $false }
                @{ Name = 'passcodeRequired'; Sensitive = $false }
                @{ Name = 'passcodeRequiredType'; Sensitive = $false }
                @{ Name = 'safariBlockAutofill'; Sensitive = $false }
                @{ Name = 'siriBlocked'; Sensitive = $false }
            )
        }
        '#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration' = @{
            Properties = @(
                @{ Name = 'passwordBlockFingerprintUnlock'; Sensitive = $false }
                @{ Name = 'passwordMinimumLength'; Sensitive = $false }
                @{ Name = 'passwordRequiredType'; Sensitive = $false }
                @{ Name = 'securityRequireVerifyApps'; Sensitive = $false }
                @{ Name = 'vpnAlwaysOnPackageIdentifier'; Sensitive = $false }
                @{ Name = 'workProfilePasswordExpirationDays'; Sensitive = $false }
                @{ Name = 'workProfilePasswordMinimumLength'; Sensitive = $false }
                @{ Name = 'workProfilePasswordRequiredType'; Sensitive = $false }
                @{ Name = 'workProfileBlockNotificationsWhileDeviceLocked'; Sensitive = $false }
                @{ Name = 'workProfileDataSharingType'; Sensitive = $false }
            )
        }
    }
}
