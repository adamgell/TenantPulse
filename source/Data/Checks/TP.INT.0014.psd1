@{
    Id         = 'TP.INT.0014'
    Title      = 'BitLocker full-disk encryption enforced via Endpoint Security policy'
    Category   = 'Intune.EndpointSecurity'
    Severity   = 'Critical'
    Effort     = 'Medium'
    Impact     = 'High'
    Data       = @{
        Datasets = @('endpointSecurityDiskEncryptionPolicies')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseBitLockerFullDiskEncryption'
    }
    Consulting = @{
        WhatItMeans  = 'An Endpoint Security Disk Encryption policy (Intune''s dedicated "Disk encryption" blade, backed by the BitLocker CSP) can set the Windows OS drive encryption type to Full encryption, Used space only, or leave it unconfigured. This check Passes when at least one such policy enforces full encryption. It only sees policies created through the Endpoint security > Disk encryption blade - a BitLocker CSP setting pushed via a generic Settings Catalog profile outside that blade is invisible to this check by design (a planned settings-expansion-based complement closes that gap separately, without double-counting the same policy from both directions).'
        WhyItMatters = 'Used-space-only encryption only protects data written AFTER encryption was enabled - data already on disk before that point, and any data recoverable from unallocated space, remains unprotected. On a lost or stolen device, full encryption is the only mode that guarantees data at rest is unreadable without the recovery key. This is a baseline control both the CIS Intune Windows 11 benchmark and CIS M365 Benchmark §4 treat as foundational, not optional.'
        Remediation  = @(
            'Intune admin center > Endpoint security > Disk encryption > Create Policy (Windows 10 and later, BitLocker profile) - set the OS drive encryption type to Full encryption (not Used space only), and assign it to the intended device population.'
            'If a Disk Encryption policy already exists but is Failing this check, edit it and change the OS drive encryption type setting directly - do not create a second competing policy for the same population (see TP.INT.0006''s own conflict-surfacing check for what happens when two policies disagree on the same setting for overlapping devices).'
            'Pair with a recovery-key backup requirement (Require device to back up recovery information to Microsoft Entra) so an encrypted-but-unrecoverable device does not become its own incident.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/EndpointSecurityDiskEncryption')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0014--bitlocker-full-disk-encryption-enforced-via-endpoint-security-policy'
        Authorities = @(
            # PRIMARY - carries the "Full encryption vs Used space only" behavioral claim
            # this check's Consulting text makes (POST-REVIEW FIX: this claim was
            # previously attributed to the deprecated page listed second below, which
            # does not document the current Settings Catalog format's behavior).
            'https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp'
            # SECONDARY, deprecated pre-June-2023 profile-format reference only - confirms
            # this policy surface and its settings exist, but documents the OLDER profile
            # format, not the current Settings Catalog format this check's rule function
            # actually reads (see Test-PulseBitLockerFullDiskEncryption.ps1's own
            # docstring for the same caveat).
            'https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-disk-encryption-settings'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1123'; License = 'MIT' }
}
