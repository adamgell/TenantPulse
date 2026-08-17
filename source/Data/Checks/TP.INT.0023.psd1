@{
    Id         = 'TP.INT.0023'
    Title      = 'Intune Certificate Connectors healthy and on a supported version'
    Category   = 'Intune.Connectors'
    Severity   = 'High'
    Effort     = 'Medium'
    Impact     = 'Medium'
    Data       = @{
        Datasets = @('ndesConnectors')
        Gates    = @('Intune')
    }
    Rule       = @{
        Type     = 'Function'
        Function = 'Test-PulseCertificateConnectorsHealthy'
    }
    Consulting = @{
        WhatItMeans  = 'The Certificate Connector for Microsoft Intune is on-premises software that bridges Intune to a Certification Authority to deliver SCEP, PKCS, and PKCS-imported certificates to managed devices. This check Fails a connector that is not in an `active` state, is running a version older than the last known-good floor this check was authored against, or has not connected to Intune within the last hour - any one of those is enough to silently break certificate-based Wi-Fi/VPN/authentication profile delivery. Zero registered connectors is treated as a legitimate skip, not a failure, for tenants that do not use certificate-based profiles.'
        WhyItMatters = 'Certificate-based Wi-Fi, VPN, and authentication profiles depend entirely on a healthy connector to actually issue certificates to devices - when a connector goes stale or falls out of support, existing certificates keep working until they expire, but NEW and RENEWING certificate requests silently fail. This is typically discovered only when users start losing Wi-Fi or VPN access as certificates expire in a wave, well after the underlying connector problem began.'
        Remediation  = @(
            'Intune admin center > Tenant administration > Connectors and tokens > Certificate connectors - select the offending connector to see its status; a Warning means it is within the post-support grace period, an Error means it is out of support and can stop working at any time.'
            'On the Windows Server hosting the connector, confirm automatic update is not blocked (port 443 to autoupdate.msappproxy.net) - most stale-version failures trace back to a blocked automatic-update path rather than a manual oversight.'
            'If a connector has not connected recently but the server is otherwise healthy, check the connector''s own Windows Event Viewer logs (Application and Service Logs > Microsoft > Intune > Certificate Connectors) for repeated upload/download failures before assuming a full reinstall is required.'
        )
        PortalLinks  = @('https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/CertificateConnectorMenu')
    }
    References = @{
        Research    = 'docs/research/iha-v2/2026-08-16-phase3-intune-check-entries.md#tpint0023--intune-certificate-connectors-healthy-and-on-a-supported-version'
        Authorities = @(
            'https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/overview'
        )
    }
    Origin     = @{ Project = 'Maester'; Id = 'MT.1097'; License = 'MIT' }
}
