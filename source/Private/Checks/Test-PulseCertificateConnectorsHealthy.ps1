<#
    Private: TP.INT.0023 rule function - Intune Certificate Connectors healthy and on a
    supported version (Task 3.3, Maester port MT.1097 - Test-MtCertificateConnectors, MIT).

    LIVE DATASET: `ndesConnectors` maps to GraphKit 0.1.1's released `CertificateConnector`/
    `List` (beta) descriptor, PathTemplate `/deviceManagement/ndesConnectors` - confirmed
    via a live Get-GraphOperation -List enumeration, NOT Pending. ("ndesConnectors" is the
    Graph resource's own path segment - it now also fronts the unified PKCS/SCEP/revocation
    Certificate Connector, not only classic NDES-backed SCEP, per
    https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/overview.)

    FIELD NAMES (live-verified against the ndesConnector resource's own documented property
    set, Graph beta): `state`, `lastConnectionDateTime`, `connectorVersion`, `displayName`.

    VERSION FLOOR (live-verified against
    https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/overview's
    own "What's new" release history, fetched for this check): version `6.2406.0.1001`
    (released 2024-09-19) is CONFIRMED to be a real, historical connector release - carried
    through from Maester's own hardcoded floor as "known good as of this research date",
    per the research entry's own "hardcoded version floor trap" note. The same page
    documents each connector release is supported for only 6 months, after which the admin
    center itself starts showing a Warning (then, after the 6-month grace period, an Error)
    for that connector - this rule's own version-floor comparison is therefore already a
    LOOSER bar than what Intune's own admin center will eventually flag; it is not a
    substitute for keeping connectors current, only a floor beneath which this check treats
    a connector as definitely unsupported.

    DETERMINISM: compares lastConnectionDateTime against $Context.EvaluationCutoffBase
    (falling back to SnapshotCreatedUtc) - never Get-Date/::Now/::UtcNow.

    FIELD-ABSENCE LENS: state, connectorVersion, or lastConnectionDateTime absent on an
    existing connector row is undecidable - throws.

    RULE: zero connectors = NotApplicable (skip - mirrors Maester's own
    ItemNotFoundException -> Skipped behavior; some tenants legitimately don't use
    certificate-based profiles). Otherwise a connector is "offending" if state is not
    `active`, OR its version compares below the 6.2406.0.1001 floor, OR its last connection
    was more than an hour before the cutoff. Fail if any connector is offending, Pass
    otherwise (this check has no Warn tier - Maester's own source treats connector health as
    a binary pass/fail).

    Compare-PulseConnectorVersion is nested inside this function (post-review MINOR fix) -
    it exists only to serve this one rule's version-floor comparison and is not referenced
    anywhere else in the module, so it follows the same file-local-helper convention
    Test-PulseStaleDevices.ps1's own ConvertTo-PulseNullableUtcDateTime already established
    rather than being a second module-scoped function name to track.
#>

function Test-PulseCertificateConnectorsHealthy {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    function Compare-PulseConnectorVersion {
        param(
            [Parameter(Mandatory)] [string] $Left,
            [Parameter(Mandatory)] [string] $Right
        )

        $leftParts = @($Left -split '\.' | ForEach-Object { $v = 0; [void][int]::TryParse($_, [ref] $v); $v })
        $rightParts = @($Right -split '\.' | ForEach-Object { $v = 0; [void][int]::TryParse($_, [ref] $v); $v })
        $max = [System.Math]::Max($leftParts.Count, $rightParts.Count)

        for ($i = 0; $i -lt $max; $i++) {
            $l = if ($i -lt $leftParts.Count) { $leftParts[$i] } else { 0 }
            $r = if ($i -lt $rightParts.Count) { $rightParts[$i] } else { 0 }
            if ($l -ne $r) { return $l.CompareTo($r) }
        }
        return 0
    }

    $connectors = @($Datasets.ndesConnectors)
    if ($connectors.Count -eq 0) {
        return New-PulseFinding -Status NotApplicable -Reason 'No Intune Certificate Connectors are registered for this tenant - certificate-based (SCEP/PKCS) profile delivery is not in use, so there is nothing for this check to evaluate.'
    }

    $cutoffBaseText = $null
    if ($Context -and $Context.ContainsKey('EvaluationCutoffBase') -and $Context.EvaluationCutoffBase) {
        $cutoffBaseText = [string] $Context.EvaluationCutoffBase
    } elseif ($Context -and $Context.ContainsKey('SnapshotCreatedUtc') -and $Context.SnapshotCreatedUtc) {
        $cutoffBaseText = [string] $Context.SnapshotCreatedUtc
    }
    if ([string]::IsNullOrWhiteSpace($cutoffBaseText)) {
        throw 'Test-PulseCertificateConnectorsHealthy: no $Context.EvaluationCutoffBase/SnapshotCreatedUtc was supplied.'
    }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $cutoff = [datetime]::Parse($cutoffBaseText, $culture, $styles)
    $connectionThreshold = $cutoff.AddHours(-1)
    $minimumVersion = '6.2406.0.1001'

    $offending = [System.Collections.Generic.List[object]]::new()
    $allRows = [System.Collections.Generic.List[object]]::new()

    for ($index = 0; $index -lt $connectors.Count; $index++) {
        $connector = $connectors[$index]

        foreach ($prop in @('state', 'connectorVersion', 'lastConnectionDateTime')) {
            if (-not (Test-PulseRowPropertyPresent -Row $connector -PropertyName $prop) -or $null -eq $connector.$prop) {
                throw "Test-PulseCertificateConnectorsHealthy: an ndesConnectors row is missing '$prop'."
            }
        }

        $state = [string] $connector.state
        $version = [string] $connector.connectorVersion
        $lastConnection = [datetime]::Parse([string] $connector.lastConnectionDateTime, $culture, $styles)

        $isInactive = $state -ne 'active'
        $isBelowFloor = (Compare-PulseConnectorVersion -Left $version -Right $minimumVersion) -lt 0
        $isStale = $lastConnection -lt $connectionThreshold

        # ORDINAL FALLBACK (Phase 3 whole-phase review, catalog-coherence finding I2): the
        # id-less fallback used to be displayName itself - two id-less connectors sharing a
        # displayName would collide on the same evidence Identity/SortKey pair and degrade
        # the whole evaluation to Error via Assert-PulseEvidenceNoDuplicates. Per-row
        # ordinal ('cert-connector-<index>', 0-based) is guaranteed unique within one
        # evaluation.
        $identity = if (Test-PulseRowPropertyPresent -Row $connector -PropertyName 'id') { [string] $connector.id } else { "cert-connector-$index" }
        $row = @{
            Identity = $identity
            Detail   = @{
                displayName            = $connector.displayName
                state                  = $state
                connectorVersion       = $version
                lastConnectionDateTime = $connector.lastConnectionDateTime
                inactive               = $isInactive
                belowVersionFloor      = $isBelowFloor
                staleConnection        = $isStale
            }
            SortKey  = $identity
        }
        $allRows.Add($row)

        if ($isInactive -or $isBelowFloor -or $isStale) {
            $offending.Add($row)
        }
    }

    if ($offending.Count -eq 0) {
        return New-PulseFinding -Status Pass -Reason "All $($connectors.Count) Intune Certificate Connector(s) are active, on a supported version, and connected within the last hour." -Evidence $allRows.ToArray()
    }

    $reason = "$($offending.Count) of $($connectors.Count) Intune Certificate Connector(s) are unhealthy (inactive, below the supported version floor, or have not connected in the last hour) - certificate-based Wi-Fi/VPN/authentication profile delivery to new and renewing devices is at risk of silently breaking behind the affected connector(s)."
    return New-PulseFinding -Status Fail -Reason $reason -Evidence $offending.ToArray()
}
