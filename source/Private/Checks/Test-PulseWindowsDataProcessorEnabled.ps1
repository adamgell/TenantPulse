<#
    Private: TP.INT.0009 rule function - Windows diagnostic data processor configuration
    enabled (Task 3.2, Maester port MT.1099 - Test-MtWindowsDataProcessor, MIT).

    PENDING DATASET (honest NA): dataProcessorServiceForWindowsFeaturesOnboarding has no
    released GraphKit 0.1.1 descriptor - DatasetMap.psd1 marks it Pending=$true. On a live
    tenant this resolves NotApplicable until GraphKit ships the descriptor (a G-batch
    request). Rule body is real and fixture-tested regardless.

    RULE (ported verbatim from Maester's own AND condition - live-verified against
    https://learn.microsoft.com/en-us/intune/privacy/enable-windows-diagnostic-data,
    fetched for this check; the research entry's own Authority URL,
    windows/privacy/manage-windows-1809-endpoints, was live-fetched and found to be an
    unrelated page about Windows network endpoints, NOT the data-processor topic - it was
    NOT used in this descriptor's References.Authorities): Pass only when BOTH
    hasValidWindowsLicense AND areDataProcessorServiceForWindowsFeaturesEnabled are $true.
    Fail otherwise.

    FIELD-ABSENCE TRAP (research entry's own Notes, honored here): a tenant without
    qualifying Windows licensing gets hasValidWindowsLicense=$false (or absent, treated
    the same way) - this is a LICENSING gap, not a configuration gap, and the two booleans
    are surfaced SEPARATELY in both evidence and the Reason text so a reader is never left
    conflating "you don't have the right Windows licenses" with "you have the licenses but
    didn't flip the toggle". Both an absent value and an explicit $false read as "not
    satisfied" - this property pair has no legitimate NotApplicable state distinct from
    Fail (unlike TP.INT.0001's mobileDeviceManagementAuthority, there is no field this
    resource can omit that would make the question itself inapplicable - a tenant that has
    simply never configured this is exactly the Fail case Maester's own check exists to
    surface).
#>

function Test-PulseWindowsDataProcessorEnabled {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Datasets,

        [Parameter()]
        [hashtable] $Context = @{}
    )

    $rows = @($Datasets.dataProcessorServiceForWindowsFeaturesOnboarding)
    if ($rows.Count -eq 0) {
        throw 'Test-PulseWindowsDataProcessorEnabled: dataProcessorServiceForWindowsFeaturesOnboarding dataset returned no rows - the service returned nothing to evaluate for this tenant-wide singleton.'
    }

    $hasValidWindowsLicense = ($rows[0].hasValidWindowsLicense -eq $true)
    $featuresEnabled = ($rows[0].areDataProcessorServiceForWindowsFeaturesEnabled -eq $true)

    $evidence = @(
        @{
            Identity = 'dataProcessorServiceForWindowsFeaturesOnboarding'
            Detail   = @{
                hasValidWindowsLicense                          = $rows[0].hasValidWindowsLicense
                areDataProcessorServiceForWindowsFeaturesEnabled = $rows[0].areDataProcessorServiceForWindowsFeaturesEnabled
            }
            SortKey  = 'dataProcessorServiceForWindowsFeaturesOnboarding'
        }
    )

    if ($hasValidWindowsLicense -and $featuresEnabled) {
        return New-PulseFinding -Status Pass -Reason 'The tenant has a valid qualifying Windows license AND has enabled Windows diagnostic data in processor configuration - the organization is the GDPR-defined controller for Windows diagnostic data from enrolled devices, and diagnostic-data-dependent Intune features (feature/driver/expedited update failure alerts, update compatibility reports) can function.' -Evidence $evidence
    }

    if (-not $hasValidWindowsLicense -and -not $featuresEnabled) {
        $reason = 'Windows diagnostic data processor configuration is NOT enabled, and the tenant does not (or has not attested to) hold a qualifying Windows license (Enterprise/Education/VDA E3 or E5, or the equivalent Microsoft 365 bundle) - this is a LICENSING gap as much as a configuration one; diagnostic-data-dependent Intune features (update compatibility reports, expedited/driver update failure alerts) will not function until both are addressed.'
    } elseif (-not $hasValidWindowsLicense) {
        $reason = 'Windows diagnostic data processor configuration is enabled, but the tenant does not (or has not attested to) hold a qualifying Windows license - confirm license entitlement and the "I confirm that my tenant owns one of these licenses" attestation (Tenant administration > Connectors and tokens > Windows data); diagnostic-data-dependent Intune features remain unavailable until the license attestation is satisfied.'
    } else {
        $reason = 'The tenant holds a qualifying Windows license, but Windows diagnostic data processor configuration has not been enabled (Tenant administration > Connectors and tokens > Windows data > "Enable features that require Windows diagnostic data in processor configuration" is Off, the default) - diagnostic-data-dependent Intune features (update compatibility reports, expedited/driver update failure alerts) will not function until this is turned on.'
    }

    return New-PulseFinding -Status Fail -Reason $reason -Evidence $evidence
}
