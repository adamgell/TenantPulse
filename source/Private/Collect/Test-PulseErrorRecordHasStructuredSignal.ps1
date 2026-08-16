<#
    Private: report whether a Get-GraphObject failure's ErrorRecord carries ANY structured
    classification signal Get-PulseFailureClass can read - CategoryInfo.Category (GraphKit
    0.1.1 maps this from the HTTP status; the PowerShell default when nothing set it is the
    literal string 'NotSpecified') or a parseable Telemetry last-attempt StatusCode.

    Used ONLY by Invoke-PulseCollection's generic-Failed branch to decide whether to append
    '(status unknown)' to the reason: that suffix now means the ErrorRecord itself carried
    nothing structured at all (not, as under GraphKit 0.1.0, that a separate out-of-band
    recovery call failed - there is no such call anymore). Kept as its own small, directly
    testable function rather than inlined, for the same reason Get-PulseFailureClass is
    isolated: it is the one place that has to know GraphKit's ErrorRecord shape.

    TOTAL by construction, exactly like Get-PulseFailureClass: must never itself throw. A
    $null ErrorRecord, or one whose CategoryInfo/TargetObject/Telemetry properties are
    missing or malformed, is reported as carrying no structured signal rather than causing
    an unhandled failure in a per-dataset catch block.
#>

function Test-PulseErrorRecordHasStructuredSignal {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    try {
        if ($null -eq $ErrorRecord) { return $false }

        # GraphKit's New-GraphOperationFailureRecord only ever sets CategoryInfo.Category
        # to one of these values (mapped directly from an HTTP status). A bare PowerShell
        # `throw "<string>"` - the shape an unstructured upstream failure takes - defaults
        # CategoryInfo.Category to 'OperationStopped', which is NOT in this set, so it
        # correctly reports no structured signal rather than being mistaken for one.
        $knownGraphKitCategories = @(
            'AuthenticationError', 'PermissionDenied', 'ObjectNotFound',
            'OperationTimeout', 'LimitsExceeded', 'ResourceUnavailable', 'InvalidResult'
        )

        $categoryInfoProperty = $ErrorRecord.PSObject.Properties['CategoryInfo']
        if ($null -ne $categoryInfoProperty -and $null -ne $categoryInfoProperty.Value) {
            $categoryProperty = $categoryInfoProperty.Value.PSObject.Properties['Category']
            if ($null -ne $categoryProperty) {
                $category = [string] $categoryProperty.Value
                if ($knownGraphKitCategories -contains $category) {
                    return $true
                }
            }
        }

        $targetObjectProperty = $ErrorRecord.PSObject.Properties['TargetObject']
        if ($null -ne $targetObjectProperty -and $null -ne $targetObjectProperty.Value) {
            $telemetryProperty = $targetObjectProperty.Value.PSObject.Properties['Telemetry']
            if ($null -ne $telemetryProperty -and $null -ne $telemetryProperty.Value) {
                $attempts = @($telemetryProperty.Value)
                if ($attempts.Count -gt 0) {
                    $lastAttempt = $attempts[$attempts.Count - 1]
                    $statusProperty = $lastAttempt.PSObject.Properties['StatusCode']
                    if ($null -ne $statusProperty -and $null -ne $statusProperty.Value) {
                        return $true
                    }
                }
            }
        }

        return $false
    } catch {
        return $false
    }
}
