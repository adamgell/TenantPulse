<#
    Private: strip GraphKit's per-row provenance stamps before a dataset is serialized.

    Get-GraphObject stamps every returned row with four provenance fields: _Tenant (the
    GraphKit ProfileId - e.g. 'ivy24' - not the raw tenant GUID, but still an
    operator-chosen identifier with no place in a pseudonymized artifact),
    _RetrievedUtc, _GraphPath and _ApiVersion. Task 1.11's live gate (Ivy24 lab tenant)
    found these surviving unredacted into datasets/<Name>.json - not the manifest's
    `tenant` field and not a reason string, so outside the letter of
    Get-PulseTenantSnapshot's own pseudonymization docstring, but a real residual
    identifier in the artifact tree all the same.

    STRIP, not pseudonymize: all four are exact duplicates of information the manifest
    already records per dataset (apiVersion, collectedUtc, sha256) or of nothing
    TenantPulse's schema needs at all (_GraphPath). Pseudonymizing _Tenant the way the
    manifest's own `tenant` field is pseudonymized would work, but would open a SECOND
    redaction path that has to be kept in sync with the first forever; deleting the field
    needs no synchronization and cannot drift. Applied inside Write-PulseDataset, before
    canonical serialization, so every dataset file written from here forward is
    unaffected by this field's presence or absence on the rows GraphKit handed back.

    Mutates each row's PSObject.Properties in place (dropping only these four
    well-known stamp names, nothing else) and returns -Data itself: safe because the only
    other reader of these same row objects, Invoke-PulseCollection's $collectedRows (used
    by a later IdFromDataset entry), only ever reads a row's `id` property - never any of
    the four stripped here.
#>

function Remove-PulseGraphRowProvenance {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        # AllowNull() alongside AllowEmptyCollection(): a Mandatory array-typed parameter
        # validates each ELEMENT, not just the array reference itself - a $null row inside
        # an otherwise non-null array (a defensive case this function is written to
        # tolerate; see below) would otherwise fail parameter binding before the function
        # body ever runs.
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Data
    )

    $stampNames = @('_Tenant', '_RetrievedUtc', '_GraphPath', '_ApiVersion')

    foreach ($row in $Data) {
        if ($null -eq $row) { continue }
        if ($row -isnot [System.Management.Automation.PSObject]) { continue }

        foreach ($stampName in $stampNames) {
            if ($null -ne $row.PSObject.Properties[$stampName]) {
                $row.PSObject.Properties.Remove($stampName)
            }
        }
    }

    return , $Data
}
