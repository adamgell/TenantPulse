<#
    Private: attempt-and-classify collection of every dataset in a resolved manifest.

    Iterates a Get-PulseCollectionManifest result (already deduped and sorted ordinally by
    Dataset name - iterated here in the order given, not re-sorted, so that invariant
    lives in exactly one place) and, for every entry:

        - Pending (see DatasetMap.psd1's header): writes Skipped with reason
          'descriptor-pending: awaiting GraphKit release' and makes no Graph call at all -
          there is no descriptor yet to resolve or assert against.
        - Otherwise: asserts the descriptor is read-only (Assert-PulseReadOnlyDescriptor -
          this throws and aborts the whole run on a violation; it is a module-authoring
          bug, not a per-dataset outcome), then attempts Get-GraphObject. A clean read
          writes Collected. A caught error is classified via Get-PulseFailureClass:
          PermissionDenied writes Skipped with reason 'permission-denied: <required
          permissions>' (read from the descriptor's own RequiredPermissions - the
          uncollected-with-reason outcome the spec requires, without a new GraphKit
          permission-preflight API); anything else writes Failed with the caught
          exception's message as the reason.

    Every dataset is attempted independently - one dataset's 403 or 500 never stops the
    rest of the manifest from being attempted (see Get-PulseTenantSnapshot for the
    different, total-failure case where Get-GraphContext itself fails before this function
    is ever called).
#>

function Invoke-PulseCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Store,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Manifest,

        [Parameter(Mandatory)]
        [pscustomobject] $Context
    )

    foreach ($entry in $Manifest) {
        if ($entry.Pending) {
            Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion `
                -Status 'Skipped' -Reason 'descriptor-pending: awaiting GraphKit release'
            continue
        }

        # A read-only violation is a module-authoring bug (a dataset map entry pointing at
        # a write-shaped or unsafe-to-replay descriptor) - it throws and aborts the whole
        # run rather than being caught per-dataset like a Graph failure below.
        Assert-PulseReadOnlyDescriptor -Type $entry.Type -Operation $entry.Operation

        try {
            $rows = @(Get-GraphObject -Context $Context -Type $entry.Type -Operation $entry.Operation)
            Write-PulseDataset -Store $Store -Name $entry.Dataset -Data $rows -ApiVersion $entry.ApiVersion -Status 'Collected'
        } catch {
            $failureClass = Get-PulseFailureClass -ErrorRecord $_

            if ($failureClass -eq 'PermissionDenied') {
                $requiredPermissions = $null
                try {
                    $descriptor = Get-GraphOperation -Type $entry.Type -Operation $entry.Operation
                    if ($null -ne $descriptor -and $descriptor.ContainsKey('RequiredPermissions')) {
                        $requiredPermissions = (@($descriptor.RequiredPermissions) | ForEach-Object {
                            if ($_ -is [System.Collections.IDictionary] -and $_.ContainsKey('Value')) { $_.Value } else { $_ }
                        }) -join ', '
                    }
                } catch {
                    # Best-effort only: a failure to re-resolve the descriptor's required
                    # permissions must never mask the original 403 classification.
                    $requiredPermissions = $null
                }

                $permissionsText = if ([string]::IsNullOrWhiteSpace($requiredPermissions)) { '(unknown)' } else { $requiredPermissions }
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion `
                    -Status 'Skipped' -Reason "permission-denied: $permissionsText"
            } else {
                Write-PulseDataset -Store $Store -Name $entry.Dataset -ApiVersion $entry.ApiVersion `
                    -Status 'Failed' -Reason $_.Exception.Message
            }
        }
    }
}
