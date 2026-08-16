<#
    Private: load (or, on first call, create) the operator's HMAC key.

    The operator key is a 32-byte secret held on the machine running TenantPulse, never
    inside a snapshot. It is used by Get-PulsePseudonym to turn tenant/object identifiers
    into stable pseudonyms so raw tenant IDs never end up in snapshots or reports. Because
    the key must never be captured alongside the data it protects, this function refuses
    to create or read a key file that lives under a snapshot root - a directory containing
    a manifest.json with a schemaVersion property.
#>

function Get-PulseOperatorKey {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter()]
        [string] $KeyPath = (Join-Path $HOME '.tenantpulse/operator.key')
    )

    $resolvedKeyPath = [System.IO.Path]::GetFullPath($KeyPath)

    $probe = [System.IO.Path]::GetDirectoryName($resolvedKeyPath)
    while (-not [string]::IsNullOrEmpty($probe)) {
        $candidateManifest = Join-Path $probe 'manifest.json'
        if (Test-Path -LiteralPath $candidateManifest -PathType Leaf) {
            $isSnapshotRoot = $false
            try {
                $manifestContent = Get-Content -LiteralPath $candidateManifest -Raw | ConvertFrom-Json -ErrorAction Stop
                if ($manifestContent.PSObject.Properties.Name -contains 'schemaVersion' -and
                    -not [string]::IsNullOrEmpty($manifestContent.schemaVersion)) {
                    $isSnapshotRoot = $true
                }
            } catch {
                $isSnapshotRoot = $false
            }

            if ($isSnapshotRoot) {
                throw "Refusing to create or read operator key at '$KeyPath': path is inside a snapshot root ('$probe' contains a manifest.json with a schemaVersion). Operator keys must never live inside a snapshot."
            }
        }

        $parent = [System.IO.Path]::GetDirectoryName($probe)
        if ($parent -eq $probe) {
            break
        }
        $probe = $parent
    }

    if (Test-Path -LiteralPath $resolvedKeyPath -PathType Leaf) {
        # Unary comma prevents PowerShell's pipeline from unrolling the byte array into
        # individual objects (which the caller would then see re-collected as Object[]).
        return , [byte[]] (Get-Content -LiteralPath $resolvedKeyPath -AsByteStream -Raw)
    }

    $keyDirectory = [System.IO.Path]::GetDirectoryName($resolvedKeyPath)
    if (-not (Test-Path -LiteralPath $keyDirectory -PathType Container)) {
        New-Item -Path $keyDirectory -ItemType Directory -Force | Out-Null
    }

    $key = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    [System.IO.File]::WriteAllBytes($resolvedKeyPath, $key)

    if (-not $IsWindows) {
        [System.IO.File]::SetUnixFileMode(
            $resolvedKeyPath,
            [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite)
    }
    # On Windows there is no POSIX permission-bit equivalent to set here; NTFS ACLs would
    # be the analogous control but are out of scope for this task.

    return , $key
}
