<#
    Private: load (or, on first call, create) the operator's HMAC key.

    The operator key is a 32-byte secret held on the machine running TenantPulse, never
    inside a snapshot. It is used by Get-PulsePseudonym to turn tenant/object identifiers
    into stable pseudonyms so raw tenant IDs never end up in snapshots or reports.

    Snapshot-root guard: this refuses to create or read a key file that lives under a
    snapshot root - a directory containing a manifest.json with a schemaVersion property.
    The guard is best-effort and fail-open by design: it is an accidental-capture net, not
    a security boundary. A manifest.json that fails to parse as JSON (or lacks a
    schemaVersion) is treated as "not a snapshot root" rather than blocking the call - the
    guard exists to catch the common mistake of pointing -KeyPath at a snapshot directory,
    not to resist an adversary who controls the manifest's contents.

    First-create race: two processes can call this concurrently with no key on disk yet.
    Key creation uses FileMode.CreateNew (which atomically fails with IOException if the
    file already exists) so only one writer's CreateNew call can succeed; the loser falls
    through to the read path and reads the winner's key. This guarantees every caller ends
    up with the same 32 bytes, never two silently-diverging keys. On non-Windows the file
    mode is set to 0600 (owner read/write) on the just-created empty file BEFORE any key
    bytes are written, so the key is never briefly readable at the platform-default mode.

    Windows permissions: no Set-Acl call is made here. The accepted rationale is that
    default %USERPROFILE% ACL inheritance already restricts access to the owning user plus
    SYSTEM and Administrators, which is roughly equivalent to 0600 for this threat model
    (accidental capture of the key alongside a snapshot, not a privileged local attacker).
    DPAPI is deliberately not used: DPAPI-protected data is bound to the encrypting user
    profile/machine, which would break key portability (copying operator.key to another
    host or restoring it from backup) - the wrong tradeoff for this threat model.
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

    $existingKey = Get-PulseOperatorKeyFromDisk -KeyPath $resolvedKeyPath
    if ($null -ne $existingKey) {
        return , $existingKey
    }

    $keyDirectory = [System.IO.Path]::GetDirectoryName($resolvedKeyPath)
    if (-not (Test-Path -LiteralPath $keyDirectory -PathType Container)) {
        New-Item -Path $keyDirectory -ItemType Directory -Force | Out-Null
        if (-not $IsWindows) {
            [System.IO.File]::SetUnixFileMode(
                $keyDirectory,
                [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite -bor [System.IO.UnixFileMode]::UserExecute)
        }
    }

    $key = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)

    try {
        # FileMode.CreateNew fails atomically (IOException) if the file already exists, so
        # exactly one concurrent caller wins this create - see the first-create race note
        # in the function help above.
        $stream = [System.IO.FileStream]::new(
            $resolvedKeyPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        try {
            if (-not $IsWindows) {
                # chmod the empty file to owner-only BEFORE any key bytes are written, so
                # the key is never briefly readable at the platform-default create mode.
                [System.IO.File]::SetUnixFileMode(
                    $resolvedKeyPath,
                    [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite)
            }
            # On Windows, no chmod-equivalent call is made here - see the Windows
            # permissions note in the function help above.

            $stream.Write($key, 0, $key.Length)
            $stream.Flush()
        } finally {
            $stream.Dispose()
        }

        return , $key
    } catch [System.IO.IOException] {
        # Another caller won the race and created the file first. Read its key instead of
        # treating this as an error.
        $winnerKey = Get-PulseOperatorKeyFromDisk -KeyPath $resolvedKeyPath
        if ($null -eq $winnerKey) {
            throw
        }
        return , $winnerKey
    }
}
