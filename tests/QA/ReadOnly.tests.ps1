<#
    QA gate: the module's read-only promise, enforced statically at CI time against the
    real GraphKit catalog, not just at runtime against a live tenant.

    Every dataset TenantPulse can collect is declared once, in source/Data/DatasetMap.psd1,
    as a {Type;Operation} pair the collector resolves via GraphKit's Get-GraphOperation
    (see Assert-PulseReadOnlyDescriptor's own docstring for why - that function backs BOTH
    the collector's runtime assertion and this gate, applying the identical predicate:

        ThrottleClass -eq 'Read' -and ReplayPolicy -eq 'Safe'

    This file does not call Assert-PulseReadOnlyDescriptor itself (that function throws,
    which is right for a runtime abort but wrong for a gate that wants to enumerate every
    violation in one run rather than stopping at the first). Instead it re-applies the same
    predicate through Test-PulseReadOnlyDatasetMap below, a small non-throwing walker local
    to this file, so every dataset gets its own reported result.

    Unlike a unit test, this file deliberately imports the REAL GraphKit module (0.1.0,
    installed as TenantPulse's own RequiredModules dependency) and calls its REAL
    Get-GraphOperation - metadata-catalog lookups only, never a network call, never a live
    tenant - to prove every RELEASED dataset entry resolves to an actual Read/Safe
    descriptor. This is the one place in the whole suite allowed to do that; every other
    test stubs GraphKit inside TenantPulse's module scope specifically so it never depends
    on GraphKit's real catalog contents. This gate exists precisely because that catalog CAN
    drift out of sync with DatasetMap.psd1 - see the deviceManagementSettings fix in this
    same commit, caught by writing this file.

    Pending-flagged entries (source/Data/DatasetMap.psd1's Pending = $true datasets) have no
    released GraphKit descriptor to resolve at all - Get-GraphOperation would simply not
    find them. For those, the gate instead asserts the map entry's own ExpectedThrottleClass
    / ExpectedReplayPolicy declaration is 'Read' / 'Safe' (see DatasetMap.psd1's own comment
    for why that is still a real, catchable assertion) and reports the skip reason plainly;
    they get re-checked against the live catalog automatically the moment the Pending flag
    drops, because Test-PulseReadOnlyDatasetMap then falls through to the same
    Get-GraphOperation path every released entry uses.
#>

BeforeDiscovery {
    $projectPath = "$($PSScriptRoot)\..\.." | Convert-Path
    $datasetMapPath = Join-Path -Path $projectPath -ChildPath 'source/Data/DatasetMap.psd1'

    $realDatasetMap = Import-PowerShellDataFile -Path $datasetMapPath

    $script:releasedDatasetCases = @(
        $realDatasetMap.Keys |
            Where-Object { -not $realDatasetMap[$_].Pending } |
            Sort-Object -Culture ([System.Globalization.CultureInfo]::InvariantCulture) |
            ForEach-Object {
                @{
                    Name  = $_
                    Type  = $realDatasetMap[$_].Type
                    Op    = $realDatasetMap[$_].Operation
                }
            }
    )

    $script:pendingDatasetCases = @(
        $realDatasetMap.Keys |
            Where-Object { $realDatasetMap[$_].Pending } |
            Sort-Object -Culture ([System.Globalization.CultureInfo]::InvariantCulture) |
            ForEach-Object {
                @{
                    Name                  = $_
                    Type                  = $realDatasetMap[$_].Type
                    Op                    = $realDatasetMap[$_].Operation
                    ExpectedThrottleClass = $realDatasetMap[$_].ExpectedThrottleClass
                    ExpectedReplayPolicy  = $realDatasetMap[$_].ExpectedReplayPolicy
                }
            }
    )

    # Discovery-time vacuum guard, mirroring SecretScan.tests.ps1's: if BOTH case lists are
    # empty, every -ForEach block below silently produces zero leaf tests - a
    # DatasetMap.psd1 that failed to parse into any entries (or a Where-Object filter that
    # quietly stopped matching anything) would leave this whole gate green while asserting
    # nothing, indistinguishable from a real pass by looking at the NUnit result alone. Not
    # leaning on Assert-GateResult.ps1's suite-wide -MinimumTests floor to catch this for
    # THIS file specifically - that floor only notices a large-enough drop in the TOTAL
    # count, not this one file quietly going empty while other files keep growing.
    if ($script:releasedDatasetCases.Count -eq 0 -and $script:pendingDatasetCases.Count -eq 0) {
        throw 'Static read-only gate: discovered zero DatasetMap.psd1 entries (both released and Pending) - the map failed to parse or the read/filter logic is broken.'
    }
}

BeforeAll {
    $projectPath = "$($PSScriptRoot)\..\.." | Convert-Path
    $script:datasetMapPath = Join-Path -Path $projectPath -ChildPath 'source/Data/DatasetMap.psd1'
    $script:fixtureDatasetMapPath = Join-Path -Path $projectPath -ChildPath 'tests/Fixtures/DatasetMap/mutation-write-op.psd1'

    # Real GraphKit (0.1.0), deliberately NOT stubbed in this file - see the file-level
    # docstring above for why this is the one QA test allowed to import it for real.
    Import-Module -Name GraphKit -Force -ErrorAction Stop

    <#
        Walks a DatasetMap.psd1-shaped hashtable and returns every read-only-predicate
        violation as a string (empty array = every entry is provably read-only). Applies
        the SAME predicate as Assert-PulseReadOnlyDescriptor
        (ThrottleClass -eq 'Read' -and ReplayPolicy -eq 'Safe'), but never throws - a gate
        wants every violation reported in one pass, not a stop at the first one.

        Released entries are resolved through the real Get-GraphOperation (metadata lookup
        only). Pending entries are never sent to Get-GraphOperation at all (there is nothing
        released to resolve); instead their ExpectedThrottleClass/ExpectedReplayPolicy
        declaration is checked directly - this is what lets the mutation-check below prove
        the walker's OWN logic can fail without ever touching or corrupting the real
        catalog.
    #>
    function Test-PulseReadOnlyDatasetMap {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory)]
            [hashtable] $DatasetMap
        )

        $violations = [System.Collections.Generic.List[string]]::new()

        foreach ($name in ($DatasetMap.Keys | Sort-Object -Culture ([System.Globalization.CultureInfo]::InvariantCulture))) {
            $entry = $DatasetMap[$name]

            if ($entry.Pending) {
                $expectedThrottle = [string] $entry.ExpectedThrottleClass
                $expectedReplay = [string] $entry.ExpectedReplayPolicy

                if ($expectedThrottle -ne 'Read' -or $expectedReplay -ne 'Safe') {
                    $violations.Add("Pending dataset '$name' ($($entry.Type)/$($entry.Operation)) does not declare an expected Read/Safe descriptor (ExpectedThrottleClass='$expectedThrottle', ExpectedReplayPolicy='$expectedReplay') - descriptor-pending: cannot verify against the live GraphKit catalog until it releases, so its OWN declaration must already be read-only.")
                }

                continue
            }

            try {
                $descriptor = Get-GraphOperation -Type $entry.Type -Operation $entry.Operation -ErrorAction Stop
            } catch {
                $violations.Add("Dataset '$name' ($($entry.Type)/$($entry.Operation)) could not be resolved against the GraphKit catalog: $($_.Exception.Message)")
                continue
            }

            if ($null -eq $descriptor) {
                $violations.Add("Dataset '$name' ($($entry.Type)/$($entry.Operation)) resolved to no GraphKit descriptor.")
                continue
            }

            $throttleClass = [string] $descriptor.ThrottleClass
            $replayPolicy = [string] $descriptor.ReplayPolicy

            if ($throttleClass -ne 'Read' -or $replayPolicy -ne 'Safe') {
                $violations.Add("Dataset '$name' ($($entry.Type)/$($entry.Operation)) is NOT read-only (ThrottleClass='$throttleClass', ReplayPolicy='$replayPolicy') - TenantPulse only ever collects through descriptors where ThrottleClass is 'Read' and ReplayPolicy is 'Safe'.")
            }
        }

        return $violations.ToArray()
    }
}

Describe 'Static read-only gate' -Tag 'QA', 'ReadOnly' {

    Context 'every released dataset resolves to a Read/Safe GraphKit descriptor' {
        It "dataset '<Name>' (<Type>/<Op>) is Read/Safe" -ForEach $script:releasedDatasetCases {
            $descriptor = Get-GraphOperation -Type $Type -Operation $Op -ErrorAction Stop

            $descriptor | Should -Not -BeNullOrEmpty -Because "GraphKit must resolve '$Type/$Op' for dataset '$Name' - if this fails, DatasetMap.psd1 has drifted from the released GraphKit catalog (see the deviceManagementSettings fix in this same commit for a real example)"
            $descriptor.ThrottleClass | Should -Be 'Read' -Because "dataset '$Name' must only ever be collected through a read-class GraphKit operation"
            $descriptor.ReplayPolicy | Should -Be 'Safe' -Because "dataset '$Name' must only ever be collected through a safe-to-replay GraphKit operation"
        }
    }

    Context 'every Pending dataset declares an expected Read/Safe descriptor' {
        It "Pending dataset '<Name>' (<Type>/<Op>) declares ExpectedThrottleClass='Read' and ExpectedReplayPolicy='Safe'" -ForEach $script:pendingDatasetCases {
            # No live descriptor exists to resolve - GraphKit 0.1.0 genuinely does not have
            # this Type/Operation pair yet. Confirm that (rather than silently trusting the
            # Pending flag) so a descriptor that quietly shipped early is caught, then assert
            # the map's own declaration is read-only.
            { Get-GraphOperation -Type $Type -Operation $Op -ErrorAction Stop } |
                Should -Throw -Because "dataset '$Name' is marked Pending - its descriptor must genuinely be absent from the released GraphKit catalog; if this no longer throws, GraphKit shipped it and the Pending flag (and its 0.1.1-release TODO) must be dropped"

            $ExpectedThrottleClass | Should -Be 'Read' -Because "Pending dataset '$Name' must still declare the read-only shape its future descriptor is expected to have"
            $ExpectedReplayPolicy | Should -Be 'Safe' -Because "Pending dataset '$Name' must still declare the read-only shape its future descriptor is expected to have"
        }
    }

    Context 'the whole-map walker (Test-PulseReadOnlyDatasetMap) agrees with the per-dataset assertions above' {
        It 'reports zero violations for the real DatasetMap.psd1' {
            $realMap = Import-PowerShellDataFile -Path $script:datasetMapPath
            $violations = @(Test-PulseReadOnlyDatasetMap -DatasetMap $realMap)

            $violations | Should -BeNullOrEmpty -Because ("every dataset must be provably read-only; violations found:`n" + ($violations -join "`n"))
        }
    }

    Context 'mutation check: a Write-class op in the map makes the gate fail' {
        <#
            Proves the GATE CODE (Test-PulseReadOnlyDatasetMap) actually catches a mutation
            - it does not prove anything about the real catalog, and it never touches or
            depends on a live tenant. The fixture map's single entry points at a Type/
            Operation pair that does not exist in the real GraphKit catalog at all
            (FixtureMutationResource/Create); Get-GraphOperation is mocked, scoped to this
            Context only, to resolve that specific pair as a Write-class, unsafe-to-replay
            descriptor - exactly the shape the read-only predicate must reject. After this
            Context, the mock goes out of scope and every other Context in this file keeps
            resolving through the real, unmodified GraphKit catalog.
        #>
        BeforeAll {
            Mock -CommandName Get-GraphOperation -ParameterFilter {
                $Type -eq 'FixtureMutationResource' -and $Operation -eq 'Create'
            } -MockWith {
                [pscustomobject]@{
                    Type          = 'FixtureMutationResource'
                    Operation     = 'Create'
                    ThrottleClass = 'Write'
                    ReplayPolicy  = 'Unsafe'
                    ApiVersion    = 'v1.0'
                }
            }
        }

        It 'the fixture map resolves through the mock, not the real catalog' {
            $fixtureMap = Import-PowerShellDataFile -Path $script:fixtureDatasetMapPath

            $fixtureMap.Keys.Count | Should -Be 1 -Because 'the mutation fixture is a single deliberately-bad entry, nothing else'

            $entry = $fixtureMap[$fixtureMap.Keys[0]]
            $entry.Type | Should -Be 'FixtureMutationResource'
            $entry.Operation | Should -Be 'Create'
        }

        It 'Test-PulseReadOnlyDatasetMap reports exactly one violation for the mutated entry' {
            $fixtureMap = Import-PowerShellDataFile -Path $script:fixtureDatasetMapPath
            # @(...) forces array-ness: PowerShell unwraps a single-element array returned
            # from a function back into a bare string, which would silently turn
            # $violations[0] into a character index instead of the violation message.
            $violations = @(Test-PulseReadOnlyDatasetMap -DatasetMap $fixtureMap)

            $violations.Count | Should -Be 1 -Because 'the fixture map has exactly one entry and it is a Write-class op'
            $violations[0] | Should -Match 'NOT read-only' -Because 'the gate must name the mutation as a read-only violation, not fail silently or for an unrelated reason'
            $violations[0] | Should -Match "ThrottleClass='Write'"
            $violations[0] | Should -Match "ReplayPolicy='Unsafe'"
        }
    }
}
