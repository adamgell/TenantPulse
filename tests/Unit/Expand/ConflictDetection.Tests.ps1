BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/TenantPulse') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built TenantPulse module found under output/module/TenantPulse; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'TenantPulse.psd1') -Force

    function New-TestRow {
        param(
            [string] $PolicyId,
            [string] $PolicyName = $null,
            [string] $DefId = 'def-1',
            $Value = 'v',
            [bool] $Redacted = $false,
            [bool] $NameResolved = $true,
            [string] $SettingName = 'settingA',
            [object[]] $Assignments = @()
        )
        return [pscustomobject]@{
            schemaVersion       = '1'
            policyId            = $PolicyId
            policyType          = 'compliance'
            policyName          = $PolicyName
            templateFamily      = $null
            isBaseline          = $false
            settingPath         = $DefId
            settingDefinitionId = $DefId
            settingName         = $SettingName
            nameResolved        = $NameResolved
            instanceId          = "$PolicyId/p:$DefId"
            value               = if ($Redacted) { $null } else { $Value }
            valueLabel          = $null
            labelResolved       = $false
            redacted            = $Redacted
            valueState          = $null
            applicability       = $null
            assignments         = $Assignments
        }
    }

    function Invoke-ConflictBuild {
        param([object[]] $Rows)
        return InModuleScope TenantPulse -ArgumentList (, $Rows) {
            param($rows)
            ConvertTo-PulseConflictRecords -Rows $rows
        }
    }

    function New-TestAssignment {
        param([string] $TargetType = 'group', [string] $GroupId = $null, [string] $FilterId = $null)
        return [pscustomobject]@{ intent = $null; targetType = $TargetType; groupId = $GroupId; filterId = $FilterId; filterType = $null }
    }
}

Describe 'ConvertTo-PulseConflictRecords' {
    It 'returns an empty array for zero rows' {
        $result = Invoke-ConflictBuild -Rows @()
        @($result).Count | Should -Be 0
    }

    It 'does not flag a defId as a conflict when every policy sets the identical value' {
        $rows = @(
            (New-TestRow -PolicyId 'p1' -Value 'same'),
            (New-TestRow -PolicyId 'p2' -Value 'same')
        )
        $result = Invoke-ConflictBuild -Rows $rows
        @($result).Count | Should -Be 0
    }

    It 'flags a conflict when two distinct policies set two distinct values for the same defId' {
        $rows = @(
            (New-TestRow -PolicyId 'p1' -PolicyName 'Policy One' -Value 'valueA'),
            (New-TestRow -PolicyId 'p2' -PolicyName 'Policy Two' -Value 'valueB')
        )
        $result = (Invoke-ConflictBuild -Rows $rows)
        $result.Count | Should -Be 1
        $result[0].settingDefinitionId | Should -Be 'def-1'
        $result[0].settingName | Should -Be 'settingA'
        $result[0].values.Count | Should -Be 2
        ($result[0].values | ForEach-Object { $_.canonicalValue }) | Should -Be @('valueA', 'valueB')
        $result[0].values[0].policies[0].policyId | Should -Be 'p1'
        $result[0].values[1].policies[0].policyId | Should -Be 'p2'
    }

    It 'is NOT a conflict when a single policy repeats the same defId with two different values but no OTHER policy sets it' {
        $rows = @(
            (New-TestRow -PolicyId 'p1' -Value 'valueA'),
            (New-TestRow -PolicyId 'p1' -Value 'valueB')
        )
        $result = Invoke-ConflictBuild -Rows $rows
        @($result).Count | Should -Be 0
    }

    It 'zero conflicts is a valid outcome for a corpus with no disagreeing setting' {
        $rows = @(
            (New-TestRow -PolicyId 'p1' -DefId 'def-a' -Value 'x'),
            (New-TestRow -PolicyId 'p2' -DefId 'def-b' -Value 'y')
        )
        $result = Invoke-ConflictBuild -Rows $rows
        @($result).Count | Should -Be 0
    }

    Context 'secret redaction never un-redacts' {
        It 'a redacted row and a plain value row for the same defId still conflict, without ever exposing the secret' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value 'plain'),
                (New-TestRow -PolicyId 'p2' -Redacted $true)
            )
            $result = (Invoke-ConflictBuild -Rows $rows)
            $result.Count | Should -Be 1
            $redactedGroup = $result[0].values | Where-Object { $_.redacted }
            $plainGroup = $result[0].values | Where-Object { -not $_.redacted }
            $redactedGroup.canonicalValue | Should -BeNullOrEmpty
            $plainGroup.canonicalValue | Should -Be 'plain'

            $serialized = InModuleScope TenantPulse -ArgumentList (, $result) {
                param($conflicts) ConvertTo-PulseCanonicalJson -InputObject $conflicts
            }
            $serialized | Should -Not -Match 'REDACTED-SETTING-VALUE'
        }

        It 'two different policies both redacting the same setting are NOT flagged as conflicting with each other' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Redacted $true),
                (New-TestRow -PolicyId 'p2' -Redacted $true)
            )
            $result = Invoke-ConflictBuild -Rows $rows
            @($result).Count | Should -Be 0
        }

        It 'a legitimate null value and a redacted value are kept in distinct groups (never conflated)' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value $null),
                (New-TestRow -PolicyId 'p2' -Redacted $true)
            )
            $result = (Invoke-ConflictBuild -Rows $rows)
            $result.Count | Should -Be 1
            $result[0].values.Count | Should -Be 2
        }
    }

    Context 'assignment overlap - core slice deferred assignments' {
        It 'is unknown with the deferred reason when any conflicting policy carries assignments:null' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value 'a' -Assignments $null),
                (New-TestRow -PolicyId 'p2' -Value 'b' -Assignments @((New-TestAssignment -GroupId 'g1')))
            )
            $result = (Invoke-ConflictBuild -Rows $rows)
            $result[0].assignmentOverlap | Should -Be 'unknown'
            $result[0].assignmentOverlapReason | Should -Match 'assignments-deferred'
        }
    }

    Context 'assignment overlap - four states from real assignment data' {
        It 'proven: identical concrete target sets, no filters' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value 'a' -Assignments @((New-TestAssignment -GroupId 'g1'))),
                (New-TestRow -PolicyId 'p2' -Value 'b' -Assignments @((New-TestAssignment -GroupId 'g1')))
            )
            (Invoke-ConflictBuild -Rows $rows)[0].assignmentOverlap | Should -Be 'proven'
        }

        It 'possible: an All-target on either side' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value 'a' -Assignments @((New-TestAssignment -TargetType 'allDevices'))),
                (New-TestRow -PolicyId 'p2' -Value 'b' -Assignments @((New-TestAssignment -GroupId 'g1')))
            )
            (Invoke-ConflictBuild -Rows $rows)[0].assignmentOverlap | Should -Be 'possible'
        }

        It 'possible: a filter present' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value 'a' -Assignments @((New-TestAssignment -GroupId 'g1' -FilterId 'f1'))),
                (New-TestRow -PolicyId 'p2' -Value 'b' -Assignments @((New-TestAssignment -GroupId 'g1')))
            )
            (Invoke-ConflictBuild -Rows $rows)[0].assignmentOverlap | Should -Be 'possible'
        }

        It 'possible: shared groupId but not an identical set' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value 'a' -Assignments @((New-TestAssignment -GroupId 'g1'), (New-TestAssignment -GroupId 'g2'))),
                (New-TestRow -PolicyId 'p2' -Value 'b' -Assignments @((New-TestAssignment -GroupId 'g1')))
            )
            (Invoke-ConflictBuild -Rows $rows)[0].assignmentOverlap | Should -Be 'possible'
        }

        It 'none: complete data, demonstrably disjoint concrete sets, no filters' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value 'a' -Assignments @((New-TestAssignment -GroupId 'g1'))),
                (New-TestRow -PolicyId 'p2' -Value 'b' -Assignments @((New-TestAssignment -GroupId 'g2')))
            )
            (Invoke-ConflictBuild -Rows $rows)[0].assignmentOverlap | Should -Be 'none'
        }

        It 'none: one policy assigned nowhere' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value 'a' -Assignments @()),
                (New-TestRow -PolicyId 'p2' -Value 'b' -Assignments @((New-TestAssignment -GroupId 'g2')))
            )
            (Invoke-ConflictBuild -Rows $rows)[0].assignmentOverlap | Should -Be 'none'
        }

        It 'dynamic/exclusion group targets can never yield none' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -Value 'a' -Assignments @((New-TestAssignment -TargetType 'exclusionGroup' -GroupId 'g9'))),
                (New-TestRow -PolicyId 'p2' -Value 'b' -Assignments @((New-TestAssignment -GroupId 'g2')))
            )
            (Invoke-ConflictBuild -Rows $rows)[0].assignmentOverlap | Should -Not -Be 'none'
        }
    }

    Context 'cross-family conflicts' {
        It 'a settingsCatalog-shaped row (assignments:null) conflicting with a typed-policy row is unknown, not proven/possible/none' {
            $scRow = New-TestRow -PolicyId 'sc-1' -Value 'catalogValue' -Assignments $null
            $scRow.policyType = 'settingsCatalog'
            $typedRow = New-TestRow -PolicyId 'typed-1' -Value 'typedValue' -Assignments @((New-TestAssignment -GroupId 'g1'))
            $result = (Invoke-ConflictBuild -Rows @($scRow, $typedRow))
            $result[0].assignmentOverlap | Should -Be 'unknown'
        }
    }

    Context 'determinism' {
        It 'produces byte-identical output regardless of input row order' {
            $rowsA = @(
                (New-TestRow -PolicyId 'p1' -DefId 'def-x' -Value 'a1'),
                (New-TestRow -PolicyId 'p2' -DefId 'def-x' -Value 'a2'),
                (New-TestRow -PolicyId 'p3' -DefId 'def-y' -Value 'b1'),
                (New-TestRow -PolicyId 'p4' -DefId 'def-y' -Value 'b2')
            )
            $rowsB = @($rowsA[3], $rowsA[1], $rowsA[2], $rowsA[0])

            $resultA = Invoke-ConflictBuild -Rows $rowsA
            $resultB = Invoke-ConflictBuild -Rows $rowsB

            $jsonA = InModuleScope TenantPulse -ArgumentList (, $resultA) { param($c) ConvertTo-PulseCanonicalJson -InputObject $c }
            $jsonB = InModuleScope TenantPulse -ArgumentList (, $resultB) { param($c) ConvertTo-PulseCanonicalJson -InputObject $c }

            $jsonA | Should -Be $jsonB
        }

        It 'sorts conflicts ordinally by settingDefinitionId' {
            $rows = @(
                (New-TestRow -PolicyId 'p1' -DefId 'zzz' -Value 'a'),
                (New-TestRow -PolicyId 'p2' -DefId 'zzz' -Value 'b'),
                (New-TestRow -PolicyId 'p3' -DefId 'aaa' -Value 'a'),
                (New-TestRow -PolicyId 'p4' -DefId 'aaa' -Value 'b')
            )
            $result = (Invoke-ConflictBuild -Rows $rows)
            $result[0].settingDefinitionId | Should -Be 'aaa'
            $result[1].settingDefinitionId | Should -Be 'zzz'
        }
    }
}
