BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:workflowPath = Join-Path $script:repoRoot '.github/workflows/ci.yml'
    $script:workflow = Get-Content -LiteralPath $script:workflowPath -Raw

    function Get-PulseCiStepBlock {
        param([Parameter(Mandatory)] [string] $Name)

        $escapedName = [regex]::Escape($Name)
        $match = [regex]::Match(
            $script:workflow,
            "(?ms)^      - name: $escapedName\s*\r?\n(?<body>.*?)(?=^      - name: |\z)"
        )
        if (-not $match.Success) {
            return $null
        }

        return $match.Value
    }
}

Describe 'CI workflow revision identity' -Tag 'QA' {
    It 'checks out the event-specific exact SHA without persisting credentials' {
        $checkoutSteps = @([regex]::Matches($script:workflow, '(?m)^      - name: Checkout\s*$'))
        $checkoutSteps.Count | Should -Be 1

        $checkoutBlock = Get-PulseCiStepBlock -Name 'Checkout'
        $checkoutBlock | Should -Not -BeNullOrEmpty
        $expectedExpression = 'ref: ${{ github.event_name == ''pull_request'' && github.event.pull_request.head.sha || github.sha }}'
        $checkoutBlock | Should -Match ([regex]::Escape($expectedExpression))
        $checkoutBlock | Should -Match '(?m)^\s+persist-credentials:\s+false\s*$'

        $graphKitBlock = Get-PulseCiStepBlock -Name 'Stage exact GraphKit 0.3.1 dependency'
        $graphKitBlock | Should -Not -BeNullOrEmpty
        $graphKitBlock | Should -Match 'GRAPHKIT_SHA:\s+158c9a0152e25f30153e4d6a310dc5357ea6a80d'
        $graphKitBlock | Should -Match 'git clone --no-checkout https://github\.com/adamgell/GraphKit\.git'
        $graphKitBlock | Should -Match 'git -C \$graphKitRoot config core\.autocrlf false'
        $graphKitBlock.IndexOf('config core.autocrlf false') |
            Should -BeLessThan $graphKitBlock.IndexOf('checkout --detach')
        $graphKitBlock | Should -Match 'GraphKit checkout revision mismatch'
        $graphKitBlock | Should -Match "'\.psm1'"
        $graphKitBlock | Should -Match "'\.psd1'"
        $graphKitBlock | Should -Match "'\.ps1xml'"
        $graphKitBlock | Should -Match "'\.txt'"
        $graphKitBlock | Should -Match 'Get-ChildItem.*-File.*-Recurse'
        $graphKitBlock | Should -Match 'Replace\("`r`n", "`n"\)\.Replace\("`r", "`n"\)'
        $graphKitBlock | Should -Match "#Region '"
        $graphKitBlock | Should -Match "#EndRegion '"
        $graphKitBlock | Should -Match ([regex]::Escape("Replace('\', '/')"))
        $graphKitBlock | Should -Match 'UTF8Encoding.*false'
        $graphKitBlock | Should -Match 'Get-PulseModuleTreeDigest'
        $graphKitBlock | Should -Match 'Get-FileHash.*SHA256'
        $graphKitBlock | Should -Match "GraphKit\|0\.3\.1"
    }

    It 'immediately proves git HEAD is the event-specific expected SHA' {
        $stepNames = @(
            [regex]::Matches($script:workflow, '(?m)^      - name:\s*(?<name>.+?)\s*$') |
                ForEach-Object { $_.Groups['name'].Value }
        )
        $stepNames.Count | Should -BeGreaterOrEqual 2
        $stepNames[0] | Should -BeExactly 'Checkout'
        $stepNames[1] | Should -BeExactly 'Assert checkout revision'

        $assertionBlock = Get-PulseCiStepBlock -Name 'Assert checkout revision'
        $assertionBlock | Should -Not -BeNullOrEmpty
        $assertionBlock | Should -Match '(?m)^\s+shell:\s+pwsh\s*$'
        $expectedExpression = 'EXPECTED_SHA: ${{ github.event_name == ''pull_request'' && github.event.pull_request.head.sha || github.sha }}'
        $assertionBlock | Should -Match ([regex]::Escape($expectedExpression))

        $runMatch = [regex]::Match(
            $assertionBlock,
            '(?ms)^        run:\s*\|\s*\r?\n(?<script>(?:          .*(?:\r?\n|$))+)'
        )
        $runMatch.Success | Should -BeTrue
        $runText = @(
            $runMatch.Groups['script'].Value -split '\r?\n' |
                ForEach-Object {
                    if ($_.StartsWith('          ')) {
                        $_.Substring(10)
                    }
                    else {
                        $_
                    }
                }
        ) -join [Environment]::NewLine
        $runScript = [scriptblock]::Create($runText)

        $originalExpectedSha = $env:EXPECTED_SHA
        try {
            $env:EXPECTED_SHA = (& git rev-parse HEAD).Trim()
            { & $runScript } | Should -Not -Throw

            $env:EXPECTED_SHA = '0000000000000000000000000000000000000000'
            { & $runScript } | Should -Throw -ExpectedMessage '*Checkout revision mismatch*'
        }
        finally {
            $env:EXPECTED_SHA = $originalExpectedSha
        }
    }
}
