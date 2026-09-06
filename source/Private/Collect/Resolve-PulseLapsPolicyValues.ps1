function Resolve-PulseLapsPolicyValues {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Settings
    )

    $settingRows = @(Get-PulseEndpointSecuritySettingTokens -Settings $Settings)

    function Get-CriterionRows {
        param([string] $Pattern)
        return , [object[]]@($settingRows | Where-Object { ([string] $_.DefinitionId) -match $Pattern })
    }

    function Get-TrailingNumber {
        param([string] $Token)
        $match = [regex]::Match($Token, '(?:_|-)(\d+)$')
        if ($match.Success) { return [int] $match.Groups[1].Value }
        if ($Token -match '^\d+$') { return [int] $Token }
        return $null
    }

    function Test-CriterionValue {
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]] $Rows,
            [Parameter(Mandatory)] [ValidateSet('Backup', 'Complexity', 'Length', 'PostAuthentication')] [string] $Criterion
        )

        if ($Rows.Count -eq 0) {
            throw "LAPS $Criterion setting was not returned."
        }

        $sawKnownTrue = $false
        $sawKnownFalse = $false
        $sawUnknown = $false
        $tokenCount = 0
        foreach ($row in $Rows) {
            foreach ($tokenValue in @($row.Tokens)) {
                $tokenCount++
                $token = [string] $tokenValue
                $number = Get-TrailingNumber -Token $token
                switch ($Criterion) {
                    'Backup' {
                        if ($number -eq 1 -or $token -match '(?i)(entra|azure|aad)') { $sawKnownTrue = $true; continue }
                        if ($number -in @(0, 2) -or $token -match '(?i)(none|onprem|active.?directory)') { $sawKnownFalse = $true; continue }
                        $sawUnknown = $true
                    }
                    'Complexity' {
                        if ($null -ne $number) {
                            if ($number -ge 4) { $sawKnownTrue = $true } else { $sawKnownFalse = $true }
                            continue
                        }
                        $sawUnknown = $true
                    }
                    'Length' {
                        if ($null -ne $number) {
                            if ($number -ge 14) { $sawKnownTrue = $true } else { $sawKnownFalse = $true }
                            continue
                        }
                        $sawUnknown = $true
                    }
                    'PostAuthentication' {
                        if ($token -match '(?i)(reset|rotate)') { $sawKnownTrue = $true; continue }
                        if ($number -in @(1, 3, 5, 11)) { $sawKnownTrue = $true; continue }
                        if ($null -ne $number) { $sawKnownFalse = $true; continue }
                        $sawUnknown = $true
                    }
                }
            }
        }

        # Unknown or contradictory values take precedence over a positive token: mixed
        # evidence cannot become an authoritative policy result.
        if ($tokenCount -eq 0 -or $sawUnknown -or ($sawKnownTrue -and $sawKnownFalse)) {
            throw "LAPS $Criterion setting value is unknown."
        }
        if ($sawKnownTrue) { return [bool] $true }
        return [bool] $false
    }

    $backupRows = Get-CriterionRows -Pattern '(?i)laps.*backup(directory)?'
    $complexityRows = Get-CriterionRows -Pattern '(?i)laps.*passwordcomplexity'
    $lengthRows = Get-CriterionRows -Pattern '(?i)laps.*passwordlength'
    $postRows = Get-CriterionRows -Pattern '(?i)laps.*postauthenticationactions?'

    return [pscustomobject][ordered]@{
        backsUpToEntra          = [bool] (Test-CriterionValue -Rows $backupRows -Criterion 'Backup')
        hasSufficientComplexity = [bool] (Test-CriterionValue -Rows $complexityRows -Criterion 'Complexity')
        hasSufficientLength     = [bool] (Test-CriterionValue -Rows $lengthRows -Criterion 'Length')
        hasPostAuthAction       = [bool] (Test-CriterionValue -Rows $postRows -Criterion 'PostAuthentication')
    }
}
