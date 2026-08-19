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
        @($settingRows | Where-Object { ([string] $_.DefinitionId) -match $Pattern })
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
            [Parameter(Mandatory)] [object[]] $Rows,
            [Parameter(Mandatory)] [ValidateSet('Backup', 'Complexity', 'Length', 'PostAuthentication')] [string] $Criterion
        )

        if ($Rows.Count -eq 0) {
            throw "LAPS $Criterion setting was not returned."
        }


        foreach ($row in $Rows) {
            foreach ($tokenValue in @($row.Tokens)) {
                $token = [string] $tokenValue
                $number = Get-TrailingNumber -Token $token
                switch ($Criterion) {
                    'Backup' {
                        if ($number -eq 1 -or $token -match '(?i)(entra|azure|aad)') { return [bool] $true }
                    }
                    'Complexity' {
                        if ($null -ne $number -and $number -ge 4) { return [bool] $true }
                    }
                    'Length' {
                        if ($null -ne $number -and $number -ge 14) { return [bool] $true }
                    }
                    'PostAuthentication' {
                        if ($token -match '(?i)(reset|rotate)') { return [bool] $true }
                        if ($number -in @(1, 3)) { return [bool] $true }
                    }
                }
            }
        }

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
