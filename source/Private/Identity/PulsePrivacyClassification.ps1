<#
    Private: TenantPulse 1.0 privacy classification contract (TP9A / AC-25).

    Every tenant-derived field that can reach a 1.0 snapshot, finding, gap, error, sort
    key, or JSON document must declare exactly one of the five classes below. Construction
    of a classified value with a missing or unknown class fails closed. Safe-share
    conversion of a document that still has unclassified tenant-derived fields also fails
    closed.

    Classes:
      Identity            - HMAC-pseudonymize under the operator key (tp-<hex>).
      SecretSensitive     - irreversible redaction; the raw value never survives.
      SafeTechnical       - retain (counts, booleans, ISO timestamps, relative paths,
                            already-pseudonymized tp- tokens, ordinal enum tokens).
      SafeOperatorLabel   - retain intentionally (policy/setting display names).
      BoundedReviewedText - retain author-reviewed or reason-coded text; HTML consumers
                            must HTML-encode it.

    Compatibility: optional RedactDetailKeys and free-text reasons still construct through
    New-PulseFinding / Protect-PulseReason. Those outputs are labeled non-safe
    (privacy.complete = false, privacy.boundary = 'local-only'). ConvertTo-PulseSafeShareDocument
    is the supported 1.0 classified path. C0 D6 (safe-share UX) remains Proposed; this is
    the recommended working default, not an owner-locked operator command.

    ReportBundle / XLSX classification is TP9B and is out of scope here.
#>

$script:PulsePrivacyClasses = @(
    'Identity'
    'SecretSensitive'
    'SafeTechnical'
    'SafeOperatorLabel'
    'BoundedReviewedText'
)

$script:PulsePrivacyIdentityShapedPattern = '(?i)([^\s@]+@[^\s@]+\.[^\s@]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
$script:PulsePrivacySecretShapedPattern = '(?i)(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|-----BEGIN |(password|secret|accountkey|sharedaccesssignature)\s*=|[?&]sig=)'
$script:PulsePrivacyUnsafePathPattern = '(?i)([A-Za-z]:\\Users\\|[/\\]Users[/\\]|[/\\]home[/\\])'
$script:PulsePrivacyMarkupPattern = '<[^>]+>'
$script:PulsePrivacySafeTechnicalStringPattern = '^(tp-[a-f0-9]{64}|[A-Za-z0-9._/-]+|\d{4}-\d{2}-\d{2}T[\d:.]+Z?)$'

function Get-PulsePrivacyClasses {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return [string[]] $script:PulsePrivacyClasses
}

function Test-PulsePrivacyClassName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Class
    )

    if ([string]::IsNullOrWhiteSpace($Class)) {
        return $false
    }

    return $script:PulsePrivacyClasses -contains $Class
}

function Get-PulseOperatorKeyLifecycleText {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
TenantPulse operator-key lifecycle (no public rotate cmdlet):

Backup: copy the 32-byte operator.key file (default ~/.tenantpulse/operator.key) with
owner-only permissions to operator-controlled offline storage. Never copy it into a
snapshot, findings file, log, ticket, vault reference, or git repository.

Replacement: after backing up the previous file, write a new cryptographically random
32-byte key to the same path. The next assessment under the new key emits different
tp-... pseudonyms for the same source identities.

Join-break: reports produced under key generation N cannot be joined to reports
produced under generation N+1 on identity. This is intentional. Restore the backed-up
key to rejoin historical reports from that generation.

There is no public rotate cmdlet. C0 has not selected one. Synthetic keys used by
tests must live only under test temp roots, never under ~/.tenantpulse or a snapshot
root. Real configured-key creation, backup, rotation, revocation, or storage change
remains approval-gated.
'@
}

function ConvertTo-PulseHtmlEncodedText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Test-PulsePrivacyIdentityShapedValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or $Value -isnot [string]) {
        return $false
    }

    $text = [string] $Value
    if ($text -match '^tp-[a-f0-9]{64}$') {
        return $false
    }

    return [regex]::IsMatch($text, $script:PulsePrivacyIdentityShapedPattern)
}

function Test-PulsePrivacySecretShapedValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $false
    }

    return [regex]::IsMatch([string] $Value, $script:PulsePrivacySecretShapedPattern)
}

function Test-PulsePrivacyUnsafePathValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or $Value -isnot [string]) {
        return $false
    }

    return [regex]::IsMatch([string] $Value, $script:PulsePrivacyUnsafePathPattern)
}

function Test-PulsePrivacyMarkupValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or $Value -isnot [string]) {
        return $false
    }

    return [regex]::IsMatch([string] $Value, $script:PulsePrivacyMarkupPattern)
}

function Test-PulseValueFitsPrivacyClass {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Class,

        [Parameter()]
        [AllowNull()]
        $Value
    )

    switch ($Class) {
        'Identity' {
            return $true
        }
        'SecretSensitive' {
            return $true
        }
        'SafeTechnical' {
            if ($null -eq $Value) { return $true }
            if ($Value -is [bool]) { return $true }
            if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [uint16] -or
                $Value -is [int] -or $Value -is [uint32] -or $Value -is [int64] -or
                $Value -is [uint64] -or $Value -is [decimal]) {
                return $true
            }
            if ($Value -is [double] -or $Value -is [float]) {
                return -not [double]::IsNaN([double] $Value) -and -not [double]::IsInfinity([double] $Value)
            }
            if ($Value -is [datetime]) { return $true }
            if ($Value -isnot [string]) { return $false }
            $text = [string] $Value
            if ([string]::IsNullOrEmpty($text)) { return $true }
            if (Test-PulsePrivacyIdentityShapedValue -Value $text) { return $false }
            if (Test-PulsePrivacySecretShapedValue -Value $text) { return $false }
            if (Test-PulsePrivacyUnsafePathValue -Value $text) { return $false }
            if (Test-PulsePrivacyMarkupValue -Value $text) { return $false }
            if ($text.Contains('..')) { return $false }
            return [regex]::IsMatch($text, $script:PulsePrivacySafeTechnicalStringPattern)
        }
        'SafeOperatorLabel' {
            if ($null -eq $Value) { return $true }
            if ($Value -isnot [string]) { return $false }
            $text = [string] $Value
            if (Test-PulsePrivacyIdentityShapedValue -Value $text) { return $false }
            if (Test-PulsePrivacySecretShapedValue -Value $text) { return $false }
            if (Test-PulsePrivacyUnsafePathValue -Value $text) { return $false }
            if (Test-PulsePrivacyMarkupValue -Value $text) { return $false }
            return $true
        }
        'BoundedReviewedText' {
            if ($null -eq $Value) { return $true }
            if ($Value -isnot [string]) { return $false }
            $text = [string] $Value
            if (Test-PulsePrivacyIdentityShapedValue -Value $text) { return $false }
            if (Test-PulsePrivacySecretShapedValue -Value $text) { return $false }
            return $true
        }
        default {
            return $false
        }
    }
}

function New-PulseSecretRedactionMarker {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [pscustomobject][ordered]@{
        redacted = $true
        class    = 'SecretSensitive'
    }
}

function New-PulseClassifiedValue {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Class,

        [Parameter()]
        [AllowNull()]
        $Value,

        [Parameter()]
        [byte[]] $OperatorKey,

        [Parameter()]
        [switch] $DeferProtection
    )

    if (-not (Test-PulsePrivacyClassName -Class $Class)) {
        throw "New-PulseClassifiedValue: privacy class is required and must be one of: $($script:PulsePrivacyClasses -join ', ')."
    }

    if (-not (Test-PulseValueFitsPrivacyClass -Class $Class -Value $Value)) {
        throw "New-PulseClassifiedValue: value is not valid for privacy class '$Class'."
    }

    $protected = $false
    $outputValue = $Value

    switch ($Class) {
        'Identity' {
            if ($DeferProtection) {
                $outputValue = $Value
                $protected = $false
            } else {
                if ($null -eq $OperatorKey -or $OperatorKey.Length -ne 32) {
                    throw 'New-PulseClassifiedValue: Identity class requires a 32-byte OperatorKey unless -DeferProtection is set.'
                }
                if ($null -eq $Value -or [string]::IsNullOrEmpty([string] $Value)) {
                    $outputValue = $Value
                    $protected = $true
                } else {
                    $outputValue = Get-PulsePseudonym -Value ([string] $Value) -Key $OperatorKey
                    $protected = $true
                }
            }
        }
        'SecretSensitive' {
            if ($DeferProtection) {
                $outputValue = $Value
                $protected = $false
            } else {
                $outputValue = New-PulseSecretRedactionMarker
                $protected = $true
            }
        }
        default {
            $outputValue = $Value
            $protected = $true
        }
    }

    return [pscustomobject][ordered]@{
        PSTypeName = 'TenantPulse.ClassifiedValue'
        Class      = $Class
        Value      = $outputValue
        Protected  = $protected
    }
}

function Test-PulseReasonCode {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ReasonCode
    )

    if ([string]::IsNullOrEmpty($ReasonCode)) {
        return $false
    }

    return [regex]::IsMatch(
        $ReasonCode,
        '^[a-z0-9]+(?:-[a-z0-9]+)*$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
}

function Assert-PulseReasonCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ReasonCode
    )

    if (-not (Test-PulseReasonCode -ReasonCode $ReasonCode)) {
        # Never echo the rejected value: the validation boundary exists specifically so an
        # identity- or secret-shaped value cannot become serialized diagnostic text.
        throw 'ReasonCode must be a lowercase hyphenated token.'
    }
}

function ConvertTo-PulseClassifiedReason {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ReasonCode,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter()]
        [AllowNull()]
        [object[]] $Arguments
    )

    Assert-PulseReasonCode -ReasonCode $ReasonCode

    $classifiedArguments = @()
    foreach ($argument in @($Arguments)) {
        if ($null -eq $argument) {
            continue
        }

        $isClassified = $false
        if ($argument -is [pscustomobject] -or $argument -is [hashtable] -or $argument -is [System.Collections.IDictionary]) {
            $classValue = $null
            if ($argument -is [System.Collections.IDictionary]) {
                if ($argument.Contains('Class')) { $classValue = $argument['Class'] }
            } elseif ($argument.PSObject.Properties.Name -contains 'Class') {
                $classValue = $argument.Class
            }

            if (Test-PulsePrivacyClassName -Class ([string] $classValue)) {
                $isClassified = $true
            }
        }

        if (-not $isClassified) {
            throw 'ConvertTo-PulseClassifiedReason: every reason argument must be a classified value.'
        }

        $classifiedArguments += $argument
    }

    if (-not [string]::IsNullOrEmpty($Text) -and -not (Test-PulseValueFitsPrivacyClass -Class 'BoundedReviewedText' -Value $Text)) {
        throw 'ConvertTo-PulseClassifiedReason: -Text is not valid BoundedReviewedText (identity or secret shaped).'
    }

    return [pscustomobject][ordered]@{
        PSTypeName = 'TenantPulse.ClassifiedReason'
        ReasonCode = $ReasonCode
        Text       = $Text
        Arguments  = $classifiedArguments
        Class      = 'BoundedReviewedText'
    }
}

function Protect-PulseClassifiedValue {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $InputObject,

        [Parameter()]
        [byte[]] $OperatorKey
    )

    if ($null -eq $InputObject -or $InputObject.PSObject.Properties.Name -notcontains 'Class') {
        throw 'Protect-PulseClassifiedValue: input is not a classified value.'
    }

    if ([bool] $InputObject.Protected) {
        return $InputObject
    }

    return New-PulseClassifiedValue -Class ([string] $InputObject.Class) -Value $InputObject.Value -OperatorKey $OperatorKey
}

function ConvertTo-PulsePrivacyEnvelope {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [bool] $Complete = $false
    )

    return [pscustomobject][ordered]@{
        classification = '1.0'
        complete       = [bool] $Complete
        boundary       = if ($Complete) { 'classified' } else { 'local-only' }
        compatLayer    = -not [bool] $Complete
    }
}

function Get-PulseEvidenceFieldClassMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [AllowNull()]
        $Entry
    )

    $map = @{}
    if ($null -eq $Entry) {
        return $map
    }

    $raw = $null
    if ($Entry -is [System.Collections.IDictionary]) {
        foreach ($key in @($Entry.Keys)) {
            if ($key -eq 'FieldClasses') { $raw = $Entry[$key]; break }
        }
    } elseif ($Entry.PSObject.Properties.Name -contains 'FieldClasses') {
        $raw = $Entry.FieldClasses
    }

    if ($null -eq $raw) {
        return $map
    }

    if ($raw -is [System.Collections.IDictionary]) {
        foreach ($key in @($raw.Keys)) {
            $map[[string] $key] = [string] $raw[$key]
        }
        return $map
    }

    foreach ($property in @($raw.PSObject.Properties)) {
        $map[$property.Name] = [string] $property.Value
    }

    return $map
}

function Test-PulseClassifiedEvidenceComplete {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $Entry
    )

    if ($null -eq $Entry) {
        return $true
    }

    $fieldClasses = Get-PulseEvidenceFieldClassMap -Entry $Entry
    $identityClass = $fieldClasses['Identity']
    if ([string]::IsNullOrEmpty($identityClass)) {
        $identityClass = $fieldClasses['identity']
    }
    if (-not (Test-PulsePrivacyClassName -Class $identityClass)) {
        return $false
    }

    $sortKeyClass = $fieldClasses['SortKey']
    if ([string]::IsNullOrEmpty($sortKeyClass)) {
        $sortKeyClass = $fieldClasses['sortKey']
    }
    if (-not (Test-PulsePrivacyClassName -Class $sortKeyClass)) {
        return $false
    }

    $detail = $null
    if ($Entry -is [System.Collections.IDictionary]) {
        foreach ($key in @($Entry.Keys)) {
            if ($key -eq 'Detail') { $detail = $Entry[$key]; break }
        }
    } elseif ($Entry.PSObject.Properties.Name -contains 'Detail') {
        $detail = $Entry.Detail
    }

    if ($null -eq $detail) {
        return $true
    }

    $detailKeys = @()
    if ($detail -is [System.Collections.IDictionary]) {
        $detailKeys = @($detail.Keys | ForEach-Object { [string] $_ })
    } elseif ($detail -is [pscustomobject]) {
        $detailKeys = @($detail.PSObject.Properties.Name)
    } else {
        return $false
    }

    foreach ($detailKey in $detailKeys) {
        if (-not (Test-PulsePrivacyClassName -Class $fieldClasses[$detailKey])) {
            return $false
        }
    }

    return $true
}

function Assert-PulsePrivacyClassification {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $InputObject,

        [Parameter()]
        [string] $Path = 'value'
    )

    if ($null -eq $InputObject) {
        throw "Assert-PulsePrivacyClassification: '$Path' is unclassified (null with no class)."
    }

    $className = $null
    $value = $InputObject
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains('Class')) {
            $className = [string] $InputObject['Class']
            if ($InputObject.Contains('Value')) { $value = $InputObject['Value'] }
        }
    } elseif ($InputObject.PSObject.Properties.Name -contains 'Class') {
        $className = [string] $InputObject.Class
        if ($InputObject.PSObject.Properties.Name -contains 'Value') {
            $value = $InputObject.Value
        }
    }

    if (-not (Test-PulsePrivacyClassName -Class $className)) {
        throw "Assert-PulsePrivacyClassification: '$Path' is unclassified. Every tenant-derived 1.0 field must declare one of: $($script:PulsePrivacyClasses -join ', ')."
    }

    if (-not (Test-PulseValueFitsPrivacyClass -Class $className -Value $value)) {
        throw "Assert-PulsePrivacyClassification: '$Path' value does not fit privacy class '$className'."
    }

    $protected = $true
    if ($InputObject.PSObject.Properties.Name -contains 'Protected') {
        $protected = [bool] $InputObject.Protected
    }
    if (($className -eq 'Identity' -or $className -eq 'SecretSensitive') -and -not $protected) {
        throw "Assert-PulsePrivacyClassification: '$Path' class '$className' is not protected and cannot be shared."
    }
}

function ConvertTo-PulseSafeShareDocument {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Document,

        [Parameter()]
        [AllowNull()]
        [hashtable] $RedactionMap,

        [Parameter()]
        [byte[]] $OperatorKey
    )

    if ($Document.PSObject.Properties.Name -contains 'RedactionMap') {
        throw 'ConvertTo-PulseSafeShareDocument: never pass the evaluation wrapper; pass Document only.'
    }

    if ($Document.PSObject.Properties.Name -contains 'privacy') {
        $privacy = $Document.privacy
        $complete = if ($null -ne $privacy -and $privacy.PSObject.Properties.Name -contains 'complete') {
            $privacy.complete
        } else {
            $null
        }
        if ($complete -isnot [bool] -or -not $complete) {
            throw 'ConvertTo-PulseSafeShareDocument: document privacy boundary is local-only or incomplete.'
        }
    }

    $json = ConvertTo-PulseCanonicalJson -InputObject $Document
    $clone = ConvertFrom-PulseJsonPreservingStrings -Json $json -Depth 64

    $map = @{}
    if ($null -ne $RedactionMap) {
        foreach ($key in @($RedactionMap.Keys)) {
            $map[[string] $key] = $RedactionMap[$key]
        }
    }

    function Get-SafeSharePseudonym {
        param([string] $Raw)
        if ([string]::IsNullOrEmpty($Raw)) { return $Raw }
        if ($Raw -match '^tp-[a-f0-9]{64}$') { return $Raw }
        if ($map.ContainsKey($Raw)) { return $map[$Raw] }
        if ($null -eq $OperatorKey -or $OperatorKey.Length -ne 32) {
            throw "ConvertTo-PulseSafeShareDocument: Identity value is not in RedactionMap and no OperatorKey was supplied."
        }
        $pseudonym = Get-PulsePseudonym -Value $Raw -Key $OperatorKey
        $map[$Raw] = $pseudonym
        return $pseudonym
    }

    function Convert-SafeShareNode {
        param(
            $Node,
            [hashtable] $FieldClasses,
            [string] $NodePath
        )

        if ($null -eq $Node) {
            return $null
        }

        if ($Node -is [System.Collections.IList]) {
            for ($index = 0; $index -lt $Node.Count; $index++) {
                $Node[$index] = Convert-SafeShareNode -Node $Node[$index] `
                    -FieldClasses $FieldClasses -NodePath "$NodePath[$index]"
            }
            return $Node
        }

        if ($Node -is [pscustomobject]) {
            foreach ($property in @($Node.PSObject.Properties)) {
                $name = $property.Name
                $childPath = "$NodePath.$name"
                $className = $null
                if ($FieldClasses.ContainsKey($name)) {
                    $className = $FieldClasses[$name]
                }
                if ([string]::IsNullOrEmpty($className) -and $FieldClasses.ContainsKey('*')) {
                    $className = $FieldClasses['*']
                }
                if ([string]::IsNullOrEmpty($className)) {
                    throw "ConvertTo-PulseSafeShareDocument: '$childPath' is unclassified."
                }

                if ($property.Value -is [pscustomobject] -or $property.Value -is [System.Collections.IList]) {
                    $childClasses = $FieldClasses
                    if (-not [string]::IsNullOrEmpty($className)) {
                        $childClasses = @{ '*' = $className }
                    }
                    $property.Value = Convert-SafeShareNode -Node $property.Value -FieldClasses $childClasses -NodePath $childPath
                    continue
                }

                # Identity and secret protection is a class rule, not a text-only rule.
                # Apply it before primitive pass-through so numeric and Boolean values
                # cannot survive raw merely because they contain no text canary.
                switch ($className) {
                    'Identity' {
                        if ($null -ne $property.Value) {
                            $property.Value = Get-SafeSharePseudonym -Raw ([string] $property.Value)
                        }
                        continue
                    }
                    'SecretSensitive' {
                        $property.Value = New-PulseSecretRedactionMarker
                        continue
                    }
                }

                if ($null -eq $property.Value -or $property.Value -is [bool] -or
                    $property.Value -is [byte] -or $property.Value -is [int16] -or
                    $property.Value -is [uint16] -or $property.Value -is [int] -or
                    $property.Value -is [uint32] -or $property.Value -is [int64] -or
                    $property.Value -is [uint64] -or $property.Value -is [double] -or
                    $property.Value -is [float] -or $property.Value -is [decimal]) {
                    continue
                }

                if (-not (Test-PulseValueFitsPrivacyClass -Class $className -Value $property.Value)) {
                    throw "ConvertTo-PulseSafeShareDocument: '$childPath' value does not fit class '$className'."
                }

                # Safe classes retain the validated value.
            }
            return $Node
        }

        $leafClass = if ($FieldClasses.ContainsKey('*')) { [string] $FieldClasses['*'] } else { $null }
        if ([string]::IsNullOrEmpty($leafClass)) {
            if ($Node -is [bool] -or $Node -is [byte] -or $Node -is [int16] -or
                $Node -is [uint16] -or $Node -is [int] -or $Node -is [uint32] -or
                $Node -is [int64] -or $Node -is [uint64] -or $Node -is [double] -or
                $Node -is [float] -or $Node -is [decimal]) {
                return $Node
            }
            throw "ConvertTo-PulseSafeShareDocument: '$NodePath' is unclassified."
        }

        # Identity and secret protection applies to every scalar type. A number or Boolean
        # can itself be a tenant identifier or sensitive value, even though it cannot match
        # one of the text-shaped canaries used to validate safe classes.
        switch ($leafClass) {
            'Identity' { return Get-SafeSharePseudonym -Raw ([string] $Node) }
            'SecretSensitive' { return New-PulseSecretRedactionMarker }
        }

        # Primitive non-text values classified into a safe class cannot contain an identity,
        # secret, path, or markup canary, so retain them after the sensitive classes above
        # have been handled.
        if ($Node -isnot [string]) {
            return $Node
        }

        if (-not (Test-PulseValueFitsPrivacyClass -Class $leafClass -Value $Node)) {
            throw "ConvertTo-PulseSafeShareDocument: '$NodePath' value does not fit class '$leafClass'."
        }

        return $Node
    }

    foreach ($finding in @($clone.findings)) {
        $reasonCode = $null
        if ($finding.PSObject.Properties.Name -contains 'reasonCode') {
            $reasonCode = $finding.reasonCode
        }

        if (-not [string]::IsNullOrEmpty([string] $reasonCode)) {
            Assert-PulseReasonCode -ReasonCode ([string] $reasonCode)
        }

        if ($finding.PSObject.Properties.Name -contains 'reason' -and -not [string]::IsNullOrEmpty([string] $finding.reason)) {
            if ([string]::IsNullOrEmpty([string] $reasonCode)) {
                throw "ConvertTo-PulseSafeShareDocument: finding '$($finding.id)' reason is free text without a reasonCode."
            }
            if (-not (Test-PulseValueFitsPrivacyClass -Class 'BoundedReviewedText' -Value $finding.reason)) {
                throw "ConvertTo-PulseSafeShareDocument: finding '$($finding.id)' reason is not valid BoundedReviewedText."
            }
        }

        foreach ($evidence in @($finding.evidence)) {

            $fieldClasses = Get-PulseEvidenceFieldClassMap -Entry $evidence
            if (-not $fieldClasses.ContainsKey('identity') -and -not $fieldClasses.ContainsKey('Identity')) {
                $fieldClasses['identity'] = 'Identity'
            }
            if (-not $fieldClasses.ContainsKey('sortKey') -and -not $fieldClasses.ContainsKey('SortKey')) {
                $fieldClasses['sortKey'] = 'Identity'
            }

            if ($null -ne $evidence.detail -and $evidence.detail -is [pscustomobject]) {
                foreach ($detailProperty in @($evidence.detail.PSObject.Properties)) {
                    $className = $fieldClasses[$detailProperty.Name]
                    if (-not (Test-PulsePrivacyClassName -Class $className)) {
                        throw "ConvertTo-PulseSafeShareDocument: evidence detail.$($detailProperty.Name) is unclassified."
                    }
                }
            }

            if ($evidence.PSObject.Properties.Name -contains 'identity') {
                if (-not (Test-PulsePrivacyClassName -Class $fieldClasses['identity']) -and -not (Test-PulsePrivacyClassName -Class $fieldClasses['Identity'])) {
                    throw "ConvertTo-PulseSafeShareDocument: evidence identity is unclassified."
                }
                $evidence.identity = Get-SafeSharePseudonym -Raw ([string] $evidence.identity)
            }

            if ($evidence.PSObject.Properties.Name -contains 'sortKey') {
                $sortClass = $fieldClasses['sortKey']
                if ([string]::IsNullOrEmpty($sortClass)) { $sortClass = $fieldClasses['SortKey'] }
                if ($sortClass -eq 'Identity') {
                    $evidence.sortKey = Get-SafeSharePseudonym -Raw ([string] $evidence.sortKey)
                } elseif (-not (Test-PulsePrivacyClassName -Class $sortClass)) {
                    throw 'ConvertTo-PulseSafeShareDocument: evidence sortKey is unclassified.'
                } elseif (-not (Test-PulseValueFitsPrivacyClass -Class $sortClass -Value $evidence.sortKey)) {
                    throw "ConvertTo-PulseSafeShareDocument: evidence sortKey does not fit class '$sortClass'."
                }
            }

            if ($null -ne $evidence.detail -and $evidence.detail -is [pscustomobject]) {
                foreach ($detailProperty in @($evidence.detail.PSObject.Properties)) {
                    $className = $fieldClasses[$detailProperty.Name]
                    if (-not (Test-PulsePrivacyClassName -Class $className)) {
                        throw "ConvertTo-PulseSafeShareDocument: evidence detail.$($detailProperty.Name) is unclassified."
                    }
                    if (-not (Test-PulseValueFitsPrivacyClass -Class $className -Value $detailProperty.Value)) {
                        throw "ConvertTo-PulseSafeShareDocument: evidence detail.$($detailProperty.Name) does not fit class '$className'."
                    }
                    switch ($className) {
                        'Identity' {
                            if ($null -ne $detailProperty.Value -and -not [string]::IsNullOrEmpty([string] $detailProperty.Value)) {
                                $detailProperty.Value = Get-SafeSharePseudonym -Raw ([string] $detailProperty.Value)
                            }
                        }
                        'SecretSensitive' {
                            $detailProperty.Value = New-PulseSecretRedactionMarker
                        }
                    }
                }
            }

            if ($evidence.PSObject.Properties.Name -contains 'fieldClasses') {
                $evidence.PSObject.Properties.Remove('fieldClasses') | Out-Null
            }
            if ($evidence.PSObject.Properties.Name -contains 'FieldClasses') {
                $evidence.PSObject.Properties.Remove('FieldClasses') | Out-Null
            }
            if ($evidence.PSObject.Properties.Name -contains 'RedactDetailKeys') {
                $evidence.PSObject.Properties.Remove('RedactDetailKeys') | Out-Null
            }
        }
    }

    # The schema-level map classifies major document sections. Fixed scaffolding fields are
    # safe technical metadata, and the defaults keep legacy hand-built test/renderer inputs
    # compatible while still walking every scalar in every nested list and object.
    $documentFieldClasses = @{
        schemaVersion      = 'SafeTechnical'
        generatedUtc       = 'SafeTechnical'
        tenant             = 'Identity'
        producer           = 'SafeTechnical'
        coverage           = 'SafeTechnical'
        scores             = 'SafeTechnical'
        findings           = 'BoundedReviewedText'
        collectionOutcomes = 'SafeTechnical'
        privacyClasses     = 'SafeTechnical'
        privacy            = 'SafeTechnical'
        notices            = 'BoundedReviewedText'
        references         = 'SafeTechnical'
    }
    if ($clone.PSObject.Properties.Name -contains 'privacyClasses' -and $null -ne $clone.privacyClasses) {
        foreach ($property in @($clone.privacyClasses.PSObject.Properties)) {
            if (-not (Test-PulsePrivacyClassName -Class ([string] $property.Value))) {
                throw "ConvertTo-PulseSafeShareDocument: document privacy class '$($property.Name)' is invalid."
            }

            if ($documentFieldClasses.ContainsKey($property.Name)) {
                $fixedClass = [string] $documentFieldClasses[$property.Name]
                if ($fixedClass -ne [string] $property.Value) {
                    throw "ConvertTo-PulseSafeShareDocument: document privacy class '$($property.Name)' conflicts with fixed schema class '$fixedClass'."
                }
                continue
            }

            $documentFieldClasses[$property.Name] = [string] $property.Value
        }
    }

    $clone = Convert-SafeShareNode -Node $clone -FieldClasses $documentFieldClasses -NodePath 'document'

    $clone | Add-Member -NotePropertyName privacy -NotePropertyValue (ConvertTo-PulsePrivacyEnvelope -Complete $true) -Force
    return $clone
}

function ConvertTo-PulseCompatPrivacyLabel {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return ConvertTo-PulsePrivacyEnvelope -Complete $false
}
