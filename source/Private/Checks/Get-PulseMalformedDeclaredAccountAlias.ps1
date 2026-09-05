<#
    Private: derive a stable, bounded evidence alias for an operator-supplied account value
    that failed the canonical Entra object-id contract.

    The raw value is required in memory long enough to classify it and compare it with a
    policy, but it must not be copied into a normal finding. A deterministic HMAC-SHA256 digest
    prefix lets repeated findings be correlated without persisting the UPN, display name,
    secret-like token, or other arbitrary operator input. The digest is keyed by the same
    local operator key as normal pseudonyms so a guessed UPN cannot be checked against a
    globally stable unkeyed digest and the same value cannot be correlated across operators.
    Normal findings need this protection even when -Redact was not requested. Null, empty,
    and whitespace-only declarations carry no secret material and collapse to one fixed
    `blank` alias so malformed profile input remains reportable instead of throwing. Case
    is canonicalized invariantly so checks correlate the same account spelling, but the
    value is deliberately not trimmed: surrounding whitespace is format-significant and
    must not turn malformed input into a valid identifier.
#>
function Get-PulseMalformedDeclaredAccountAlias {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value,

        [Parameter(Mandatory)]
        [ValidateCount(32, 1024)]
        [byte[]] $Key
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'malformed-declared-account:blank'
    }

    $pseudonym = Get-PulsePseudonym -Value $Value.ToLowerInvariant() -Key $Key
    return 'malformed-declared-account:' + $pseudonym.Substring(3, 24)
}
