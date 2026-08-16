<#
    Fixture: a single, deliberately non-read-only DatasetMap.psd1-shaped entry.

    Used ONLY by tests/QA/ReadOnly.tests.ps1's mutation-check Context, which mocks
    Get-GraphOperation (scoped to that Context) to resolve this exact Type/Operation pair
    as a Write-class, unsafe-to-replay descriptor. FixtureMutationResource/Create does not
    exist in the real GraphKit catalog and never will - it exists purely to prove
    Test-PulseReadOnlyDatasetMap's own walking/reporting logic actually rejects a mutation,
    without ever touching or depending on a live tenant or the real catalog.
#>
@{
    fixtureMutation = @{ Type = 'FixtureMutationResource'; Operation = 'Create'; ApiVersion = 'v1.0' }
}
