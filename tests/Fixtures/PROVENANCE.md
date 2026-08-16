# Fixture provenance

Every file under `tests/Fixtures/` must be listed here with its provenance so a later
static gate (see the phase plan) can check fixtures were not copied from a real tenant
or a third-party source without attribution. One line per fixture file.

- `tests/Fixtures/Checks/valid/a-second.psd1` — synthetic
- `tests/Fixtures/Checks/valid/b-first.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/duplicate-id/one.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/duplicate-id/two.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/bad-severity/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/missing-research/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/empty-datasets/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/unknown-rule-type/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/bad-rule-function/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/bad-id/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/missing-consulting/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/unknown-dataset-name/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/array-id/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/array-id-duplicate/one.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/array-id-duplicate/two.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/array-severity/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/numeric-title/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/scalar-datasets/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/scalar-authorities/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/empty-authorities/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/missing-expression/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/bad-effort/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/bad-impact/bad.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/parse-failure/broken.psd1` — synthetic
- `tests/Fixtures/Checks/invalid/bad-expression-syntax/bad.psd1` — synthetic
- `tests/Fixtures/DatasetMap/malformed-syntax.psd1` — synthetic
- `tests/Fixtures/DatasetMap/mutation-write-op.psd1` — synthetic
