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
