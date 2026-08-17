# CIS Benchmark cross-references: cite-only, in our own words

This is TenantPulse's own summary of why `References.Cis` (the optional check-descriptor
field, Task 4.5) is restricted to a bare benchmark citation and nothing more. It is written
from our own understanding of the licensing situation, for our own repo - it is not a copy of
any CIS document or of any third party's research report, and none of the wording below is
CIS's own text.

## The rule

A `References.Cis` entry may contain **only**:

- the benchmark's name (e.g. "CIS Microsoft 365 Foundations Benchmark")
- its version (e.g. "v7.0.0")
- the recommendation's numeric ID (e.g. "Rec. 5.2.2.1")
- its profile level (e.g. "E3 Level 1")

A `References.Cis` entry must **never** contain:

- a CIS recommendation's title, even paraphrased close to verbatim
- any of a recommendation's Description, Rationale, Audit, or Remediation text
- any statement that a check's Pass/Fail result equals, implies, or measures CIS Benchmark
  compliance, certification, or alignment

## Why

CIS publishes its benchmarks under CC BY-NC-SA 4.0 plus its own non-member terms of use.
That license is non-commercial and share-alike - incompatible with TenantPulse's MIT license,
which permits commercial and closed-derivative use. Copyright protects the *expression* CIS
wrote (titles, descriptions, rationale, audit/remediation prose), not the underlying *fact*
that a given Graph/tenant setting corresponds to a given numbered CIS recommendation. Citing
a benchmark name, version, and recommendation number is citing a fact, not reproducing
copyrighted text, so it stays clear of the CC BY-NC-SA/MIT conflict. Separately, CIS's own
non-member terms prohibit representing or claiming a level of CIS compliance without paid
CIS SecureSuite vendor certification - which is why every check that ever does carry a
`References.Cis` entry ships alongside a disclaimer, never a bare "compliant" claim (see the
"CIS compliance disclaimer" section in the top-level `README.md`, and the runtime wiring in
`Invoke-PulseEvaluation.ps1`'s `notices.cisDisclaimer`).

Several other MIT/Apache-licensed open-source tools in this space (Maester, Monkey365) ship
CIS ID cross-references under this same cite-only pattern without incident; the most
conservative comparable project (CISA's ScubaGear, CC0) avoids CIS entirely in favor of its
own SCuBA baselines. TenantPulse's posture sits with the former: cite IDs, author every check's
own content ourselves, never claim compliance.

## What this means for check authors

If you add a `References.Cis` entry to a check descriptor:

1. Confirm the mapping against the benchmark PDF or CIS WorkBench yourself - don't infer it
   from a summary, and don't copy a mapping table from a third party.
2. Write the string as `"<Benchmark name> v<version>, Rec. <id> (<profile level>)"` - nothing
   else.
3. Never add the recommendation's title or any of its prose anywhere in the descriptor
   (`Title`, `Consulting.*`, etc. must stay entirely your own words, same as every other
   check in this catalog already is).
4. Leave the compliance-disclaimer wiring alone - it is automatic (see
   `Invoke-PulseEvaluation.ps1`) and fires the moment any check in the run carries a
   `References.Cis` entry.

## Status as of Phase 4 (Task 4.5)

Zero of the 28 shipped checks carry a `References.Cis` entry. The Phase 4 check research this
catalog was authored from cites ScuBA/CISA, Maester/EIDSCA, and Microsoft Learn exclusively -
no verified CIS mapping exists yet for any check in this catalog. The schema field and the
disclaimer wiring are built and tested (synthetic fixture data) ahead of that first real
mapping, not after it.
