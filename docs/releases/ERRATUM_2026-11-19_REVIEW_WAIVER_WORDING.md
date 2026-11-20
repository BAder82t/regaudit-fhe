# Erratum, 2026-11-19: review-waiver wording in the release records

Dated 2026-11-19. This erratum corrects how the earlier release records can be read. It does not change them. The
original records stay as written, so that the history of what was said at the time is kept.

## Records affected

| Record | Wording that can be misread |
|---|---|
| `docs/releases/RELEASE_0.1.1_RECORD.md` | Lines 3 to 4 say "Human code review was waived by the owner (AI-only assurance waiver)". Line 86 says "an AI reviewer, not a human". |
| `docs/releases/RELEASE_0.2.0_RECORD.md` | Lines 3 to 4 repeat the waiver sentence. Line 87 says "human code review was waived". |
| `docs/releases/RELEASE_0.2.1_RECORD.md` | Line 42 lists "Independent human code review" under "Not performed". This one already states that it was not performed. |

## What the earlier wording means

"Waived" suggests that a review was due and that someone with the authority to waive it decided to skip it. No gate
in this repository requires an independent review, and the records show no request for one to anyone else. The records
show no independent review of these releases, so there was nothing to waive. The word does not describe a review that
took place, and it does not describe a review that was formally excused by a third party.

## What the releases 0.1.1, 0.2.0 and 0.2.1 did not receive

- No independent code review by a person other than the maintainer. The records show none.
- No independent external security audit.
- No regulator approval, certification or conformity assessment.
- No independent qualification of the encrypted backend. The repository records none.

Nothing in the records or in this erratum is a claim of audit, certification, production readiness or regulatory
compliance.

## What was and was not checked

Checked, as each record lists in its own evidence tables:

- Automated tests, static analysis and the executable checks named in the record.
- The GitHub Actions pipeline runs recorded in each record, for the tagged commit.
- AI-assisted review: AI agents read and tested the code under the maintainer's direction. This is a form of
  automated checking. It does not replace an independent reviewer, and agents can share the blind spots of the
  process that produced the code.
- The maintainer's own checks of the release steps. Statements marked `[owner]` in the records are statements by the
  account holder that the repository cannot confirm. In particular the PyPI trusted-publisher settings cannot be read
  from the repository.

Not checked:

- That the signed claims in a report match what a given run really computed. A signature shows who signed a claim,
  not that the computation was correct or that encryption was used.
- That the configured security parameters give the security level they name.
- The differential-privacy layer. Its parameters are declared by the caller and are not validated.
- Behaviour on platforms and with dependencies outside the CI matrix.

## What applies today

- Independent expert review has not yet been performed, and no gate enforces it. `docs/RELEASE_PROCESS.md` says so.
- The limitations that came to light after those releases are in `docs/advisories/` and in `SECURITY.md`.
- Anyone relying on a release should treat the records as an account of the checks that were made. They are not an
  assurance statement.
