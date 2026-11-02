# Replay protection limitations in v0.2.1

Published November 2026. Applies to `regaudit-fhe` 0.2.1, the supported release. Corrections are planned for the next
security release. This advisory describes replay detection only. It does not change any code or published artifact.

**Changing replay freshness settings:** Increasing `max_age` or `clock_skew` while reusing an existing replay-state
store can permit a previously accepted signed report to be accepted again. The `max_age` case is reachable through the
CLI (`--max-age-seconds`) and through the server (`REGAUDIT_FHE_MAX_AGE_S`).

**Mitigation:** Keep replay freshness settings fixed for each existing replay-state store. Do not increase them in
place. If a policy change is necessary, suspend verification and perform a separately validated replay-state migration;
do not assume that starting with an empty store preserves replay history. Do not reset or discard replay history as a
workaround.

**Zero clock skew:** Python library integrations explicitly using `clock_skew=0` can accept a report twice at an exact
freshness boundary. The published CLI and server use a nonzero default and do not expose that specific setting. Until
the correction is released, library integrators should retain a positive clock-skew allowance and avoid `clock_skew=0`.

**Replay-state scope:** Replay detection is limited to the configured state store and its persistence and integrity. It
does not establish global replay prevention across independent stores, lost state, or attacker-controlled clock changes.

**Development configurations:** Where replay-state persistence is unavailable in a `development` configuration, a
verifier may still accept a report while reporting `REPLAY_STATE_UNAVAILABLE`. That is not equivalent to enforced replay
protection.

These limitations affect replay detection; they do not imply that an attacker can forge an issuer's cryptographic
signature.
