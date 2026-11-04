# Replay file permissions in v0.2.1 and earlier

Published November 2026. Applies to `regaudit-fhe` 0.2.1, the supported release, and to 0.2.0, 0.1.1 and 0.1.0. This
advisory describes replay detection only. It does not change any code or published artifact. Trust-key integrity is a
separate issue with a larger consequence, described in
[trust-store-permissions-0.2.1.md](trust-store-permissions-0.2.1.md).

**Summary.** In regaudit-fhe from 0.1.0 to 0.2.1, `SqliteReplayCache` does not check who owns the replay file or who can
write to it. If another local account has the ability to write to the file or a directory above it then this account
would be able to change the replay records. A signed report that the verifier has already refused as a replay can then
be accepted again while it is still within its `max_age`. The verifier would still show `replay_durable: true`.

**What this does not mean.** This does not allow anyone to forge a signature. A report would still need to be correctly
signed with a trusted key and be fresh. There is no evidence that it can be reached remotely without write access to the
file locally. This is only for replay detection.

**Who is affected.** Deployments using replay checking with a replay file: the CLI with `--replay-mode` and
`--replay-db`, the server with `REGAUDIT_FHE_REPLAY_DB`, or the library with `SqliteReplayCache`, where the file or a
directory above it is writable by another account. A file created by these versions is `0644`, or `0600` under umask
`077`. So another account can read it but cannot write to it unless the file or a directory was later made writable, or
the file is in a shared directory. Replay checking turned off and the in-memory cache are not in scope since they do not
claim durable local records.

**Mitigation.**

- Run the verifier under its own account.
- Set the replay file to `0600` and its directory to `0700`, owned by that account.
- Check all the directories above it and make sure that none of them are writable by accounts you do not trust. If the
  path goes through a symbolic link also check the directories the link would go through and where it would end as well.
- Do not keep the file directly in a shared directory such as `/tmp`.
- Do not use a network filesystem for it unless you can confirm how ownership is enforced.
- Treat the recovery of a replay file from a backup as forgetting all reports since that backup.
- A correct mode now does not show that records were not changed previously. If the file or a directory above it was
  writable by another account then any reports accepted when it was exposed and still within their `max_age` should be
  considered possibly used twice.

**What remains.** Permissions would only stop other unprivileged accounts. The records are not authenticated so a
process under the same account, an administrator or someone restoring an older copy can change the records. The verifier
would not notice. This is the wider limit already described in
[replay-limitations-0.2.1.md](replay-limitations-0.2.1.md). Permission checks do not remove this limit. Anyone needing
protection from these parties would need to have an independent replay store. This is what regaudit-fhe does not
provide.

**Check script.** `check_storage.py` is published in [the advisory for the trust store](trust-store-permissions-0.2.1.md) and covers this file as well. A
clean result would not show that the records were not changed earlier.

**Fix status.** No patch release for 0.2.x is planned. Checks that would refuse this file under `confidential`,
`high-assurance`, and `secure-v1` are on the review branch of pull request #65 at commit `13437c93f6604e8ac61d0fe30fe8661f78e1951e`. They are not in any
release yet. There is no release date. `development` is still able to load this file and will warn. Until a release has
these checks use the mitigation above.
