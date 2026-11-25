# Storage platform notes

This page states what the local storage checks for the trust store and the replay file do, on which platforms, and what
they do not do. It describes behaviour of the code. It is not a statement of audit, certification, production readiness
or regulatory compliance.

## What the policy guards against

The checks guard against **another unprivileged local account** changing the trust store or the replay file, or
changing a directory on the way to either. Concretely they refuse a file or a directory on the path that:

- belongs to an account other than the one running the command or root;
- is writable by group or others (a sticky directory above the parent is allowed; the parent itself may not be sticky);
- is reached through a symbolic link whose own directory or owner fails the same test;
- has more than one hard link, or is not a regular file;
- on macOS, carries an ACL entry that lets another principal write it.

An unsafe store is refused or reported. Nothing in this page makes a store more permissive than the policy says.

## Platforms

| Platform | Status |
| --- | --- |
| Linux | Supported. Owner, mode, link and hard-link checks apply. |
| macOS | Supported. The same checks, plus an ACL check on the file and on each directory on the path. |
| Windows and others | Not supported. The policy cannot establish owner and permissions and reports a problem. A strict profile refuses. |

## Writing the trust store (`trust add`)

- A new store is created with mode 0600, whatever the umask.
- An existing store keeps the permission bits it has. They are neither widened nor narrowed. A store created earlier at
  0644 stays 0644 and is reported as before; change it yourself with `chmod` if you want it narrower.
- The write goes to a temporary file in the same directory, is flushed and `fsync`ed, gets its mode, replaces the store
  with `os.replace`, and the directory is then `fsync`ed. A failure before the replace leaves the old store as it was and
  removes the temporary file.
- Reading, validating and writing happen under an exclusive `flock` on the directory that holds the store. This orders
  concurrent `regaudit-fhe` runs that edit the store on one local filesystem, so two edits do not lose each other's change.
  No lock file is created and the store format does not change. `trust add`, `trust retire` and `trust revoke` take this
  lock. `trust migrate` writes a new file and refuses an existing target; it does not take it.
- Where the lock cannot be taken, the command refuses (exit 3, `cannot lock`) and writes nothing. That includes a platform
  without `flock` and a store directory the account cannot open for reading (for example mode 0300, which worked before the
  lock existed). Locking the store file instead would not order writers, because the replace creates a new file, so the
  command does not fall back to it. Make the directory readable, or do not use `trust add` there.
- `trust retire` and `trust revoke` also re-read the store just before the replace and refuse if it changed.

## Write outcomes and recovery

A write ends in exactly one of three ways.

| Outcome | What happened | `trust add` exit and message | Store | What you do |
| --- | --- | --- | --- | --- |
| 1. Failed | An error before `os.replace`: temp file write, file `fsync`, `chmod` or the replace itself | 2, `cannot write ...` | The old content, byte for byte; no temp file | Fix the cause and run it again |
| 2. Written, durability not confirmed | `os.replace` succeeded, then opening or `fsync`ing the directory failed | 3, `NOT confirmed durable: ... is in ... and is visible, but syncing it to disk failed ...`; no success JSON | The new content is in place and visible | Run the same `trust add` again, or `trust status` |
| 3. Durable | Every step succeeded | 0 and the JSON result | The new content | Nothing |

Outcome 2 is never reported as success, and it is never reported as "nothing written". `trust retire` and `trust revoke`
use the same wording and exit 3.

**Repeating `trust add` after outcome 2.** An identical repeat (same `key_id`, same issuer, same key, entry still plain
`active`) replaces nothing, `fsync`s the store file and its directory again, and exits 0 with `already_enrolled: true` only if
that works; if the sync fails again it exits 3 with the same message. The same `key_id` with a different key or issuer, or an
entry that is no longer plain `active`, is refused with exit 2 as before. No file needs editing by hand. For `trust retire`
and `trust revoke`, check with `trust status`; the edit is in the store, and a repeat reports what the store now holds.

**Operations that can end in outcome 2:** the store replace in `trust add`, `trust retire` and `trust revoke` (directory open or
`fsync` after the replace), and the re-sync on an identical `trust add` repeat. `trust migrate` creates a new file and removes it
if its directory sync fails, so it ends in outcome 1. The replay file and the revocation pin and state stores have their own
commit code and are not changed here.

**An interrupted process** (`SIGKILL`, power loss) leaves the store either as it was or as the new content, never partly
written, because the replace is atomic. A killed process can leave one `.trust-*.tmp` file in the store directory; it is never
read as the store and can be deleted. After a crash, run `trust status` to see which one you have, and repeat the command.

**Limits.** These are tested on a local filesystem on macOS. The outcomes depend on `fsync` and `os.replace` being honoured:
on a network or synced filesystem outcome 3 can be reported for a write that is not durable, and `flock` may not order writers.
They do not stop the same account or an administrator, or another program that ignores the lock. On a platform without `flock`
(Windows) the commands that edit the store refuse.

## Linux

- On Linux the policy reads the mode bits only. A POSIX ACL entry that allows writing shows in the group bits, because
  the group bits of `stat` report the ACL mask, so the mode check refuses it. This reasoning is from `acl(5)`. The
  macOS ACL tests run only on macOS. One Linux test (`test_linux_acl_that_lets_another_user_write...`) needs `setfacl`; it
  skips elsewhere and has not been run on a Linux host for this document, so the Linux behaviour is untested here.
- NFSv4 ACLs and other filesystem-specific access controls are not read. If the store sits on a filesystem that grants
  access in a way the mode bits do not show, the policy does not see it.
- Extended attributes, capabilities, SELinux or AppArmor labels, and container or bind-mount permissions are not read.

## macOS

- The ACL on the file and on each directory on the path is read. An allow entry with any right beyond reading, for a
  principal other than the current user or root, is refused. An ACL that cannot be read reliably is refused.

## Network and other non-local filesystems

- `flock` may be a no-op, emulated, or only local to one client on NFS and other network filesystems. Concurrent
  `trust add` runs from different machines are not ordered.
- `fsync` and `os.replace` guarantees depend on the server. A server can acknowledge a write before it is durable.
- Owner and mode reported by the client can differ from what the server enforces (root squashing, ID mapping). The
  checks use what the client reports.
- Keep the trust store and the replay file on a local filesystem.

## Replay file

- The replay file is a SQLite database. It is created with mode 0600, is opened without following a final symbolic link,
  and SQLite does its own locking. The same owner, mode, link and ACL checks as above apply to it.
- SQLite locking has the same limits on network filesystems as above.

## What is not protected

- **The same account.** Any process running as the account that owns the store can edit, replace or delete it. The
  policy does not distinguish the maintainer's shell from other code running as that account.
- **An administrator.** root, and anyone who can become root or the owning account, can change anything.
- **Restored backups and copies.** A store or replay file restored from a backup, a snapshot or another machine is
  checked only for owner, mode and links at the time it is used. An older store can bring back a revoked or retired key
  as it was, and an older replay file can bring back identifiers that were already used. The policy has a floor for the
  replay file that detects some restores while the object is alive; it is not rollback prevention.
- **Another program ignoring the lock.** The lock is advisory and orders only cooperating `regaudit-fhe` processes.
- **Power loss on hardware or filesystems that do not honour `fsync`.**
- **Contents.** The trust store is a local, unauthenticated file. Nothing here proves that a key in it was enrolled by
  the maintainer or that it belongs to the issuer it names.
- **Time of check versus time of use.** The path checks run before the file is opened. A change made by the same account
  or an administrator in between is out of scope.
