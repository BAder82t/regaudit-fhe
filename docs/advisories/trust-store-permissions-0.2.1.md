# Trust store file permissions in v0.2.1 and earlier

Published November 2026. Applies to `regaudit-fhe` 0.2.1, the supported release, and to 0.2.0, 0.1.1, 0.1.0 and the
yanked 0.0.8. This advisory describes trust-key integrity only. It does not change any code or published artifact.
Replay history is a separate issue, described in [replay-file-permissions-0.2.1.md](replay-file-permissions-0.2.1.md).

**Summary.** In regaudit-fhe 0.1.0, 0.1.1, 0.2.0, 0.2.1 and the yanked 0.0.8 loading a trust store from a file does not
check who owns the file or who can write to it. The trust store decides which signing keys a verifier would trust.
Another local account would be able to add its own key if it can write to the file or a directory above it. A report
signed with this key would verify as `TRUSTED`, under `development`, `confidential` and `high-assurance`.

**What this does not mean.** This does not allow anyone to forge a signature made with a key already in the store. It
does not expose any private keys. The trust store is only used to store public keys. There is no evidence that this can
be reached remotely without local write access to the file. This is not related to replay detection.

**Who is affected.** Deployments that load a trust store from a file: the CLI with `--trusted-keys`, the server with
`REGAUDIT_FHE_TRUST_STORE` or `--trust-store`, or the library with `TrustStore.from_json`, where the file or a directory
above it is writable by another account. `trust add` in 0.2.0 and 0.2.1 will write the file as `0644` so another account
cannot write to it unless the file or a directory was later made writable or the directory was already shared. 0.1.0,
0.1.1 and 0.0.8 have no command to create a store. Therefore, its mode will be what the operator's tools gave it. A
store created in memory using `TrustStore.from_dict` is not in scope. Versions before 0.0.8 will not load a trust store
from a file.

**Mitigation.**

- Run the verifier under its own account.
- Keep the trust store owned by that account or by root and not writable by group or others. For example, `0640`.
- Check all the directories above it to make sure that none of them are writable by untrusted accounts. If the path goes
  through a symbolic link check the directories the link goes through as well as where it ends.
- Do not keep the file directly in a shared directory such as `/tmp`.
- In a container mount the file read-only and do not share the volume with other workloads.
- Do not use a network filesystem for it unless you can confirm how the ownership is enforced there.
- Keep a record of the expected key fingerprints somewhere the verifier's host cannot change. Compare it with `trust
  list` (0.2.0 and later) or a hash of the file before each server restart and after any intended changes. The server
  will read the store when it starts. The CLI will read it on every run.
- Before any edit and before tightening a mode check the file's keys. `trust add`, and any tool that writes a new file
  when you retire or revoke a key, removes a loose mode, an ACL or a second name. It keeps what the file already had. A
  correct mode after does not show that the file was safe before.
- After `trust add` check the mode again. `trust add` will set it to `0644` no matter what it was before.
- If the file might have been changed compare its keys with the issuers' fingerprints and verify again any report
  accepted since then using a known good copy.

**What remains.** Permissions would only keep out other unprivileged accounts. The file is not authenticated so a
process under the same account, an administrator or someone recovering an old copy would be able to change it. The
verifier would not know. Anyone needing protection from these parties would need a trust source outside of the
verifier's reach. This is not what regaudit-fhe provides.

**Check script.** `check_storage.py` below is used to check the file and everything going to it. This includes following
symbolic links. It reports what another account could change. It only looks at names, owners, modes, and ACLs. Run it as
the account that would run the verifier. A clean result would not show that the file was not changed earlier.

```python
#!/usr/bin/env python3
"""Could another local account change this regaudit-fhe trust store or replay file? Read-only.

Run it as the account that runs the verifier: python3 check_storage.py /path/to/file [more paths]
It only looks at names, owners, modes and ACLs. It never opens the file and changes nothing.
Exit 0: nothing found. Exit 1: something to review. Exit 2: could not check.
A clean result does not show the file was not changed earlier, and says nothing about the
same account, an administrator, a restored backup or a network filesystem.
"""
import os
import stat
import subprocess
import sys

READ_ONLY = {"read", "execute", "search", "list", "readattr", "readextattr", "readsecurity", "file_inherit", "directory_inherit", "limit_inherit", "only_inherit"}
TRUSTED = (os.geteuid(), 0) if hasattr(os, "geteuid") else ()


def acl_allows_more_than_reading(path):
    if sys.platform != "darwin":
        return False  # On Linux an ACL entry granting write shows in the group bits.
    out = subprocess.run(["/bin/ls", "-lde", path], capture_output=True, text=True, check=False)
    for line in out.stdout.splitlines()[1:]:
        if " deny " not in line and (" allow " not in line or set(line.split(" allow ", 1)[1].strip().split(",")) - READ_ONLY):
            return True
    return False


def problems(path, info, sticky_ok):
    found = [f"{path}: owned by uid {info.st_uid}, not this account or root"] if info.st_uid not in TRUSTED else []
    if stat.S_IMODE(info.st_mode) & 0o022 and not (sticky_ok and info.st_mode & stat.S_ISVTX):
        found.append(f"{path}: mode {stat.S_IMODE(info.st_mode):04o} lets group or others write")
    if acl_allows_more_than_reading(path):
        found.append(f"{path}: a macOS ACL lets someone else write")
    return found


def walk(directory, found):
    """Follow each directory and link the way the kernel does, and check all of them. Returns where it ended."""
    pending, current, links = list(reversed(directory.split("/"))), "/", 0
    found += problems("/", os.lstat("/"), True)
    while pending:
        part = pending.pop()
        if part == "..":
            current = os.path.dirname(current)
        elif part not in ("", "."):
            candidate = os.path.join(current, part)
            info = os.lstat(candidate)
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > 40:
                    raise OSError("too many symbolic links")
                if info.st_uid not in TRUSTED:
                    found.append(f"{candidate}: symbolic link owned by uid {info.st_uid}")
                target = os.readlink(candidate)
                current = "/" if target.startswith("/") else current
                pending.extend(reversed(target.split("/")))
            else:
                found += problems(candidate, info, True)
                current = candidate
    return current


def check(path):
    found, current = [], os.path.join(os.getcwd(), path)
    for _ in range(41):
        head, tail = os.path.split(current)
        directory = walk(head, found)
        found += problems(directory, os.lstat(directory), False)  # A sticky parent still lets others create the name first.
        target = os.path.join(directory, tail)
        info = os.lstat(target)
        if not stat.S_ISLNK(info.st_mode):
            found += problems(target, info, False)
            if not stat.S_ISREG(info.st_mode):
                found.append(f"{target}: not a regular file")
            elif info.st_nlink != 1:
                found.append(f"{target}: has {info.st_nlink} names")
            return sorted(set(found))
        if info.st_uid not in TRUSTED:
            found.append(f"{target}: symbolic link owned by uid {info.st_uid}")
        current = os.path.join(directory, os.readlink(target))
    raise OSError("too many symbolic links")


def main(paths):
    if not paths or not sys.platform.startswith(("linux", "darwin")):
        print("usage on Linux or macOS: check_storage.py PATH [PATH...]", file=sys.stderr)
        return 2
    worst = 0
    for path in paths:
        try:
            found = check(path)
        except OSError as exc:
            print(f"{path}: COULD NOT CHECK: {exc}")
            worst = 2
            continue
        print(f"{path}: {'REVIEW' if found else 'nothing found'}")
        print("".join(f"  {line}\n" for line in found), end="")
        worst = max(worst, 1 if found else 0)
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

**Fix status.** No patch release for 0.2.x is planned. Checks that would refuse this file under `confidential`,
`high-assurance`, and `secure-v1` are on the review branch of pull request #65 at commit `13437c93f6604e8ac61d0fe30fe8661f78e1951e`. These checks are not
in any release yet. There is no release date. `development` will still load this file and warn. Until a release has
these checks use the mitigation above.
