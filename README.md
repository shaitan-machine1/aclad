# aclad

Phase 1 device-ACL service for the decoupled login stack.

- `aclad` owns root-only `org.decoupling.aclad1.Manager.{Grant,Revoke}`.
- `pam_aclad.so` synchronously grants before PAM open returns and revokes on
  PAM close.
- Grants persist as root-only JSON records under `/run/aclad/grants`.
- ACLs on each seat's `uaccess` devices are recomputed as the exact union of
  granted UIDs. Named-user entries are replaced, the base ACL and named groups
  are preserved, and libacl recomputes the POSIX mask.
- A monitor-first `seat-udev` cache handles hotplug and seat moves. Static
  seat0 nodes are discovered through `/run/udev/static_node-tags/uaccess`.
- `SessionRemoved` is an equal revocation source. aclad subscribes before
  `ListSessions`, reconciles persisted grants when sessiond is reachable, and
  retries periodically if sessiond starts later. With no sessiond it remains a
  PAM-only service and retains loaded grants.

## Build and test

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The pure service tests use fake ACL/store backends and require no root. Live
udev, PAM, POSIX ACL, and sessiond integration can be exercised on a private
D-Bus daemon; physical VT/audio/hotplug acceptance remains an M5 Artix VM
check.

## Installation

Install `aclad`, `libpam_aclad.so` as the platform PAM module name, the D-Bus
policy from `dist/dbus`, and the s6 longrun from `dist/s6`. aclad requires the
system D-Bus and completed udev coldplug. Link the daemon with libacl and
libudev. See `dist/pam/README.md` for stack ordering.
