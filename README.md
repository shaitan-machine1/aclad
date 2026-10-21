# aclad

Phase 1 device-ACL service for the decoupled login stack.

- `aclad` owns root-only `org.decoupling.aclad1.Manager` grant, revoke and
  deterministically ordered grant-inventory methods.
- `acladctl` provides readable `list`, `grant` and `revoke` commands over the
  system bus; daemon peer credentials remain the authorization boundary.
- `pam_aclad.so` synchronously grants before PAM open returns and revokes on
  PAM close; failures include operation context and are reported through
  `pam_syslog()` with a constant format string.
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

Administrative client commands are:

```sh
acladctl list
acladctl grant SESSION_ID UID SEAT
acladctl revoke SESSION_ID
```

`list` prints an aligned `SESSION`/`UID`/`SEAT` table or `No grants.`.
Mutations repeat the affected session and grant details and do not prompt.

## Build and test

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The pure service tests use fake ACL/store backends and require no root; one
filesystem test exercises real libacl. Root-required end-to-end harnesses are
also committed:

```sh
./tests/root-e2e.sh
./tests/root-sessiond-e2e.sh
./tests/pam-syslog.sh
```

The first uses a private D-Bus daemon and a no-device test service to verify
root authorization, persistence, `pam_aclad` grant/revoke, and the no-seat path
without touching host device ACLs. The second builds sibling scoped/sessiond
checkouts (override with `SCOPED_REPO` and `SESSIOND_REPO`) and verifies restart
reconciliation plus unclean-exit `SessionRemoved` revocation. Both require
passwordless `sudo` and return status 77 when prerequisites are unavailable.
`pam-syslog.sh` interposes a test logger and verifies contextual system-bus,
grant, session, uid and seat details with the literal `%s` format. Physical
VT/audio/USB-hotplug acceptance remains an M5 Artix VM check.

## Installation

Install `aclad` and `acladctl` under `/usr/bin`, `libpam_aclad.so` as the
platform PAM module name, the D-Bus
policy from `dist/dbus`, the udev rules from `dist/udev`, and the s6 longrun
from `dist/s6`.

`dist/udev/70-uaccess.rules` replaces the file systemd and elogind ship. It
only tags devices: the `uaccess` builtin it would otherwise invoke asks
logind which session is active, so aclad applies the ACLs instead. Nothing is
tagged without it, which leaves aclad with no devices to manage, and it must
sort before `71-seat.rules` from `seat-udev`, which makes every `uaccess`
device a seat member. Existing devices pick the rules up on
`udevadm control --reload` plus `udevadm trigger`, or at the next boot.
 aclad requires the
system D-Bus and completed udev coldplug. Link the daemon with libacl and
libudev. See `dist/pam/README.md` for stack ordering.
