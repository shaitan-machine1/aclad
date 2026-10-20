# PAM integration

Install `libpam_aclad.so` as `pam_aclad.so`. Place it after `pam_sessiond.so`
and any module that supplies `XDG_SEAT`:

```text
session required pam_sessiond.so timeout=30s
session optional pam_env.so
session required pam_aclad.so timeout=30s
```

PAM closes session modules in reverse order, so `pam_aclad` revokes before
`pam_sessiond` tears down and emits `SessionRemoved`. If `XDG_SEAT` is absent,
only `PAM_TTY=ttyN` (or `/dev/ttyN`) implies `seat0`; SSH/PTY sessions receive
no device ACL and succeed without contacting aclad.
