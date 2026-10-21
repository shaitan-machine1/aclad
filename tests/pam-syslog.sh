#!/bin/bash
# Verify pam-aclad routes contextual failures through pam_syslog with "%s".
set -euo pipefail

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for command in cargo cc; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 77; }
done
cargo build --manifest-path "$repo/Cargo.toml" -p pam-aclad

work=$(mktemp -d /tmp/pam-aclad-syslog.XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir "$work/pam.d"
cat >"$work/shim.c" <<'EOF'
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void pam_syslog(const pam_handle_t *pamh, int priority, const char *format, ...) {
    (void)pamh;
    (void)priority;
    FILE *file = fopen(getenv("PAM_SYSLOG_CAPTURE"), "a");
    if (file == NULL) return;
    fprintf(file, "format=%s\nmessage=", format);
    va_list arguments;
    va_start(arguments, format);
    vfprintf(file, format, arguments);
    va_end(arguments);
    fputc('\n', file);
    fclose(file);
}
EOF
cat >"$work/app.c" <<'EOF'
#include <security/pam_appl.h>
#include <stdlib.h>

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data) {
    (void)count; (void)messages; (void)data; *responses = NULL; return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    struct pam_conv conv = {conversation, NULL};
    pam_handle_t *handle = NULL;
    int status = pam_start_confdir("aclad-syslog", argv[1], &conv, argv[2], &handle);
    if (status != PAM_SUCCESS) return 1;
    if (pam_set_item(handle, PAM_TTY, "tty7") != PAM_SUCCESS) return 2;
    if (pam_putenv(handle, "XDG_SESSION_ID=0123456789abcdef0123456789abcdef") != PAM_SUCCESS) return 3;
    status = pam_open_session(handle, 0);
    pam_end(handle, status);
    return status == PAM_SESSION_ERR ? 0 : 4;
}
EOF
cc -shared -fPIC "$work/shim.c" -o "$work/shim.so"
cc "$work/app.c" -lpam -o "$work/app"
printf 'session required %s timeout=50ms\n' \
    "$repo/target/debug/libpam_aclad.so" >"$work/pam.d/aclad-syslog"

capture="$work/syslog"
PAM_SYSLOG_CAPTURE="$capture" \
LD_PRELOAD="$work/shim.so" \
DBUS_SYSTEM_BUS_ADDRESS="unix:path=$work/missing-bus" \
    "$work/app" "$(id -un)" "$work/pam.d"

grep -Fx 'format=%s' "$capture"
grep -E '^message=connect to the system bus for aclad Grant for session 0123456789abcdef0123456789abcdef, uid [0-9]+, seat seat0: ' "$capture"

echo "pam-aclad pam_syslog diagnostic test passed"
