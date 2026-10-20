#!/bin/bash
# Hermetic root/private-D-Bus and pam_aclad integration.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for command in cargo cc dbus-daemon busctl pgrep sudo; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 77; }
done
sudo -n true || { echo "passwordless sudo is required" >&2; exit 77; }
cargo build --manifest-path "$repo/Cargo.toml" --example fake-aclad
cargo build --manifest-path "$repo/Cargo.toml" -p pam-aclad

work=$(mktemp -d /tmp/aclad-root-e2e.XXXXXX)
chmod 755 "$work"
cat >"$work/bus.conf" <<EOF
<busconfig><type>system</type><listen>unix:path=$work/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_type="method_call"/><allow send_type="method_return"/><allow send_type="error"/><allow send_type="signal"/><allow receive_type="method_call"/><allow receive_type="method_return"/><allow receive_type="error"/><allow receive_type="signal"/></policy></busconfig>
EOF
cat >"$work/pam-app.c" <<'EOF'
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data) {
    (void)count; (void)messages; (void)data; *responses = NULL; return PAM_CONV_ERR;
}
int main(int argc, char **argv) {
    if (argc != 5) return 64;
    struct pam_conv conversation_data = {conversation, NULL};
    pam_handle_t *handle = NULL;
    int status = pam_start_confdir(argv[1], "root", &conversation_data, argv[4], &handle);
    if (status != PAM_SUCCESS) return 1;
    pam_putenv(handle, "XDG_SESSION_ID=0123456789abcdef0123456789abcdef");
    if (strcmp(argv[3], "-") != 0) pam_putenv(handle, argv[3]);
    status = pam_open_session(handle, 0);
    if (status != PAM_SUCCESS) { fprintf(stderr, "open: %s\n", pam_strerror(handle, status)); pam_end(handle, status); return 2; }
    FILE *result = fopen(argv[2], "w");
    if (result == NULL) return 3;
    fputs("open\n", result); fclose(result); sleep(1);
    status = pam_close_session(handle, 0);
    pam_end(handle, status);
    return status == PAM_SUCCESS ? 0 : 4;
}
EOF
cc "$work/pam-app.c" -lpam -o "$work/pam-app"
mkdir "$work/pam.d"
printf 'session required %s timeout=5s\n' "$repo/target/debug/libpam_aclad.so" >"$work/pam.d/aclad-e2e"

bus_pid=$(dbus-daemon --config-file="$work/bus.conf" --fork --print-pid)
address="unix:path=$work/bus"
daemon_wrapper= pam_wrapper= pam_pid=
cleanup() {
    status=$?
    trap - EXIT
    set +e
    [ -n "$pam_pid" ] && sudo kill -KILL "$pam_pid" 2>/dev/null
    [ -n "$daemon_wrapper" ] && sudo kill "$daemon_wrapper" 2>/dev/null
    wait 2>/dev/null
    kill "$bus_pid" 2>/dev/null
    if [ "$status" -ne 0 ]; then
        for log in "$work"/*.log; do [ -f "$log" ] && { echo "--- $log" >&2; sudo tail -100 "$log" >&2; }; done
    fi
    sudo rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT
wait_name() {
    for _ in $(seq 1 100); do
        busctl --address="$address" list 2>/dev/null | grep -q "$1" && return 0
        sleep .05
    done
    echo "timed out waiting for $1" >&2
    return 1
}
wait_file() {
    for _ in $(seq 1 100); do sudo test -f "$1" && return 0; sleep .02; done
    echo "timed out waiting for $1" >&2
    return 1
}

sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$repo/target/debug/examples/fake-aclad" "$work/grants" >"$work/aclad.log" 2>&1 & daemon_wrapper=$!
wait_name org.decoupling.aclad1
sid=1123456789abcdef0123456789abcdef
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" busctl --address="$address" call org.decoupling.aclad1 /org/decoupling/aclad1 org.decoupling.aclad1.Manager Grant sus "$sid" 0 seat0
sudo test -f "$work/grants/$sid"
if busctl --address="$address" call org.decoupling.aclad1 /org/decoupling/aclad1 org.decoupling.aclad1.Manager Revoke s "$sid" 2>/dev/null; then
    echo "unprivileged revoke unexpectedly succeeded" >&2
    false
fi
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" busctl --address="$address" call org.decoupling.aclad1 /org/decoupling/aclad1 org.decoupling.aclad1.Manager Revoke s "$sid"
sudo test ! -e "$work/grants/$sid"

sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$work/pam-app" aclad-e2e "$work/seat-open" XDG_SEAT=seat0 "$work/pam.d" >"$work/pam.log" 2>&1 & pam_wrapper=$!
wait_file "$work/seat-open"
pam_pid=$(pgrep -P "$pam_wrapper" -f pam-app)
sudo test -f "$work/grants/0123456789abcdef0123456789abcdef"
wait "$pam_wrapper"
pam_wrapper= pam_pid=
sudo test ! -e "$work/grants/0123456789abcdef0123456789abcdef"

# SSH-style/no-seat PAM must succeed without contacting any aclad endpoint.
DBUS_SYSTEM_BUS_ADDRESS="unix:path=$work/does-not-exist" "$work/pam-app" aclad-e2e "$work/no-seat-open" - "$work/pam.d"
test -f "$work/no-seat-open"

echo "aclad root/private-D-Bus/PAM end-to-end tests passed"
