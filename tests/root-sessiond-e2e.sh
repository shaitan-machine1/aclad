#!/bin/bash
# Cross-repository SessionRemoved and restart-reconciliation integration.
set -euo pipefail
aclad_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sessiond_repo=${SESSIOND_REPO:-"$aclad_repo/../sessiond"}
scoped_repo=${SCOPED_REPO:-"$aclad_repo/../scoped"}
for command in cargo cc dbus-daemon busctl pgrep sudo; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 77; }
done
sudo -n true || { echo "passwordless sudo is required" >&2; exit 77; }
cargo build --manifest-path "$scoped_repo/Cargo.toml" -p scoped
cargo build --manifest-path "$sessiond_repo/Cargo.toml" -p sessiond --bin sessiond --example hold-session
cargo build --manifest-path "$aclad_repo/Cargo.toml" --example fake-aclad

work=$(mktemp -d /tmp/sessiond-aclad-e2e.XXXXXX)
chmod 755 "$work"
cgroup="sessiond-aclad-e2e-$$"
cat >"$work/bus.conf" <<EOF
<busconfig><type>system</type><listen>unix:path=$work/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_type="method_call"/><allow send_type="method_return"/><allow send_type="error"/><allow send_type="signal"/><allow receive_type="method_call"/><allow receive_type="method_return"/><allow receive_type="error"/><allow receive_type="signal"/></policy></busconfig>
EOF
cat >"$work/launcher.c" <<'EOF'
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t stop;
static void handler(int signal) { (void)signal; stop = 1; }
int main(void) { char byte; if (read(3, &byte, 1) != 1) return 1; byte = 1; if (write(4, &byte, 1) != 1) return 2; signal(SIGTERM, handler); while (!stop) pause(); return 0; }
EOF
cc "$work/launcher.c" -o "$work/launcher"
cat >"$work/sessiond.toml" <<EOF
runtime_parent = "$work/user"
state_dir = "$work/state"
[session]
open_timeout = "5s"
[session.shutdown]
mode = "scope"
leader_timeout = "100ms"
scope_timeout = "1s"
[user_service_manager]
launcher = "$work/launcher"
entrypoint = "$work/unused"
ready_timeout = "5s"
[user_service_manager.shutdown]
mode = "leader"
leader_timeout = "1s"
scope_timeout = "1s"
EOF

bus_pid=$(dbus-daemon --config-file="$work/bus.conf" --fork --print-pid)
address="unix:path=$work/bus"
scoped_wrapper= sessiond_wrapper= aclad_wrapper= aclad_pid= hold_wrapper= hold_pid=
cleanup() {
    status=$?
    trap - EXIT
    set +e
    [ -n "$hold_pid" ] && sudo kill -KILL "$hold_pid" 2>/dev/null
    [ -n "$aclad_pid" ] && sudo kill "$aclad_pid" 2>/dev/null
    [ -n "$sessiond_wrapper" ] && sudo kill "$sessiond_wrapper" 2>/dev/null
    [ -n "$scoped_wrapper" ] && sudo kill "$scoped_wrapper" 2>/dev/null
    wait 2>/dev/null
    kill "$bus_pid" 2>/dev/null
    sudo find "/sys/fs/cgroup/$cgroup" -depth -type d -exec rmdir {} \; 2>/dev/null
    if [ "$status" -ne 0 ]; then
        for log in "$work"/*.log; do [ -f "$log" ] && { echo "--- $log" >&2; sudo tail -100 "$log" >&2; }; done
    fi
    sudo rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT
wait_name() {
    for _ in $(seq 1 100); do busctl --address="$address" list 2>/dev/null | grep -q "$1" && return 0; sleep .05; done
    echo "timed out waiting for $1" >&2; return 1
}
start_aclad() {
    sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$aclad_repo/target/debug/examples/fake-aclad" "$work/grants" >>"$work/aclad.log" 2>&1 & aclad_wrapper=$!
    wait_name org.decoupling.aclad1
    aclad_pid=$(pgrep -P "$aclad_wrapper" -f fake-aclad)
}

sudo mkdir "/sys/fs/cgroup/$cgroup"
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$scoped_repo/target/debug/scoped" --bus system --scope-root "$cgroup" >"$work/scoped.log" 2>&1 & scoped_wrapper=$!
wait_name org.decoupling.scoped1
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$sessiond_repo/target/debug/sessiond" --bus system --config "$work/sessiond.toml" >"$work/sessiond.log" 2>&1 & sessiond_wrapper=$!
wait_name org.decoupling.sessiond1
start_aclad
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$sessiond_repo/target/debug/examples/hold-session" 0 "$work/sid" >"$work/hold.log" 2>&1 & hold_wrapper=$!
for _ in $(seq 1 100); do sudo test -f "$work/sid" && break; sleep .05; done
sid=$(sudo head -n1 "$work/sid")
hold_pid=$(pgrep -P "$hold_wrapper" -f hold-session)
stale=1123456789abcdef0123456789abcdef
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" busctl --address="$address" call org.decoupling.aclad1 /org/decoupling/aclad1 org.decoupling.aclad1.Manager Grant sus "$sid" 0 seat0
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" busctl --address="$address" call org.decoupling.aclad1 /org/decoupling/aclad1 org.decoupling.aclad1.Manager Grant sus "$stale" 0 seat0

# Restart reconciliation keeps the live session grant and removes the stale one.
sudo kill "$aclad_pid"
wait "$aclad_wrapper" || true
aclad_pid= aclad_wrapper=
start_aclad
sudo test -f "$work/grants/$sid"
sudo test ! -e "$work/grants/$stale"

# An unclean PAM host exit causes sessiond SessionRemoved and equal-source revoke.
sudo kill -KILL "$hold_pid"
wait "$hold_wrapper" || true
hold_pid= hold_wrapper=
for _ in $(seq 1 200); do sudo test ! -e "$work/grants/$sid" && break; sleep .05; done
sudo test ! -e "$work/grants/$sid"
echo "sessiond-to-aclad restart and SessionRemoved end-to-end test passed"
