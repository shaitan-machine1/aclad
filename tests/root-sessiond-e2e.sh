#!/bin/bash
# Cross-repository no-sender SessionRemoved and restart reconciliation.
set -euo pipefail
aclad_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sessiond_repo=${SESSIOND_REPO:-"$aclad_repo/../sessiond"}
for command in cargo cc dbus-daemon busctl sudo; do command -v "$command" >/dev/null || exit 77; done
sudo -n true || exit 77
work=$(mktemp -d /tmp/sessiond-aclad-e2e.XXXXXX)
cgroup="sessiond-aclad-e2e-$$"
pam_service="sessiond-user-aclad-e2e-$$"
cat >"$work/manager.c" <<'EOF'
#include <signal.h>
#include <string.h>
#include <unistd.h>
static volatile sig_atomic_t stop; static void h(int s){(void)s;stop=1;}
int main(int c,char **v){if(c!=3||strcmp(v[1],"--ready-fd")||strcmp(v[2],"3"))return 64;char b=1;if(write(3,&b,1)!=1)return 1;close(3);signal(SIGTERM,h);while(!stop)pause();return 0;}
EOF
cc "$work/manager.c" -o "$work/manager"
SESSIOND_USER_SERVICE_MANAGER="$work/manager" cargo build --manifest-path "$sessiond_repo/Cargo.toml" -p sessiond --bin sessiond --example hold-session
cargo build --manifest-path "$sessiond_repo/Cargo.toml" -p sessiond-user-launcher
cargo build --manifest-path "$aclad_repo/Cargo.toml" --example fake-aclad
cat >"$work/bus.conf" <<EOF
<busconfig><type>system</type><listen>unix:path=$work/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_type="method_call"/><allow send_type="method_return"/><allow send_type="error"/><allow send_type="signal"/><allow receive_type="method_call"/><allow receive_type="method_return"/><allow receive_type="error"/><allow receive_type="signal"/></policy></busconfig>
EOF
cat >"$work/sessiond.toml" <<EOF
cgroup_root = "/sys/fs/cgroup/$cgroup"
runtime_parent = "$work/user"
state_dir = "$work/state"
[session]
open_timeout = "5s"
[session.shutdown]
mode = "scope"
leader_timeout = "100ms"
scope_timeout = "1s"
[user_service_manager]
launcher = "$sessiond_repo/target/debug/sessiond-user-launcher"
pam_service = "$pam_service"
ready_timeout = "5s"
[user_service_manager.shutdown]
mode = "leader"
leader_timeout = "1s"
scope_timeout = "1s"
EOF
sudo chown -R root:root "$work"; sudo chmod 1777 "$work"
printf 'session required pam_permit.so\n' | sudo tee "/etc/pam.d/$pam_service" >/dev/null
sudo mkdir "/sys/fs/cgroup/$cgroup"
bus_pid=$(sudo dbus-daemon --config-file="$work/bus.conf" --fork --print-pid); address="unix:path=$work/bus"
sessiond_pid= aclad_pid= hold_pid=
cleanup(){ status=$?;trap - EXIT;set +e;[ -n "$hold_pid" ]&&sudo kill -KILL "$hold_pid" 2>/dev/null;[ -n "$aclad_pid" ]&&sudo kill "$aclad_pid" 2>/dev/null;[ -n "$sessiond_pid" ]&&sudo kill "$sessiond_pid" 2>/dev/null;sudo kill "$bus_pid" 2>/dev/null;sudo rm -f "/etc/pam.d/$pam_service";sudo sh -c 'echo 1 > "$1/cgroup.kill"' sh "/sys/fs/cgroup/$cgroup" 2>/dev/null;sudo find "/sys/fs/cgroup/$cgroup" -depth -type d -exec rmdir {} \; 2>/dev/null;sudo rm -rf "$work";exit "$status";};trap cleanup EXIT
wait_name(){ for _ in $(seq 1 100);do busctl --address="$address" list 2>/dev/null|grep -q "$1"&&return;sleep .05;done;return 1;}
start_aclad(){ sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$aclad_repo/target/debug/examples/fake-aclad" "$work/grants" >>"$work/aclad.log" 2>&1 & aclad_pid=$!;wait_name org.decoupling.aclad1; }
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$sessiond_repo/target/debug/sessiond" --bus system --config "$work/sessiond.toml" >"$work/sessiond.log" 2>&1 & sessiond_pid=$!;wait_name org.decoupling.sessiond1
start_aclad
sudo -E env DBUS_SYSTEM_BUS_ADDRESS="$address" "$sessiond_repo/target/debug/examples/hold-session" 0 "$work/session" "$work/sessiond.toml" >"$work/hold.log" 2>&1 & hold_pid=$!
for _ in $(seq 1 100);do sudo test -f "$work/session"&&break;sleep .05;done
sid=$(sudo head -n1 "$work/session"); stale=1123456789abcdef0123456789abcdef
sudo busctl --address="$address" call org.decoupling.aclad1 /org/decoupling/aclad1 org.decoupling.aclad1.Manager Grant sus "$sid" 0 seat0
sudo busctl --address="$address" call org.decoupling.aclad1 /org/decoupling/aclad1 org.decoupling.aclad1.Manager Grant sus "$stale" 0 seat0
sudo kill "$aclad_pid";wait "$aclad_pid"||true;aclad_pid=;start_aclad
sudo test -f "$work/grants/$sid";sudo test ! -e "$work/grants/$stale"
# Initial stale targets are discovery-only; arm live leader observation first.
sleep 1
leader=$(sudo head -n1 "/sys/fs/cgroup/$cgroup/sessiond/user/0/session/$sid/cgroup.procs");sudo kill -KILL "$leader"
for _ in $(seq 1 200);do sudo test ! -e "$work/grants/$sid"&&break;sleep .05;done
sudo test ! -e "$work/grants/$sid";hold_pid=
echo "sessiond-to-aclad reconciliation and SessionRemoved test passed"
