#!/usr/bin/env bash
set -euo pipefail

# Ensure Open vSwitch runtime directories exist
mkdir -p /var/run/openvswitch /etc/openvswitch /var/log/openvswitch

# Initialize OVS config DB if absent
if [ ! -f /etc/openvswitch/conf.db ]; then
  ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

# Start ovsdb-server if not already running
if ! pgrep -x ovsdb-server >/dev/null 2>&1; then
  ovsdb-server /etc/openvswitch/conf.db \
    --remote=punix:/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile=/var/run/openvswitch/ovsdb-server.pid \
    --log-file=/var/log/openvswitch/ovsdb-server.log \
    --detach
fi

ovs-vsctl --no-wait init

# Detect whether Linux kernel openvswitch module is available; fall back cleanly to netdev userspace
OVS_DATAPATH_MODE="netdev"
if modprobe openvswitch >/dev/null 2>&1 || [ -d /sys/module/openvswitch ]; then
  OVS_DATAPATH_MODE="system"
fi
export OVS_DATAPATH_MODE

# Start ovs-vswitchd (works in netdev userspace mode even without openvswitch.ko)
if ! pgrep -x ovs-vswitchd >/dev/null 2>&1; then
  ovs-vswitchd unix:/var/run/openvswitch/db.sock \
    --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
    --log-file=/var/log/openvswitch/ovs-vswitchd.log \
    --detach
fi

# Clean any leftover Mininet artifacts
mn -c >/dev/null 2>&1 || true

exec "$@"
