# bhyve-in-jail: defence-in-depth recipe

This document describes how to run `bhyve(8)` micro-VMs **inside a
FreeBSD jail** so that an escape from the hypervisor user-space lands
the attacker in a near-empty vnet jail instead of in the host. This is
the FreeBSD-flavoured analogue of Firecracker's [jailer][fc-jailer]
pattern.

[fc-jailer]: https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md

`crate` itself does **not** manage bhyve VMs today (see [TODO2](../TODO2)
items A and B for the planned backend and the planned `crate vm-wrap`
helper). Until those land, the recipe below is fully manual but works
on stock FreeBSD 13+.

---

## Threat model

We assume the attacker has already executed code inside the guest OS
running under bhyve. The defence-in-depth question is: **what does
the attacker reach if they find a bug in the bhyve user-space process
and break out of the VM?**

| Scenario                          | Without jail wrapper | With jail wrapper          |
|-----------------------------------|----------------------|----------------------------|
| bhyve user-space CVE              | Host root            | Empty vnet jail, no root   |
| `vmm.ko` kernel CVE               | Host kernel          | Host kernel (no defence)   |
| Disk image confused-deputy        | Host filesystem      | One ZFS dataset, isolated  |
| Network: ARP/DHCP shenanigans     | Host bridge          | Jail's vnet, isolated      |
| Side-channel (Spectre/L1TF)       | Host memory          | Host memory (no defence)   |

The wrapper is a **second wall**, not a kernel boundary. It only helps
against bugs that are confined to the bhyve user-space binary or its
ancillary devices. Kernel-level VMM bugs cross the boundary just as
easily either way.

---

## Recipe

### 1. Prerequisites

```sh
# Host kernel modules
kldload vmm
kldload nmdm
kldload if_bridge
kldload if_tap

# vnet support is built into GENERIC since 12.0; verify:
sysctl kern.features.vimage
# kern.features.vimage: 1
```

### 2. Devfs ruleset for the jail

The jail needs to see `/dev/vmm/<vmname>`, `/dev/vmmctl`, the
console pair (`/dev/nmdm*A`/`B`), and exactly one tap device. Anything
else stays hidden.

Append to `/etc/devfs.rules`:

```
[devfsrules_bhyve_jail=20]
add include $devfsrules_hide_all
add include $devfsrules_unhide_basic
add include $devfsrules_unhide_login
add path 'vmm/myvm' unhide
add path vmmctl unhide
add path 'nmdm0*' unhide
add path tap42 unhide
```

Notes:
* `'vmm/myvm'` is the path bhyve creates when you launch a VM named
  `myvm`. The jail will only see *its* VM, not other VMs on the host.
* `tap42` is whatever index you pre-allocated for this VM. The host
  attaches it to the bridge before the jail starts; the jail just uses
  it.
* Replace the literal names with whatever your VM uses. **Do not** use
  glob patterns like `tap*` — that defeats the isolation.

Reload devfs:

```sh
service devfs restart
```

### 3. jail.conf fragment

```
myvm-cage {
    # vnet so the tap can live inside the jail's network stack
    vnet;
    vnet.interface = "tap42";

    # Required: lets the jail call vmm syscalls
    allow.vmm;

    # Don't let it raise its own limits or load modules
    allow.raw_sockets = 0;
    allow.sysvipc = 0;

    # Only the devfs nodes from the ruleset above
    devfs_ruleset = 20;

    path = "/usr/jails/myvm-cage";
    host.hostname = "myvm-cage";

    # Optional but recommended: capsicum for the bhyve binary
    # itself is enabled per-invocation via `bhyve -S`.

    exec.start = "/bin/sh /etc/rc";
    exec.stop  = "/bin/sh /etc/rc.shutdown";
}
```

The path can be near-empty — the jail does not run a userland of its
own. You only need `/bin/sh`, `/sbin/ifconfig`, and the bhyve binary
present (or bind-mount them in via nullfs).

### 4. ZFS dataset for the disk

Give the jail exclusive ownership of the VM's disk dataset:

```sh
# Create dataset and pre-write the disk image
zfs create -o mountpoint=none zroot/vms/myvm
truncate -s 8G /dev/zvol/zroot/vms/myvm/disk0  # or use a flat file

# Hand it to the jail
jail -c name=myvm-cage         # start the cage
zfs jail myvm-cage zroot/vms/myvm
```

Now `zfs list` from inside `myvm-cage` shows only that one dataset.
A bhyve escape sees one disk image, not your whole pool.

### 5. Bridge + tap on the host

```sh
# One-time
ifconfig bridge0 create
ifconfig bridge0 addm em0 up

# Per-VM
ifconfig tap42 create
ifconfig bridge0 addm tap42
ifconfig tap42 up
```

The tap is created **on the host** and moved into the jail's vnet
when the jail starts (because of `vnet.interface = "tap42"`).

### 6. Launch bhyve from inside the cage

```sh
jexec myvm-cage \
    bhyve -A -H -P -S \
          -c 2 -m 1G \
          -s 0:0,hostbridge \
          -s 1:0,virtio-net,tap42 \
          -s 2:0,virtio-blk,/dev/zvol/zroot/vms/myvm/disk0 \
          -s 31:0,lpc \
          -l com1,/dev/nmdm0A \
          myvm
```

* `-S` enables Capsicum sandboxing inside bhyve itself — a third wall.
* The console attaches to the host on `/dev/nmdm0B`; cu(1) into it
  from the host (not from inside the cage).

### 7. Teardown

```sh
jexec myvm-cage bhyvectl --destroy --vm=myvm
jail -r myvm-cage
ifconfig tap42 destroy
```

---

## Why this works

* `allow.vmm` is the only jail param that grants vmm(4) access. It
  was added specifically for this use case.
* The devfs ruleset is enforced by the kernel — even root inside the
  jail cannot see hidden device nodes.
* `vnet` gives the jail its own network stack; the tap inside the
  jail cannot see host interfaces or sniff the host bridge.
* `zfs jail` makes `zfs(8)` inside the jail operate on the delegated
  dataset only.

## Why this doesn't work for everything

* `vmm.ko` is the same kernel module on host and inside the jail.
  A bug in vmm itself is a kernel bug and bypasses the jail.
* CPU side-channels (Spectre, L1TF, MDS) are not jail-scoped.
* Live migration between hosts requires either bhyve-migrate (work in
  progress upstream) or a checkpoint/restore loop that runs on the
  host — which by definition lives outside the cage.

## Operational gotchas

* **vnet jails on FreeBSD < 14 leak listening sockets** if you stop
  the jail without first cleanly shutting down the VM. Always
  `bhyvectl --destroy` before `jail -r`.
* **Console (nmdm)** is a host device. Reading from it inside the
  cage is fine, but the host side `nmdm0B` exists in the host's
  devfs — keep it readable only by your operator user, not by other
  jails.
* **Bridge MAC table flooding** isn't bounded by jails. Use ipfw on
  the host's bridge interface to rate-limit ARP/MAC churn from
  malicious guests.
* **Capsicum (`bhyve -S`)** is the strongest layer — turn it on. The
  jail wrapper is the *fallback* if `-S` is somehow bypassed, not the
  primary defence.

## Future: `crate vm-wrap`

[TODO2 item B](../TODO2) tracks a future `crate vm-wrap <vmname>
--jail <name>` command that automates steps 2 + 3 + 4 above:
generates the devfs ruleset, writes the jail.conf fragment, runs
`zfs jail`, and prints the exact `jexec … bhyve` invocation to use.
Until that ships, copy the templates here.
