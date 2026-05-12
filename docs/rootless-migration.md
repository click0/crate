# Rootless migration guide

**Audience:** operators running `crate(1)` setuid-root on ≤ 0.9.x
who are upgrading to the rootless model that ships in **1.0.0**.

**Current status (1.0.0):** the rootless model is the default
and `crate(1)` no longer ships with the setuid bit. The
`Makefile install` target installs the binary at mode 0755;
every privileged operation is delegated to `crated(8)` over
the libnv privops socket (or the HTTPS API for remote clients).
New installs (and old installs whose `crated.conf` doesn't set
`rootless_per_user` explicitly) compose paths, ZFS prefixes,
network sub-CIDRs, and RCTL umbrellas from the connecting
operator's uid. Operators wanting the legacy single-tenant
shape must opt out explicitly with `rootless_per_user: false`
— see the "Rolling back" section below.

---

## TL;DR

Rootless mode delegates **every privileged operation** —
jail-create, mount, RCTL apply, ZFS attach, interface config,
firewall rule injection — to `crated`, which runs as root.
The `crate(1)` binary has its setuid bit removed (1.0.0) and
talks to `crated` over the existing control-socket API, which
gained 14 new verbs in 0.9.0–0.9.7.

**For a single-tenant homelab,** rootless mode adds nothing.
The setuid model is well-hardened for that use case (env-
sanitization, absolute paths, no shell, audit logging) and
will stay supported via the legacy fallback.

**For multi-tenant deployments** — multiple operators sharing
one host — rootless mode is the recommended path. Each operator
gets:

- A per-user filesystem subtree under `/var/run/crate/<uid>/`
  for leases, exports, imports, and audit log tail
- A per-user ZFS dataset prefix under
  `<zfs_master_prefix>/<uid>/`
- A per-user IPv4 sub-CIDR carved deterministically from the
  master `network_master_cidr_v4`
- A per-user IPv6 sub-CIDR (analogous)
- A per-user RCTL **umbrella loginclass** (`crate-<uid>`) that
  caps total resource usage across all of that operator's
  jails

Alice can't see bob's jails. Bob can't run a jail in alice's
ZFS prefix. The kernel enforces the boundaries.

---

## What changed since 0.8.x

### 0.9.0 — privops verb taxonomy

`lib/privops_pure.{h,cpp}` declares 14 privileged-operation
verbs (`create_jail`, `mount_nullfs`, `set_rctl`, etc.) with
per-verb request structs and validators. Defines the contract
the daemon must honour.

### 0.9.1 — JSON wire format

`POST /api/v1/privops/<verb>` with a JSON body. Wire format
locked down; daemon returns 501 for every verb.

### 0.9.2–0.9.7 — handlers

One verb-handler per release, simplest first:

| Release | Verbs |
|---------|-------|
| 0.9.2 | `set_rctl` |
| 0.9.3 | `clear_rctl` |
| 0.9.4 | `attach_zfs`, `detach_zfs` |
| 0.9.5 | `mount_nullfs`, `unmount_nullfs` |
| 0.9.6 | `configure_iface`, `teardown_iface` |
| 0.9.7 | pf+ipfw rules, `create_jail`, `destroy_jail` |

All 14 verbs handled. Operator can now drive a complete jail
lifecycle through `crated` without `crate(1)` ever needing
root.

### 0.9.8 — runtime path scheme

`lib/runtime_paths_pure.{h,cpp}` introduces per-user paths:

```
/var/run/crate/<uid>/              # per-user root (mode 0700)
/var/run/crate/<uid>/leases/       # IP leases
/var/run/crate/<uid>/exports/      # export staging
/var/run/crate/<uid>/imports/      # import staging
/var/run/crate/<uid>/audit.log     # audit tail
```

uid is the stable key (operators on NIS/LDAP have mutable
uid→name maps).

### 0.9.9 — ZFS dataset prefix

`composePerUserDataset(master, uid, jail)` →
`<master>/<uid>/<jail>`. Master prefix is operator-supplied
in `crated.conf`.

### 0.9.10 — network sub-CIDR

`composeIpv4(master, subLen, uid)` carves a per-user sub-CIDR
deterministically: `slot = uid mod 2^(subLen − masterLen)`.
Stable across crated restarts; collisions at slot capacity.

### 0.9.11 — RCTL accounting groups

Each operator gets a loginclass `crate-<uid>` whose RCTL
umbrella caps total usage across all of that operator's jails.

### 0.9.12 — config schema

`crated.conf` gains:

```yaml
rootless_per_user: true              # master toggle (default
                                     # since 0.9.30; was off
                                     # in 0.9.12–0.9.29)

zfs_master_prefix: "zroot/jails"     # per-user datasets land
                                     # under <prefix>/<uid>/
network_master_cidr_v4: "10.66.0.0/16"
network_sub_prefix_len_v4: 24
network_master_cidr_v6: ""           # empty disables v6 per-user
network_sub_prefix_len_v6: 64
```

Setting `rootless_per_user: false` makes every helper fall
back to legacy single-tenant behaviour, byte-identical to
0.8.x. Set this if you upgraded from 0.8.x and don't yet
want the per-user split.

### 0.9.13 — wiring flip

`lib/network_lease.cpp` switches to per-user lease files when
the toggle is on. RCTL handlers apply both per-jail and
loginclass umbrella rules. Audit log gets a per-user copy.

### 0.9.14 — libnv privops listener

`crated` opens an AF_UNIX socket and accepts nvlist-encoded
privops requests from local clients. `getpeereid(2)` extracts
the operator's uid for free, feeding the per-user audit hook.
HTTP `/api/v1/privops/<verb>` remains for remote/CI clients.

### 0.9.15–0.9.29 — call-site wiring + verb expansion

`crate(1)` call sites moved through privops one mini-PR at a
time: `set_rctl`/`clear_rctl`, `attach_zfs`, `destroy_jail`
on stop, `mount_nullfs`, `iface` atoms (`set_iface_up`,
`disable_iface_offload`, `bridge_add_member`, `bridge_del_member`,
`set_iface_inet_addr`, `create_epair`), `set_loginclass_rctl` /
`clear_loginclass_rctl`. The privops verb taxonomy grew from
14 to 21 verbs; the original 14 stayed wire-stable.

0.9.27 lazy-resolved network leases to per-user paths when
the privops socket is detected. 0.9.29 added an opt-in
`rctl_umbrella:` block that the daemon auto-applies to the
operator's `crate-<uid>` loginclass after `create_jail`.

### 0.9.30 — default flip

`bool rootlessPerUser = true;` in `daemon/config.h`. The
sample `crated.conf` shows the flag commented out at its new
default value; existing crated.conf files without the field
auto-flip on upgrade. Operators wanting the legacy single-
tenant path must add `rootless_per_user: false` explicitly —
see "Rolling back" below.

### 1.0.0 — setuid removed

`Makefile install` switches from `-m 04755` to `-m 0755`.
`crate(1)` can no longer self-elevate; it must talk to
`crated` over the libnv privops socket (local) or the HTTPS
API (remote). Legacy operators who want the old model patch
the Makefile back to `-m 04755` or pin to 0.9.30. The
rootless track is complete with this release.

---

## Migration steps for a single-tenant deployment

Single-tenant operators upgrading from ≤ 0.9.29 to ≥ 0.9.30
auto-flip into rootless mode unless their `crated.conf` sets
`rootless_per_user: false` explicitly. Choose one of the two
paths below.

### Path A — accept the flip

```sh
# 1. Upgrade the package (default flips to true).
pkg upgrade crate

# 2. Restart crated.
service crated restart

# 3. Stop and restart your jails so they re-create with the
#    per-user layout. (No automatic in-place migration; the
#    daemon does not rearrange ZFS datasets on upgrade.)
crate stop myjail
crate run myjail
ls /var/run/crate/$(id -u)/leases/
```

### Path B — keep the legacy single-tenant shape

```sh
# 1. Pin the toggle off before restarting crated.
cat >> /usr/local/etc/crated.conf <<'EOF'

# Pinned to legacy single-tenant shape (was the default
# pre-0.9.30; explicit setting required from 0.9.30 onward).
rootless_per_user: false
EOF

# 2. Restart crated.
service crated restart

# 3. Verify legacy behaviour preserved.
crate run myjail            # works as before
ls /var/run/crate/          # contains crated.sock + legacy files,
                            # no per-uid subdirs
```

### Rolling back

If you upgraded to 0.9.30+ and the per-user split misbehaves:

```sh
# 1. Stop active jails.
crate stop --all

# 2. Pin the toggle off.
sed -i '' 's/^# *rootless_per_user:.*/rootless_per_user: false/' \
       /usr/local/etc/crated.conf
grep -q '^rootless_per_user:' /usr/local/etc/crated.conf || \
       echo 'rootless_per_user: false' >> /usr/local/etc/crated.conf

# 3. Restart and recycle jails.
service crated restart
crate run myjail
```

No package downgrade needed — the toggle is preserved across
0.9.30+ releases. Downgrading to ≤ 0.9.29 is also supported
(the YAML key is the same and the legacy code path is the
0.9.29 default).

---

## Migration steps for a new multi-tenant deployment

Greenfield: enable rootless from day one.

### 1. Plan resource pools

| Resource | Master | Per-user shape |
|----------|--------|----------------|
| ZFS | `zroot/crate-tenants` | `zroot/crate-tenants/<uid>/<jail>` |
| IPv4 | `10.66.0.0/16` | `/24` per uid (256 slots) |
| IPv6 | `fd00:dead::/48` | `/64` per uid (16 slots) |
| RCTL | `crate-<uid>` loginclass | umbrella caps per uid |

### 2. Create UNIX accounts

```sh
pw groupadd crate-operators
for u in alice bob; do
  pw useradd $u -G crate-operators -m -L crate-$(id -u $u)
done
```

(login.conf entries for `crate-<uid>` classes get auto-created
by `crated` at first contact in 0.9.13.)

### 3. Configure crated

```yaml
# /usr/local/etc/crated.conf

rootless_per_user: true

zfs_master_prefix: "zroot/crate-tenants"
network_master_cidr_v4: "10.66.0.0/16"
network_sub_prefix_len_v4: 24
network_master_cidr_v6: "fd00:dead::/48"
network_sub_prefix_len_v6: 64

# 0.7.10 control sockets — give each operator a getpeereid-
# authenticated unix-socket entry, scoped to their pool:
control_sockets:
  - path: /var/run/crate/control/alice.sock
    group: alice
    mode: 0660
    pools: ["alice"]
    role: admin
  - path: /var/run/crate/control/bob.sock
    group: bob
    mode: 0660
    pools: ["bob"]
    role: admin
```

### 4. Smoke test isolation

```sh
# As alice
$ id -u
1000
$ crate run web                        # via alice.sock
$ zfs list zroot/crate-tenants/1000    # alice's subtree
NAME                              USED
zroot/crate-tenants/1000          234M
zroot/crate-tenants/1000/web      234M
$ ls /var/run/crate/1000/leases
web.lease

# As bob
$ id -u
1001
$ crate run web                        # SAME jail name, no clash
$ zfs list zroot/crate-tenants/1001
NAME                              USED
zroot/crate-tenants/1001          198M
zroot/crate-tenants/1001/web      198M
```

Both jails named `web`. Different uids, different ZFS subtrees,
different IP sub-CIDRs, different RCTL umbrellas. No cross-
tenant interference.

---

## Migration steps for an existing setuid deployment

Live migration from 0.8.x to rootless requires planning. The
short version:

1. **Audit current state.** List all jails, snapshots, leases.
   `crate inspect <jail>` for each. Save outputs.
2. **Snapshot ZFS.** `zfs snapshot -r zroot/jails@pre-rootless`.
3. **Stop jails.** `crate stop --all`.
4. **Reorganize ZFS.** Move each operator's jails under their
   per-uid prefix:
   ```sh
   zfs rename zroot/jails/web zroot/crate-tenants/1000/web
   ```
   Repeat for every jail. Use the operator who owns the spec.
5. **Update specs.** Each `*.crate.yml` continues to use the
   bare jail name; the per-uid prefix is derived at runtime
   from the connecting operator's uid.
6. **Restart crated** with rootless toggle on.
7. **Restart jails.** `crate run <jail>` from each operator's
   account.
8. **Smoke test.** Each operator should see only their own
   jails in `crate list`.
9. **Roll back plan.** If anything misbehaves: stop jails,
   `zfs rename` back, set `rootless_per_user: false`, restart
   crated.

The migration is the operator's call — `crated` does not
auto-rearrange ZFS datasets.

---

## What the daemon takes over

After 1.0.0 (setuid bit removed), `crate(1)` can no longer:

- Call `jail(8)` directly → uses `POST /api/v1/privops/create_jail`
- Call `mount(8)` directly → `mount_nullfs`
- Call `rctl(8)` directly → `set_rctl` / `clear_rctl`
- Call `zfs jail` → `attach_zfs`
- Call `ifconfig(8)` for vnet → `configure_iface`
- Call `pfctl(8)` / `ipfw(8)` → `add_pf_rule` / `add_ipfw_rule`

For each operation, `crate(1)` opens the local control socket
(filesystem-perm gated, getpeereid-authenticated), POSTs the
verb, gets a JSON response, surfaces success/failure to the
operator's terminal.

The operator never sees any of this — `crate run myjail`
behaves identically. What changed is the trust boundary:

- **Before:** `crate(1)` runs setuid root. A bug in libssl /
  yaml-cpp / tar landing on the user's invocation path means
  root.
- **After:** `crate(1)` runs as the user. Same bug means user
  UID, not root. `crated` runs as root but accepts only the
  validated verb set; nothing the user passes through reaches
  `system(3)` or a shell.

---

## Compliance checklist

For shops that need to satisfy "no setuid root binaries":

- [ ] Upgrade to ≥ 1.0.0
- [ ] Verify `ls -l /usr/local/bin/crate` shows no `s` bit
- [ ] Verify `/usr/local/sbin/crated` is the only privileged
      binary (`find / -perm -u=s` → only `crated` from this
      port)
- [ ] Unit-socket auth scoped via `listen.unix_owner` /
      `listen.unix_group` / `listen.unix_mode` (0.8.19)
- [ ] Bearer tokens (if used) carry `expires_at:` (0.7.1) and
      `scope:` (0.7.1)
- [ ] Audit log dual-writes to syslog via `cap_syslog` (0.8.24)

---

## Out of scope for 0.9.x

The following land in **1.x** or beyond:

- True `getpeereid(2)`-based unix-socket auth in `crated`
  itself (currently filesystem-perm gate only — see
  `daemon/control_socket.cpp` for partial impl). Needs the
  cpp-httplib accept loop fork or a hand-rolled listener.
- State-backed per-user CIDR allocator (today's modulo
  scheme caps at 2^slotBits operators).
- Auto-creation of `/etc/login.conf` entries for `crate-<uid>`
  classes. 0.9.13 will add this.
- crate-hub-side multi-tenant view (alice's jails only,
  filtered server-side).

---

## Questions / feedback

Open an issue at https://github.com/click0/crate/issues with
the `rootless` label.
