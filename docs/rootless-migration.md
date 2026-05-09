# Rootless migration guide

**Audience:** operators running `crate(1)` setuid-root today,
considering the move to the rootless model that lands in
**1.0.0**.

**Current status (0.9.12):** the rootless model is opt-in. The
default install is unchanged — `crate(1)` is still installed
with `mode 04755` (setuid root), and `crated.conf` ships with
`rootless_per_user: false`. This document tells you what
changes when you flip the toggle, what infrastructure the
daemon takes over, and how to migrate existing single-tenant
deployments without downtime.

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

### 0.9.12 — config schema (this release)

`crated.conf` gains:

```yaml
rootless_per_user: false             # master toggle, default off

zfs_master_prefix: "zroot/jails"     # per-user datasets land
                                     # under <prefix>/<uid>/
network_master_cidr_v4: "10.66.0.0/16"
network_sub_prefix_len_v4: 24
network_master_cidr_v6: ""           # empty disables v6 per-user
network_sub_prefix_len_v6: 64
```

When `rootless_per_user: false` (the default), every helper
that consults the config falls back to legacy single-tenant
behaviour. **Existing deployments are byte-identical to 0.8.x**
until the operator explicitly opts in.

### 0.9.13 (planned) — wiring flip

`lib/network_lease.cpp` switches to per-user lease files when
the toggle is on. RCTL handlers apply both per-jail and
loginclass umbrella rules. Audit log gets a per-user copy.

### 0.9.14 (planned) — default flip

`crated.conf.sample` ships with `rootless_per_user: true` by
default. Operators upgrading see a one-line `pkg upgrade`
warning pointing at this doc.

### 1.0.0 (planned) — setuid removed

`Makefile install` target switches from `-m 04755` to
`-m 0755`. `crate(1)` can no longer self-elevate; it must
talk to `crated`. Legacy operators who want the old model
patch the Makefile or pin to 0.9.x.

---

## Migration steps for a single-tenant deployment

Single-tenant operators don't need rootless mode but may want
to opt in to dry-run the new flow before 1.0.0 lands.

```sh
# 1. Update crated.conf — opt-in toggle plus defaults
cat >> /usr/local/etc/crated.conf <<'EOF'

# 0.9.12 — rootless namespacing (off by default)
rootless_per_user: false
EOF

# 2. Restart crated
service crated restart

# 3. Verify legacy behaviour preserved
crate run myjail            # works as before
ls /var/run/crate/          # contains crated.sock + legacy files,
                            # no per-uid subdirs

# 4. Opt in (dry-run)
sed -i '' 's/rootless_per_user: false/rootless_per_user: true/' \
       /usr/local/etc/crated.conf
service crated restart

# 5. Stop and restart your jails so they re-create with the
#    per-user layout. (No automatic in-place migration in 0.9.12;
#    that lands in 0.9.13 with the wiring flip.)
crate stop myjail
crate run myjail
ls /var/run/crate/$(id -u)/leases/
```

Rolling back is `rootless_per_user: false` + `service crated
restart` + jail recycle.

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
