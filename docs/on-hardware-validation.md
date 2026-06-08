# On-hardware validation — 1.1.10..1.1.15

The features shipped via PRs #210..#213 each carry an unchecked test-plan
checkbox marked "on real FreeBSD hardware." This document is the single
runbook that closes those checkboxes. It pairs with
`scripts/on-hardware-validation.sh` — that script automates the static and
near-static checks; this doc covers the genuinely-manual end-to-end ones
(GUI viewing, foreign-tenant `403`s through the privops socket).

Audience: operator with root on a FreeBSD 14.2+ host, a ZFS pool, and a
`crate(1)` / `crated(8)` from `main` ≥ 1.1.15.

---

## 0. Setup

```sh
# 0.1 build + install
gmake && gmake install   # populates /usr/local/{bin,sbin}, crated.conf.sample
sysrc crated_enable=YES
service crated start

# 0.2 verify version
crate --version           # expect 1.1.15+
crated --version 2>&1     # same

# 0.3 (optional, enables the 1.1.15 gate) — pick a pool root for tenants
install -d -m 0755 /jails-tenants
install -d -o 1000 /jails-tenants/1000   # per-uid scratch space

cat >> /usr/local/etc/crated.conf <<'EOF'
rootless:
  per_user: true
  zfs_master_prefix: zroot/jails
  path_master_prefix: /jails-tenants     # 1.1.15
EOF
service crated restart

# 0.4 run the driver
sh scripts/on-hardware-validation.sh > /tmp/onhw-report.txt 2>&1
cat /tmp/onhw-report.txt
```

A clean run prints `PASSED=N FAILED=0 SKIPPED=M`. `SKIP` is normal for
optional components (wayvnc, seatd, GPU). `FAIL` is a real defect — keep
the output and file a regression.

---

## 1. PR #210 — `gui.mode: compositor`

### 1.1 Headless backend + wayvnc (loopback default)

```yaml
# /tmp/sway-headless.yml
name: sway-headless
pkg:   { install: [sway, wayvnc] }
options: [net]
gui:
    mode: compositor
    backend: headless       # default; can omit
    compositor: sway
    vnc: true               # wayvnc on 5900, bound to 127.0.0.1
```

```sh
crate create -s /tmp/sway-headless.yml -o sway-headless.crate
crate run -f sway-headless.crate &
sleep 5

# 1.1 PASS criteria
# - `crate gui list` shows mode=compositor, vncPort=5900
# - inside the jail: jexec <jid> sockstat -l | grep 5900 -> wayvnc bound 127.0.0.1
# - from a remote host: vncviewer <host-ip>:5900 -> connection refused (loopback bind)
# - over an SSH tunnel: ssh -L 5900:127.0.0.1:5900 root@<host>; vncviewer 127.0.0.1:5900 -> sway desktop visible
```

Failure modes:
- wayvnc not started → check `jls -j <jid> path` + `jexec <jid> ps -ax | grep wayvnc`
- connection refused on tunnel → wayvnc may have died, check syslog
- VNC reachable directly (without SSH) → secure default broke, **file regression**

### 1.2 DRM backend (seatd)

> ⚠️ The `drm` backend exposes `/dev/dri/*` and `/dev/input/*` into the
> jail. The jail then has host-wide input visibility. Use only on a
> single-tenant host. See [`trust-model.md`](trust-model.md) §"GUI
> device exposure".

```sh
service seatd onestart
# spec: as 1.1 but with `backend: drm`, no `vnc:` (uses the physical display)
```

Pass: a sway session takes over the console; keyboard/mouse work.

### 1.3 `gui.vnc_bind` opt-in to a wider bind

```yaml
gui:
    ...
    vnc: true
    vnc_bind: 0.0.0.0       # explicit opt-in
```

Pass: `crate run` prints the warning
`gui.compositor: wayvnc bound to 0.0.0.0 with no authentication — ...`
and VNC is reachable from the network. (Use sparingly — built-in
`wayvnc` auth is the follow-up tracked in PR #210's body.)

---

## 2. PR #211 (1.1.13) — jid→owner registry

### 2.1 `create_jail` records, `destroy_jail` forgets

Run as a non-root operator (`uid 1000`) talking to the privops socket.

```sh
# as operator (uid 1000)
crate create -s /jails-tenants/1000/web.yml -o /tmp/web.crate
crate run -f /tmp/web.crate &
sleep 2

# as root: registry must contain the entry
grep -E "$\(jls -j sway-headless jid\)\b" /var/db/crate/jid_owners.tsv
# expected: <jid>\t1000\tweb\t/jails-tenants/1000/web
```

Pass: a line appears with `uid=1000` matching the running jail's name+path.

```sh
crate stop web    # as the same operator
grep web /var/db/crate/jid_owners.tsv || echo OK
```

Pass: the line is gone (`destroy_jail` forgot).

### 2.2 Foreign-uid `signal_jail` denied 403

```sh
# uid 1001 (different operator) tries to signal alice's jail
sudo -u "#1001" crate stop web
```

Pass: stderr contains
`forbidden: jid is owned by a different operator`, jail is still running.

### 2.3 Registry persistence across crated restart

```sh
service crated restart
crate ls --owner-uid 1000      # still lists web with the correct uid
```

Pass: ownership is recovered from `/var/db/crate/jid_owners.tsv` (driver
script's 211.4 also asserts the TSV stays well-formed).

---

## 3. PR #212 (1.1.14) — path-scoped privops authz

### 3.1 Own mount target — Allow

```sh
# as uid 1000; the jail's path is /jails-tenants/1000/web
crate run web -- mount -t nullfs /some/local/cache /var/cache
```

Pass: succeeds.

### 3.2 Foreign mount target — Deny

```sh
# uid 1001 tries to mount into alice's jail tree
sudo -u "#1001" \
  curl --unix-socket /var/run/crate/privops.sock \
       -X POST http://localhost/api/v1/privops/mount_nullfs \
       -d '{"source":"/etc","target":"/jails-tenants/1000/web/host_etc"}'
```

Pass: `HTTP/1.1 403`, body contains
`path lies inside a jail owned by a different operator`.

### 3.3 devfs `mount_path` shape

Operators rarely call this directly — `crate run` does it automatically.
The check is that, when called via the privops socket with
`mount_path=/jails-tenants/1000/web/dev`, the gate resolves to alice's
jail (longest-prefix from PR #212). Verify with `apply_devfs_ruleset`:

```sh
# as uid 1001 (foreign)
sudo -u "#1001" \
  curl --unix-socket /var/run/crate/privops.sock \
       -X POST http://localhost/api/v1/privops/apply_devfs_ruleset \
       -d '{"mount_path":"/jails-tenants/1000/web/dev","ruleset":4}'
```

Pass: `HTTP/1.1 403` with the same `DenyForeignPath` reason.

---

## 4. PR #213 (1.1.15) — `create_jail` path-prefix

### 4.1 Inside-prefix create — Allow

```sh
# as uid 1000
crate create -s /tmp/alice.yml -o /tmp/alice.crate \
  --override-jail-path /jails-tenants/1000/alice-app
crate run -f /tmp/alice.crate
```

Pass: jail starts, `jls` shows it.

### 4.2 Out-of-prefix create — Deny

```sh
sudo -u "#1000" \
  curl --unix-socket /var/run/crate/privops.sock \
       -X POST http://localhost/api/v1/privops/create_jail \
       -d '{"name":"escape","path":"/jails-tenants/1001/escape","hostname":"escape","vnet":false,"parameters":""}'
```

Pass: `HTTP/1.1 403`, body contains
`create_jail path is outside the caller's per-user path prefix`.

Try also a clearly-foreign path:

```sh
sudo -u "#1000" \
  curl --unix-socket /var/run/crate/privops.sock \
       -X POST http://localhost/api/v1/privops/create_jail \
       -d '{"name":"home","path":"/etc/passwd-jail","hostname":"x","vnet":false,"parameters":""}'
```

Same Pass criterion.

### 4.3 Unconfigured deployment — Allow (legacy preserved)

Remove `path_master_prefix` from `crated.conf`, restart, and repeat 4.2.
Expected: the same request now succeeds (kernel may still refuse the
jail at `/etc/passwd-jail` because the path doesn't exist, but the
privops gate did **not** fire a 403). This proves the upgrade path
keeps working for operators who don't opt into the new gate.

### 4.4 End-to-end: operator session cannot escape via create

This is the headline manual check the driver script flags as
`SKIP 213.4`:

1. SSH as uid 1000.
2. Run `crate(1)` against the privops socket (the rootless flow).
3. Try to create a jail at `/jails-tenants/1001/...` or anywhere
   outside `/jails-tenants/1000/...`.
4. Confirm the `403` and that no jail is created (verify with
   `jls` from root).

Pass criterion: every attempt outside the operator's prefix returns
`403 DenyForeignCreatePath`, no jail is created, and `jls` is
unchanged.

---

## 5. Reporting back

```sh
sh scripts/on-hardware-validation.sh > /tmp/onhw-report.txt 2>&1
# also paste the outcomes of any §1.* / §2.* / §3.* / §4.* manual checks
```

Attach `/tmp/onhw-report.txt` plus the manual-section outcomes to the PR
checklist (or a new tracking comment). A clean run unblocks the
remaining unchecked checkboxes in #210..#213.

Anything `FAIL` is a regression worth a new issue/PR; anything `SKIP`
that the deployment intends to use (e.g. `seatd` for `drm` backend) is
the operator's TODO to provision, not a crate defect.
