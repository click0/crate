# On-hardware validation — 1.1.10..1.1.15

The features shipped via PRs #210..#213 each carry an unchecked test-plan
checkbox marked "on real FreeBSD hardware." This document is the single
runbook that closes those checkboxes. It pairs with
`scripts/on-hardware-validation.sh` — that script automates the static and
near-static checks; this doc covers the genuinely-manual end-to-end ones
(GUI viewing, foreign-tenant `403`s through the privops socket).

Audience: operator with root on a FreeBSD 14.2+ host, a ZFS pool, and a
`crate(1)` / `crated(8)` from `main` ≥ 1.1.16.

---

## 0. Setup

```sh
# 0.1 build + install
gmake && gmake install   # populates /usr/local/{bin,sbin}, crated.conf.sample
sysrc crated_enable=YES
service crated start

# 0.2 verify version
crate --version           # expect 1.1.16+
crated --version 2>&1     # same

# 0.3 (optional, enables the 1.1.15 gate). Since 1.1.39 a rootless
# `crate run` puts jail directories under /var/run/crate/<uid>/ (crated
# creates and chowns that root on the first privops connection), so the
# create_jail path gate must use the same prefix:
cat >> /usr/local/etc/crated.conf <<'EOF'
rootless:
  per_user: true
  zfs_master_prefix: zroot/jails
  path_master_prefix: /var/run/crate     # 1.1.15 gate; per-user slice = /var/run/crate/<uid>
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
crate create -s /var/run/crate/1000/jail-web-1a2b.yml -o /tmp/web.crate
crate run -f /tmp/web.crate &
sleep 2

# as root: registry must contain the entry
grep -E "$\(jls -j sway-headless jid\)\b" /var/db/crate/jid_owners.tsv
# expected: <jid>\t1000\tweb\t/var/run/crate/1000/jail-web-1a2b
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
# as uid 1000; the jail's path is /var/run/crate/1000/jail-web-1a2b
crate run web -- mount -t nullfs /some/local/cache /var/cache
```

Pass: succeeds.

### 3.2 Foreign mount target — Deny

```sh
# uid 1001 tries to mount into alice's jail tree
sudo -u "#1001" \
  curl --unix-socket /var/run/crate/privops.sock \
       -X POST http://localhost/api/v1/privops/mount_nullfs \
       -d '{"source":"/etc","target":"/var/run/crate/1000/jail-web-1a2b/host_etc"}'
```

Pass: `HTTP/1.1 403`, body contains
`path lies inside a jail owned by a different operator`.

### 3.3 devfs `mount_path` shape

Operators rarely call this directly — `crate run` does it automatically.
The check is that, when called via the privops socket with
`mount_path=/var/run/crate/1000/jail-web-1a2b/dev`, the gate resolves to alice's
jail (longest-prefix from PR #212). Verify with `apply_devfs_ruleset`:

```sh
# as uid 1001 (foreign)
sudo -u "#1001" \
  curl --unix-socket /var/run/crate/privops.sock \
       -X POST http://localhost/api/v1/privops/apply_devfs_ruleset \
       -d '{"mount_path":"/var/run/crate/1000/jail-web-1a2b/dev","ruleset":4}'
```

Pass: `HTTP/1.1 403` with the same `DenyForeignPath` reason.

---

## 4. PR #213 (1.1.15) — `create_jail` path-prefix

### 4.1 Inside-prefix create — Allow

```sh
# as uid 1000 — the jail directory is chosen by crate run:
# /var/run/crate/1000/jail-alice-app-<hex>, inside the caller's slice
crate create -s /tmp/alice.yml -o /tmp/alice-app.crate
crate run -f /tmp/alice-app.crate
# 1.1.40: the in-jail command runs through the exec_in_jail verb
# (crated pdfork + jail_attach; crate run waits on the returned process
# descriptor). First end-to-end rootless run — check all of:
#   - `jls` shows the jail; the command's stdout reaches this terminal
#   - `crate console alice-app` (as uid 1000) gets a login prompt
#   - Ctrl-C in crate run stops the command and destroys the jail
#   - as uid 1001: `crate console alice-app` -> 403 (jid not owned)
#   - /var/run/crate/1000/audit.log has an exec_in_jail line per exec
```

Pass: jail starts, `jls` shows it.

### 4.2 Out-of-prefix create — Deny

```sh
sudo -u "#1000" \
  curl --unix-socket /var/run/crate/privops.sock \
       -X POST http://localhost/api/v1/privops/create_jail \
       -d '{"name":"escape","path":"/var/run/crate/1001/escape","hostname":"escape","vnet":false,"parameters":""}'
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
3. Try to create a jail at `/var/run/crate/1001/...` or anywhere
   outside `/var/run/crate/1000/...`.
4. Confirm the `403` and that no jail is created (verify with
   `jls` from root).

Pass criterion: every attempt outside the operator's prefix returns
`403 DenyForeignCreatePath`, no jail is created, and `jls` is
unchanged.

---

## 4a. 1.1.58 — thin jail (`base/mode: host-ro`)

Pure logic is unit-tested; the mounts, the base.txz subset extraction
and the create-time chroot are not. One pass as root, one rootless.

```sh
# root
crate create -s examples/fetch-thin.yml -o fetch-thin.crate
ls -l fetch-thin.crate                      # a few MB, not ~100+
tar -tJf fetch-thin.crate | grep -c '^./usr/bin/'   # expect 0 (mount point only)
tar -xJOf fetch-thin.crate +CRATE.THIN      # mode/osrelease/hostdir lines
crate run -f fetch-thin.crate -- -o /dev/null https://www.freebsd.org/
# while it runs, from another shell:
mount | grep "jail-fetch-thin"              # nullfs read-only entries are hidden (MNT_IGNORE); use
mount -v | grep -c "jail-fetch-thin.*read-only"   # expect the number of hostdir lines minus skipped
```

Pass criteria: `crate run` exits 0 and fetched the page; `mount -v`
shows every `hostdir` of the manifest mounted read-only under the jail
directory (minus `/usr/lib32`, `/rescue`, `/usr/include` when the host
lacks them); after exit `mount` shows none of them and the jail directory
is gone; `jls` is unchanged.

Then the same with a `pkg/install: [curl]` added to the spec (pkg
bootstraps into the container's own `/usr/local` through the mounted
`/usr/sbin/pkg`), and once as uid 1000 against the privops socket
(`crated` logs `mount_nullfs ... read_only=true` for each directory,
`unmount_nullfs` at teardown).

Negative checks: a spec with `base/host-dirs: [/usr]` or `[/etc]` is
refused by `crate validate` / `crate create` at parse time; a thin crate
whose `+CRATE.THIN` was deleted is refused by `crate run` with the
"re-create it" message.

---

## 4b. 1.1.59 — profiles (`crate run <name>`) and `--template` in the archive

The name rules, search order and `.local` policy are unit-tested; the
build-on-first-use, the mtime refresh and the YAML merge inside a real
`crate create` are not. The build runs `crate create`, which is not
rootless: do the first pass as root, then the rootless variant below.

```sh
# as root, examples installed (pkg or `make install-examples`)
crate run fetch -- -o /dev/null https://www.freebsd.org/
#   expect: "profile 'fetch': building ~/.local/share/crate/profiles/fetch.crate from
#            /usr/local/share/examples/crate/fetch.yml", a normal create, the page fetched
ls -l ~/.local/share/crate/profiles/            # fetch.crate + fetch.yml (generated header)
crate run fetch -- -o /dev/null https://www.freebsd.org/   # second run: no build, starts at once
grep fetch /var/run/crate/spec-registry.txt     # points at /root/.local/share/crate/profiles/fetch.crate

# rootless: the first run must refuse with the exact recipe, which root then follows
sudo -u "#1000" crate run fetch
#   expect: "profile 'fetch': .../fetch.crate has not been built yet and building needs root ...
#            as root: crate create -s /home/<user>/.local/share/crate/profiles/fetch.yml -o .../fetch.crate && chown 1000 ..."
#   and /home/<user>/.local/share/crate/profiles/fetch.yml exists (the merged spec)
crate create -s /home/<user>/.local/share/crate/profiles/fetch.yml -o /home/<user>/.local/share/crate/profiles/fetch.crate
chown 1000 /home/<user>/.local/share/crate/profiles/fetch.crate
sudo -u "#1000" crate run fetch -- -o /dev/null https://www.freebsd.org/   # runs through privops, no build
grep fetch /var/run/crate/1000/spec-registry.txt

# .local override
mkdir -p ~/.config/crate/profiles
printf 'pkg:\n  install: [curl]\noptions:\n  - ssl-certs\n' > ~/.config/crate/profiles/fetch.local.yml
crate run fetch -- -o /dev/null https://www.freebsd.org/   # rebuilds (the .local is newer); curl is in the jail
tar -xJOf ~/.local/share/crate/profiles/fetch.crate +CRATE.SPEC | grep -c curl   # expect 1: the merge is IN the archive

# refused .local
printf 'dirs:\n  share:\n    - [/etc, /etc]\n' > ~/.config/crate/profiles/fetch.local.yml
crate run fetch        # expect: "fetch.local.yml: dirs/share: a .local override may only share directories under your home"
printf 'dbus:\n  mode: filter\n' > ~/.config/crate/profiles/fetch.local.yml
crate run fetch        # expect: "... may not set 'dbus' ..."
rm ~/.config/crate/profiles/fetch.local.yml

# bad names and conflicts
crate run ../fetch     # refused at argument validation
crate run fetch -f x.crate   # refused: one or the other
crate run nosuchprofile      # "profile 'nosuchprofile' not found; searched ..." listing the three paths
```

`--template` fix: `crate create --template privacy -s examples/firefox.yml -o f.crate`, then
`tar -xJOf f.crate +CRATE.SPEC` must show `encrypted`, `cow`, `dns_filter`,
`clipboard` AND the `tor` option together with firefox's `net x11 gl video`
(before 1.1.59 the archive held firefox.yml alone).

Pass criteria: first run builds, second run does not; the registry entry
points at the built archive; a `.local` change triggers exactly one
rebuild and its content is visible in `+CRATE.SPEC`; every refused case
above prints the quoted reason and creates nothing.

---

## 4c. 1.1.60 — `crate profile-from-trace`

The parser was written against the truss(1) line shapes of FreeBSD 14
(`open`/`openat`, `execve` with argv, `socket`, `connect`, `bind`,
`listen`, `sendto`, `{ AF_INET a.b.c.d:port }` addresses) without a
recorded trace to hand. The first thing to check is that a real trace
parses at all.

```sh
# a base-system program: no pkg, a net option, certificates
crate profile-from-trace --keep-trace /tmp/fetch.truss -o /tmp/fetch.yml -- fetch -o /dev/null https://www.freebsd.org/
cat /tmp/fetch.yml
#   expect: run/command "fetch -o /dev/null https://www.freebsd.org/", options net outbound [wan, dns]
#   (or the plain `net` if the resolver is on the LAN and the host is also contacted), ssl-certs,
#   "# outbound destinations seen:" with the resolver and the web server; no pkg: block
grep -c . /tmp/fetch.truss                     # a few hundred lines
crate validate -s /tmp/fetch.yml               # the draft is a valid spec
crate profile-from-trace --trace-file /tmp/fetch.truss | diff - /tmp/fetch.yml
#   expect: the only difference is the "## from one run of:" header (the trace file carries no command)

# a desktop program: packages, state dirs, X11, GPU, D-Bus
crate profile-from-trace -o /tmp/ff.yml -- firefox https://www.freebsd.org/      # close the window when it has loaded
cat /tmp/ff.yml
#   expect: pkg/install firefox (+ xdg-utils if a handler ran), "$HOME/.mozilla" in the state block,
#   "$HOME/Downloads" only if something was saved, x11, gl (with /dev/dri), dbus session: true,
#   net outbound [wan, dns], a sound note if audio was initialised, no /usr/local/* shares
crate create -s /tmp/ff.yml -o /tmp/ff.crate && crate run -f /tmp/ff.crate      # the draft runs as-is

# negative
crate profile-from-trace                        # "give the command to trace after '--', or --trace-file"
crate profile-from-trace --trace-file /etc/rc.conf   # "no syscalls recognised in N lines"
crate profile-from-trace --trace-file /tmp/fetch.truss -- fetch   # "mutually exclusive"
```

Pass criteria: `summary.parsed` is non-zero on both traces (the first
error message above would say otherwise); the generated specs validate
and the firefox one starts; nothing under `/usr/local`, `/etc`, `/var`
or `/tmp` appears in a share; `--trace-file` reproduces the `--` run. If
a line shape from a real trace is not recognised, paste the line into
`tests/unit/trace_pure_test.cpp` as the regression.

---

## 4d. 1.1.61 — `crate audit`

The probe script and its parsers were written against the FreeBSD 14
output formats of `mount -p`, `ifconfig -a`, `netstat -rn`, `sysctl -e`,
`sockstat -l`, `ps -axo user=,pid=,ucomm=`, `nc -z` and `drill -Q`
without a jail to run them in. First check: every section comes back
and nothing lands in the `probe` category.

```sh
# a desktop jail with X11, D-Bus and the home shared
crate run -f firefox.crate &          # or: crate run firefox
crate audit firefox
#   expect: no "probe:" category; jail: jailed PASS, vnet "own network stack", hostid PASS or WARN
#   (WARN = kern.hostid inside equals the host's — tell us which); mounts: one line per nullfs
#   share with "from host <path>", the home share WARN if the whole $HOME is rw; devfs: gpu
#   (dri) when gl is on, no raw/disks/input; sockets: /tmp/.X11-unix/X0 WARN "host X11 display
#   socket (nullfs from host /tmp/.X11-unix)", the D-Bus socket WARN, syslog sockets collapsed
#   into "jail-local"; interfaces: lo0 + epair with the address, default-route via the host side;
#   connectivity: gateway "reachable (tcp/22 refused)" or "tcp/22 open", dns "www.freebsd.org -> a.b.c.d"
echo "exit $?"                        # 1 when any WARN, 0 when none, 2 only if the probe did not run
crate audit firefox -j | python3 -m json.tool | head    # the doctor JSON shape: checks[] + summary

# a network-less jail (templates/minimal.yml): the probes must be skipped, not failed
crate audit minimal
#   expect: interfaces default-route "none — no outbound network", connectivity gateway
#   "no default route — outbound probes skipped", dns WARN "lookup ... failed ... no nameserver configured"
crate audit minimal --offline         # connectivity: probes "skipped (--offline)", no dns line

# rootless (operator in the privops group, crated running): same output through exec_in_jail
crate audit firefox --dns example.org
# negative
crate audit nosuchjail                # "container 'nosuchjail' not found or not running"
crate audit firefox --dns "a;id"      # "--dns: 'a;id' is not a valid host name"
```

Pass criteria: no `probe:` category on any jail (a section the script
did not print means a tool is missing from base or its output shape
changed — paste the raw output of that tool into
`tests/unit/jail_audit_pure_test.cpp` as the regression); every nullfs
share of the spec appears under `mounts` with the right rw/ro; the X11
and D-Bus sockets are recognised as host sockets; the gateway probe
says reachable on a `host`-enabled spec and "not reachable" on one
without; `--offline` produces no traffic (watch with `tcpdump -ni
epairNa` on the host).

---

## 4e. 1.1.62 — device classes and the private devfs ruleset

Until 1.1.61 the jail's devfs had no ruleset at all (the host's whole
`/dev` was visible). 1.1.62 builds a private ruleset per jail. The
`devfs rule -s N add …` / `devfs -m M ruleset N` / `rule applyset`
sequence was written from devfs(8) without a host to run it on, so the
first check is that it applies at all and hides what it should.

```sh
# a plain jail: basic nodes only
crate run -f fetch.crate -- -o /dev/null https://www.freebsd.org/ &
crate audit fetch
#   expect: devfs entries ~ 15-20 (null, zero, random, urandom, crypto, tty, ptmx, pts, fd, stdin,
#   stdout, stderr, fuse, zfs, bpf*), no gpu/sound/input/disks/raw lines, no yellow "devices: devfs
#   rules failed" on the crate run console; jail: devfs-ruleset "ruleset 1NNNN"
ls /jail-root/dev                       # same from the host side of the mount
devfs rule -s 1NNNN show                # the rules, "hide" first, "path ... unhide" after

# a desktop jail: the classes it asks for
crate run firefox &                     # examples/firefox.yml: gl, video, devices/sound
crate audit firefox
#   expect: devfs gpu (dri, drm), video (video0 if a webcam exists), sound (dsp*, mixer*, sndstat);
#   no input, no disks, no raw; firefox plays audio and renders with the GPU
#   (about:support -> Compositing: WebRender, not software)

# rootless: the same through apply_devfs_rules
sudo -u alice crate run firefox         # then crate audit as alice: identical devfs lines

# the escape hatches
#   terminal/devfs_ruleset: 4 in a spec -> "ruleset 1NNNN" still, rules start with "include 4",
#   classes on top; devices: all -> the full host /dev again, crate validate warns

# negative
crate validate -s x.yml                 # devices: {keyboard: true} -> "unknown class 'keyboard'"
                                        # devices: [input] -> warning about keystrokes
```

Pass criteria: no "devices: devfs rules failed" warning on any run; a
jail without classes shows only the basic nodes in `crate audit`; the
classes show exactly their devices; sound and GPU work in the firefox
example; a second run with the same pid-derived number (restart until
`crate run` gets a reused pid, or run `devfs rule -s 1NNNN add path
mem unhide` by hand before a run) does not inherit the stale rule. If
`devfs rule -s N add hide` or the `include` form is refused by devfs(8),
paste the error here: the rulespec grammar in `lib/privops_pure.cpp`
and the emitter in `lib/devices_pure.cpp` are the places to fix.

---

## 5. Reporting back

```sh
sh scripts/on-hardware-validation.sh > /tmp/onhw-report.txt 2>&1
# also paste the outcomes of any §1.* / §2.* / §3.* / §4.* / §4a / §4b / §4c / §4d / §4e manual checks
```

Attach `/tmp/onhw-report.txt` plus the manual-section outcomes to the PR
checklist (or a new tracking comment). A clean run unblocks the
remaining unchecked checkboxes in #210..#213.

Anything `FAIL` is a regression worth a new issue/PR; anything `SKIP`
that the deployment intends to use (e.g. `seatd` for `drm` backend) is
the operator's TODO to provision, not a crate defect.
