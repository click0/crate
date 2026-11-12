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

## 4f. 1.1.63 — `:ro` shares, `tmpfs:`, `etc/keep`

```sh
# a spec with all three
cat > /tmp/m.yml <<'EOF'
pkg: {install: [fetch]}
run: {command: /bin/sh}
dirs:
    share:
        - $HOME/Downloads
        - $HOME/Documents:ro
tmpfs:
    /tmp: 64m
    $HOME/.cache:
etc:
    keep: [localtime, hosts]
options: [net]
EOF
crate validate -s /tmp/m.yml                   # no errors; no warnings except the etc/keep one on a full jail
crate create -s /tmp/m.yml -o /tmp/m.crate
tar -tJf /tmp/m.crate | grep -E '^\./etc/(localtime|hosts)$'   # both present in the archive
crate run -f /tmp/m.crate -- -c 'mount -p; touch $HOME/Documents/x; echo rc=$?; df -h /tmp $HOME/.cache; ls -ld /tmp $HOME/.cache'
#   expect: the Documents nullfs line says ro, touch fails "Read-only file system"; two tmpfs lines
#   (/tmp 64M, $HOME/.cache unlimited); /tmp is drwxrwxrwt root, $HOME/.cache drwx------ <user>
crate audit <name>                             # mounts: "/home/<u>/Documents nullfs ro from host ...", tmpfs rw lines

# rootless: same through mount_nullfs(read_only) and the new mount_tmpfs verb
sudo -u alice crate run -f /tmp/m.crate -- -c 'mount -p'

# a stack volume with :ro now mounts read-only (it was parsed and dropped before 1.1.63)
#   volumes: [certs:/etc/letsencrypt:ro] in a stack -> mount -p inside the member says ro

# negative
#   files: {share: [$HOME/x:ro]}        -> "a file share is a hard link or a copy and cannot be read-only"
#   tmpfs: [/etc]                        -> "tmpfs on /etc would hide the jail's own files"
#   tmpfs: {/tmp: 64mb}                  -> "tmpfs size must be digits with an optional k/m/g suffix"
#   etc: {keep: [ssl/certs]}             -> "only a plain name under /etc is allowed"
```

Pass criteria: the read-only share refuses writes from inside; both
tmpfs mounts appear with the right owner, mode and size; the kept
`/etc` entries are in the archive and in the running jail; nothing
regressed for specs without the new keys (shares mount rw as before).
If nmount(2) rejects a tmpfs option string (`size`, `uid`, `gid`,
`mode`), paste the errmsg: `lib/mounts_pure.cpp` (`tmpfsParams`) is the
one place that formats them.

---

## 4g. 1.1.64 — `run/user`

```sh
# default: the operator's mirrored account (unchanged)
crate run -f fetch.crate -- -o - https://www.freebsd.org/ >/dev/null; crate run -f sh.crate -- -c id
#   expect: uid=<operator uid>(<operator>) — as before 1.1.64

# a root operator: the dedicated account instead of root
sudo crate run -f sh.crate -- -c 'id; ls -ld $HOME'
#   expect: "run/user: the command runs as 'crate' (operator is root: dedicated unprivileged account)",
#   id -> uid=100x(crate), home /home/crate created by pw; no "group root already exists" error

# an explicit account the image creates
cat > /tmp/u.yml <<'EOF'
pkg: {install: [nginx]}
run: {command: /usr/bin/id, user: www}
EOF
crate create -s /tmp/u.yml -o /tmp/u.crate     # "run/user: account 'www' exists in the jail (uid 80)" — nginx's package user
crate run -f /tmp/u.crate                      # uid=80(www)
sed -i '' 's/user: www/user: appuser/' /tmp/u.yml
crate create -s /tmp/u.yml -o /tmp/u2.crate    # "run/user: creating the account 'appuser' in the jail"
crate run -f /tmp/u2.crate                     # uid=1001(appuser) or whatever pw picked; not in wheel
crate audit <name>                             # processes: the command's user, not root

# root on request
crate validate -s x.yml                        # run: {user: root} -> warning "runs as root inside the jail"
```

Pass criteria: no behaviour change for a non-root operator without
`run/user`; `sudo crate run` works and runs the command as `crate`; a
package account is picked up without creating anything; a new account is
created once at `crate create` and found at `crate run`; `id` inside the
jail shows no `wheel` for the created account.

---

## 4h. 1.1.65 — `--status-fd`, `run/timeout`, `stack up` over the status pipe

```sh
# the stream, end to end
crate run --status-fd 3 -f fetch.crate 3>/tmp/st.jsonl -- -o /dev/null https://www.freebsd.org/
cat /tmp/st.jsonl
#   expect, in order: started(pid) jail_created(jid,name,path) net_ready(mode,ip?) mounts_ready
#   services_started exec_started(user,command) exited(code 0, "exited normally", timed_out false) teardown_done
#   every line parses: python3 -c 'import json,sys; [json.loads(l) for l in sys.stdin]' < /tmp/st.jsonl
crate run --status-fd 2 -f fetch.crate               # refused: "descriptor 2 is stdin/stdout/stderr"
crate run --status-fd 7 -f fetch.crate               # refused: "not an open descriptor"
crate run --status-fd 3 -f sh.crate 3>&- 2>&1 -- -c 'ls -l /dev/fd/'   # (3>&- closes it: refused too)

# nothing inside the jail sees the descriptor
crate run --status-fd 3 -f sh.crate 3>/tmp/st2.jsonl -- -c 'ls /dev/fd; sleep 1'
#   expect: 0 1 2 only (close-on-exec)

# a failing run: failed + teardown_done, non-zero exit
crate run --status-fd 3 --var X=1 -f broken.crate 3>/tmp/st3.jsonl; tail -2 /tmp/st3.jsonl

# the reader goes away: the run must continue
( crate run --status-fd 3 -f sh.crate -- -c 'sleep 5; echo alive' ) 3>&1 | head -1
#   expect: "alive" printed after ~5 s, exit 0, no SIGPIPE death

# run/timeout
cat > /tmp/t.yml <<'EOF'
run: {command: /bin/sleep 300, timeout: 5}
EOF
crate create -s /tmp/t.yml -o /tmp/t.crate
time crate run --status-fd 3 -f /tmp/t.crate 3>/tmp/st4.jsonl; echo "exit=$?"
#   expect: ~5 s, "run/timeout: the command was killed after 5 s", exit=124,
#   exited line has "code":124,"reason":"timed out after 5 s (run/timeout)","timed_out":true
crate validate -s /tmp/t.yml                          # no warning
printf 'run: {service: [sshd], timeout: 1h}\n' > /tmp/t2.yml; crate validate -s /tmp/t2.yml
#   expect: warning "service-only crate — the container itself is stopped"
printf 'run: {command: /bin/true, timeout: 0}\n' > /tmp/t3.yml; crate validate -s /tmp/t3.yml   # error: 0 means no timeout
printf 'run: {command: /bin/true, timeout: 31d}\n' > /tmp/t4.yml; crate validate -s /tmp/t4.yml  # error: unknown unit

# stack up without polling
crate stack up -f examples/stack-web.yml -p
#   expect: each member "Started:" as soon as its jail exists (no 100 ms jls polling in truss),
#   a member with a broken spec: "[stack] Failed to start: <name> — crate run failed: <error text>"
#   instead of a bare "Failed to start" after 120 s
truss -f -p $(pgrep -n crate) 2>&1 | grep -c jail_get   # 0 while waiting for the next member

# crated: owner recorded from the stream
crate-ctl start nginx     # or the control socket / HTTP start
tail -f /var/log/crated.log
#   expect: "container 'nginx' started as pid N -> jail nginx_pidN (jid J) recorded for uid U" within
#   a second of the jail appearing (was: up to 1 s poll); a failing start logs
#   "crated: container 'nginx' (pid N): crate run failed: ... ; owner not recorded"
```

Pass criteria: the event order above on every mode (NAT, bridge with a
static IP shows `ip`, DHCP omits it); refusals for descriptors 0-2 and
closed ones; no descriptor leaks into the jail; a closed reader never
kills the run; `run/timeout` gives exit 124 and the timed_out event at
the deadline (+ up to 10 s for a program that ignores SIGTERM); `stack
up` and crated report the failure reason instead of timing out.

---

## 4i. 1.1.66 — `crate wrap install|remove|list`

```sh
# as an ordinary user (nothing here needs root)
crate wrap list                                   # "no launchers installed by `crate wrap` in ..."
crate wrap install fetch
#   expect: "installed /home/<u>/.local/bin/fetch  ->  crate run fetch -- "$@"" and, when ~/.local/bin
#   is not in $PATH, the yellow note; file mode 0755, 4 lines, "# crate wrap: fetch (crate 1.1.66)"
PATH=$HOME/.local/bin:$PATH fetch -o /dev/null https://www.freebsd.org/
#   expect: the fetch profile's container runs (first time: the profile build / chown recipe as with `crate run fetch`)
crate wrap install firefox --desktop
#   expect: both files; the .desktop has Exec=/usr/local/bin/crate run firefox -- %U, Terminal=false, Icon=firefox
desktop-file-validate ~/.local/share/applications/crate-firefox.desktop   # from devel/desktop-file-utils: no errors
crate wrap install nginx --desktop --no-launcher   # Terminal=true (no x11/gui in the profile); no ~/.local/bin/nginx
crate wrap install fetch --name sfetch             # a second launcher name for the same profile
crate wrap list                                    # fetch: two launchers; firefox: launcher + desktop; nginx: desktop
XDG_DATA_HOME=/tmp/xdg crate wrap install mpv --desktop --no-launcher; ls /tmp/xdg/applications/

# never clobber the operator's own files
printf '#!/bin/sh\necho mine\n' > ~/.local/bin/gimp; chmod 755 ~/.local/bin/gimp
crate wrap install gimp                            # refused: "exists and was not written by `crate wrap`; use --force"
crate wrap remove gimp                             # "kept ...: not written by `crate wrap`", file still there
crate wrap install gimp --force; crate wrap remove gimp; rm -f ~/.local/bin/gimp
crate wrap install no-such-profile                 # refused: "profile 'no-such-profile' not found; searched ..."
crate wrap install firefox --name crate            # refused by validate: would shadow crate itself

# in a desktop session: the menu entry starts the container
#   open the application menu, "Firefox (crate)" -> `crate list` shows firefox_pid<N>; a URL dropped on it
#   arrives in the containerised firefox (%U)

crate wrap remove firefox; crate wrap remove fetch; crate wrap remove fetch --name sfetch; crate wrap remove nginx
crate wrap list                                   # empty again
```

Pass criteria: the launcher starts the profile's container with the
arguments passed through; the `.desktop` entry validates and works from
a menu; files not written by `crate wrap` are neither replaced (without
`--force`) nor removed; `--name`, `--no-launcher`, `--icon` and
`XDG_DATA_HOME` do what the help says.

---

## 4j. 1.1.67 — `privacy/hostid`, `privacy/hostname`

```sh
sysctl kern.hostuuid kern.hostid kern.hostname            # the host's values, for comparison

# default: unchanged — the jail carries the host's identity
crate run -f sh.crate -- -c 'sysctl -n kern.hostuuid kern.hostid kern.hostname; cat /etc/hostid'
#   expect: the host's three values; /etc/hostid as in the image
crate audit <name>                                       # jail/hostid WARN "same as the host", hostname WARN

# random: new every run
cat > /tmp/p.yml <<'EOF'
privacy: {hostid: random, hostname: random}
run: {command: /bin/sh}
EOF
crate create -s /tmp/p.yml -o /tmp/p.crate
crate run -p -f /tmp/p.crate -- -c 'sysctl -n kern.hostuuid kern.hostid kern.hostname; cat /etc/hostid'
#   expect: -p prints "privacy: jail hostname crate-xxxxxxxx" and "privacy: jail host UUID <uuid> (kern.hostid N)";
#   inside: that UUID, that N (decimal), that hostname; /etc/hostid == the UUID;
#   md5 check: echo -n <uuid> | md5 | cut -c1-8 == printf %08x N
crate run -f /tmp/p.crate -- -c 'sysctl -n kern.hostuuid'   # a different UUID the second time
crate audit <name>                                            # jail/hostid PASS "(differs from the host)"

# fixed: stable for the crate
sed -i '' 's/hostid: random/hostid: 123e4567-e89b-12d3-a456-426614174000/; s/hostname: random/hostname: box/' /tmp/p.yml
crate create -s /tmp/p.yml -o /tmp/p2.crate
crate run -f /tmp/p2.crate -- -c 'sysctl -n kern.hostuuid kern.hostid kern.hostname'
#   expect: 123e4567-e89b-12d3-a456-426614174000 / 993178332 / box, every run

# rootless (crated privops): the same through create_jail's parameter list
crate run -p -f /tmp/p.crate -- -c 'sysctl -n kern.hostuuid'  # as an unprivileged member of the privops group
#   expect: a UUID != the host's; crated log shows create_jail with host.hostuuid=... host.hostid=...
#   a hand-crafted request with host.hostid=4294967296 or host.hostuuid=x is refused (400) by the validator

# validation and the shipped specs
printf 'options: [tor]\nrun: {command: /bin/sh}\n' > /tmp/t.yml; crate validate -s /tmp/t.yml
#   expect: warning "tor/i2pd without privacy/hostid"
crate validate -s examples/tor.yml; crate validate -s examples/chromium+tor.yml; crate validate -s templates/privacy.yml   # no such warning
printf 'privacy: {hostid: yes}\n' > /tmp/b.yml; crate validate -s /tmp/b.yml     # error: not 'host', 'random' or a UUID
printf 'privacy: {hostname: "a b"}\n' > /tmp/b.yml; crate validate -s /tmp/b.yml  # error: not a host name
```

Pass criteria: no change without `privacy:`; `random` gives a UUID, a
matching decimal hostid (first 32 bits of md5 of the UUID text) and a
`crate-<hex>` hostname that differ from the host's and between runs;
a literal UUID / name is used as given; `/etc/hostid` inside equals
`kern.hostuuid`; the same holds through crated; `crate audit` turns the
hostid row from WARN to PASS.

---

## 4k. 1.1.68 — `stack up` composes the member spec; `crate run --var`

```sh
# a two-member stack with a template, a pool, DNS, a secret and a volume
mkdir -p /tmp/stk/certs; echo s3cret > /tmp/stk/pw
cat > /tmp/stk/db.yml <<'EOF'
options: {net: {outbound: dns}}
run: {command: /bin/sh -c 'cat /etc/hosts; cat /etc/resolv.conf; echo "pw=${DB_PASSWORD}"; sleep 120'}
scripts:
  run:before-start-services:
    - "echo member-script-ran > /tmp/marker"
EOF
cat > /tmp/stk/web.yml <<'EOF'
options: [net]
run: {command: /bin/sh -c 'ls /etc/letsencrypt; sleep 120'}
EOF
cat > /tmp/stk/stack.yml <<'EOF'
containers:
  db:
    spec: db.yml
    template: privacy                      # a NAME: found in the template dirs
    vars: { DB_PASSWORD: { from_file: /tmp/stk/pw } }
  web:
    spec: web.yml
    depends: [db]
    volumes: [certs:/etc/letsencrypt:ro]
volumes: { certs: /tmp/stk/certs }
networks:
  backend: { bridge: bridge77, subnet: 10.77.0.0/24, gateway: 10.77.0.1, ip_range: 10.77.0.100-10.77.0.110, dns: true }
EOF
cp /usr/local/share/crate/templates/privacy.yml /tmp/stk/   # or rely on the installed one
cd /tmp/stk && crate stack up stack.yml -p
#   expect: "[stack] db: composed spec at /tmp/crate-stack-XXXXXX/db.yml" (removed when stack up ends),
#   both members Started

# what the archive holds is the composed spec
tar -xOf db.crate +CRATE.SPEC
#   expect: privacy: {hostid: random, hostname: random} (the template), options/net/ip: 10.77.0.100/24,
#   gateway: 10.77.0.1, scripts/run:before-start-services with "": [member line], __crate_stack_hosts,
#   __crate_stack_dns — and the LITERAL text pw=${DB_PASSWORD} (the secret is not in the archive)
tar -xOf web.crate +CRATE.SPEC | grep -A2 'dirs:'
#   expect: share: - [/etc/letsencrypt, /tmp/stk/certs, ro]
grep -c s3cret db.crate web.crate                     # 0 0 (xz-compressed; also: tar -xOf db.crate +CRATE.SPEC | grep -c s3cret → 0)

# the run saw all of it
J=$(jls -N | awk '/^db_pid/{print $1}'); crate logs $J | head -20
#   expect: /etc/hosts has "10.77.0.100 db" and "10.77.0.101 web", resolv.conf "nameserver 10.77.0.1",
#   "pw=s3cret" (the --var reached the run), kern.hostuuid inside != the host's
jexec $J cat /tmp/marker                              # member-script-ran (the spec's own script still runs)
crate stack exec stack.yml web -- ls /etc/letsencrypt # the volume is mounted, read-only
crate stack down stack.yml

# template resolution
sed -i '' 's/template: privacy/template: nope/' stack.yml; crate stack up stack.yml
#   expect: "containers/db: template 'nope' not found (searched ~/.config/crate/templates/nope.yml,
#   /usr/local/share/crate/templates/nope.yml, /tmp/stk/nope.yml)", nothing started
sed -i '' 's/template: nope/template: privacy.yml/' stack.yml; crate stack up stack.yml -p   # the copy next to the stack file

# crate run --var on its own
printf 'run: {command: /bin/sh -c "echo hello=${WHO}"}\n' > /tmp/v.yml
crate create -s /tmp/v.yml -o /tmp/v.crate --var WHO=build
crate run -f /tmp/v.crate --var WHO=runtime             # hello=runtime (was: hello=${WHO})
crate run -f /tmp/v.crate                              # hello=${WHO} — an unset var stays literal, as before
```

Pass criteria: the composed spec, not the bare one, is in every member's
`+CRATE.SPEC`; the template, address, scripts and volume take effect in
the running jail; the member's own `run:before-start-services` lines
still run; no secret value in any `.crate`; `--var` on `crate run`
substitutes at run time; a template name is resolved through the three
locations and a miss names them.

---

## 4l. 1.1.69 — TODO §7 MED: backup chains, prune, update --pkg-only, restart --warm-base, clean vs run, top

```sh
# --- backup / replicate chains (needs a jail on ZFS and a remote with ssh + zfs) ---
J=web; DS=$(zfs list -H -o name $(jls -j $(jls -N | awk '/^web_pid/{print $1}') path))
crate backup $J --output-dir /backup                      # full
crate backup $J --output-dir /backup --auto-incremental   # inc-from-<full>
crate backup $J --output-dir /backup --auto-incremental   # inc-from-<inc1>  (chained)
zfs list -t snapshot -o name -d 1 $DS | grep @backup-     # exactly the three backup-* snapshots
# a child dataset's snapshot must NOT become a base
zfs create $DS/data; zfs snapshot $DS/data@backup-2099-01-01T00:00:00Z
crate backup $J --output-dir /backup --auto-incremental   # inc-from-<inc2>, not from the 2099 one
zfs destroy $DS/data@backup-2099-01-01T00:00:00Z; zfs destroy $DS/data
# a failed send leaves no snapshot: fill the target to ENOSPC, or point --output-dir at a read-only fs
crate backup $J --output-dir /backup-ro --auto-incremental; zfs list -t snapshot -d 1 $DS | grep -c @backup-   # unchanged

# replicate: its own repl-* family, base = newest snapshot on BOTH sides
crate replicate $J --to root@backuphost --dest-dataset tank/backup/web                     # full, repl-<ts>
crate backup $J --output-dir /backup --auto-incremental                                   # a file backup in between
crate replicate $J --to root@backuphost --dest-dataset tank/backup/web --auto-incremental # incremental FROM THE repl- snapshot
#   expect: "incremental", the remote accepts it (was: "incremental source does not match")
ssh root@backuphost zfs destroy -r tank/backup/web
crate replicate $J --to root@backuphost --dest-dataset tank/backup/web --auto-incremental
#   expect: the yellow "no snapshot is present on both sides — sending a full stream" and a full send
# a failed replicate leaves no local snapshot
crate replicate $J --to root@nohost --dest-dataset tank/x; zfs list -t snapshot -d 1 $DS | grep -c @repl-    # unchanged

# template warm: a failed clone leaves no snapshot
crate template warm $J --output tank/templates/exists-already   # (create that dataset first) → fails
zfs list -t snapshot -d 1 $DS | grep -c @warm-                   # unchanged

# --- backup-prune: a chain follows its base ---
ls /backup                      # F, inc-from-F, inc-from-inc1, inc-from-inc2
crate backup-prune /backup --keep daily=7 --delete-orphans -n
#   expect: all four kept, nothing "orphan" (was: inc2 and inc3 listed as orphans and deleted)
rm /backup/*inc-from-<inc1>*; crate backup-prune /backup --keep daily=7 -n
#   expect: F + inc1 kept, inc3 reported as orphan

# --- update --pkg-only on a pkg: crate ---
crate create -s examples/nginx.yml -o /tmp/nginx.crate
tar -tf /tmp/nginx.crate | grep -c 'usr/local/sbin/pkg$\|var/db/pkg/local.sqlite'   # 2 (kept by default)
crate run -f /tmp/nginx.crate &  sleep 5
crate update nginx --pkg-only -n            # pkg upgrade -n runs inside the jail (was: ENOENT /usr/sbin/pkg)
printf 'pkg: {install: nginx, keep-pkg: false}\nrun: {service: nginx}\n' > /tmp/n2.yml
crate create -s /tmp/n2.yml -o /tmp/n2.crate; tar -tf /tmp/n2.crate | grep -c 'var/db/pkg/local.sqlite'   # 0
crate run -f /tmp/n2.crate & sleep 5; crate update n2 --pkg-only -n
#   expect: "jail 'n2_pid…' has no pkg(8) and no package database — the crate was built with pkg/keep-pkg: false …"

# --- restart of a --warm-base run ---
crate template warm nginx --output tank/templates/nginx-warm
crate run --warm-base tank/templates/nginx-warm --name nginxw &  sleep 5
grep nginxw /var/run/crate/spec-registry.txt         # "nginxw warm-base=tank/templates/nginx-warm"
crate restart nginxw
#   expect: "Restarting container nginxw from warm template tank/templates/nginx-warm...", the jail is back
#   (was: "Container stopped but cannot restart: no .crate file found")

# --- clean vs a run in progress ---
crate run -f /tmp/big.crate &                 # something that extracts for > 10 s
sleep 2; crate clean
#   expect: "in use (a crate run/create holds it): /var/run/crate/jail-big-xxxx — skipped"; the run completes normally
crate create -s examples/firefox.yml -o /tmp/ff.crate &  sleep 20; crate clean -n
#   expect: the chroot-create-ff-xxxx directory is skipped as in use; after a `kill -9` of the create it IS swept
truss -f crate run -f /tmp/sh.crate -- -c 'ls -l /dev/fd' 2>&1 | grep -c 'flock'   # the lock is taken; the jail sees fds 0-2 only

# --- top ---
crate top | head -3
#   expect: header "... MEM     WRITE/s  PROC", rates like "12.5 MB/s", CPU% moving every second (pcpu),
#   footer "WRITE <rate>" (was: "DISK <bytes>")
```

Pass criteria: the backup base is always a snapshot of the SAME dataset
that a stream file holds; replicate's base is on both sides or the send
is full; no snapshot survives a failed send/clone; a prune keeps a whole
kept chain and orphans only what lost its base; `update --pkg-only`
works on a default-built crate and explains itself on a keep-pkg: false
one; a warm-base container restarts; `crate clean` never touches a
directory a live run/create holds and sweeps dead chroot-create-*
ones; `crate top` shows rates and a smooth CPU%.

---

## 4m. 1.1.70 — regressions of 1.1.65–1.1.69 and the teardown crash

```sh
# the success-path teardown of a plain (no x11/gui) run — it died with SIGSEGV before 1.1.70
printf 'run: {command: /bin/echo hello}\n' > /tmp/e.yml && crate create -s /tmp/e.yml -o /tmp/e.crate
crate run -f /tmp/e.crate; echo "exit=$?"
#   expect: "hello", exit=0, no "Segmentation fault", no core file
ls /var/run/crate | grep -c '^jail-e-'            # 0: the jail directory was removed
mount | grep -c /var/run/crate/jail-e-             # 0: nothing left mounted
# the same for a NAT run (fw slot / lease handles) and a bridge run on an existing bridge
crate run -f fetch.crate -- -o /dev/null https://www.freebsd.org/; echo "exit=$?"   # exit=0, no crash

# --warm-base: the clone and its snapshot are gone after the run (1.1.69 leaked both)
crate run --warm-base tank/templates/nginx-warm --name nginxw -- /bin/echo ok
zfs list -H -o name -r $(zfs list -H -o name $(dirname /var/run/crate/x)) | grep -c 'warm-run\|nginxw'   # 0
zfs list -H -t snapshot -o name tank/templates/nginx-warm | grep -c '@warm-run-'                       # 0

# crate clean keeps a warm-base registry entry whose dataset exists, drops one whose dataset is gone
grep nginxw /var/run/crate/spec-registry.txt                  # nginxw warm-base=tank/templates/nginx-warm
crate clean -n | grep nginxw                                  # nothing: the dataset exists
zfs rename tank/templates/nginx-warm tank/templates/nginx-warm.old
crate clean -n | grep nginxw                                  # "would remove registry entry: nginxw -> warm-base=… (dataset no longer exists)"
zfs rename tank/templates/nginx-warm.old tank/templates/nginx-warm

# stack pool addresses: NAT members are not given one any more (1.1.68 stopped `stack up` on them)
cat > /tmp/stk2/stack.yml <<'EOF'
containers:
  nat:    { spec: nat.yml }      # options: {net: {outbound: dns}}
  br:     { spec: br.yml }       # options: {net: {mode: bridge, bridge: bridge78}}
  brdhcp: { spec: brdhcp.yml }   # options: {net: {mode: bridge, bridge: bridge78, ip: dhcp}}
networks:
  n: { bridge: bridge78, subnet: 10.78.0.0/24, gateway: 10.78.0.1, ip_range: 10.78.0.100-10.78.0.110 }
EOF
crate stack up /tmp/stk2/stack.yml -p
#   expect: all three Started; WARNs "container 'nat' gets no pool address" and the same for 'brdhcp';
#   "DNS mappings: br=10.78.0.100"; br's +CRATE.SPEC has ip: 10.78.0.100/24, gateway: 10.78.0.1
crate stack down /tmp/stk2/stack.yml

# crated: no zombies after starts and failed starts
crate-ctl start broken; crate-ctl start nginx; sleep 15
ps -o pid,stat,comm -p $(pgrep -d, -P $(cat /var/run/crate/crated.pid)) | grep -c ' Z'   # 0
crate-ctl stop nginx; sleep 5; ps -axo stat,comm | grep -c '^Z.*crate'                     # 0: reaped when it exited
```

Pass criteria: no SIGSEGV on any success path and a complete teardown;
no warm-run clone or snapshot left; warm-base registry entries survive
`crate clean` while their dataset exists; a stack with NAT, bridge and
bridge+dhcp members starts, with a pool address only on the bridge
member and a warning for the others; crated leaves no zombie behind a
failed or finished `crate run`.

The HIGH findings of the same bug hunt, folded into 1.1.70:

```sh
# 1. only stdio reaches the jail: no host socket, no crated descriptor
printf 'run: {command: /bin/sleep 300}\n' > /tmp/s.yml && crate create -s /tmp/s.yml -o /tmp/s.crate
crate run -f /tmp/s.crate & sleep 5
jid=$(jls -h jid path | awk '/jail-s-/ {print $1}')
procstat -f $(pgrep -j $jid sleep) | awk '$3 ~ /^[0-9]+$/ && $3 > 2' | wc -l   # 0 (before: a UDP socket of the host stack)
# the same for a jail crated started (crate-ctl start …) and for a ws-console shell
kill %1

# 2. devfs: tenants fill only private rulesets; the shared ones stay as they were
devfs rule -s 4 show > /tmp/rs4.before
# as a per-user tenant (rootless, path_master_prefix set):
crate run -p -f /tmp/e.crate 2>&1 | grep 'private devfs ruleset'   # a number in 10000..59999
devfs rule -s 4 show | diff - /tmp/rs4.before && echo "ruleset 4 untouched"
# a libnv apply_devfs_rules with ruleset=4, or add_devfs_unhide_rule, from a tenant -> 403
# (unit-tested in privops_authz_pure_test; crated's log shows the deny reason)

# 3. backup-prune counts each jail on its own
mkdir -p /tmp/bk && cd /tmp/bk
for j in web db; do for d in 01 02 03; do touch "$j-backup-2026-01-${d}T00:00:00Z.zstream"; done; done
crate backup-prune /tmp/bk --keep daily=1 --dry-run
#   expect: keep 2 (web-…-03, db-…-03), remove 4 — before 1.1.70 one jail's newest was the only survivor

# 4. HTTP export packs only the jail's own filesystem
#    (a run with dirs/share of /usr/local/share/doc, then:)
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9800/api/v1/containers/<name>/export
tar tJf /var/run/crate/<name>-*.crate | grep -c usr/local/share/doc      # 0

# 5. targets by container name; restart decides before it stops
crate run -f nginx.crate & sleep 10; crate list                           # nginx_pid<N> (privops) or <jid> (root)
crate restart nginx                                                       # stops and starts again (new jail)
crate restart nginx_pid<N>                                                # the same by kernel name
crate stop nginx                                                          # stops it
crate run -f /tmp/unregistered-copy.crate &                               # a .crate whose registry entry you then delete
crate restart unregistered-copy                                           # "cannot restart … it keeps running"; still in jls
crate-ctl start nginx; crate-ctl start nginx                              # the second answers 409, one jail only
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9800/api/v1/containers/nginx/restart   # restarted:true

# 6. the browser profiles open a window again
crate run firefox                                                         # a window (before: "cannot open display")
mount | grep jail-firefox | grep -n 'tmpfs\|X11-unix'                     # the /tmp tmpfs is listed BEFORE the X11 nullfs

# 7. `crate -p stack up` starts the members (each run refused --log-progress after `run`)
crate -p stack up /tmp/stk2/stack.yml; crate stack down /tmp/stk2/stack.yml

# 8. one terminal event: a failing run:after-execute script after the command exited
#    (scripts: {run:after-execute: "exit 1"} in the spec)
crate run --status-fd 3 -f /tmp/ae.crate 3>/tmp/ae.jsonl; grep -c '"event":"\(exited\|failed\)"' /tmp/ae.jsonl   # 1

# 9. jail_created names the jail the kernel has (root path, no crated: its jid)
crate run --status-fd 3 -f /tmp/e.crate 3>/tmp/e.jsonl; grep jail_created /tmp/e.jsonl   # "name" = the jid jls showed
```

Pass criteria: a jailed process holds nothing above fd 2; ruleset 4 is
unchanged after tenant runs; `backup-prune` keeps the newest stream of
every jail; the HTTP export holds no shared host files; restart / stop /
start find a container by its container name, restart refuses before
stopping when nothing is recorded, and a running container is not
started twice; firefox and chromium open a window; `crate -p stack up`
starts every member; one terminal event per stream; `jail_created`
carries the kernel's jail name.

---

## 4n. 1.1.71 — the bug hunt's MED findings

```sh
# 1. mount_nullfs: a source ABOVE the tenant root is refused. As a tenant (rootless, crated
#    with path_master_prefix: /var/run/crate), a spec that shares /var/run into the jail:
printf 'dirs:\n  share:\n    - [/mnt/v, /var/run]\nrun: {command: /bin/ls /mnt/v}\n' > /tmp/up.yml
#    built by root (crate create -s /tmp/up.yml -o /tmp/up.crate), run by the tenant:
crate run -f /tmp/up.crate 2>&1 | grep 'contains the per-user tenant root'   # 403, nothing mounted
#    the same spec with [/mnt/v, $HOME/data] still mounts.

# 2. ${VAR:-default}: the examples parse without --var
for f in /usr/local/share/examples/crate/*.yml; do case $f in */stack-*) continue;; esac
  crate validate "$f" >/dev/null || echo "FAIL $f"; done            # no FAIL lines
crate create -s examples/postgres.yml -o /tmp/pg.crate               # installs postgresql16-server
crate create -s examples/postgres.yml --var PG_VERSION=17 -o /tmp/pg17.crate   # postgresql17-server

# 3. .local policy: each of these is refused with the reason
for k in 'security-advanced: {}' 'security: {securelevel: 0}' 'devices: [gpu]' \
         'ipc: {raw-sockets: true}' 'zfs: {datasets: [zroot/x]}'; do
  printf '%s\n' "$k" > ~/.config/crate/profiles/firefox.local.yml; crate run firefox 2>&1 | head -1; done
printf 'dirs:\n  share:\n    - [/a, $HOME/a]\n  share:\n    - [/b, /etc]\n' > ~/.config/crate/profiles/firefox.local.yml
crate run firefox 2>&1 | head -1                                      # "names 'dirs/share' twice"
rm ~/.config/crate/profiles/firefox.local.yml

# 4. the profile cache follows content: removing the .local rebuilds, re-running does not
crate run firefox; ls ~/.local/share/crate/profiles/firefox.key       # the key file exists
crate -p run firefox 2>&1 | grep 'is up to date'                      # second run: reused
touch -t 202001010000 ~/.config/crate/profiles/firefox.yml            # an OLDER mtime ...
echo '# x' >> ~/.config/crate/profiles/firefox.yml; crate run firefox 2>&1 | grep building   # ... still rebuilds

# 5. etc/keep with a file base.txz already has
printf 'etc:\n  keep: [hosts, resolv.conf, ssl]\nrun: {command: /bin/cat /etc/hosts}\n' > /tmp/k.yml
crate create -s /tmp/k.yml -o /tmp/k.crate && crate run -f /tmp/k.crate   # the HOST's /etc/hosts

# 6. run/user under root: its own HOME, and the X cookie readable (as root)
printf 'run:\n  command: /bin/sh\n  args: [-c, "echo $HOME $USER; pwd"]\n  user: crate\n' > /tmp/u.yml
crate create -s /tmp/u.yml -o /tmp/u.crate && crate run -f /tmp/u.crate   # "/home/crate crate", "/home/crate"
#    xeyes.yml with `user: crate` added under run: opens its window (before: "No protocol specified");
#    in the jail, /home/crate/.Xauthority is -rw------- crate and /root/.Xauthority is gone

# 7. profile-from-trace: a listed directory is shared as a directory
crate profile-from-trace -o /tmp/ls.yml -- /bin/ls ~/Music /srv
grep -A3 'dirs:' /tmp/ls.yml                                          # $HOME/Music and /srv, no files/share

# 8. crate audit on a NAT jail: no WARN for the gateway probe or bpf
crate run -f fetch.crate -- -o /dev/null https://www.freebsd.org/ &
crate audit fetch | grep -E 'gateway|bpf'                             # both PASS; exit status 0 if nothing else warns

# 9. backup / export: private files, no symlink followed
crate backup web --output-dir /tmp && ls -l /tmp/web-*.zstream        # -rw------- root
ln -s /etc/motd.template /tmp/x.crate; crate export web -o /tmp/x.crate   # refused: exists
rm /tmp/x.crate; crate export web -o /tmp/x.crate && ls -l /tmp/x.crate   # -rw------- , owner = you

# 10. crated starts a warm-base container (a control socket from control_sockets: in crated.conf,
#     and the HTTP API with an admin token)
crate run --warm-base tank/templates/nginx-warm --name nginxw &  sleep 5; crate stop nginxw
curl --unix-socket /var/run/crate/control/<group>.sock -X POST http://x/v1/control/containers/nginxw/start   # 202, before 404
jls name | grep -c '^nginxw_pid'                                                                             # 1
curl -H "Authorization: Bearer $ADMIN" -X POST http://127.0.0.1:9800/api/v1/containers/nginxw/restart       # 200
```

Pass criteria: no tenant can mount a directory above the tenant root;
every example validates; each loosening `.local` is refused; the profile
cache rebuilds on content and only then; `etc/keep` keeps existing
files; `run/user` runs with its own HOME and reads its X cookie;
directory listings become directory shares; `crate audit` passes a
networked vnet jail; backup / export files are 0600 and refuse links; a
warm-base container starts through crated.

---

## 4o. 1.1.72 / 1.1.73 — privops next to root, data-loss guards, /var/run/crate layout

```sh
# 1.1.72: root next to crated's privops socket (crated.conf: privops_socket set)
ls -l /var/run/crate/crated-privops.sock && crate run -f /tmp/e.crate; echo "exit=$?"   # exit=0
ls -ld /var/db/crate                                   # drwx------ root, created by crated
sudo -u alice crate run -f chromium-privacy.crate &     # NAT + firewall: through privops as a tenant
pfctl -a 'crate/*' -sr | head                          # the policy and the nat/rdr lines are loaded

# a tenant cannot remove a jail by its jid: unit-tested (privops_authz_pure_test,
# destroy_numeric_name_is_gated_as_jid); with a libnv client at hand, destroy_jail
# name=<another tenant's jid> answers 403

# crate clean never deletes through a mount
mkdir -p /var/run/crate/0/jail-x-00000000/mnt && mount -t nullfs /tmp/keep /var/run/crate/0/jail-x-00000000/mnt
crate clean | grep 'still has file systems mounted'   # refused; /tmp/keep intact
umount /var/run/crate/0/jail-x-00000000/mnt && crate clean   # removed
# a running root jail keeps its anchor
crate run -f fetch.crate -- -o /dev/null https://www.freebsd.org/ & sleep 5; crate clean; pfctl -a 'crate/*' -s Anchors   # still listed

# backup refuses a jail without its own dataset (a plain run); a --warm-base one works
crate backup <plain jail> --output-dir /tmp      # "has no ZFS dataset of its own"
# stack network_policy stays after `stack up`, goes with `stack down`
crate stack up s.yml; ipfw list | grep -c 'via bridge'   # > 0
crate stack down s.yml; ipfw list | grep -c 'via bridge' # 0
# crate-hub polls a TLS node; snmpwalk sees the scalars
snmpwalk -v2c -c public localhost .1.3.6.1.4.1.59999     # four values

# 1.1.73: layout
ls -ld /var/run/crate /var/run/crate/0                   # drwx--x--x root, drwx------ root
crate run -f /tmp/e.crate & sleep 3; jls path            # /var/run/crate/0/jail-e-…
sudo -u alice ls /var/run/crate/0                        # Permission denied
sudo -u alice crate run -f /tmp/e.crate                  # rootless: reaches the socket now
# with a jail of 1.1.72 still running from /var/run/crate/jail-*: crated keeps 0700 and says so
crate run --warm-base tank/templates/nginx-warm --name nw & sleep 5; zfs get -H -o value mountpoint $(zfs list -H -o name | grep jail-nw-)   # = the jail path
```

Pass criteria: root runs work next to the privops socket; crated
starts containers without aborting; firewall policies load under
rootless; no jail is removable by jid; clean never deletes through a
mount and keeps live anchors; backup never sends a containing
dataset; a stack keeps its policy; /var/run/crate is 0711 with root's
jails in a 0700 /var/run/crate/0; a warm clone is mounted at its jail
path.

---

## 4p. 1.1.74 — the bug hunt's remaining HIGH findings

```sh
# privops: a FIFO for the per-user audit log no longer pins the listener
U=$(id -u alice); sudo -u alice sh -c "rm -f /var/run/crate/$U/audit.log; mkfifo /var/run/crate/$U/audit.log"
sudo -u alice crate run -f /tmp/e.crate; echo "exit=$?"   # exit=0; crated's log: audit_per_user open … Device not configured
# one uid holds at most 16 connections (alice in the privops group)
for i in $(jot 17); do sleep 40 | sudo -u alice nc -U /var/run/crate/crated-privops.sock > /tmp/p.$i & done; sleep 2
ls -l /tmp/p.17      # non-empty at once (503); p.1..p.16 stay empty until the 30 s deadline
crate run -f /tmp/e.crate; echo "exit=$?"                 # another uid (root here) is not locked out

# HTTP: at most 8 streams; /healthz keeps answering; stop does not hang
for i in $(jot 9); do curl -sN -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $VIEWER" \
    "http://127.0.0.1:9800/api/v1/containers/e/logs?follow=true" & done; sleep 2   # one prints 503
curl -s http://127.0.0.1:9800/healthz                     # answers
time service crated stop                                  # seconds, with the streams still open

# firewall: the policy names the jail's address; the host's own traffic is not touched
crate run -f chromium-privacy.crate &                     # default: block
pfctl -a 'crate/*' -sr                                    # "block drop quick from <jail ip> to any", no "block drop all"
fetch -o /dev/null https://www.freebsd.org/               # from the host: works while the jail runs
# a bridge-mode spec with a firewall: map: the SNAT/rdr lines survive the policy load
pfctl -a 'crate/*' -sn                                    # nat / rdr still listed
# NAT mode on a host without pf: a clear refusal
kldunload pf; crate run -f chromium-privacy.crate         # "firewall: the spec's policy needs pf …"

# netgraph: the bridge is named crate_br_<jid>_<n>, the jail gets the ngeth
crate run -f nginx-netgraph.crate & sleep 10; ngctl list | grep crate_br_   # one per interface
jexec <jid> ifconfig -l                                   # ngethN present
# once the run has ended, or failed after the bridge was attached:
ngctl list | grep -c crate_br_                            # 0, and em0 still receives

# snapshot restore never removes newer snapshots
crate snapshot create <dataset> s1; crate snapshot create <dataset> s2
crate snapshot restore <dataset> s1                       # refused, zfs names @s2
zfs list -t snapshot <dataset>                            # s1 and s2 both still there

# gui nested / headless / gpu: only the run's own X socket
crate run -f lxqt-desktop-nested.crate & sleep 10
mount -p | grep '.X11-unix/.crate-'                       # nullfs ro from /tmp/.X11-unix/.crate-…
jexec <jid> ls -a /tmp/.X11-unix                          # . .. X<N> — no X0
jexec <jid> sh -c 'ls /root/.Xauthority /home/*/.Xauthority'   # no such file
crate audit <name> | grep X11-unix                        # PASS "this run's own X server only"
# the desktop itself still draws (connecting through a read-only nullfs is allowed)
# after the run: ls -a /tmp/.X11-unix shows no .crate-* directory
```

Pass criteria: a FIFO audit log and one uid's idle connections do not
lock other users out of privops; streams are capped at 8 and stop
does not wait for them; policy rules carry the jail's address and the
host's traffic passes; bridge-mode SNAT/rdr survive; netgraph runs and a
failed one leaves no ng_bridge on the NIC; restore keeps newer
snapshots; a nested jail sees only its own X socket, has no host
cookie, and its desktop works.

---

## 4q. 1.1.75 — hooks inside the jail, trusted warm-template specs

```sh
# a spec with hooks in every place (hooks.yml):
#   scripts:
#     run:begin:              ["hostname > /tmp/h-begin"]
#     run:after-create-jail:  ["hostname > /tmp/h-after; ifconfig -l > /tmp/if-after"]
#     run:before-execute:     ["id -u > /tmp/id"]
#     run:after-remove-jail:  ["hostname > /tmp/h-gone"]
crate create -s hooks.yml -o /tmp/hooks.crate && crate run -f /tmp/hooks.crate -- /bin/sleep 3 &
sleep 2; J=$(jls path | grep jail-hooks- | head -1)
cat $J/tmp/h-after $J/tmp/if-after   # the jail's hostname and ITS interfaces (lo0, epair…b), not the host's
cat $J/tmp/id                        # 0 — the jail's root
# run:begin / run:after-remove-jail ran in a jail: `jls` showed a short-lived jail with path=$J
# rootless: a spec with run:begin is refused up front
sudo -u alice crate run -f /tmp/hooks.crate          # "scripts/run:begin runs outside the jail … needs root"
# a spec with only run:before-start-services hooks (nginx.yml) runs rootless now
sudo -u alice crate run -f nginx.crate &             # starts; the hook ran inside the jail

# warm templates: the trusted spec
crate run -f nginx.crate & sleep 5
crate template warm nginx --output tank/templates/nginx-warm   # "spec from /…/nginx.crate"
ls -l /var/db/crate/warm/                                      # <guid>.spec, -rw------- root
# a rewritten +CRATE.SPEC inside the template is not used
echo 'options: [net]' >> $(zfs get -H -o value mountpoint tank/templates/nginx-warm)/+CRATE.SPEC
crate run --warm-base tank/templates/nginx-warm --name nw -- /bin/echo ok   # runs with the stored spec
# a template made before 1.1.75: refused until trusted
zfs create tank/templates/hand-made; crate run --warm-base tank/templates/hand-made --name hm   # "no trusted spec … crate template trust"
crate template trust tank/templates/nginx-warm --spec nginx.crate                               # re-records it
```

Pass criteria: in-jail hooks see the jail's hostname and interfaces as
uid 0 of the jail; the outside sections run in a short-lived jail;
rootless refuses only the outside sections; `template warm` records the
spec in /var/db/crate/warm and `run --warm-base` ignores the clone's
own +CRATE.SPEC; an untrusted template is refused with the remedy.

## 4r. 1.1.76 — no symlink followed into the tree, mount_devfs

```sh
# a warm template whose source jail turned /etc into a link to the host's /etc
crate run -f nginx.crate & sleep 5
J=$(jls path | grep jail-nginx- | head -1)
mv $J/etc $J/etc.real && ln -s /etc $J/etc       # what a hostile jail root can do
crate template warm nginx --output tank/templates/evil
cp /etc/rc.conf /tmp/rc.conf.before
crate run --warm-base tank/templates/evil --name ev -- /bin/echo ok
#   expect: refused — "'etc' is a symbolic link, which is not followed from the host"
cmp /etc/rc.conf /tmp/rc.conf.before             # unchanged
# the X cookie of a root run: a planted /root/.Xauthority link is not copied
#   (run a gui spec with run/user: crate after `ln -sf /etc/master.passwd $J/root/.Xauthority`
#   in its template): "run/user: .Xauthority not copied into /home/crate (… symbolic link …)"

# rootless: the jail's /dev comes from crated
sudo -u alice crate run -f nginx.crate -- /bin/ls /dev     # null, zero, random, … — no EPERM
grep mount_devfs /var/run/crate/$(id -u alice)/audit.log | tail -1   # target=…/dev, allowed
# a spec with cow: {backend: unionfs} is refused up front
sudo -u alice crate run -f cow.crate                        # "cow/backend: unionfs … needs root"
```

Pass criteria: a symlinked directory or file in the tree stops the write
with the "symbolic link" message and leaves the host file as it was; a
rootless run mounts its /dev through `mount_devfs` and gets its private
ruleset as before (§4e); `cow:` unionfs is refused before anything is
mounted.

## 4s. 1.1.77 — shares, mount targets and the socket proxy

```sh
# a template whose source jail planted links (as in §4r)
crate run -f share.crate & sleep 5; J=$(jls path | grep jail-share- | head -1)
#   share.yml:  files/share: [{host: /home/alice/app.conf, jail: /etc/app.conf}]
#               dirs/share:  [{host: /home/alice/data, jail: /data/}]     (trailing slash)
#               socket_proxy: {proxy: [{host: /var/run/x.sock, jail: /var/run/proxy/x.sock}]}
ln -sf /etc/master.passwd $J/etc/app.conf            # the jail file is a link to a host file
rm -rf $J/var/run/proxy && ln -s /etc $J/var/run/proxy
crate template warm share --output tank/templates/evil-share
crate run --warm-base tank/templates/evil-share --name es -- /bin/echo ok
#   expect: the files/share step either replaces the link (host file exists) or refuses it
#   ("is not a regular file"); /home/alice/app.conf is never a link or copy of master.passwd
#   expect: socket proxy refused — "'proxy' is a symbolic link …"; no x.sock in /etc
ls -l /etc/x.sock 2>/dev/null; ls -li /home/alice/app.conf /etc/master.passwd
# a plain run: shares, the trailing-slash dir share, tmpfs and the GUI sockets mount as before
crate run -f share.crate -- /bin/sh -c 'mount | grep -c nullfs; ls -l /var/run/proxy/x.sock'
# a share whose jail path runs through a link inside the tree is refused
#   (dirs/share jail: /lnk/data, the tree has /lnk -> tmp): "'lnk' is a symbolic link …"
```

Pass criteria: no host file is linked, copied or created through a link
in the tree; the socket appears only inside the jail; ordinary shares,
tmpfs and GUI sockets mount as before (a trailing slash included).

---

## 5. Reporting back

```sh
sh scripts/on-hardware-validation.sh > /tmp/onhw-report.txt 2>&1
# also paste the outcomes of any §1.* / §2.* / §3.* / §4.* / §4a / §4b / §4c / §4d / §4e / §4f / §4g / §4h / §4i / §4j manual checks
```

Attach `/tmp/onhw-report.txt` plus the manual-section outcomes to the PR
checklist (or a new tracking comment). A clean run unblocks the
remaining unchecked checkboxes in #210..#213.

Anything `FAIL` is a regression worth a new issue/PR; anything `SKIP`
that the deployment intends to use (e.g. `seatd` for `drm` backend) is
the operator's TODO to provision, not a crate defect.
