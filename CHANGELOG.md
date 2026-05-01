# Changelog

All notable changes to **crate** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.5.8] — 2026-05-01

ed25519 signatures for `.crate` archives via `crate export -K
<secret-key>` and `crate import -V <public-key>`. Closes the last
"high priority" item in TODO and pairs with the 0.5.4 symmetric
encryption to give independent **confidentiality** + **authenticity**.

### Added

- **`lib/sign_pure.cpp`/`.h`** (new):
  - `validateSecretKeyFile` — must be regular, non-empty, mode 0600.
  - `validatePublicKeyFile` — must be regular, non-empty (mode irrelevant).
  - `buildSignArgv(secretKey, archive, sigOut)` — pinned to
    `openssl pkeyutl -sign -rawin -inkey ... -in ... -out ...`.
  - `buildVerifyArgv(publicKey, archive, sigFile)` — pinned to
    `openssl pkeyutl -verify -pubin -rawin -inkey ... -sigfile ...`.
  - `sidecarPath(archive)` — `<archive>.sig`.
- **CLI**:
  - `crate export -K, --sign-key <file>` — sign with ed25519 secret key
  - `crate import -V, --verify-key <file>` — verify with ed25519 public key
- **Auto-detection on import**: if `<archive>.sig` exists, `-V` is
  required (or `--force` to skip). If `-V` is given but no sidecar
  exists, the import fails (or `--force` to skip).
- The signature covers the **on-disk archive bytes**, including any
  encryption layer added by 0.5.4. So a tampered ciphertext fails
  signature check **before** the recipient enters their passphrase.

### Threat model recap

| Property | Provided by |
|---|---|
| Confidentiality | `-P` (AES-256-CBC + PBKDF2, 0.5.4) |
| Content integrity | `.sha256` sidecar |
| **Authenticity** | `-K` / `-V` (ed25519, 0.5.8) |

The three are independent; combine as needed.

### Added — tests (+13 cases)

`tests/unit/sign_pure_test.cpp`:
- Secret key file: 0600 OK; 0644 / 0640 / empty / missing / dir rejected
- Public key file: 0644 OK; 0600 also OK; empty / missing rejected
- argv shape pinned for sign + verify (positions 0–9 for sign, 0–10 for verify)
- `-rawin` flag presence (ed25519 requires it)
- Sidecar path computation

### Added — documentation

`README.md` + `README_UK.md` gain a "Signed export/import (ed25519)"
section with:
- One-time keypair generation (openssl genpkey)
- Combined `-P` + `-K` example for confidentiality + authenticity
- What gets signed (on-disk bytes including encryption layer)

### Verification

- `make build-unit-tests` → 29 binaries built
- `cd tests && kyua test unit` → **444/444 pass** (was 431, +13)

---

## [0.5.7] — 2026-05-01

`pkg install` failure inside a jail no longer eats its own diagnostics.
When `crate create` shells `pkg` inside a jail and `pkg` exits non-zero,
the captured stdout/stderr is now appended to a per-jail log file so
operators running crate non-interactively (cron, CI) can recover the
output.

### Why

Previously, `runChrootCommand()` inherited the controlling terminal —
so an interactive `crate create` user saw `pkg`'s output, but a
background invocation (cron, CI, daemon) lost it entirely. The thrown
`Exception` only said `'install the requested packages...' failed
with exit status N` — no log path, no error context, nothing for
post-mortem.

### Added

- **`Util::execCommandLogged(argv, what, logFile)`** — like
  `execCommand` but redirects child stdout AND stderr to `logFile`
  (open with `O_CREAT | O_APPEND`, mode 0640). On non-zero exit the
  thrown Exception's message includes the log path:
  ```
  exec command: 'install the requested packages into the jail'
    failed with exit status 1 — output captured in
    /var/log/crate/create-myapp.log
  ```
- **`Util::Fs::mkdirIfNotExists(dir, mode)`** — `mkdir(2)` that
  tolerates `EEXIST`; lets callers lazily create shared directories
  like `/var/log/crate` without racing.
- **`lib/log_pure.cpp`** (new): `LogPure::sanitizeName` and
  `LogPure::createLogPath` — filesystem-safe path computation.
  - `sanitizeName` replaces `/`, `\`, NUL with `_`; collapses
    leading dots (`.` and `..` can't be valid log names); empty
    name → `unnamed`.
  - `createLogPath(logsDir, kind, name)` →
    `<logsDir>/<kind>-<sanitized>.log`.

### Changed

- `lib/create.cpp::runChrootCommand` now takes an optional
  `logFile` parameter. When set, it routes through
  `execCommandLogged` and the captured pkg/script output is appended
  to that file.
- `installAndAddPackagesInJail` accepts the log path and threads it
  through every chroot invocation in the function.
- `createCrate` computes the log path from `Config::get().logs`
  (default `/var/log/crate`) and the jail's basename, lazily
  creating the log directory with `mkdirIfNotExists`.

### Lifecycle on failure (recap)

A `pkg` failure now leaves:
- The jail directory **deleted** (existing `RunAtEnd destroyJailDir`
  RAII at lib/create.cpp:447 — unchanged).
- The captured pkg output **preserved** at
  `/var/log/crate/create-<jail>.log` for post-mortem.
- An Exception message that **points to the log path**.

### Added — tests (+11 cases)

`tests/unit/log_pure_test.cpp`:
- `sanitizeName`: passthrough of safe names; replacement of `/`,
  `\`, NUL; collapsing of leading dots; empty → `unnamed`; long
  input passthrough; mid-string dots preserved.
- `createLogPath`: basic shape; sanitisation removes path
  separators (no traversal escape); `kind` distinguishes outputs.

### Verification

- `make build-unit-tests` → 28 binaries built
- `cd tests && kyua test unit` → **431/431 pass** (was 420, +11)

---

## [0.5.6] — 2026-05-01

X11 shared-mode security hardening: the warning is now always
visible (was previously gated behind the verbosity flag), the
`crate validate` warnings list includes it, and the README documents
all five X11 modes with their isolation properties.

### Fixed

- **Security warning for `x11/mode=shared` is now always shown at
  runtime.** Previously the WARN sat under `if (logProgress)` in
  `lib/run_gui.cpp`, so a user running `crate run app.crate` without
  `-p` would silently start a shared-mode container with full
  host-X access. The warning has real security implications and
  must not be gated by a verbosity flag.
- Operators who knowingly accept the risk can suppress the runtime
  warning with `CRATE_X11_SHARED_ACK=1`.

### Added — `crate validate` warnings

`ValidatePure::gatherWarnings` now flags:
- `x11/mode=shared` — explicit shared mode
- `options: [x11]` without `x11/mode` block — implicit shared default

### Added — tests (+3 cases)

`tests/unit/validate_pure_test.cpp`:
- `x11_shared_warns`
- `x11_headless_no_warn` (negative — must NOT warn)
- `x11_option_implicit_shared_warns` (no x11Options block)

### Added — documentation

`README.md` + `README_UK.md` gained an "X11 mode security" section
with a comparison table of the 5 modes (nested/headless/gpu/shared/none),
explanation of why `shared` is dangerous (keystroke leak, window
manipulation, screen capture), and a do/don't YAML example.

### Verification

- `make build-unit-tests` → 27 binaries built
- `cd tests && kyua test unit` → **420/420 pass** (was 417, +3)

---

## [0.5.5] — 2026-05-01

`pkg/add` spec section now works (was a stub returning a "not yet
implemented" error).

### Fixed

- **`pkg/add` is no longer rejected by the spec parser.** The
  underlying executor `installAndAddPackagesInJail()` (lib/create.cpp)
  has actually shipped support for adding pre-built `.txz` packages
  via `pkg add` for a long time — it copies each listed file into
  `/tmp/<basename>` inside the jail and invokes `pkg add`. The spec
  parser was the one rejecting `pkg/add` entries with a
  `not yet implemented` message. Replace the stub with a list parser
  matching `pkg/install`.

### Added — validation

- `Spec::validate()` now requires every `pkg/add` entry to be an
  absolute path. Relative paths are rejected before the jail is
  created, with a clear error.

### Added — tests (+3 cases)

`tests/unit/spec_validate_test.cpp`:
- `pkg_add_relative_path_throws`
- `pkg_add_absolute_path_ok`
- `pkg_add_multiple_one_relative_throws`

### Spec example

```yaml
pkg:
    add:
      - /host/local/pkgs/myapp-1.0.txz
      - /host/local/pkgs/mylib-2.3.txz
```

### Verification

- `make build-unit-tests` → 27 binaries built
- `cd tests && kyua test unit` → **417/417 pass** (was 414, +3)

---

## [0.5.4] — 2026-05-01

Optional **passphrase-based encryption** for `.crate` archives via
`crate export -P <passphrase-file>` and `crate import -P
<passphrase-file>`. Lets operators move container images privately
between hosts — addressing the use case where reproducible
applications travel as `.crate` artefacts.

### Added — encryption envelope

- `lib/crypto_pure.cpp`/`.h` (new): AES-256-CBC + PBKDF2 envelope
  layered on top of the existing tar+xz pipeline using the standard
  `openssl enc` CLI. No new build-time deps — `openssl(1)` is already
  installed on FreeBSD by default.
- New CLI flags:
  - `crate export -P, --passphrase-file <path>`
  - `crate import -P, --passphrase-file <path>`
- Auto-detection on import via magic bytes:
  - `Salted__` prefix (8 bytes) → encrypted, requires `-P`
  - `\xFD7zXZ\x00` xz magic → plain
  - anything else → reject
- Passphrase files are validated: must be a regular non-empty file
  with mode `0600` (owner-only). Loose permissions reject the
  invocation before any work starts.
- Passphrases are passed to `openssl` via `-kfile`, never on the
  command line — so they don't leak via `ps`/`procfs`.

### Security model

- **Confidentiality**: AES-256-CBC with PBKDF2 key derivation (OpenSSL
  default ≈ 10 000 iterations). Per-archive 8-byte random salt.
- **Integrity**: provided by the existing `.sha256` sidecar, which is
  computed over the encrypted ciphertext on export. Out-of-band
  verification of that hash before decryption is the operator's
  responsibility.
- **Authenticity**: not yet provided. Asymmetric signing (ed25519/GPG)
  remains open in TODO.
- The passphrase itself is never embedded in the artefact — same
  passphrase produces a different ciphertext each time (random salt).

### Added — tests (+17 cases)

`tests/unit/crypto_pure_test.cpp`:
- Magic-byte detection: xz/Salted/short/garbage/almost-match.
- File-level detection on real `mkstemp` fixtures (xz / Salted /
  missing).
- Passphrase-file validation: 0600 OK, world-readable rejected,
  group-readable rejected, empty rejected, missing rejected, dir
  rejected.
- argv shape pinned for both encrypt and decrypt invocations,
  including a regression guard that the passphrase is **never**
  passed inline (no `-k`/`-pass`, only `-kfile <path>`).

### Verification

- `make build-unit-tests` → 27 binaries built
- `cd tests && kyua test unit` → **414/414 pass** (was 397, +17)

---

## [0.5.3] — 2026-04-29

Version-string sync. Tag `v0.5.3` was published from the 0.5.2 merge
commit (`aa5e6bf`); the release artefacts are named
`crate-0.5.3-freebsd-*-amd64.tar.xz`, but the source still reported
`0.5.2`. Bump the in-source version strings so `crate --version`,
`port/Makefile` `PORTVERSION`, and the SNMP `crateVersion` MIB scalar
all report `0.5.3` to match the release tag.

No code changes — pure version-string synchronisation.

---

## [0.5.2] — 2026-04-29

`xorg.conf` generator and `crate snapshot list` renderer under test.

### Changed — extracted to pure modules

- `lib/run_gui_pure.cpp`: added `RunGuiPure::generateGpuXorgConf` —
  full headless-GPU `xorg.conf` body builder. Now uses the
  hardened `parseResolution` (so a malformed resolution like
  `"abc"` falls back to `1280x720` instead of throwing via
  `Util::toUInt`).
- `lib/snapshot_pure.cpp` (new): `SnapshotPure::renderTable` for
  `crate snapshot list` output.

### Added — tests (+11 cases)

- `run_gui_pure_test`: 6 new cases for `generateGpuXorgConf`
  (default driver → `dummy`, explicit driver + BusID, NVIDIA
  extras present, no NVIDIA extras for non-NVIDIA, all required
  sections present, garbage resolution falls back to 1280x720).
- `snapshot_pure_test` (new, 5): empty dataset, header presence,
  data columns, multiple rows, long names don't crash padding.

### Verification

- `make build-unit-tests` → 26 binaries built
- `cd tests && kyua test unit` → **397/397 pass** (was 386, +11)

---

## [0.5.1] — 2026-04-29

GUI mode VESA-CVT modeline math + resolution helpers under test.

### Changed — extracted to pure module

- `lib/run_gui_pure.cpp` (new):
  - `RunGuiPure::computeCvtModeline(w, h, refresh)` — VESA CVT v1.1
    reduced-blanking timing calculation. Drives the `xrandr --newmode`
    output for `crate gui` non-default resolutions.
  - `RunGuiPure::resolveResolution(spec)` — picks effective resolution
    from `guiOptions` / `x11Options`, fallback `1280x720`.
  - `RunGuiPure::parseResolution("WxH", w, h)` — `WxH` parser.

### Added — tests (+13 cases)

`tests/unit/run_gui_pure_test.cpp` covers:
- CVT modeline pinned values for 720p/1080p/4K@60Hz; structural
  invariants across 6 common sizes; higher refresh → higher
  pixel clock.
- `resolveResolution` default / `guiOptions` overrides /
  `x11Options` fallback / `guiOptions` wins over `x11Options`.
- `parseResolution` basic / zero rejected / garbage / extra
  chars (leading/trailing whitespace).

### Hardened along the way

`parseResolution` initially relied on `std::stoul`, which silently
skips leading whitespace — so `" 1920x1080"` would parse as valid.
Added explicit checks rejecting whitespace at position 0 and
position-after-`x`. (Same kind of latent bug the 0.4.5 `Util::toUInt`
fix addressed for unsigned overflow.)

### Verification

- `make build-unit-tests` → 25 binaries built
- `cd tests && kyua test unit` → **386/386 pass** (was 373, +13)

---

## [0.5.0] — 2026-04-28

Daemon Bearer-token auth and `crate list` rendering now under unit-test
coverage. Both pieces touched user-facing behaviour that previously had
zero direct tests.

### Changed — extracted to pure modules

- `lib/auth_pure.cpp` (new): `AuthPure::parseBearerToken`,
  `AuthPure::checkTokenRole`, `AuthPure::checkBearerAuth`. The full
  Bearer-token gate from `daemon/auth.cpp` is now in a tiny pure module
  parameterised by an injected `sha256Fn` — production passes
  `OpenSSL::SHA256` indirectly via `daemon/auth.cpp::sha256hex`, tests
  pass an identity-mapping fake. No new CI dependencies needed.
- `lib/list_pure.cpp` (new): `ListPure::renderJson`,
  `ListPure::renderTable` and stream/string variants. The display logic
  for `crate list` (and `crate list -j`) lives here as pure functions
  taking a `vector<Entry>`. `lib/list.cpp` keeps the FreeBSD-jail
  discovery side and forwards to these for output.

### Added — tests (+24 cases)

- `tests/unit/auth_pure_test.cpp` (+15) — Bearer-token parsing
  (basic, empty, just-prefix, wrong-scheme, embedded spaces); role
  gate (unknown hash, viewer-allows-any, admin-required, writer-required,
  admin-as-superset, empty-tokens); end-to-end happy/missing-header/
  wrong-scheme/role-escalation-blocked/admin-superset.
- `tests/unit/list_pure_test.cpp` (+9) — JSON output (empty,
  single entry, comma separator, healthcheck=false); Table output
  (empty, headers, singular/plural footer, dash-for-empty fields,
  `Y/-` healthcheck column).

### Verification

- `make build-unit-tests` → 24 binaries built
- `cd tests && kyua test unit` → **373/373 pass** (was 349, +24)

---

## [0.4.8] — 2026-04-28

Four more small pure helpers extracted, 13 new test cases.

### Changed — extracted to pure modules

- `lib/run_pure.cpp` (new): `RunPure::argsToString` (from `lib/run.cpp`),
  `RunPure::envOrDefault` (from `lib/run_net.cpp`).
- `lib/autoname_pure.cpp` (new): `AutoNamePure::snapshotName` (from
  `lib/snapshot.cpp::autoSnapshotName`), `AutoNamePure::exportName`
  (from `lib/export.cpp::autoExportName`).

The originals are now thin forwarders.

### Added — tests (+13 cases)

- `tests/unit/run_pure_test.cpp` (+8): `argsToString` empty/basic/
  injection-quoting; `envOrDefault` unset/valid/garbage/empty/
  overflow (verifies the 0.4.5 `toUInt` overflow guard does flow
  through to `envOrDefault`).
- `tests/unit/autoname_test.cpp` (+5): `snapshotName` format check
  (15 chars `YYYYMMDDTHHMMSS`), year sanity; `exportName` regex
  match, basename preservation, empty-basename edge case.

### Verification

- `make build-unit-tests` → 22 binaries built
- `cd tests && kyua test unit` → **349/349 pass** (was 336, +13)

---

## [0.4.7] — 2026-04-28

`validateCrateSpec` warning logic now under unit-test coverage. The
`crate validate <spec>` CLI emits warnings for security-relevant
configuration choices (sysvipc, allow_chflags, securelevel < 2, COW
backend implications, X11 nested mode, etc.). A regression that
silently drops a warning ships unannounced risk; this PR pins down
each branch with a dedicated test.

### Changed — extracted to pure module

- The 30+ warning branches inside `validateCrateSpec()` (lib/validate.cpp)
  moved into a new pure helper `ValidatePure::gatherWarnings(spec)` in
  `lib/validate_pure.cpp`. The CLI now just calls that and prints
  what it returns.

### Added — `tests/unit/validate_pure_test.cpp` (+30 cases)

Covers every warning branch:
- ipc/sysvipc, net/lan-with-tor, ipv6 (no-outbound + with-tor)
- limits-without-maxproc (positive + negative)
- encrypted, dns_filter (empty rules + without-net)
- allow_chflags, allow_mlock, securelevel < 2 (positive + negative)
- children_max, cpuset (invalid char + valid)
- COW backend=zfs / mode=persistent
- x11 nested, clipboard isolated (without/with nested)
- dbus session, socket_proxy empty
- firewall (without net + block-no-allow)
- capsicum, mac_bsdextended rules
- terminal devfs_ruleset
- multi-warning sanity check

### Verification

- `make build-unit-tests` → 20 binaries built
- `cd tests && kyua test unit` → **336/336 pass** (was 306, +30)

---

## [0.4.6] — 2026-04-28

`Spec::validate()` now under unit-test coverage — the largest
previously-untested function in the codebase (~200 lines, 30+ branches).

### Changed — extracted to pure module

- **`Spec::validate()`** moved from `lib/spec.cpp` to `lib/spec_pure.cpp`.
  Pulls in: `allOptionsSet` constant, `lst-all-script-sections.h`
  (generated header), and `Config::get()` (declared in
  `lib/config.h`, stubbed for tests).
- **`Spec::NetOptDetails::createDefault`**, **`Spec::TorOptDetails`
  ctor + `createDefault`**, **`Spec::optionNet/optionNetWr/optionTor`**,
  and the `getOptionDetails` template helpers also moved to
  `spec_pure.cpp` so the test suite can construct/inspect Spec
  objects without linking against yaml-cpp-bound `lib/spec.cpp`.

### Added — Config test stub

`tests/unit/_test_config_stub.cpp` provides minimal stubs for
`Config::get`, `Config::load`, `Config::resolveCrateFile`. Returns an
empty `Settings` object so `optNet->networkName` lookups in
`Spec::validate()` always fail with "not found" — exactly the
scenario tests want to assert.

### Added — `tests/unit/spec_validate_test.cpp` (+48 cases)

Covers **every branch** of `Spec::validate()`:
- "must do something": `runCmdExecutable`, `runServices`, or `tor`
- duplicate `pkg-local-override` entries
- absolute-path checks for `runCmdExecutable`, `dirsShare`, `filesShare`
- options whitelist (every documented option) + unknown rejected
- script sections whitelist + empty section rejected
- `inboundPortsTcp/Udp` span consistency
- `networkName` lookup against (empty stub) Config
- mode-specific validation:
  - `bridge`/`passthrough`/`netgraph` need their iface fields
  - `nat` rejects `bridge`/`dhcp`/`static`/`vlan`/`static-mac`/`ip6=slaac|static`
  - non-NAT rejects `inbound-tcp/udp`
  - `gateway` requires static IP
  - `ip6=static` requires address
  - `extra` interfaces require non-NAT primary; `extra mode=nat` rejected
- ZFS dataset names: empty / absolute / `..`
- RCTL limits: known list (~25 names), unknown rejected
- Encryption: method/keyformat/cipher whitelists
- `enforce_statfs` range `0..2`
- Firewall ports `1..65535`
- Terminal `devfs_ruleset` range `0..65535`

### Verification

- `make build-unit-tests` → 19 binaries built
- `cd tests && kyua test unit` → **306/306 pass** (was 258, +48)

---

## [0.4.5] — 2026-04-28

Boundary / adversarial test pass. **Two more real bugs caught and fixed**
— making this the fifth bug found by the tests added in this PR cycle.

### Fixed

- **`Util::toUInt`** silently truncated when the parsed value
  exceeded `UINT_MAX`. On 64-bit platforms `unsigned long` is 64-bit
  but `unsigned` is 32-bit, so e.g. `toUInt("99999999999")` returned
  the low 32 bits instead of throwing. Practical impact: a port-range
  spec like `99999999999` would parse as a random small port. Also
  silently accepted leading-`-` and leading whitespace via `stoul`'s
  permissiveness. Fix: explicit guard against `-`/whitespace and
  range-check the parsed value before casting.
- **`StackPure::parseCidr`** accepted any prefix length — including
  `/64` for IPv4 (silently kept) and `/-1` (parsed by `std::stoul` as
  `ULONG_MAX`). Fix: reject prefixes outside `0..32` and reject leading
  `-`. `/-1` and `/64` now return `false`.

### Changed — extracted to pure module

- `Scripts::escape` moved from `lib/scripts.cpp` to
  `lib/scripts_pure.cpp` (`ScriptsPure::escape`).

### Added — tests (+36 cases)

- `tests/unit/scripts_test.cpp` (+5) — covers `escape` with empty
  input, plain text, single quote, classic injection attempt, and a
  `/bin/sh` round-trip.
- `tests/unit/adversarial_test.cpp` (+31) — boundary/edge tests
  across the existing pure surface:
  - `shellQuote`: 100KB input, 1000 single quotes, embedded null
    bytes, high-byte (0x80–0xFF) bytes
  - `splitString`: only-delimiters, 1000-element split, leading/
    trailing delimiters
  - `Fs::hasExtension`: case sensitivity, dotfile, no-dot
  - `isUrl`: minimum-valid (8 vs 9 chars), uppercase scheme
  - `parseCidr`: 0/32 boundaries, oversize, negative, extra text,
    empty addr/prefix
  - `parsePortRange`: overflow, negative, inverted range
  - `humanBytes`: `UINT64_MAX`, just-below-1K
  - `MibPure`: 1023-byte octet string, empty OID
  - `topoSort`: 100-node chain, fan-out
  - `isLong`: triple-dash, just `--`

### Bug-discovery score so far this PR cycle

| Release | Bug found | Severity |
|---|---|---|
| 0.4.0 | `safePath` accepts `/foo_neighbour` for prefix `/foo` | path-traversal in setuid binary |
| 0.4.0 | `isLong` rejects every long option | every `--help`-style flag broken |
| 0.4.4 | `pathSubstituteVarsInString` infinite loop on `$HOMER` | DoS |
| 0.4.5 | `Util::toUInt` silent truncation past UINT_MAX | wrong port/limits silently accepted |
| 0.4.5 | `parseCidr` accepts impossible prefixes (`/64`, `/-1`) | wrong netmask silently accepted |

### Verification

- `make build-unit-tests` → 18 binaries built
- `cd tests && kyua test unit` → **258/258 pass** (was 222, +36)

---

## [0.4.4] — 2026-04-27

Variable-substitution coverage + a third real bug caught by new tests.

### Fixed

- **`Util::pathSubstituteVarsInString()`** had an infinite loop when
  the input contained a token that matched `$HOME`/`$USER` as a prefix
  but was followed by an alphanumeric (e.g. `"$HOMER"`, `"$USERNAME"`).
  The loop's word-boundary check prevented substitution but did not
  advance the cursor, so `s.find(key)` returned the same offset
  forever. Fixed by walking with an explicit `pos` cursor that
  advances past every match (substituted or not). Caught by the new
  `stringSubst_word_boundary` test, which timed out at 300 s before
  the fix.

### Changed — extracted to pure modules

- `Util::pathSubstituteVarsInPath`, `Util::pathSubstituteVarsInString`
  moved from `lib/util.cpp` to `lib/util_pure.cpp`.
- `substituteVars` moved from `lib/spec.cpp` to `lib/spec_pure.cpp`
  (now `SpecPure::substituteVars`).

### Added — tests (+22 cases)

- `tests/unit/util_subst_test.cpp` (+11 cases) — `pathSubstituteVarsInPath`
  and `pathSubstituteVarsInString` coverage, including the adversarial
  `$HOMER` / `$USERNAME` cases that surfaced the infinite-loop bug.
- `tests/unit/spec_subst_test.cpp` (+11 cases) — `${KEY}` substitution
  used by `crate create --var KEY=VALUE`. Covers empty input, multiple
  keys, repeated tokens, unknown keys, empty values, recursion guard
  (a value containing `${X}` is not re-expanded), adjacent tokens,
  `$X`-without-braces ignored.

### Verification

- `make build-unit-tests` → 16 binaries built
- `cd tests && kyua test unit` → **222/222 pass** (was 200, +22)

---

## [0.4.3] — 2026-04-27

CLI input-validation hardening: 36 new test cases for `Args::validate`.

### Changed

- **`Args::validate()`** moved from `cli/args.cpp` into `cli/args_pure.cpp`
  so it can be linked into unit tests without dragging in
  `cli/args.cpp`'s rang/usage()/exit() dependencies.
- The default `CmdNone` branch now throws `Exception` (via `ERR(...)`)
  instead of calling the static `err()` helper that printed `usage()`
  and `exit(1)`. Net behaviour is the same — `cli/main.cpp`'s catch
  chain prints `e.what()` in red and returns 1 — except that the
  bare `crate` (no args) path no longer prints the usage hint.
- `Util::Fs::fileExists`, `Util::Fs::dirExists`, `Util::Fs::getUserHomeDir`
  moved from `lib/util.cpp` to `lib/util_pure.cpp`. All three are
  POSIX (`stat`, `getpwuid`) so they compile and link on Linux too.

### Added — tests

`tests/unit/args_validate_test.cpp` (+36 cases) exercises every branch
of `Args::validate()`:
- `Create`: empty, spec-only, template-not-found
- `Run`: empty, missing file, existing file
- `Validate`: empty, with spec
- `Snapshot`: each subcommand's required-arg combinations
- `List` / `Clean`: no-arg paths
- Target-only commands (`Info`, `Console`, `Stats`, `Logs`, `Stop`,
  `Restart`): empty + set
- `Gui`: subcommand variations (focus/attach/url/screenshot/resize
  require target; resize requires resolution)
- `Stack`: `up`/`exec` argument requirements
- `CmdNone`: bare-crate path

### Verification

- `make build-unit-tests` → 14 binaries built
- `cd tests && kyua test unit` → **200/200 pass** (was 164, +36)

---

## [0.4.2] — 2026-04-27

Test methodology rollout: every unit test now links against the real
production code. The old "duplicate the function under test into the
test source" pattern is gone. A regression in any extracted helper
will now actually fail the suite.

### Changed — extraction of pure helpers into `*_pure.cpp` modules

| New module | Function(s) extracted from |
|---|---|
| `cli/args_pure.cpp`        | `cli/args.cpp`        — `strEq`, `isShort`, `isLong`, `isCommand` |
| `snmpd/mib_pure.cpp`       | `snmpd/mib.cpp`       — `encodeUint32`, `encodeOid`, `encodeOctetString` |
| `daemon/metrics_pure.cpp`  | `daemon/metrics.cpp`  — `parseRctlUsage` |
| `lib/stack_pure.cpp`       | `lib/stack.cpp`       — `parseCidr`, `ipToString`, `ipFromCidr`, `buildHostsEntries`; templated `topoSort<T>`. Also hosts `isIpv6Address` from `lib/net.cpp`. |
| `lib/spec_pure.cpp`        | `lib/spec.cpp`        — `parsePortRange`; pure methods of `Spec::NetOptDetails` (`allowOutbound`, `allowInbound`, `isNatMode`, `needsIpfw`, `needsDhcp`); `Spec::optionExists`; ctors/dtors for `OptDetails` and `NetOptDetails` |
| `lib/lifecycle_pure.cpp`   | `lib/lifecycle.cpp`   — `humanBytes` |
| `lib/import_pure.cpp`      | `lib/import.cpp`      — `parseSha256File`, `archiveHasTraversal`, `normalizeArchiveEntry` |

Every original `.cpp` keeps a thin forwarder (or `using` declaration)
so existing call sites are unchanged.

### Changed — tests

All 13 unit-test files no longer duplicate the function under test.
They `#include` the appropriate `*_pure.h` and link against the
matching `*_pure.cpp`. Result: every test now exercises the real
production symbol.

### Build

`Makefile` `tests/unit/%` rule links every test against the full set
of pure modules:
```
TEST_LINK_SRCS = lib/util_pure.cpp lib/err.cpp lib/spec_pure.cpp \
                 lib/stack_pure.cpp lib/lifecycle_pure.cpp \
                 lib/import_pure.cpp cli/args_pure.cpp \
                 daemon/metrics_pure.cpp snmpd/mib_pure.cpp
```

`-Icli`/`-Idaemon`/`-Isnmpd` added to test include path so the
respective `*_pure.h` files resolve.

`topoSort` is now a header-only template (`StackPure::topoSort<T>`)
so production and test code share one implementation.

### Notes

- 164/164 kyua unit tests pass on Linux.
- Test-count dropped from 166 (0.4.1) to 164 because two duplicated
  `toUInt` cases that used to live in both `util_test` and `spec_test`
  now live only in `spec_test` (against the real `Util::toUInt`).

---

## [0.4.1] — 2026-04-27

Unit-test methodology fix: tests can now link against the production
code instead of embedding frozen copies of the functions under test.

### Changed

- **Pure helpers extracted from `lib/util.cpp` into `lib/util_pure.cpp`**.
  The platform-independent subset (`filePathToBareName`,
  `filePathToFileName`, `splitString`, `stripTrailingSpace`, `toUInt`,
  `reverseVector`, `shellQuote`, `safePath`, `isUrl`, `Fs::hasExtension`)
  now lives in a separate translation unit with no FreeBSD-specific
  dependencies. Production `crate`/`crated`/`crate-snmpd` still pull
  these in via `LIB_SRCS` (Makefile updated), so behaviour is identical.
- **`lib/util.h`** no longer `#include <rang.hpp>` — the include was
  unused inside the header and blocked unit-test inclusion on Linux
  (no `librang-dev`). Files that use `rang::fg` / `rang::style` now
  include `<rang.hpp>` explicitly (`lib/capsicum_ops.cpp`).
- **`lib/err.h`** no longer `#include <rang.hpp>`. The `WARN(...)` macro
  still uses rang colours; callers that use `WARN` and didn't already
  include `<rang.hpp>` had it added (`lib/{ctx,config,mount,pfctl_ops,
  gui_registry,ipfw_ops,vm_run,vm_stack}.cpp`).
- **Test build rule** now links every test against
  `lib/util_pure.cpp + lib/err.cpp`. Tests can `#include "util.h"` /
  `#include "err.h"` and call the real `Util::shellQuote` etc. instead
  of duplicating the implementation.
- **`tests/unit/util_security_test.cpp`** rewritten to use the real
  `Util::safePath` and `Util::shellQuote` from `lib/util_pure.cpp`.
  This is the proof-of-concept: a regression introduced into
  `safePath` will now fail the suite (versus the previous pattern,
  which only checked a frozen copy in the test source).
- **`tests/unit/err_test.cpp`** rewritten to use the real `Exception`
  class. Adds one new case (`err2_macro_throws_with_message`) that
  exercises the `ERR2` macro directly.

### Notes

- 165/165 kyua unit tests pass on Linux.
- The remaining test files still use the duplicate-the-function
  pattern — they will be migrated incrementally as their target code
  joins `lib/util_pure.cpp` or new pure modules.

---

## [0.4.0] — 2026-04-26

Test-coverage and CLI argument parser hardening release. Two real
bugs were caught by new unit tests during this cycle (one CLI parser,
one path-validation) and fixed in the same commit.

### Security

- **`Util::safePath()`** (lib/util.cpp) — the canonical-path prefix
  guard used a raw string-prefix comparison without requiring a path
  separator after the prefix. With `requiredPrefix = "/var/run/crate"`,
  the path `"/var/run/crate_attacker/payload"` was wrongly accepted as
  inside the prefix. One-line fix: also require
  `canonical[prefix.size()] == '/'`. `crate` is installed setuid root,
  so the impact is real if any caller relies on `safePath()` to scope
  filesystem access.

### Fixed

- **`isLong()`** (cli/args.cpp) — long-option parser had a logically
  impossible loop condition (`!islower || !isdigit`, which always
  evaluates true since no character is *both* lowercase AND a digit).
  Result: every long option (`--help`, `--log-progress`, command-level
  `--help`, etc.) returned `nullptr` from `isLong()` and silently fell
  through to "unknown argument". The CLI worked only for the few options
  with explicit `strEq` checks before `isLong` (`--no-color`,
  `--version`, `--use-pkgbase`, `--var`). Fix accepts `[a-z0-9-]+`,
  matching the documented surface.

### Added — tests

Added 6 new unit-test files, **83 new ATF cases**, all passing.
Total kyua suite: **165/165** (was 82).

| File | Cases | Covers |
|---|---|---|
| `snmpd_mib_test`      | 14 | AgentX wire encoders byte-exact vs RFC 2741 |
| `daemon_metrics_test` |  9 | `parseRctlUsage` parser |
| `stack_test`          | 17 | `ipFromCidr`, `buildHostsEntries`, `topoSort` (cycles, duplicates, missing deps, diamond, disconnected) |
| `util_security_test`  | 11 | `safePath` traversal guard + `shellQuote` injection escaping (with `/bin/sh` round-trip) |
| `import_test`         | 14 | `.sha256` parsing (BSD/GNU formats), tar-listing `..` detection, archive entry normalisation |
| `cli_args_test`       | 18 | `strEq`, `isShort`, `isLong`, `isCommand` |

### Added — build

- `make build-unit-tests` — builds every unit-test binary without
  running anything (handy when CI builds as user but runs kyua as root).
- `make coverage` — gcov/lcov instrumented build + HTML report at
  `coverage-html/index.html`. Note: tests embed local copies of the
  functions under test, so the report measures coverage of the test-
  local copies — useful for spotting un-exercised branches in test
  logic, less useful as production-code coverage.
- `.github/workflows/{linux-unit,freebsd-build-lite}.yml` now drive
  the test build through the Makefile (`make test-unit` /
  `gmake build-unit-tests`) so adding a new test takes a single edit
  (`UNIT_TESTS` in `Makefile`) instead of three (Makefile + Kyuafile +
  workflow).

---

## [0.3.15] — 2026-04-22

Full FreeBSD build restoration. After the 0.3.0 firewall rewrite,
the new CI matrix (14.2 + 15.0, full `gmake crate`) surfaced a
large backlog of latent compile/link issues that had been hidden
by the old CI (which only built a subset of files). This patch
release fixes every one of them so `gmake crate`, `gmake crated`,
and `gmake crate-snmpd` succeed cleanly on both FreeBSD versions.

### Added
- `.github/workflows/release.yml` — on tag push, builds on FreeBSD
  14.2 + 15.0 and attaches `crate-<ver>-freebsd-<rel>-amd64.tar.xz`
  (with SHA256) as GitHub Release assets. Previously the Release
  page only had auto-generated source tarballs.
- Release tarball layout: `bin/crate`, `sbin/crated`,
  `sbin/crate-snmpd`, `man/man5/crate.5.gz`,
  `share/snmp/mibs/CRATE-MIB.txt`, `crated.conf.sample`,
  `crated.rc`, `README.md`, `LICENSE`, `CHANGELOG.md`.
- `cpp-httplib` added to CI `pkg install` for the `crated` daemon.

### Fixed — missing system headers (FreeBSD 14.2 / 15.0 clang)
- `run_jail.cpp` — add `<sys/param.h>` before `<sys/jail.h>` (for
  `MAXPATHLEN`, `MAXHOSTNAMELEN`); add `<sys/wait.h>` for
  `WIFSIGNALED`/`WIFEXITED`/`WEXITSTATUS`; add `<signal.h>` for
  `SIGKILL`.
- `jail_query.cpp` — add `<sys/param.h>` before `<sys/jail.h>`.
- `zfs_ops.cpp` — add `<sys/wait.h>` for `waitpid`.
- `capsicum_ops.cpp` — add `<sys/socket.h>`, `<netinet/in.h>`,
  `<arpa/inet.h>`, `<syslog.h>`.
- `ifconfig_ops.cpp`, `stack.cpp` — add `<netinet/in.h>` for
  `struct in_addr`/`sockaddr_in`.
- `stack.cpp` — add `<sys/socket.h>` for `AF_INET`.
- `mac_ops.cpp` — add `<sys/param.h>` + `<sys/mount.h>` for
  `fsid_t` / `struct statfs`.
- `netgraph_ops.cpp` — add `<sys/socket.h>` before netgraph
  headers (for `sa_family_t`).
- `daemon/main.cpp` — add `<fcntl.h>` for `::open()`.
- `import.cpp` — add `<iomanip>` for `std::setprecision`.
- `snmpd/collector.h`, `snmpd/mib.cpp` — add `<cstdint>` for
  `uint8_t`/`uint16_t`/`uint32_t`/`uint64_t`.

### Fixed — language / standards issues
- `cli/args.cpp`, `lib/stack.cpp` — wrap raw `std::stoul` /
  `std::stoi` to throw `Exception` via `ERR2` instead of leaking
  `std::invalid_argument`/`std::out_of_range` (continuation of
  0.3.0 Util::toUInt fix).
- `run_net.h`, `run_jail.h`, `run_gui.h`, `run_services.h`,
  `pfctl_ops.h` — replace `const class Spec &spec` in-namespace
  forward declarations with proper `#include "spec.h"`. The
  in-namespace form silently created `RunNet::Spec` etc. instead
  of referencing the global `::Spec`.
- `lib/spec.h` + `lib/spec.cpp` — add `Spec` copy constructor
  and copy-assignment with deep-copy of 13 `unique_ptr` members.
  Required by `preprocess()` and `mergeSpecs()`. Previously
  silently relied on compiler-specific copy-elision behaviour.
- `lib/spec.h` — add missing `RestartPolicy` struct + `unique_ptr`
  member that were referenced in the parser but never declared.
- `lib/spec.cpp` — include `servicesAutoStart` field in copy
  constructor (was silently defaulted to `true` on copy).
- `ctx.h`, `gui_registry.h` — move `FwUsers` / `FwSlots` /
  `GuiRegistry` default constructors from `private` to `public`.
  FreeBSD 15.0 libc++ (clang 19) enforces that `std::make_unique`
  requires a public constructor.
- `lib/stack.cpp`, `lib/vm_spec.cpp` — fix yaml-cpp temp-ref
  binding (`auto &x = node["key"]`) → `auto x = ...`.
- `ipfw_ops.cpp` — remove explicit `op->ctxid = 0`. The `ctxid`
  field only exists in FreeBSD 15.0+ `ip_fw3_opheader`; callers
  already zero the struct with `memset`.
- `daemon/auth.cpp`, `daemon/routes.cpp`, `daemon/server.cpp` —
  define `CPPHTTPLIB_OPENSSL_SUPPORT` before `#include <httplib.h>`
  in every translation unit that uses httplib (ODR violation
  otherwise — different `httplib::Server` layout).
- `daemon/auth.h` — change forward declaration of `httplib::Request`
  from `class` to `struct` (`-Wmismatched-tags`).
- `run_gui.cpp` — guard `X11Ops::getResolution()` call with
  `#ifdef HAVE_X11` (was unconditional but `x11_ops.cpp` only
  compiles with `WITH_X11`).
- `cli/args.cpp` — remove `const` from scalar return type
  (`-Wignored-qualifiers`).
- `lib/spec.cpp` — add braces around ambiguous `if ... ERR ...` /
  `for` block (`-Wmisleading-indentation`).

### Fixed — linker
- `Makefile` — add `-lnetgraph` (NgMkSockNode etc.), `-lmd`
  (SHA256_Data), `-lpthread` (std::thread) to base `LIBS`. These
  are transitively required by always-compiled lib/ files.

### Fixed — tests
- `tests/functional/crate_info_test` — change shebang from
  `#!/bin/sh` to `#!/usr/bin/env atf-sh`. ATF shell functions
  (`atf_test_case`, `atf_check`) require the atf-sh interpreter;
  plain `sh` produced no ATF protocol output and kyua reported
  "broken: Invalid header for test case list".

### Removed — dead / non-functional code
- `RunNet::setupPfAnchor()` — never called; superseded by
  `PfctlOps::loadContainerPolicy()` introduced in 0.3.0.
- `PfctlOps::addNatRule()`, `PfctlOps::addRdrRule()`,
  `IpfwOps::addNatForJail()`, `IpfwOps::addPortForward()` — never
  called.
- `MacOps::nativeAddRule()` / `nativeRemoveRule()` ioctl path (79
  lines): `MAC_BSDEXTENDED_ADD_RULE` / `_REMOVE_RULE` are not
  defined in any public FreeBSD header, and `/dev/ugidfw` does
  not exist on stock FreeBSD. The `ugidfw(8)` command fallback
  is preserved and is the correct interface.
- `lib/stack.cpp::updateStackDns()` — defined but never called.
- `lib/clean.cpp::getRunningJailJids()`, `pidAlive()` — defined
  but never called.
- Duplicate `fwSlotSize` / `fwRuleRangeOutBase` statics in
  `lib/run.cpp` — single source of truth is `run_net.cpp`.

### Verification
- 39/39 non-FreeBSD files pass `-Wall -Wextra -Werror=reorder
  -Werror=return-type -Werror=mismatched-tags`.
- 16 FreeBSD-only files compile on FreeBSD CI (require
  `<sys/jail.h>`, `<libzfs.h>`, `<libpfctl.h>`, etc.).
- 82/82 kyua unit tests pass on both Linux (libatf) and FreeBSD.

---

## [0.3.1] — 2026-04-19

### Fixed
- **Build error in full `gmake crate`**: `const class Spec &spec`
  forward declarations inside `RunNet`, `RunJail`, `RunGui`,
  `RunServices` namespaces created `RunNet::Spec` (etc.) instead of
  referencing the global `::Spec`, causing "member access into
  incomplete type" errors. Replaced with proper `#include "spec.h"`
  in all five headers (`run_net.h`, `run_jail.h`, `run_gui.h`,
  `run_services.h`, `pfctl_ops.h`). This bug was hidden by the old
  CI (which compiled only 5 files) and surfaced once the new
  `freebsd-build.yml` ran the full `gmake crate`.

---

## [0.3.0] — 2026-04-19

### Added
- **Per-container firewall policy** — full IPv4+IPv6 support:
  - IPv6 outbound rules consolidated into `RunNet::setupFirewallRules()`
    (previously inline in `run.cpp`).
  - IPv6 inbound port forwarding via `ipfw fwd` (global IPv6 addresses,
    no NAT needed).
  - Unified cleanup lambda handles both IPv4 and IPv6 rule deletion.
- **`PfctlOps::loadContainerPolicy()`** — single authoritative place to
  build per-container pf rules from `spec.firewallPolicy`, with dual
  IPv4/IPv6 output.
- **Neighbor-safe firewall operations**:
  - `pfctl -s Anchors` probe on first use — `WARN` if
    `anchor "crate/*"` is missing from `/etc/pf.conf`.
  - `ipfw nat N show` probe before `configureNat()` — `WARN` on
    collision with other jail managers.
  - `CRATE_IPFW_RULE_BASE_IN`, `CRATE_IPFW_RULE_BASE_OUT`,
    `CRATE_IPFW_SLOT_SIZE` environment variables override the default
    ipfw rule ranges (10000 / 50000 / 10) so operators can avoid
    collisions with bastille/appjail/custom rulesets.
  - `PfLock` RAII (`O_EXLOCK` on `/var/run/crate/pfctl.lock`) serializes
    concurrent pfctl operations from parallel `crate run` processes.
- **CI workflows**:
  - `linux-unit.yml` — ~30 s unit-test job on `ubuntu-latest` using
    `kyua` + `libatf-dev` from Ubuntu universe.
  - `freebsd-build-lite.yml` — fast smoke check on feature branches.
  - `freebsd-build.yml` — full gated build (matrix 14.2 + 15.0) on
    master / PRs / weekly cron, with artifact upload.
- `make test-unit` target — runs `kyua test unit` (skips FreeBSD-only
  `functional/crate_info_test`), enabling local Linux development.

### Changed
- **`Util::toUInt()`** now wraps `std::stoul` and converts
  `std::invalid_argument` / `std::out_of_range` into the project's
  `Exception` via `ERR2`. No more raw stdlib exceptions leaking from
  YAML config parsing.
- Applied the same wrapping idiom across **9 additional call sites**:
  `cli/args.cpp` (logs/stop/restart timeout args), `lib/stack.cpp`
  `parseCidr()`, `lib/net.cpp` netmask, `lib/run_net.cpp` epair+CIDR,
  `lib/run_gui.cpp` resolution, `lib/lifecycle.cpp` rctl output,
  `snmpd/main.cpp` `-i interval`, `lib/spec.cpp` `children_max`,
  `lib/ctx.cpp` pid-file reader.
- `PfctlOps::flushRules()` and `IpfwOps::deleteNat()` now emit `WARN`
  on failure instead of silently swallowing exceptions.

### Removed
- Dead code: `RunNet::setupPfAnchor()` (never called, superseded by
  inline code in `run.cpp` which is now in `PfctlOps::loadContainerPolicy`).
- Dead code: `PfctlOps::addNatRule()`, `PfctlOps::addRdrRule()` — never
  called from anywhere in the tree.
- Dead code: `IpfwOps::addNatForJail()`, `IpfwOps::addPortForward()` —
  never called from anywhere in the tree.
- Duplicate `fwSlotSize` / `fwRuleRangeOutBase` statics in `run.cpp`
  (single source of truth is now `run_net.cpp`, configurable via env).

### Fixed
- Failing ATF tests `parsePortRange_invalid_throws`,
  `toUInt_empty_throws`, `toUInt_negative_throws`,
  `toUInt_trailing_chars_throws` (expected `std::runtime_error` but
  received `std::invalid_argument` from unwrapped `stoul`).

---

## [0.2.5] — 2026-03-07

### Added
- **Native FreeBSD API wrappers** — replace fork+exec shell commands with
  direct library calls where available:
  - `lib/jail_query.{cpp,h}` — libjail `jailparam_*` API replaces `jls(8)` parsing
  - `lib/zfs_ops.{cpp,h}` — libzfs/libzfs_core replaces `zfs(8)` commands
  - `lib/ifconfig_ops.{cpp,h}` — libifconfig replaces `ifconfig(8)` commands
  - `lib/pfctl_ops.{cpp,h}` — libpfctl replaces `pfctl(8)` commands
  - `lib/mac_ops.{cpp,h}` — ugidfw ioctl + `sysctlbyname()` replaces `ugidfw(8)`
  - `lib/ipfw_ops.{cpp,h}` — ipfw wrapper (native `IP_FW3` planned)
  - `lib/capsicum_ops.{cpp,h}` — libcasper for `cap_enter()`, `cap_dns`, `cap_syslog`
  - `lib/netgraph_ops.{cpp,h}` — `PF_NETGRAPH` socket replaces `ngctl(8)`
  - `lib/nv_protocol.{cpp,h}` — libnv nvlist IPC over Unix socket
  - `lib/vm_spec.{cpp,h}` — YAML parsing for `type: vm` (bhyve) spec
  - `lib/vm_run.{cpp,h}` — libvirt bhyve driver for VM lifecycle
  - `lib/vnc_server.{cpp,h}` — libvncserver embedded VNC (replaces x11vnc fork)
  - `lib/x11_ops.{cpp,h}` — libX11/XRandR for display management
  - `lib/drm_session.{cpp,h}` — libseat for DRM session without suid
- `JailExec` namespace — `jail_attach()` with automatic `jexec(8)` fallback
- Compile-time feature flags: `HAVE_LIBZFS`, `HAVE_LIBIFCONFIG`,
  `HAVE_LIBPFCTL`, `HAVE_CAPSICUM`, `WITH_LIBVIRT`, `WITH_LIBVNCSERVER`,
  `WITH_X11`, `WITH_LIBSEAT`
- All wrappers fall back to shell commands when compiled without optional flags

### Changed
- `list.cpp` — use `JailQuery::getAllJails()` instead of `jls -N` parsing
- `info.cpp` — use `JailQuery` for jail lookup + `JailExec` for in-jail commands
- `console.cpp` — use `JailQuery` for container resolution
- `clean.cpp` — use `JailQuery::getAllJails()` for running jail enumeration
- `export.cpp` — use `JailQuery` for container resolution
- `run.cpp` — use `JailQuery`, `JailExec`, `ZfsOps`, `MacOps` throughout
- `run_jail.cpp` — use `ZfsOps::jailDataset()`/`unjailDataset()`
- `run_net.cpp` — use `IfconfigOps`, `NetgraphOps`, `PfctlOps`
- `snapshot.cpp` — use `ZfsOps` for all ZFS snapshot operations
- `util.cpp` — delegate `isZfsEncrypted()`/`isZfsKeyLoaded()` to `ZfsOps`
- Makefile updated with optional library flags and P2-P4 source files

---

## [0.2.4] — 2026-03-07

### Fixed
- `spec.cpp` — remove dead `listOrScalarOnly()` call before `ERR` in pkg/add handler
- `run_gui.cpp` — X11 shared mode security warning now respects `logProgress` flag
  and no longer produces double output
- `config.cpp` — silent `catch(...)` blocks now emit `WARN()` messages for
  config parsing errors (system config, drop-in fragments, user config)

### Added
- `snmpd/mib.cpp` — AgentX stub warning at startup

---

## [0.2.3] — 2026-03-06

### Added
- `--var KEY=VALUE` command-line substitution for spec variables
- Healthcheck support (`healthcheck:` spec section) with configurable
  retries, interval, timeout, and start period
- `depends:` spec section for container dependency ordering
- `crate stack` command for multi-container orchestration
- Healthcheck runtime — background monitoring, retry reporting, service-only
  crate health loop
- Enhanced `crate list` with ports, mounts, and healthcheck columns
- URL fetch support for remote crate archives
- `base_container:` spec section for ZFS-clone-based container templates
- jailrun (hyphatech) comparison analysis in `docs/research/`

### Fixed
- Healthcheck retry counter off-by-one
- Timeout enforcement missing on healthcheck commands
- SIGINT handler typo in service-only crate run loop

### Changed
- Comparison docs moved to `docs/research/`

---

## [0.2.2] — 2026-03-05

### Added
- **Networking expansion** (7 phases):
  - Bridge mode with DHCP and static IP (Phase 1)
  - Static MAC address generation and VLAN support (Phase 2)
  - Passthrough mode for direct NIC assignment (Phase 3)
  - Netgraph mode with ng_bridge + eiface (Phase 4)
  - IPv6 SLAAC and static IPv6 support (Phase 5)
  - Multiple interfaces via `extra[]` config (Phase 6)
  - System config defaults and network mode templates (Phase 7)
- Named networks in system config `/usr/local/etc/crate.conf`
- `/usr/local/etc/crate.d/` drop-in config fragment support
- `loader.conf` tunable comment for VNET/VIMAGE sysctl
- Comprehensive `TODO-IMPROVEMENTS.md`

### Changed
- README.md and README_UK.md fully rewritten
- crate.5 manpage updated with new networking modes
- Docs: compatibility section — FreeBSD 13.0+ supported

---

## [0.2.1] — 2026-03-04

### Added
- **crate-snmpd** — AgentX SNMP subagent with CRATE-MIB (F3)
- **crate-hub** — multi-host aggregator dashboard skeleton (F4)
- **crated** — REST API daemon skeleton (F1)
- **libcrate.a** — extracted shared library from monolithic binary (F0)
- GUI session manager for multi-container display switching
  - GPU headless mode, 7 GUI mode example configs
- `gui` command (11th subcommand)

### Fixed
- 9 bugs in GUI manager — security, correctness, reliability
- 6 issues in GPU headless mode
- Duplicated jail/networking code removed, uses RunNet/RunJail modules
- Export/import commands wired into build and dispatch
- License corrected: ISC → BSD 3-Clause in docs

---

## [0.2.0] — 2026-03-03

### Added
- **Phase 1**: IPC controls, RCTL resource limits, `crate validate` command
- **Phase 2**: ZFS snapshots, encrypted containers, DNS filtering,
  security hardening
- **Phase 3**: COW filesystem (ZFS + unionfs), templates, X11 isolation
  (shared/nested/headless/gpu), D-Bus isolation, managed services, socket proxy
- **Phase 4**: PF firewall anchors, Capsicum/MAC stubs, template merging,
  clipboard proxy, terminal isolation
- **Phase 5**: FreeBSD 15.0 compatibility — version-mismatch detection
- **Phase 6**: Code cleanup, pkgbase support, dynamic ipfw rule allocation
- `list`, `info`, `clean`, `console`, `export`, `import` commands
- IPv6 pass-through networking
- Security hardening — securelevel, children.max, cpuset
- UX improvements — `NO_COLOR`, `--version`, shell completions
- Modularized `run.cpp` into `run_net.cpp`, `run_jail.cpp`, `run_gui.cpp`,
  `run_services.cpp`
- 3-tier config: system → drop-in → user YAML

---

## [0.1.x] — 2024–2025 (pre-fork history)

### Added
- Core jail containerization with `jail_setv()` / `jail_remove()`
- VNET networking with epair + ipfw NAT
- Crate archive format (tar.xz with `+CRATE.SPEC`)
- Variable substitution in scripts (`$HOME`, `$USER`)
- Examples: qbittorrent, qbittorrent+tor
- GitHub Actions CI for FreeBSD build testing
- FreeBSD 15.0 jail descriptor API (`JAIL_OWN_DESC`)

### Security
- Command injection hardening — exec-based process execution
- USER env spoofing prevention — `getpwuid(getuid())`
- Directory traversal validation for shared dirs/files
- RAII resource cleanup (`RunAtEnd`, `UniqueFd`)
- SIGINT/SIGTERM signal handling for clean jail shutdown
- Unpredictable jail directory names (random hex)

### Fixed
- Build fix for FreeBSD 11.3 (`_WITH_GETLINE`)
- `sys/jail.h` C++ safety with `extern "C"` wrapper
- Resource leaks — RAII popen, strdup in mount, pointer in ctx
- Base.txz URL for releases vs snapshots
