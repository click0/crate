// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate vm-wrap` — the FreeBSD-flavoured analogue
// of Firecracker's jailer pattern. crate does NOT manage the bhyve
// VM lifecycle here. vm-wrap only builds the *enclosure* (a vnet
// jail with allow.vmm + a tight devfs ruleset + an optional
// delegated ZFS dataset) so a future bhyve user-space CVE lands the
// attacker in an empty jail instead of on the host. See
// docs/bhyve-jailer.md for the threat model.
//
// The runtime side (lib/vmwrap.cpp) feeds an operator-supplied
// (vmName, jailName, [dataset], [tap], [nmdm]) tuple through these
// helpers and emits three artefacts:
//   1. a devfs ruleset block to paste into /etc/devfs.rules
//   2. a jail.conf fragment to drive `jail -c -f`
//   3. the suggested `jexec ... bhyve ...` invocation hint
//
// Default mode is print-only — no system files are touched. With
// --output-dir <DIR> each artefact lands in a separately-named
// file so the operator integrates them on their own terms (the
// jail.conf may need to merge into an existing config; the devfs
// snippet must be added to /etc/devfs.rules by hand because
// service devfs(8) only reads that one file).
//

#include <string>
#include <vector>

namespace VmWrapPure {

struct WrapSpec {
  std::string vmName;       // bhyve VM name; appears in /dev/vmm/<vmName>
  std::string jailName;     // FreeBSD jail name for the enclosure
  std::string dataset;      // optional ZFS dataset to delegate via `zfs jail`; empty = none
  int         tap   = -1;   // tap index to expose (e.g. 42 -> /dev/tap42); -1 = none
  int         nmdm  = -1;   // nmdm pair index (e.g. 0 -> nmdm0A/B); -1 = none
  std::string jailPath;     // optional jail path; empty -> "/" (host root, vm-bhyve convention)
  unsigned    rulesetNum = 0; // devfs ruleset number; 0 -> derive from jailName
};

// --- Validators (return empty string on success) ---

// Operator-supplied bhyve VM name. Must be non-empty, alphanumeric
// + dash + underscore, no leading dash or dot, length 1..63. This
// is what bhyve(8) uses verbatim for /dev/vmm/<n> so we mirror the
// bhyve(8) constraints.
std::string validateVmName(const std::string &n);

// FreeBSD jail name. Same alphabet as VM name (jail(8) imposes
// similar limits in practice). Length 1..63.
std::string validateJailName(const std::string &n);

// ZFS dataset path: pool[/dataset]+. Allowed alphabet:
// [A-Za-z0-9_./-]; first char must be alpha; no `..` segments;
// no leading/trailing slash. Empty string is allowed (no
// delegated dataset).
std::string validateDataset(const std::string &d);

// tap index 0..9999, or -1 for "none". The /dev/tap<N> name is
// what jail(8) maps into the vnet via `vnet.interface=tap<N>`.
std::string validateTap(int n);

// nmdm pair index 0..9999, or -1 for "none".
std::string validateNmdm(int n);

// devfs ruleset number 1..65535 (0 isn't a valid ruleset index in
// kernel but we reserve it as the "derive from jailName" sentinel
// in WrapSpec; deriveRulesetNum() never returns 0).
std::string validateRulesetNum(unsigned n);

// One-shot: walk the WrapSpec and return the first failure or "".
std::string validateSpec(const WrapSpec &s);

// --- Derivations ---

// Pick a stable, deterministic ruleset number from the jail name so
// re-running with the same jail name doesn't churn /etc/devfs.rules.
// Range: 100..199 to leave room for the operator's own rulesets and
// avoid the well-known low (1..7) numbers shipped in
// /etc/defaults/devfs.rules. Two jail names can collide on the
// same ruleset number; the operator can override via
// WrapSpec.rulesetNum if that happens.
unsigned deriveRulesetNum(const std::string &jailName);

// Default jail path when WrapSpec.jailPath is empty: "/" (host
// root). vm-bhyve uses the same default — the tight devfs ruleset
// + vnet + allow.vmm bound the blast radius without needing a
// populated chroot.
std::string defaultJailPath(const std::string &jailName);

// --- Builders (deterministic strings) ---

// devfs.rules ruleset block. The leading [name=N] line declares
// the ruleset; subsequent `add path ... unhide` lines whitelist
// the device nodes the jail is allowed to see. Anything else
// stays hidden by `devfsrules_hide_all`.
std::string buildDevfsRuleset(const WrapSpec &s);

// jail.conf fragment. vnet on, allow.vmm on, allow.raw_sockets
// off, allow.sysvipc off, exec.start runs nothing (bhyve is
// launched from outside via jexec), devfs_ruleset = <num>.
std::string buildJailConfFragment(const WrapSpec &s);

// argv for `service devfs restart` — used by future --apply mode.
std::vector<std::string> buildDevfsReloadArgv();

// argv for `jail -c -f <fragmentPath>` — used by future --apply mode.
std::vector<std::string> buildJailCreateArgv(const std::string &fragmentPath);

// argv for `zfs jail <jailName> <dataset>` — used by future --apply mode.
std::vector<std::string> buildZfsJailArgv(const std::string &jailName,
                                          const std::string &dataset);

// Suggested `jexec <jailName> bhyve …` invocation, multi-line for
// readability. Operator edits to taste — we don't run this.
std::string buildBhyveInvocationHint(const WrapSpec &s);

} // namespace VmWrapPure
