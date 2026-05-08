// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the privileged-operations contract — the verbs
// that crated will eventually accept from a non-setuid `crate(1)`
// over the existing control-socket plane (see daemon/control_socket_pure.h).
//
// 0.9.0 is the first release of the rootless track (TODO,
// "Rootless containers"). The track removes the setuid root bit
// from `crate(1)` and delegates privileged operations to a daemon
// (`crated`) running as root.
//
// This release does NOT change behaviour. It only declares the
// contract:
//
//   - the enum of verbs the daemon must support
//   - per-verb request structs (concrete fields, no shell-strings)
//   - per-verb validators (`validate(req) -> "" | reason`)
//
// Subsequent 0.9.x releases will:
//   - add wire-format parsers (JSON over the existing control socket)
//   - add daemon-side dispatch + handler functions, one verb per
//     release, starting with the simplest (set_rctl) and ending
//     with the broadest (create_jail)
//   - wire `crate(1)` to dispatch to crated, behind an opt-in
//     setting, so legacy setuid deployments keep working during
//     the transition
//   - flip the default in 0.9.9, remove the setuid bit in 1.0.0
//
// Why a pure-types module first:
//   - committing the verb set up-front means the wire format,
//     daemon handlers, and crate(1) callers can be developed
//     against a frozen contract instead of chasing a moving target
//   - per-verb validators run on BOTH sides — the caller validates
//     before sending (fail fast, clean error messages), the daemon
//     re-validates on receive (defence in depth — never trust the
//     caller's input even if the caller is our own binary; future
//     callers may include third-party tooling)
//   - the validators are hard-link-tested at the pure-module level
//     so the security boundary stays covered as crated grows
//
// Naming: a "PrivOp" is one privileged action, named with a verb
// (CreateJail, MountNullfs, ...). Each verb has a request struct
// (e.g. `CreateJailReq`) holding the inputs the daemon needs, and
// a free function `validate(req)` returning "" on success or a
// human-readable reason. We do NOT define response structs in this
// release — the response shape is wire-format territory and lands
// with the JSON parsers in 0.9.1.
//

#include <cstdint>
#include <string>
#include <vector>

namespace PrivOpsPure {

// --- Verb taxonomy ---

// One value per privileged operation. The set is closed: the
// daemon refuses any verb not in this list. New verbs require
// adding here, adding a request struct, adding a validator, and
// adding a handler in the daemon — four-step intentional surface
// growth, not "any operation crated can do".
enum class Verb {
  Unknown = 0,

  // Lifecycle of the jail itself (jail(8), jail.conf rules).
  CreateJail,
  DestroyJail,

  // Filesystem mounts inside a jail's chroot prefix.
  // Today implemented inline in lib/run.cpp via mount(8); the
  // rootless refactor moves these to a daemon RPC so an unprivileged
  // crate(1) can request them.
  MountNullfs,
  UnmountNullfs,

  // RCTL accounting and limits. The set/get split mirrors `rctl
  // -a` (add) and `rctl -u` (usage dump).
  SetRctl,
  ClearRctl,

  // ZFS dataset attachment to a jail. `zfs jail <jid> <dataset>`.
  AttachZfs,
  DetachZfs,

  // VNET interface configuration: epair pair creation, bridge
  // membership, IP/IPv6 assignment.
  ConfigureIface,
  TeardownIface,

  // Firewall rule injection. Today crate(1) writes to /etc/pf.conf
  // fragments and runs pfctl(8) directly; rootless moves this to
  // crated which validates each rule before applying.
  AddPfRule,
  RemovePfRule,
  AddIpfwRule,
  RemoveIpfwRule,
};

// Returns the verb's canonical wire-format token (lowercase, no
// underscores in the public name? — actually we use snake_case to
// match the existing /api/v1/ control-plane convention). E.g.
// CreateJail -> "create_jail". Returns "unknown" for Verb::Unknown
// or any unhandled value.
const char *verbName(Verb v);

// Reverse of verbName(). Returns Verb::Unknown for any unknown
// token. Case-sensitive: wire format is canonical lowercase.
Verb parseVerb(const std::string &name);

// --- Per-verb request structs ---

struct CreateJailReq {
  std::string name;            // jail name (alnum + ._-, <=64 chars)
  std::string path;            // absolute jail prefix path
  std::string hostname;        // jail hostname (RFC 1123-ish)
  bool        vnet = false;    // allocate vnet (vs. inherit host stack)
  std::string parameters;      // optional jail.conf fragment, validated separately
};

struct DestroyJailReq {
  std::string name;            // jail name
  bool        force = false;   // jail -R semantics: kill running processes
};

struct MountNullfsReq {
  std::string source;          // absolute host path (must exist, no `..`)
  std::string target;          // absolute target path under the jail prefix
  bool        readOnly = true; // default RO; spec must explicitly opt into RW
};

struct UnmountNullfsReq {
  std::string target;          // absolute target path
  bool        force = false;   // umount -f
};

struct SetRctlReq {
  long        jid = -1;        // jail ID, must be >= 1
  std::string key;              // RCTL resource key (validated via RetunePure)
  std::string rawValue;         // value (validated via RetunePure)
};

struct ClearRctlReq {
  long        jid = -1;
  std::string key;
};

struct AttachZfsReq {
  long        jid = -1;
  std::string dataset;          // pool/path/...
};

struct DetachZfsReq {
  long        jid = -1;
  std::string dataset;
};

struct ConfigureIfaceReq {
  long        jid = -1;          // target jail (epair B half goes inside)
  std::string ifname;            // interface name in jail (e.g. "epair0b")
  std::string bridge;             // bridge to attach the host-side half to
  std::string ipv4Cidr;           // optional, may be empty
  std::string ipv6Cidr;           // optional, may be empty
  std::string macAddr;            // optional explicit MAC, may be empty
};

struct TeardownIfaceReq {
  std::string ifname;             // host-side epair name to destroy
};

struct AddPfRuleReq {
  std::string anchor;              // pf anchor name (validated like pool name)
  std::string ruleText;             // rule body — validated to be one line, no shell metas
};

struct RemovePfRuleReq {
  std::string anchor;
  std::string ruleText;             // exact-match removal
};

struct AddIpfwRuleReq {
  unsigned    set = 0;              // ipfw set 0..31
  unsigned    number = 0;           // rule number 1..65534
  std::string action;                // "allow", "deny", "skipto", "nat", ...
  std::string body;                  // remainder of the rule, validated
};

struct RemoveIpfwRuleReq {
  unsigned    set = 0;
  unsigned    number = 0;
};

// --- Per-verb validators ---
//
// Each `validate*(req)` returns "" on success, otherwise a one-line
// human-readable reason. Validators are deterministic and have no
// side effects (no syscalls, no logging) so they can be called
// from both `crate(1)` (pre-flight) and `crated` (post-receive)
// with identical results.

std::string validateCreateJail(const CreateJailReq &r);
std::string validateDestroyJail(const DestroyJailReq &r);
std::string validateMountNullfs(const MountNullfsReq &r);
std::string validateUnmountNullfs(const UnmountNullfsReq &r);
std::string validateSetRctl(const SetRctlReq &r);
std::string validateClearRctl(const ClearRctlReq &r);
std::string validateAttachZfs(const AttachZfsReq &r);
std::string validateDetachZfs(const DetachZfsReq &r);
std::string validateConfigureIface(const ConfigureIfaceReq &r);
std::string validateTeardownIface(const TeardownIfaceReq &r);
std::string validateAddPfRule(const AddPfRuleReq &r);
std::string validateRemovePfRule(const RemovePfRuleReq &r);
std::string validateAddIpfwRule(const AddIpfwRuleReq &r);
std::string validateRemoveIpfwRule(const RemoveIpfwRuleReq &r);

// --- Field-level validators (exposed for tests + reuse) ---
//
// These are the building blocks the per-verb validators compose
// against. Exposed because:
//   1. tests can lock down each rule individually
//   2. future verbs can reuse without copy-paste
//   3. the daemon's wire-parser (0.9.1) will reuse them on the
//      raw JSON fields before constructing request structs

// Jail name: alnum + ._-, <=64 chars, not "." or "..".
std::string validateJailName(const std::string &name);

// Hostname: RFC 1123-ish — labels of alnum + hyphen, dots between,
// total <=253 chars. Empty allowed (jail inherits parent host).
std::string validateHostname(const std::string &h);

// Absolute path: starts with /, no `..` segments, no shell metas,
// <=1024 chars.
std::string validateAbsolutePath(const std::string &p);

// ZFS dataset: alnum + ._-/, <=255 chars, no leading or doubled /,
// no shell metas. The pool prefix is operator-supplied so we don't
// hardcode it here; the daemon's per-user pool ACL gates access.
std::string validateZfsDataset(const std::string &ds);

// Interface name: <=15 chars (IFNAMSIZ - 1), alnum + ._-,
// non-empty.
std::string validateIfaceName(const std::string &name);

// MAC address: 6 hex octets separated by `:` or `-`. Empty allowed
// (caller may want kernel-assigned MAC). Multicast bit (0x01) in
// the first octet rejected as a foot-gun.
std::string validateMacAddress(const std::string &mac);

// IPv4 CIDR: dotted quad + /<0..32>. Empty allowed.
std::string validateIpv4Cidr(const std::string &cidr);

// IPv6 CIDR: colon-hex + /<0..128>. Empty allowed.
std::string validateIpv6Cidr(const std::string &cidr);

// Single line of pf or ipfw rule text: no newlines, no shell metas
// dangerous to fragments (`; \` ` $`), <=1024 chars.
std::string validateRuleText(const std::string &text);

// pf anchor name: alnum + ._-, <=64 chars (matches pool naming).
std::string validateAnchorName(const std::string &name);

// ipfw action keyword: closed set ("allow", "deny", "skipto",
// "nat", "fwd", "count", "check-state", "reset"). Case-sensitive.
std::string validateIpfwAction(const std::string &action);

} // namespace PrivOpsPure
