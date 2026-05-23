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

  // 0.9.23: atomic host-side iface ops needed by `crate run`'s
  // setupBridgeEpair flow. The 0.9.0 ConfigureIface verb is the
  // composite "move + config + bridge attach" path; these atomic
  // verbs are the host-side primitives operators chain manually
  // when they need finer control. Targets the `IfconfigOps::setUp`
  // and `IfconfigOps::disableOffload` call sites in lib/run_net.cpp.
  SetIfaceUp,
  DisableIfaceOffload,

  // 0.9.24: bridge membership ops. Symmetric pair around
  // IfconfigOps::bridgeAddMember / bridgeDelMember. The 0.9.6
  // composite ConfigureIface verb embeds bridgeAddMember when
  // its `bridge` field is non-empty, but only for the
  // computed-pair-A pattern (epair host-side). These atomic
  // verbs target run_net.cpp's setupBridgeEpair (add) and
  // destroyBridgeEpair (del) where the iface to attach is
  // operator-supplied directly.
  BridgeAddMember,
  BridgeDelMember,

  // 0.9.25: set host-side IPv4 address on a non-jail iface.
  // Wraps IfconfigOps::setInetAddr (three-arg primitive:
  // iface + addr + prefixLen). Targets the run_net.cpp
  // createEpair flow where the host-side epair-A end gets a
  // /31 IP after the jail-side epair-B is moved into the jail.
  SetIfaceInetAddr,

  // 0.9.26: create epair pair. First response-data verb —
  // returns the kernel-assigned A/B iface names. Wraps
  // IfconfigOps::createEpair() (no inputs; output is a pair
  // of strings). Targets run_net.cpp::createEpair (line 117)
  // and setupBridgeEpair (line 396) where the existing code
  // unpacks `auto epairPair = IfconfigOps::createEpair();`.
  CreateEpair,

  // 0.9.28: per-loginclass RCTL rules. Wraps
  // `rctl -a loginclass:crate-<uid>:KEY:deny=VAL` semantics
  // (PerUserRctlPure::loginclassName generates the loginclass).
  // The set_rctl verb (0.9.0) is jail-scoped; this is the
  // umbrella variant that aggregates resource use across all
  // of a single operator's jails — alice can't exceed her
  // total memoryuse cap regardless of how many jails she
  // spawns.
  SetLoginclassRctl,
  ClearLoginclassRctl,

  // 1.0.5: reclaim a host iface from a jail's vnet (inverse of the
  // ConfigureIface-move path). Wraps `ifconfig <iface> -vnet <jail>`.
  // Targets the run_net.cpp::reclaimPassthroughInterface call site
  // where a passthrough interface is moved back to the host before
  // the jail is destroyed.
  ReclaimIfaceFromVnet,

  // 1.1.0: flush a pf anchor. Symmetric companion to AddPfRule
  // (0.9.0). Targets the run.cpp jail-teardown path where
  // PfctlOps::flushRules is called to clear the per-jail anchor.
  FlushPfAnchor,

  // 1.1.1: first read-side verb that returns command output.
  // `rctl -u jail:<jid>` is privileged on FreeBSD; rootless
  // `crate inspect` previously swallowed the failure via
  // try/catch and silently dropped the RCTL section. This
  // verb hands the read to crated and returns the textual
  // output for client-side parsing via InspectPure.
  QueryJailRctl,

  // 1.1.8: configure an ipfw NAT instance.
  // `ipfw nat <number> config <body>` — body holds the
  // `redirect_port` rules and other NAT instance settings.
  // Sibling to AddIpfwRule (which handles `ipfw add ...`);
  // needed because lib/run_net.cpp's auto-fw setup creates a
  // NAT instance before adding rules that point to it.
  ConfigureIpfwNat,

  // 1.1.9: bind a jail's processes to a CPU set.
  // Wraps `cpuset -l <cpuset> -j <jid>`. Targets the
  // `crate run` path's `spec.cpuset` application (lib/run.cpp).
  // No teardown verb — cpuset binding evaporates with the
  // jail (destroyJail handles the rest).
  SetJailCpuset,

  // 1.1.10: apply a devfs ruleset to a jail's /dev mount.
  // Runs `devfs -m <mount> ruleset <N>` followed by
  // `devfs -m <mount> rule applyset` (the two are paired —
  // setting the ruleset is meaningless without applyset).
  // Targets terminal isolation in lib/run.cpp.
  ApplyDevfsRuleset,

  // 1.1.10 (same release): add a `path <P> unhide` devfs rule
  // to a jail's /dev mount, then applyset. Used by the GUI
  // auto-unhide path in lib/run.cpp that exposes /dev/dri/* for
  // GPU-accelerated jails. Restricted to `unhide` action to
  // keep the attack surface narrow — `hide`, `unhide`,
  // `mode`, `group`, `user` are the only devfs rule actions,
  // and only `unhide` has a sensible privops use case.
  AddDevfsUnhideRule,

  // 1.1.11: send a signal to all processes in a jail.
  // Wraps `jexec <jid> /bin/kill -<signal> -1`. Targets the
  // graceful-stop path in lib/lifecycle.cpp (SIGTERM then
  // SIGKILL). The signal name is whitelisted. Without this,
  // rootless `crate stop` can't signal jail processes and
  // always falls through to the full stop-timeout + forced
  // destroy_jail.
  SignalJail,
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

// 0.9.23: atomic single-iface ops.
struct SetIfaceUpReq {
  std::string ifname;
};

struct DisableIfaceOffloadReq {
  std::string ifname;
};

// 0.9.24: bridge membership ops. Both validate via existing
// validateIfaceName for both `bridge` and `member` fields.
struct BridgeAddMemberReq {
  std::string bridge;   // bridge interface name (e.g. "bridge0")
  std::string member;   // member interface name (e.g. "epair0a")
};

struct BridgeDelMemberReq {
  std::string bridge;
  std::string member;
};

// 0.9.25: set host-side IPv4 address on a non-jail iface.
struct SetIfaceInetAddrReq {
  std::string ifname;
  std::string addr;       // IPv4 address (no /prefix here; bare addr)
  unsigned    prefixLen = 32;  // 0..32
};

// 0.9.26: create epair pair. No request fields — kernel picks
// the next free unit number (epair<N>a / epair<N>b).
struct CreateEpairReq {
};

// 0.9.28: per-loginclass RCTL rules. Loginclass is the umbrella
// "crate-<uid>" generated by PerUserRctlPure; key + value
// validate via the same RetunePure whitelist as SetRctl.
struct SetLoginclassRctlReq {
  std::string loginclass;   // e.g. "crate-1000"
  std::string key;           // RCTL key (validated via RetunePure)
  std::string rawValue;      // value (validated via RetunePure)
};

struct ClearLoginclassRctlReq {
  std::string loginclass;
  std::string key;
};

// 1.0.5: reclaim a host iface from a jail's vnet. Inverse of
// the ConfigureIface "move" path. Inputs are validated like
// ifname (no shell metachars) and a jail name (same charset
// as PoolPure::validatePoolName).
struct ReclaimIfaceFromVnetReq {
  std::string ifname;      // host iface currently inside the jail
  std::string jailName;    // jail that holds the iface
};

// 1.1.0: flush a pf anchor. Anchor is validated like
// PoolPure::validatePoolName (slashes allowed for "crate/<jail>"
// nested form).
struct FlushPfAnchorReq {
  std::string anchor;
};

// 1.1.1: query RCTL usage for a running jail by jid.
struct QueryJailRctlReq {
  unsigned jid = 0;          // jail id (validated 1..65535)
};

// 1.1.8: configure an ipfw NAT instance. The `config` field is
// the textual body following `ipfw nat <number> config` — e.g.
// "ip 192.168.1.1" or "redirect_port tcp 10.0.0.1:80 192.168.1.1:80".
// Validated like validateRuleText (no newlines, no shell metas).
struct ConfigureIpfwNatReq {
  unsigned    number = 0;     // NAT instance 1..65534
  std::string config;
};

// 1.1.9: bind a jail's processes to a CPU set. `cpuset` is the
// cpuset(1) list syntax — comma-separated cpu IDs and ranges
// (e.g., "0-3", "0,2,4-7"). Validated charset is digits, comma,
// hyphen only.
struct SetJailCpusetReq {
  unsigned    jid = 0;
  std::string cpuset;
};

// 1.1.10: apply a devfs(8) ruleset to a jail's /dev mount.
// `mountPath` is the absolute path of the jail's /dev mount;
// `ruleset` is the numeric ruleset identifier (1..65535).
struct ApplyDevfsRulesetReq {
  std::string mountPath;
  unsigned    ruleset = 0;
};

// 1.1.10: add a `path <P> unhide` rule to a jail's devfs mount,
// then `rule applyset`. The path pattern is validated for the
// limited charset devfs(8) actually accepts in a `path` glob —
// alnum, dot, slash, hyphen, underscore, asterisk.
struct AddDevfsUnhideRuleReq {
  std::string mountPath;
  std::string pathPattern;     // e.g. "dri" or "dri/*"
};

// 1.1.11: send a signal to every process in a jail. `signal` is
// the bare signal name (no "SIG" prefix, no number) and is
// whitelisted to the set crate's lifecycle path actually uses.
struct SignalJailReq {
  unsigned    jid = 0;
  std::string signal;          // "TERM", "KILL", "HUP", "INT"
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
std::string validateSetIfaceUp(const SetIfaceUpReq &r);
std::string validateDisableIfaceOffload(const DisableIfaceOffloadReq &r);
std::string validateBridgeAddMember(const BridgeAddMemberReq &r);
std::string validateBridgeDelMember(const BridgeDelMemberReq &r);
std::string validateSetIfaceInetAddr(const SetIfaceInetAddrReq &r);
std::string validateCreateEpair(const CreateEpairReq &r);
std::string validateSetLoginclassRctl(const SetLoginclassRctlReq &r);
std::string validateClearLoginclassRctl(const ClearLoginclassRctlReq &r);
std::string validateReclaimIfaceFromVnet(const ReclaimIfaceFromVnetReq &r);
std::string validateFlushPfAnchor(const FlushPfAnchorReq &r);
std::string validateQueryJailRctl(const QueryJailRctlReq &r);
std::string validateConfigureIpfwNat(const ConfigureIpfwNatReq &r);
std::string validateSetJailCpuset(const SetJailCpusetReq &r);
std::string validateApplyDevfsRuleset(const ApplyDevfsRulesetReq &r);
std::string validateAddDevfsUnhideRule(const AddDevfsUnhideRuleReq &r);
std::string validateSignalJail(const SignalJailReq &r);

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
