// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_authz_pure.h"

namespace PrivOpsAuthzPure {

namespace {

// Shared body for datasetOwned / pathOwned: `value` is the prefix root
// itself, or a slash-anchored descendant "<prefix>/...". Slash-anchored
// so "<prefix>extra" does not pass as "<prefix>".
//
// 1.1.27: when the prefix ALREADY ends in '/', that separator has been
// consumed by the prefix itself, so value[prefix.size()] is the first
// char of the child name, not a '/'. The old unconditional check then
// rejected every descendant — the same trailing-slash bug fixed in
// Util::safePath in 1.1.25. Demand the separator only when the prefix
// does not supply it.
bool ownedUnder(const std::string &value, const std::string &prefix) {
  if (prefix.empty()) return true;   // no per-user split → nothing to gate
  if (value == prefix) return true;  // the prefix root itself
  bool prefixEndsWithSep = prefix.back() == '/';
  return value.size() > prefix.size()
      && value.compare(0, prefix.size(), prefix) == 0
      && (prefixEndsWithSep || value[prefix.size()] == '/');
}

} // anon

bool datasetOwned(const std::string &dataset, const std::string &zfsPrefix) {
  return ownedUnder(dataset, zfsPrefix);
}

bool pathOwned(const std::string &path, const std::string &pathPrefix) {
  // Kept as a separate helper so each call-site reads as "is this PATH
  // inside the per-user path prefix" rather than reusing the dataset
  // spelling.
  return ownedUnder(path, pathPrefix);
}

OwnerLookup nullLookup() {
  OwnerLookup l;
  l.byJid  = [](unsigned)              { return Owner{}; };
  l.byName = [](const std::string &)   { return Owner{}; };
  l.byPath = [](const std::string &)   { return Owner{}; };
  return l;
}

namespace {

// Centralized jid/name ownership probe. Returns Allow if the lookup
// reports unknown (bootstrap concession) or matches env.uid; otherwise
// returns the appropriate deny code.
Decision checkOwnedJid(unsigned jid, const PerUserEnvPure::Env &env,
                       const OwnerLookup &lookup) {
  if (!lookup.byJid) return Decision::Allow;
  Owner o = lookup.byJid(jid);
  if (!o.known) return Decision::Allow;          // unknown jid -> bootstrap
  return o.uid == env.uid ? Decision::Allow : Decision::DenyForeignJid;
}

// 1.1.40: strict variant for exec_in_jail. Running a command as root
// inside a jail is the most powerful verb there is; the bootstrap
// concession (unknown jid -> Allow) that lets older/root-created jails
// keep working for set_rctl & co. would here let any privops-group
// member exec into the host admin's containers. A jid the registry
// does not know is therefore denied, and a missing registry (lookup
// not wired) denies too.
Decision checkOwnedJidStrict(unsigned jid, const PerUserEnvPure::Env &env,
                             const OwnerLookup &lookup) {
  if (!lookup.byJid) return Decision::DenyUnownedJid;
  Owner o = lookup.byJid(jid);
  if (!o.known) return Decision::DenyUnownedJid;
  return o.uid == env.uid ? Decision::Allow : Decision::DenyForeignJid;
}

// 1.1.43: interface-named verbs. Without an iface registry (byIface
// null) behaviour is unchanged — host-wide. With one: only epair halves
// may be named by a per-user caller (anything else is host state ->
// DenyHostIface); a half registered to someone else is denied; an
// unregistered half gets the same bootstrap Allow as an unknown jid
// (epairs created before 1.1.43 or by root).
Decision checkOwnedIface(const std::string &ifname, const PerUserEnvPure::Env &env,
                         const OwnerLookup &lookup) {
  if (!lookup.byIface) return Decision::Allow;
  if (!isEpairIfaceName(ifname)) return Decision::DenyHostIface;
  Owner o = lookup.byIface(ifname);
  if (!o.known) return Decision::Allow;
  return o.uid == env.uid ? Decision::Allow : Decision::DenyForeignIface;
}

Decision checkOwnedName(const std::string &name,
                        const PerUserEnvPure::Env &env,
                        const OwnerLookup &lookup) {
  if (!lookup.byName) return Decision::Allow;
  Owner o = lookup.byName(name);
  if (!o.known) return Decision::Allow;
  return o.uid == env.uid ? Decision::Allow : Decision::DenyForeignJailName;
}

// Path-scoped verbs (mount/unmount target, devfs mount_path).
//
// 1.1.35: the registry hit decides when there is one; when there is
// none the old rule was "Allow" (bootstrap concession for jails that
// pre-date the registry). With a per-user path split configured that
// concession let a tenant aim mount_nullfs / unmount (MNT_FORCE) /
// devfs at any host directory (/etc, /var/db/crate — the registry
// itself), at another tenant's STOPPED rootfs (destroy_jail forgets
// the entry, so the tree on disk becomes "unknown"), or at the host
// /dev. Now, when env.pathMasterPrefix is set, an unknown path is
// allowed only inside the caller's own slice (env.pathPrefix). With no
// per-user split configured the single-trust-domain model applies and
// the bootstrap Allow stands.
Decision checkOwnedPath(const std::string &path,
                        const PerUserEnvPure::Env &env,
                        const OwnerLookup &lookup) {
  Owner o = lookup.byPath ? lookup.byPath(path) : Owner{};
  if (o.known)
    return o.uid == env.uid ? Decision::Allow : Decision::DenyForeignPath;
  if (env.pathMasterPrefix.empty()) return Decision::Allow;   // not configured
  return pathOwned(path, env.pathPrefix) ? Decision::Allow
                                         : Decision::DenyUnownedPath;
}

// 1.1.17: a mount_nullfs SOURCE is "foreign" when it lies inside the
// per-user tenant root (env.pathMasterPrefix) but NOT inside the
// caller's own slice (env.pathPrefix). Host paths and GUI runtime
// sockets (/tmp/.X11-unix, the host Wayland/PulseAudio sockets, …)
// fall outside the tenant root entirely and are allowed — privops is
// a single trust domain w.r.t. the host; this gate only enforces
// tenant-vs-tenant isolation. Unconfigured deployment (empty
// pathMasterPrefix) -> nothing to gate.
bool sourceForeign(const std::string &source, const PerUserEnvPure::Env &env) {
  if (env.pathMasterPrefix.empty()) return false;       // opt-in
  return pathOwned(source, env.pathMasterPrefix)        // under the tenant root
      && !pathOwned(source, env.pathPrefix);            // but not the caller's
}

} // namespace

Decision authorize(PrivOpsPure::Verb v,
                   const Request &req,
                   const PerUserEnvPure::Env &env,
                   const OwnerLookup &lookup) {
  using V = PrivOpsPure::Verb;
  switch (v) {
    case V::AttachZfs:
    case V::DetachZfs: {
      if (!datasetOwned(req.dataset, env.zfsPrefix))
        return Decision::DenyForeignDataset;
      // 1.1.36: the jid end too — a caller could otherwise attach its
      // own dataset to, or detach one from, another tenant's jail.
      return checkOwnedJid(req.jid, env, lookup);
    }

    // 1.1.36: pf anchor verbs. crate's per-jail anchors are
    // "crate/<kernel jail name>", so the anchor carries an ownership
    // signal exactly like destroy_jail's `name`: a tenant must not
    // flush or inject into another tenant's anchor. Anything that is
    // not a per-jail crate anchor (the root "crate", nested or foreign
    // anchors) is host state a tenant has no business touching.
    case V::AddPfRule:
    case V::RemovePfRule:
    case V::FlushPfAnchor: {
      const std::string jail = anchorJailName(req.anchor);
      if (jail.empty()) return Decision::DenyForeignAnchor;
      Decision d = checkOwnedName(jail, env, lookup);
      return d == Decision::DenyForeignJailName ? Decision::DenyForeignAnchor : d;
    }

    case V::SetLoginclassRctl:
    case V::ClearLoginclassRctl:
      // env.loginclass is the caller's crate-<uid> umbrella (always
      // populated for uid > 0). An empty or foreign request loginclass
      // can't match, so it's denied — fail closed.
      return req.loginclass == env.loginclass
                 ? Decision::Allow
                 : Decision::DenyForeignLoginclass;

    // jid-scoped verbs gated against the registry (1.1.13).
    // 1.1.17: configure_iface joins the group — it carries a `jid` and
    // jexec's ifconfig INSIDE that jail + moves a host iface into its
    // vnet, so naming a foreign jid is a cross-tenant operation, not a
    // host-global one (it was wrongly in the default Allow arm).
    case V::SetRctl:
    case V::ClearRctl:
    case V::SetJailCpuset:
    case V::QueryJailRctl:
    case V::SignalJail:
    case V::AcquireFwLease:    // 1.1.57: the lease is the jail's
    case V::ReleaseFwLease:
      return checkOwnedJid(req.jid, env, lookup);

    // 1.1.43: configure_iface gates BOTH ends — the jid (1.1.17) and
    // the interface being moved into it: a per-user caller may only
    // move its own epair half, never a host NIC (that was the
    // "passthrough any NIC into my vnet" hole).
    case V::ConfigureIface: {
      Decision d = checkOwnedJid(req.jid, env, lookup);
      if (d != Decision::Allow) return d;
      return checkOwnedIface(req.ifname, env, lookup);
    }

    // 1.1.43: interface-named verbs. teardown_iface / set_iface_up /
    // disable_iface_offload / set_iface_inet_addr / set_iface_mac act on
    // "ifname"; bridge_*_member on "member" (the dispatcher copies the
    // right field into req.ifname). The bridge itself stays shared.
    case V::TeardownIface:
    case V::SetIfaceUp:
    case V::DisableIfaceOffload:
    case V::SetIfaceInetAddr:
    case V::SetIfaceMac:
    case V::BridgeAddMember:
    case V::BridgeDelMember:
      return checkOwnedIface(req.ifname, env, lookup);

    // 1.1.40: exec_in_jail — jid-scoped, but fail closed on an
    // unregistered jid (see checkOwnedJidStrict).
    case V::ExecInJail:
      return checkOwnedJidStrict(req.jid, env, lookup);

    // Name-scoped verb. The jail name itself is brand-new and there's
    // nothing in the registry to compare against on create; the gate
    // for create_jail is below (path-prefix). destroy_jail gates on
    // the name — it must be one this caller created.
    // 1.1.17: reclaim_iface_from_vnet joins the name-scoped group — it
    // names a jail (`jail_name`) and pulls an iface OUT of that jail's
    // vnet, so naming a foreign jail steals/DoSes its networking. Was
    // wrongly in the default Allow arm.
    case V::DestroyJail:
      return checkOwnedName(req.jailName, env, lookup);

    // 1.1.43: reclaim gates the jail name (1.1.17) AND the interface
    // being pulled out of it.
    case V::ReclaimIfaceFromVnet: {
      Decision d = checkOwnedName(req.jailName, env, lookup);
      if (d != Decision::Allow) return d;
      return checkOwnedIface(req.ifname, env, lookup);
    }

    // 1.1.15: create_jail's brand-new path must fall inside the
    // caller's per-user path prefix (cfg.pathMasterPrefix/<uid>). When
    // the deployment didn't configure pathMasterPrefix, env.pathPrefix
    // is empty and pathOwned() Allows — same opt-in shape as the ZFS
    // gate (cfg.zfsMasterPrefix). This is the last narrow item from
    // the 1.1.x trust-model open gap.
    case V::CreateJail:
      return pathOwned(req.path, env.pathPrefix)
                 ? Decision::Allow
                 : Decision::DenyForeignCreatePath;

    // 1.1.14: path-scoped verbs. The dispatcher fills req.path from
    // the right libnv field per verb:
    //   mount_nullfs / unmount_nullfs -> "target"  (must lie under
    //                                     an owned jail's path)
    //   apply_devfs_ruleset / add_devfs_unhide_rule -> "mount_path"
    //                                     (typically <jailPath>/dev)
    // An unknown path (no registry hit) is allowed — same bootstrap
    // concession as the jid/name gate (jails predating 1.1.13 aren't
    // in the registry).
    case V::UnmountNullfs:
    case V::ApplyDevfsRuleset:
    case V::AddDevfsUnhideRule:
    case V::ApplyDevfsRules:   // 1.1.62
      return checkOwnedPath(req.path, env, lookup);

    // 1.1.17: mount_nullfs gates BOTH ends — the target (must be inside
    // an owned jail, like 1.1.14) AND the source (must not reach into
    // another tenant's space). Previously only the target was checked,
    // so an operator could bind-mount another tenant's prefix into
    // their own jail and read it.
    case V::MountNullfs: {
      Decision td = checkOwnedPath(req.path, env, lookup);
      if (td != Decision::Allow) return td;
      return sourceForeign(req.source, env)
                 ? Decision::DenyForeignSource
                 : Decision::Allow;
    }

    default:
      // Remaining host-global verbs (teardown_iface, set_iface_up,
      // bridge_*, add_ipfw_rule, configure_ipfw_nat, create_epair, …)
      // operate on shared host state with no tenant-specific target
      // the daemon can resolve today, so they stay host-wide —
      // consistent with privops being a single trust domain for the
      // host. The iface-named ones (configure_iface ifname/bridge,
      // teardown_iface, bridge_*_member, reclaim's iface) DO carry a
      // tenant signal but need an iface→owner registry fed by
      // create_epair to gate it; tracked in TODO.
      return Decision::Allow;
  }
}

bool isEpairIfaceName(const std::string &name) {
  static const std::string kPrefix = "epair";
  if (name.size() < kPrefix.size() + 2) return false;
  if (name.compare(0, kPrefix.size(), kPrefix) != 0) return false;
  size_t i = kPrefix.size();
  const size_t digitsStart = i;
  while (i < name.size() && name[i] >= '0' && name[i] <= '9') i++;
  if (i == digitsStart || i != name.size() - 1) return false;
  return name[i] == 'a' || name[i] == 'b';
}

std::string anchorJailName(const std::string &anchor) {
  static const std::string kPrefix = "crate/";
  if (anchor.size() <= kPrefix.size()) return "";
  if (anchor.compare(0, kPrefix.size(), kPrefix) != 0) return "";
  std::string rest = anchor.substr(kPrefix.size());
  if (rest.find('/') != std::string::npos) return "";   // nested deeper
  return rest;
}

Decision authorize(PrivOpsPure::Verb v,
                   const std::string &dataset,
                   const std::string &loginclass,
                   const PerUserEnvPure::Env &env) {
  Request r;
  r.dataset    = dataset;
  r.loginclass = loginclass;
  return authorize(v, r, env, nullLookup());
}

const char *decisionReason(Decision d) {
  switch (d) {
    case Decision::Allow:
      return "allow";
    case Decision::DenyForeignDataset:
      return "dataset is outside the caller's per-user ZFS prefix";
    case Decision::DenyForeignLoginclass:
      return "loginclass is not the caller's crate-<uid> umbrella";
    case Decision::DenyForeignJid:
      return "jid is owned by a different operator";
    case Decision::DenyForeignJailName:
      return "jail name is owned by a different operator";
    case Decision::DenyForeignPath:
      return "path lies inside a jail owned by a different operator";
    case Decision::DenyForeignCreatePath:
      return "create_jail path is outside the caller's per-user path prefix";
    case Decision::DenyForeignSource:
      return "mount source lies inside another operator's per-user path prefix";
    case Decision::DenyUnownedPath:
      return "path is neither inside a jail owned by the caller nor inside the caller's per-user path prefix";
    case Decision::DenyForeignAnchor:
      return "pf anchor is not a crate/<jail> anchor of a jail owned by the caller";
    case Decision::DenyUnownedJid:
      return "jid is not registered to the caller (exec_in_jail requires a jail created through privops by the same operator)";
    case Decision::DenyForeignIface:
      return "interface is an epair half created by a different operator";
    case Decision::DenyHostIface:
      return "interface is not an epair half; host interfaces cannot be named by a per-user caller";
  }
  return "deny";
}

} // namespace PrivOpsAuthzPure
