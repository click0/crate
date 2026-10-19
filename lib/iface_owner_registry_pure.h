// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Interface -> owner registry — pure data + serde (1.1.43).
//
// An epair half belongs to whoever's create_epair made it. Until now the
// interface-named privops verbs (configure_iface's ifname, teardown_iface,
// bridge_add_member / bridge_del_member's member, reclaim_iface_from_vnet,
// set_iface_up, disable_iface_offload, set_iface_inet_addr, set_iface_mac)
// were host-global: any privops-group member could tear down another
// tenant's epair, pull it off the bridge, or move a HOST NIC into their
// own vnet. This registry gives the authz gate the missing answer, the
// same way lib/jid_owner_registry_pure.h does for jids.
//
// Pure: in-memory map + stable on-disk text form. The side-effectful
// wrapper (file I/O, mutex, live probe) is lib/iface_owner_registry.{h,cpp}.
//
// On-disk format: one entry per line, two tab-separated columns:
//
//     <ifname>\t<uid>\n
//
// Blank lines and lines starting with `#` are ignored; any other
// malformed line fails the whole parse (fail closed, like the jid file).

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>

namespace IfaceOwnerRegistryPure {

// ifname -> operator uid. std::map keeps the serialized form stable.
using EntryMap = std::map<std::string, uint32_t>;

std::string serialize(const EntryMap &entries);
bool parse(const std::string &text, EntryMap &out, std::string &err);

// "epair<N>a" / "epair<N>b" (N decimal, at least one digit, no leading
// junk). Only epair halves are ever recorded: they are the one kind of
// interface a tenant legitimately creates. Anything else a per-user
// caller names (em0, bridge0, lagg0, vlan…) is host state.
bool isEpairName(const std::string &name);

// The other half of an epair: "epair3a" <-> "epair3b". Empty when
// `name` is not an epair name.
std::string peerHalf(const std::string &name);

// The host-visible half ("epair<N>a") for either half; empty when not
// an epair. Reconciliation probes this one: the b half usually lives
// inside a jail's vnet and is invisible to the host's interface list,
// so its liveness is that of the pair.
std::string hostHalf(const std::string &name);

// Drop every entry whose pair is gone. `isLive(ifname)` is the daemon's
// probe (true iff the interface exists on the host); it is asked about
// hostHalf(entry) so both halves share one answer. Returns the number
// of entries erased.
using LiveProbe = std::function<bool(const std::string &ifname)>;
size_t reconcile(EntryMap &entries, const LiveProbe &isLive);

} // namespace IfaceOwnerRegistryPure
