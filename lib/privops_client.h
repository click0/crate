// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Client-side helpers for the libnv privops transport
// (0.9.15, rootless track).
//
// 0.9.14 added the daemon-side listener that accepts nvlist
// privops requests over /var/run/crate/crated-privops.sock and
// dispatches via getpeereid-extracted operator uid. This module
// is the *client* counterpart that crate(1) uses to actually
// send those requests.
//
// Architecture:
//
//   crate retune --rctl pcpu=20 myjail
//     │
//     ├─ legacy path (default): exec rctl(8) directly (needs root,
//     │  uses setuid bit) — UNCHANGED in 0.9.15
//     │
//     └─ privops path (opt-in, NEW): if a usable privops socket
//        is detected, build a FieldMap, connect, send nvlist,
//        parse response. Operator's uid is captured server-side
//        via getpeereid. crate(1) doesn't need root for this
//        path.
//
// Detection: env var CRATE_PRIVOPS_SOCKET takes priority; else
// the well-known path /var/run/crate/crated-privops.sock if it
// exists; else "" (no socket — fall back to legacy exec).
//
// Pure split: this module owns both the testable request-builder
// surface (FieldMap construction) and the impure send/recv
// (FreeBSD-only). Linux dev/CI builds compile the request
// builders + tests; the wire send/recv is #ifdef'd out.
//

#include "privops_nv_pure.h"

#include <string>

namespace PrivOpsClient {

// --- Detection ---

// Resolve the socket path crate(1) should use:
//   1. $CRATE_PRIVOPS_SOCKET if non-empty
//   2. /var/run/crate/crated-privops.sock if it exists (S_IFSOCK)
//   3. "" if neither
//
// Empty return signals "fall back to legacy exec path".
// The detection is side-effect-free except for one stat(2);
// callers cache the result.
std::string detectSocketPath();

// --- Pure request builders ---
//
// Construct the FieldMap that the daemon-side listener walks. One
// builder per privops verb; tests pin down the field set so a
// future verb signature change can't drift between the two
// transports.
//
// Caller fills `out` by overwriting; never partial-fill on error
// because pure builders don't fail (validation lives in
// PrivOpsPure::validate*, called daemon-side after parse).

PrivOpsNvPure::FieldMap buildSetRctl(long jid,
                                     const std::string &key,
                                     const std::string &rawValue);

PrivOpsNvPure::FieldMap buildClearRctl(long jid,
                                       const std::string &key);

PrivOpsNvPure::FieldMap buildAttachZfs(long jid,
                                       const std::string &dataset);
PrivOpsNvPure::FieldMap buildDetachZfs(long jid,
                                       const std::string &dataset);

PrivOpsNvPure::FieldMap buildMountNullfs(const std::string &source,
                                         const std::string &target,
                                         bool readOnly);
PrivOpsNvPure::FieldMap buildUnmountNullfs(const std::string &target,
                                           bool force);

PrivOpsNvPure::FieldMap buildConfigureIface(long jid,
                                            const std::string &ifname,
                                            const std::string &bridge,
                                            const std::string &ipv4Cidr,
                                            const std::string &ipv6Cidr,
                                            const std::string &macAddr);
PrivOpsNvPure::FieldMap buildTeardownIface(const std::string &ifname);

PrivOpsNvPure::FieldMap buildAddPfRule(const std::string &anchor,
                                       const std::string &ruleText);
PrivOpsNvPure::FieldMap buildRemovePfRule(const std::string &anchor,
                                          const std::string &ruleText);

PrivOpsNvPure::FieldMap buildAddIpfwRule(unsigned set, unsigned number,
                                         const std::string &action,
                                         const std::string &body);
PrivOpsNvPure::FieldMap buildRemoveIpfwRule(unsigned set, unsigned number);

PrivOpsNvPure::FieldMap buildCreateJail(const std::string &name,
                                        const std::string &path,
                                        const std::string &hostname,
                                        bool vnet,
                                        const std::string &parameters);
PrivOpsNvPure::FieldMap buildDestroyJail(const std::string &name,
                                         bool force);

// 0.9.23: atomic single-iface ops.
PrivOpsNvPure::FieldMap buildSetIfaceUp(const std::string &ifname);
PrivOpsNvPure::FieldMap buildDisableIfaceOffload(const std::string &ifname);

// 0.9.24: bridge membership ops.
PrivOpsNvPure::FieldMap buildBridgeAddMember(const std::string &bridge,
                                              const std::string &member);
PrivOpsNvPure::FieldMap buildBridgeDelMember(const std::string &bridge,
                                              const std::string &member);

// 0.9.25: set host-side IPv4 address.
PrivOpsNvPure::FieldMap buildSetIfaceInetAddr(const std::string &ifname,
                                              const std::string &addr,
                                              unsigned prefixLen);

// 0.9.26: create epair pair. No request fields. Response body
// (in Response.body) is a JSON object with `a` and `b` fields
// holding the kernel-assigned A/B iface names; clients parse
// them via PrivOpsWirePure::extractStringField.
PrivOpsNvPure::FieldMap buildCreateEpair();

// 0.9.28: per-loginclass RCTL umbrella ops.
PrivOpsNvPure::FieldMap buildSetLoginclassRctl(const std::string &loginclass,
                                                const std::string &key,
                                                const std::string &rawValue);
PrivOpsNvPure::FieldMap buildClearLoginclassRctl(const std::string &loginclass,
                                                  const std::string &key);

// 1.0.5: reclaim a host iface from a jail's vnet. Inverse of
// the ConfigureIface-move path.
PrivOpsNvPure::FieldMap buildReclaimIfaceFromVnet(const std::string &ifname,
                                                   const std::string &jailName);

// 1.1.0: flush a pf anchor. Symmetric companion to buildAddPfRule.
PrivOpsNvPure::FieldMap buildFlushPfAnchor(const std::string &anchor);

// 1.1.1: query `rctl -u jail:<jid>` output. Response carries the
// raw rctl text in the `output` field for client-side parsing.
PrivOpsNvPure::FieldMap buildQueryJailRctl(unsigned jid);

// 1.1.8: configure an ipfw NAT instance. `config` is the body
// following `ipfw nat <number> config` (one line, no shell metas).
PrivOpsNvPure::FieldMap buildConfigureIpfwNat(unsigned number,
                                               const std::string &config);

// 1.1.9: bind a jail's processes to a cpuset list (e.g., "0-3").
PrivOpsNvPure::FieldMap buildSetJailCpuset(unsigned jid,
                                            const std::string &cpuset);

// 1.1.10: apply a devfs ruleset to a jail's /dev mount (set
// ruleset + applyset). `mountPath` is the absolute path to
// the jail's /dev mount; `ruleset` is the ruleset number.
PrivOpsNvPure::FieldMap buildApplyDevfsRuleset(const std::string &mountPath,
                                                unsigned ruleset);

// 1.1.10: add a `path <pattern> unhide` rule to a jail's
// devfs mount, then `rule applyset`. Used by the GUI auto-
// unhide path for /dev/dri/*.
PrivOpsNvPure::FieldMap buildAddDevfsUnhideRule(const std::string &mountPath,
                                                 const std::string &pathPattern);

// 1.1.11: send a signal to all processes in a jail.
PrivOpsNvPure::FieldMap buildSignalJail(unsigned jid,
                                         const std::string &signal);

// --- Wire transport (FreeBSD-only) ---

struct Response {
  // HTTP-style status code echoed by the daemon's dispatcher
  // (200 = ok; 400/404/500 = various failures).
  int status = 0;
  // JSON body the daemon's handler produced (same shape as the
  // HTTP transport's response). Caller parses for detail.
  std::string body;
  // Non-empty if the wire-level operation failed (connect /
  // socket / nvlist_send / nvlist_recv). Distinct from `status`
  // — wire errors are not HTTP status codes.
  std::string transportError;
};

// Connect, send the FieldMap as an nvlist, receive the response,
// close. One round-trip per call. On Linux dev builds (no libnv)
// returns Response{0, "", "libnv unavailable"} — caller must
// fall back to the legacy exec path.
Response sendRequest(const std::string &socketPath,
                     const PrivOpsNvPure::FieldMap &fields);

} // namespace PrivOpsClient
