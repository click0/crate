// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Privileged-operations handlers for crated (rootless track,
// 0.9.2 onwards). Each release in 0.9.2..0.9.7 adds one verb's
// real handler; the rest fall back to the 501 Not Implemented
// path from PrivOpsWirePure::parseValidateAndDispatch.
//

#include "privops_pure.h"
#include "privops_wire_pure.h"

#include "../lib/privops_nv_pure.h"

#include <cstdint>
#include <string>

namespace Crated {

// Top-level dispatcher used by daemon/routes.cpp's handlePrivOp.
// Parses the body (via PrivOpsWirePure parsers), validates the
// request (via PrivOpsPure validators), then either:
//   - calls the real handler if one is wired for the verb, or
//   - falls back to PrivOpsWirePure::parseValidateAndDispatch
//     which returns 501 Not Implemented.
//
// As verbs land their real handlers, the switch in this dispatcher
// gains a case routing to the handler. Verbs without a handler
// stay on the 501 path until their release.
//
// 0.9.13: optional `operatorUid` parameter. When > 0 AND
// `rootlessPerUser` is on, the dispatcher appends a per-user
// audit line to /var/run/crate/<uid>/audit.log via
// `appendPerUserAuditLine`. The default uid=0 means "don't audit
// per-user" and preserves byte-identical 0.9.12 behaviour. The
// uid plumbing through cpp-httplib lands in 0.9.14 alongside the
// default flip; 0.9.13 wires the contract so test harnesses and
// the control_socket plane can drive it today.
PrivOpsWirePure::DispatchResult dispatchPrivOp(PrivOpsPure::Verb v,
                                                const std::string &body,
                                                bool rootlessPerUser = false,
                                                uint32_t operatorUid = 0);

// 0.9.14: parallel dispatcher for the libnv transport. The verb
// is read from the FieldMap's "verb" key; per-verb fields come
// from the rest of the map. Same handler set as `dispatchPrivOp`,
// same audit hook, same DispatchResult shape (status + JSON body
// — body is wrapped into nvlist by the listener).
//
// Why a separate function instead of refactoring dispatchPrivOp:
// keeps the HTTP path byte-identical to 0.9.13 (zero risk to
// existing /api/v1/privops/:verb consumers) while adding the
// new transport. A future release can fold both into a single
// std::variant-based dispatch if the duplication becomes a
// real cost.
PrivOpsWirePure::DispatchResult dispatchPrivOpFromMap(
    const PrivOpsNvPure::FieldMap &m,
    bool rootlessPerUser = false,
    uint32_t operatorUid = 0);

// --- Per-verb handlers ---
// Each takes an already-validated request struct and returns a
// DispatchResult{status, body}. The request struct fields are
// trusted by these handlers (the validator gate is upstream),
// but exec(8) failures, "jail not running", and similar runtime
// conditions become 4xx/5xx responses with structured error bodies.

// 0.9.2 — set RCTL limit on a running jail. Equivalent to what
// `crate retune --rctl KEY=VAL` does today, but reachable via the
// privops IPC. The pre-validated `key` is from RetunePure's
// whitelist; `rawValue` is operator-supplied (and validator-
// approved) — the handler passes both to rctl(8) via execv.
PrivOpsWirePure::DispatchResult handleSetRctl(const PrivOpsPure::SetRctlReq &r);

// 0.9.3 — clear an RCTL rule on a running jail.
// `rctl -r jail:<jid>:<key>:deny`. Equivalent to
// `crate retune --clear KEY`.
PrivOpsWirePure::DispatchResult handleClearRctl(const PrivOpsPure::ClearRctlReq &r);

// 0.9.4 — attach / detach a ZFS dataset to a running jail.
// `zfs jail <jid> <dataset>` / `zfs unjail <jid> <dataset>`.
// Reuses the existing ZfsOps::jailDataset / unjailDataset which
// pick libzfs when available and fall back to zfs(8) otherwise.
PrivOpsWirePure::DispatchResult handleAttachZfs(const PrivOpsPure::AttachZfsReq &r);
PrivOpsWirePure::DispatchResult handleDetachZfs(const PrivOpsPure::DetachZfsReq &r);

// 0.9.5 — nullfs mount / unmount. mount(2)/unmount(2) syscalls
// directly (mirroring lib/mount.cpp's nmount(2) iov pattern, but
// without the RAII unmount-on-destruct from the Mount class —
// privops mounts persist across handler returns, lifetime owned
// by the operator via paired unmount_nullfs calls).
PrivOpsWirePure::DispatchResult handleMountNullfs(const PrivOpsPure::MountNullfsReq &r);
PrivOpsWirePure::DispatchResult handleUnmountNullfs(const PrivOpsPure::UnmountNullfsReq &r);

// 0.9.6 — VNET interface configuration / teardown.
//
// configure_iface assumes the iface (typically epair Nb) already
// exists on the host (operator created the epair pair via a
// separate ifconfig call). The handler:
//   1. moves ifname into the jail's vnet
//   2. inside the jail, sets ipv4/ipv6/mac (those that are non-empty)
//   3. inside the jail, brings the iface up
//   4. on the host side, attaches the pair-A half (computed from
//      the in-jail name when it follows the epair Nb pattern) to
//      the requested bridge
//
// teardown_iface destroys a host-side interface via
// IfconfigOps::destroyInterface. If the interface is still inside
// a jail, the destroy will fail; the operator should issue
// `ifconfig <iface> -vnet <jail>` first or rely on jail teardown
// to release the interface.
PrivOpsWirePure::DispatchResult handleConfigureIface(const PrivOpsPure::ConfigureIfaceReq &r);
PrivOpsWirePure::DispatchResult handleTeardownIface(const PrivOpsPure::TeardownIfaceReq &r);

// 0.9.7 — pf / ipfw firewall rules + jail lifecycle.
//
// add_pf_rule: load `ruleText` into the named anchor via
// PfctlOps::addRules (atomically replaces the anchor's existing
// rules). For now ruleText is single-line per the validator;
// multi-rule anchors land via either repeated calls (using a
// future per-rule append verb) or future relaxation of the
// validator.
// remove_pf_rule: flushes the anchor entirely (pfctl has no
// per-rule removal primitive). The `ruleText` field is ignored
// but kept in the request for forward compat.
//
// add_ipfw_rule: `ipfw add <number> set <set> <action> <body>`.
// `set` is mandatory in the wire format; default 0 if the operator
// doesn't care about ipfw sets.
// remove_ipfw_rule: `ipfw delete <number>`. The `set` field is
// ignored at this layer (ipfw delete is set-agnostic by rule
// number).
//
// create_jail: `jail -c name=X path=Y host.hostname=H [vnet]
// [params...] persist`. Builds the jail; everything else
// (mount, ZFS attach, iface config) is the operator's
// responsibility via the other privops verbs.
// destroy_jail: `jail -r NAME` (or `jail -R NAME` if force=true).
PrivOpsWirePure::DispatchResult handleAddPfRule(const PrivOpsPure::AddPfRuleReq &r);
PrivOpsWirePure::DispatchResult handleRemovePfRule(const PrivOpsPure::RemovePfRuleReq &r);
PrivOpsWirePure::DispatchResult handleAddIpfwRule(const PrivOpsPure::AddIpfwRuleReq &r);
PrivOpsWirePure::DispatchResult handleRemoveIpfwRule(const PrivOpsPure::RemoveIpfwRuleReq &r);
PrivOpsWirePure::DispatchResult handleCreateJail(const PrivOpsPure::CreateJailReq &r);
PrivOpsWirePure::DispatchResult handleDestroyJail(const PrivOpsPure::DestroyJailReq &r);

// 0.9.23: atomic single-iface ops needed by setupBridgeEpair flow.
// Wrap IfconfigOps::setUp / disableOffload (which themselves use
// libifconfig with shell fallback). Both succeed silently on
// idempotent calls (already up / already disabled).
PrivOpsWirePure::DispatchResult handleSetIfaceUp(const PrivOpsPure::SetIfaceUpReq &r);
PrivOpsWirePure::DispatchResult handleDisableIfaceOffload(const PrivOpsPure::DisableIfaceOffloadReq &r);

// 0.9.24: bridge membership ops. Wraps
// IfconfigOps::bridgeAddMember / bridgeDelMember.
PrivOpsWirePure::DispatchResult handleBridgeAddMember(const PrivOpsPure::BridgeAddMemberReq &r);
PrivOpsWirePure::DispatchResult handleBridgeDelMember(const PrivOpsPure::BridgeDelMemberReq &r);

} // namespace Crated
