// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// nvlist-transport parsers for the privileged-operations IPC
// (0.9.14, rootless track).
//
// 0.9.1 added the HTTP/JSON transport for privops via
// PrivOpsWirePure (lib/privops_wire_pure.cpp). 0.9.14 adds a
// **second transport** — libnv over Unix socket — without
// touching the JSON path. Both transports drive the same
// validators (PrivOpsPure) and the same handlers
// (Crated::handle{SetRctl, ...}); only the wire format and the
// auth model differ:
//
//   HTTP transport (kept):       libnv transport (NEW):
//   - bearer token                - SO_PEERCRED / getpeereid
//   - cpp-httplib parsing         - kernel-blessed nvlist
//   - JSON in body                - typed nv fields
//   - remote-friendly             - local-only (Unix socket)
//   - used by hub, CI, tooling    - used by crate(1) → crated
//
// The pure module here owns the field-map → typed-request-struct
// conversion. The Unix-socket listener
// (daemon/privops_listener.cpp) walks an nvlist on the wire and
// flattens it into a `FieldMap` (string-keyed string-valued map);
// this module then turns the map into a typed request, exactly
// the same shape PrivOpsWirePure has for JSON.
//
// Why std::map instead of nvlist directly:
//   - Linux dev/CI builds (no <sys/nv.h>) compile + test the pure
//     parser end-to-end — same approach as lib/nv_protocol.cpp.
//   - Tests express fixtures inline as std::initializer_list maps
//     instead of building nvlists in fixtures.
//   - Conversion overhead in the listener is one tree walk; the
//     wire is already small (privops requests are tiny).
//
// Fields use the same names as the JSON transport (snake_case)
// so operators reading both sides see the same vocabulary.
//

#include "privops_pure.h"

#include <map>
#include <string>

namespace PrivOpsNvPure {

// Flattened field map. nvlist values are stringified by the
// listener into this representation:
//   nv string  -> as-is
//   nv number  -> std::to_string(value)
//   nv bool    -> "true" / "false"
// The parsers below decode types back from string. Same approach
// the JSON parsers use (where everything starts as text).
using FieldMap = std::map<std::string, std::string>;

// --- Generic accessors (exposed for tests + future verbs) ---

// Required-field readers. Return "" on success, otherwise a
// one-line error: either "missing field 'foo'" or a per-type
// parse error.
std::string requireString(const FieldMap &m,
                          const std::string &key,
                          std::string &out);

std::string requireLong(const FieldMap &m,
                        const std::string &key,
                        long &out);

std::string requireUnsigned(const FieldMap &m,
                            const std::string &key,
                            unsigned &out);

// Optional-field readers. Return "" if absent (out unchanged) or
// successfully parsed; otherwise the parse error. Distinguished
// from required readers: absence is silent success.
std::string optionalString(const FieldMap &m,
                           const std::string &key,
                           std::string &out);

std::string optionalBool(const FieldMap &m,
                         const std::string &key,
                         bool &out);

// --- Per-verb parsers ---
//
// One-to-one with PrivOpsWirePure::parseXxx in field set + types
// + optional/required split. Differences are only in source
// container (FieldMap vs JSON string). Returns "" on parse
// success, otherwise a one-line wire-format error.

std::string parseCreateJail(const FieldMap &m,
                            PrivOpsPure::CreateJailReq &out);
std::string parseDestroyJail(const FieldMap &m,
                             PrivOpsPure::DestroyJailReq &out);
std::string parseMountNullfs(const FieldMap &m,
                             PrivOpsPure::MountNullfsReq &out);
std::string parseUnmountNullfs(const FieldMap &m,
                               PrivOpsPure::UnmountNullfsReq &out);
std::string parseSetRctl(const FieldMap &m,
                         PrivOpsPure::SetRctlReq &out);
std::string parseClearRctl(const FieldMap &m,
                           PrivOpsPure::ClearRctlReq &out);
std::string parseAttachZfs(const FieldMap &m,
                           PrivOpsPure::AttachZfsReq &out);
std::string parseDetachZfs(const FieldMap &m,
                           PrivOpsPure::DetachZfsReq &out);
std::string parseConfigureIface(const FieldMap &m,
                                PrivOpsPure::ConfigureIfaceReq &out);
std::string parseTeardownIface(const FieldMap &m,
                               PrivOpsPure::TeardownIfaceReq &out);
std::string parseAddPfRule(const FieldMap &m,
                           PrivOpsPure::AddPfRuleReq &out);
std::string parseRemovePfRule(const FieldMap &m,
                              PrivOpsPure::RemovePfRuleReq &out);
std::string parseAddIpfwRule(const FieldMap &m,
                             PrivOpsPure::AddIpfwRuleReq &out);
std::string parseRemoveIpfwRule(const FieldMap &m,
                                PrivOpsPure::RemoveIpfwRuleReq &out);
std::string parseSetIfaceUp(const FieldMap &m,
                            PrivOpsPure::SetIfaceUpReq &out);
std::string parseDisableIfaceOffload(const FieldMap &m,
                                     PrivOpsPure::DisableIfaceOffloadReq &out);
std::string parseBridgeAddMember(const FieldMap &m,
                                 PrivOpsPure::BridgeAddMemberReq &out);
std::string parseBridgeDelMember(const FieldMap &m,
                                 PrivOpsPure::BridgeDelMemberReq &out);
std::string parseSetIfaceInetAddr(const FieldMap &m,
                                  PrivOpsPure::SetIfaceInetAddrReq &out);
std::string parseCreateEpair(const FieldMap &m,
                             PrivOpsPure::CreateEpairReq &out);
std::string parseSetLoginclassRctl(const FieldMap &m,
                                   PrivOpsPure::SetLoginclassRctlReq &out);
std::string parseClearLoginclassRctl(const FieldMap &m,
                                     PrivOpsPure::ClearLoginclassRctlReq &out);
std::string parseReclaimIfaceFromVnet(const FieldMap &m,
                                      PrivOpsPure::ReclaimIfaceFromVnetReq &out);
std::string parseFlushPfAnchor(const FieldMap &m,
                               PrivOpsPure::FlushPfAnchorReq &out);
std::string parseQueryJailRctl(const FieldMap &m,
                               PrivOpsPure::QueryJailRctlReq &out);
std::string parseConfigureIpfwNat(const FieldMap &m,
                                  PrivOpsPure::ConfigureIpfwNatReq &out);
std::string parseSetJailCpuset(const FieldMap &m,
                               PrivOpsPure::SetJailCpusetReq &out);

// --- Verb routing ---

// The `verb` field on the wire is required for every privops
// request. Returns Verb::Unknown if missing or not in the closed
// set (parseVerb tokens are snake_case lowercase).
PrivOpsPure::Verb extractVerb(const FieldMap &m);

} // namespace PrivOpsNvPure
