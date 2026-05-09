// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// JSON wire format for the privileged-operations IPC (0.9.1).
//
// The 0.9.0 release defined the verb taxonomy + request structs +
// validators in privops_pure.{h,cpp}. This module turns the wire
// surface concrete:
//
//   POST /api/v1/privops/<verb>
//   Content-Type: application/json
//
//   {
//     "name": "alpine",
//     "path": "/zroot/jails/alpine",
//     "hostname": "alpine.local",
//     "vnet": true
//   }
//
// One parser per verb. Each parser:
//
//   1. extracts every required field (caller-side schema)
//   2. assembles the request struct (no validation)
//   3. returns "" on parse success, otherwise a one-line error
//      describing the wire-format problem (missing field, wrong
//      type, malformed JSON)
//
// Parsers do NOT call the per-verb validators from privops_pure.h.
// Wire-format errors (HTTP 400 "missing field 'name'") are kept
// distinct from validation errors (HTTP 400 "name contains shell
// metacharacters") so the operator-facing diagnostics tell them
// where the problem is — typo-in-curl vs. typo-in-spec.
//
// The daemon route handler in 0.9.1 chains:
//
//   parse -> 400 if non-empty
//   validate -> 400 if non-empty
//   dispatch -> 501 (no handlers in 0.9.1)
//
// Subsequent releases (0.9.2..0.9.7) wire actual handlers behind
// the dispatch step, one verb per release.
//
// Why hand-rolled JSON: same reason as routes_pure.cpp's
// extractStringField — request bodies are tiny, the daemon
// already avoids pulling in a JSON library, and tight purpose-
// built parsing keeps the security surface small. We do NOT
// support nested objects, arrays of objects, or unicode escapes
// beyond the routes_pure.cpp set; future verbs that need richer
// payloads can switch to a real parser at that point.
//

#include "privops_pure.h"

#include <string>

namespace PrivOpsWirePure {

// --- Generic field extractors ---
//
// Each `extract*Field` returns "" if the field is absent, "PRESENT"
// (sentinel) if found and decoded into `out`, or a one-line error
// describing why a syntactically present field couldn't be decoded.
//
// The caller distinguishes "absent" from "wrong type" by checking
// the return value: empty = absent, "PRESENT" = ok, anything else
// = error.
//
// Empty return for absent matches the routes_pure.cpp convention so
// callers can write idiomatic optional-field handling. Required
// fields use `requireString` etc. which returns a clear error on
// absence.

extern const char *const kPresent; // sentinel returned on success

std::string extractStringField(const std::string &body,
                               const std::string &fieldName,
                               std::string &out);

std::string extractLongField(const std::string &body,
                             const std::string &fieldName,
                             long &out);

std::string extractUnsignedField(const std::string &body,
                                 const std::string &fieldName,
                                 unsigned &out);

std::string extractBoolField(const std::string &body,
                             const std::string &fieldName,
                             bool &out);

// --- Required-field helpers ---
//
// `requireXxx` returns "" on success, otherwise a one-line error
// (either "missing field 'foo'" or "field 'foo' is not a string").

std::string requireStringField(const std::string &body,
                               const std::string &fieldName,
                               std::string &out);

std::string requireLongField(const std::string &body,
                             const std::string &fieldName,
                             long &out);

std::string requireUnsignedField(const std::string &body,
                                 const std::string &fieldName,
                                 unsigned &out);

// --- Per-verb parsers ---
//
// Each parser fills the supplied struct from the JSON body and
// returns "" on parse success or a one-line wire-format error.
// On error the struct's contents are unspecified (caller must
// not consume them).

std::string parseCreateJail(const std::string &body,
                            PrivOpsPure::CreateJailReq &out);

std::string parseDestroyJail(const std::string &body,
                             PrivOpsPure::DestroyJailReq &out);

std::string parseMountNullfs(const std::string &body,
                             PrivOpsPure::MountNullfsReq &out);

std::string parseUnmountNullfs(const std::string &body,
                               PrivOpsPure::UnmountNullfsReq &out);

std::string parseSetRctl(const std::string &body,
                         PrivOpsPure::SetRctlReq &out);

std::string parseClearRctl(const std::string &body,
                           PrivOpsPure::ClearRctlReq &out);

std::string parseAttachZfs(const std::string &body,
                           PrivOpsPure::AttachZfsReq &out);

std::string parseDetachZfs(const std::string &body,
                           PrivOpsPure::DetachZfsReq &out);

std::string parseConfigureIface(const std::string &body,
                                PrivOpsPure::ConfigureIfaceReq &out);

std::string parseTeardownIface(const std::string &body,
                               PrivOpsPure::TeardownIfaceReq &out);

std::string parseAddPfRule(const std::string &body,
                           PrivOpsPure::AddPfRuleReq &out);

std::string parseRemovePfRule(const std::string &body,
                              PrivOpsPure::RemovePfRuleReq &out);

std::string parseAddIpfwRule(const std::string &body,
                             PrivOpsPure::AddIpfwRuleReq &out);

std::string parseRemoveIpfwRule(const std::string &body,
                                PrivOpsPure::RemoveIpfwRuleReq &out);

std::string parseSetIfaceUp(const std::string &body,
                            PrivOpsPure::SetIfaceUpReq &out);

std::string parseDisableIfaceOffload(const std::string &body,
                                     PrivOpsPure::DisableIfaceOffloadReq &out);

std::string parseBridgeAddMember(const std::string &body,
                                 PrivOpsPure::BridgeAddMemberReq &out);

std::string parseBridgeDelMember(const std::string &body,
                                 PrivOpsPure::BridgeDelMemberReq &out);

std::string parseSetIfaceInetAddr(const std::string &body,
                                  PrivOpsPure::SetIfaceInetAddrReq &out);

// --- Verb routing helper ---
//
// Parse the URL path's verb segment. The route pattern is
// `/api/v1/privops/<verb>`. Returns the parsed verb or
// `PrivOpsPure::Verb::Unknown` if the path doesn't match.
PrivOpsPure::Verb parseVerbFromPath(const std::string &path);

// --- Response body builders ---
//
// `formatNotImplemented` builds the 501 response body for
// already-known verbs that don't yet have a handler. Includes the
// verb name + the planned release that lands the handler.
std::string formatNotImplemented(PrivOpsPure::Verb v);

// `formatParseError` / `formatValidateError` wrap an error string
// into a `{"error":"..."}` body suitable for an HTTP 400 response.
std::string formatParseError(const std::string &reason);
std::string formatValidateError(const std::string &reason);

// --- Combined parse + validate helper ---
//
// Pure dispatcher that the daemon route handler delegates to. Runs:
//
//   1. parseXxx(body) -> if non-empty error -> {400, parse-error body}
//   2. validateXxx(req) -> if non-empty error -> {400, validate-error body}
//   3. otherwise -> {501, not-implemented body}
//
// The 501 case is what 0.9.1 ships for every verb. Subsequent
// 0.9.x releases replace the 501 step with an actual handler call;
// this helper goes away (or grows a `bool dispatched` indirection)
// at that point.
struct DispatchResult {
  int status = 200;
  std::string body;
};

DispatchResult parseValidateAndDispatch(PrivOpsPure::Verb v,
                                        const std::string &body);

// --- Per-verb success/error response builders ---
//
// Real handlers (landing 0.9.2..0.9.7) build their response bodies
// through these. Keeping the JSON shape pure means the wire format
// is locked down by tests, not by accident in handler code.

// Generic 500 / 404 wrapper. Used by handlers when an upstream call
// fails (rctl(8) returns non-zero, jail-not-found, etc.). The
// `kind` token classifies the failure for operator-side log
// triage (e.g. "exec_failed", "jail_not_found").
std::string formatHandlerError(const std::string &kind,
                               const std::string &reason);

// 200 OK body for `set_rctl`. Operator gets confirmation of what
// was applied — useful for `curl -X POST | jq` workflows.
std::string formatSetRctlSuccess(long jid,
                                 const std::string &key,
                                 const std::string &rawValue);

// 200 OK body for `clear_rctl`.
std::string formatClearRctlSuccess(long jid, const std::string &key);

// 200 OK body for `attach_zfs` / `detach_zfs`. The verb shape is
// the same; the field name (`attached` vs `detached`) tells the
// operator which way the operation went.
std::string formatAttachZfsSuccess(long jid, const std::string &dataset);
std::string formatDetachZfsSuccess(long jid, const std::string &dataset);

// 200 OK body for `mount_nullfs` / `unmount_nullfs`.
std::string formatMountNullfsSuccess(const std::string &source,
                                     const std::string &target,
                                     bool readOnly);
std::string formatUnmountNullfsSuccess(const std::string &target);

// 200 OK body for `configure_iface`. Echoes back the request so
// operator scripting can verify exactly which fields were applied
// (e.g. checking `ipv4_cidr` empty when only ipv6 was requested).
std::string formatConfigureIfaceSuccess(long jid,
                                        const std::string &ifname,
                                        const std::string &bridge,
                                        const std::string &ipv4Cidr,
                                        const std::string &ipv6Cidr,
                                        const std::string &macAddr);

// 200 OK body for `teardown_iface`.
std::string formatTeardownIfaceSuccess(const std::string &ifname);

// 200 OK body for `add_pf_rule` / `remove_pf_rule`.
// Note: remove_pf_rule flushes the entire anchor (pfctl doesn't
// support exact-match per-rule removal); the response reflects
// that with `flushed_anchor: true`.
std::string formatAddPfRuleSuccess(const std::string &anchor,
                                   const std::string &ruleText);
std::string formatRemovePfRuleSuccess(const std::string &anchor);

// 200 OK body for `add_ipfw_rule` / `remove_ipfw_rule`.
std::string formatAddIpfwRuleSuccess(unsigned set, unsigned number,
                                     const std::string &action,
                                     const std::string &body);
std::string formatRemoveIpfwRuleSuccess(unsigned set, unsigned number);

// 200 OK body for `create_jail` / `destroy_jail`.
std::string formatCreateJailSuccess(const std::string &name,
                                    const std::string &path);
std::string formatDestroyJailSuccess(const std::string &name);

// 0.9.23: 200 OK bodies for atomic single-iface ops.
std::string formatSetIfaceUpSuccess(const std::string &ifname);
std::string formatDisableIfaceOffloadSuccess(const std::string &ifname);

// 0.9.24: 200 OK bodies for bridge membership ops.
std::string formatBridgeAddMemberSuccess(const std::string &bridge,
                                         const std::string &member);
std::string formatBridgeDelMemberSuccess(const std::string &bridge,
                                         const std::string &member);

// 0.9.25: 200 OK body for set_iface_inet_addr.
std::string formatSetIfaceInetAddrSuccess(const std::string &ifname,
                                          const std::string &addr,
                                          unsigned prefixLen);

} // namespace PrivOpsWirePure
