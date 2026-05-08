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
PrivOpsWirePure::DispatchResult dispatchPrivOp(PrivOpsPure::Verb v,
                                                const std::string &body);

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

} // namespace Crated
