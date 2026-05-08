// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_handlers.h"

#include "jail_query.h"
#include "pathnames.h"
#include "retune_pure.h"
#include "util.h"

#include <exception>
#include <string>

namespace Crated {

using PrivOpsPure::Verb;
using PrivOpsWirePure::DispatchResult;

// --- handleSetRctl ---

DispatchResult handleSetRctl(const PrivOpsPure::SetRctlReq &r) {
  // The validator already enforced jid >= 1 and the key/value
  // shape. What it can't enforce: jail-still-running (a TOCTOU
  // window between client validate and daemon handler is
  // unavoidable). Re-check here.
  auto jail = JailQuery::getJailByJid((int)r.jid);
  if (!jail) {
    return {404, PrivOpsWirePure::formatHandlerError(
                  "jail_not_found",
                  "no running jail with jid " + std::to_string(r.jid))};
  }

  RetunePure::RctlPair pair{r.key, r.rawValue};
  auto argv = RetunePure::buildSetArgv((int)r.jid, pair);

  try {
    Util::execCommand(argv, "privops set_rctl");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }

  return {200, PrivOpsWirePure::formatSetRctlSuccess(r.jid, r.key, r.rawValue)};
}

// --- handleClearRctl ---

DispatchResult handleClearRctl(const PrivOpsPure::ClearRctlReq &r) {
  auto jail = JailQuery::getJailByJid((int)r.jid);
  if (!jail) {
    return {404, PrivOpsWirePure::formatHandlerError(
                  "jail_not_found",
                  "no running jail with jid " + std::to_string(r.jid))};
  }

  auto argv = RetunePure::buildClearArgv((int)r.jid, r.key);

  // Soft-fail clears are common in `crate retune` (the rule may
  // simply not exist yet). For the IPC surface we return the
  // operator's exec error verbatim so they can decide; the
  // dual semantics (idempotent vs. strict) can be added later
  // via a `?strict` flag if needed.
  try {
    Util::execCommand(argv, "privops clear_rctl");
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }

  return {200, PrivOpsWirePure::formatClearRctlSuccess(r.jid, r.key)};
}

// --- Top-level dispatcher ---

DispatchResult dispatchPrivOp(Verb v, const std::string &body) {
  switch (v) {
    case Verb::SetRctl: {
      PrivOpsPure::SetRctlReq r;
      if (auto e = PrivOpsWirePure::parseSetRctl(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateSetRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleSetRctl(r);
    }
    case Verb::ClearRctl: {
      PrivOpsPure::ClearRctlReq r;
      if (auto e = PrivOpsWirePure::parseClearRctl(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateClearRctl(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleClearRctl(r);
    }
    default:
      return PrivOpsWirePure::parseValidateAndDispatch(v, body);
  }
}

} // namespace Crated
