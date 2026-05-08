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

// --- Top-level dispatcher ---

DispatchResult dispatchPrivOp(Verb v, const std::string &body) {
  // 0.9.2 routes set_rctl to its real handler. All other verbs go
  // through the pure parse/validate pipeline and end at 501.
  if (v == Verb::SetRctl) {
    PrivOpsPure::SetRctlReq r;
    if (auto e = PrivOpsWirePure::parseSetRctl(body, r); !e.empty())
      return {400, PrivOpsWirePure::formatParseError(e)};
    if (auto e = PrivOpsPure::validateSetRctl(r); !e.empty())
      return {400, PrivOpsWirePure::formatValidateError(e)};
    return handleSetRctl(r);
  }
  return PrivOpsWirePure::parseValidateAndDispatch(v, body);
}

} // namespace Crated
