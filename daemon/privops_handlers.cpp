// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_handlers.h"

#include "jail_query.h"
#include "pathnames.h"
#include "retune_pure.h"
#include "util.h"
#include "zfs_ops.h"

#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>
#endif
#include <cstdlib>
#include <cstring>
#include <errno.h>

#include <exception>
#include <string>
#include <vector>

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

// --- handleAttachZfs / handleDetachZfs ---

DispatchResult handleAttachZfs(const PrivOpsPure::AttachZfsReq &r) {
  auto jail = JailQuery::getJailByJid((int)r.jid);
  if (!jail) {
    return {404, PrivOpsWirePure::formatHandlerError(
                  "jail_not_found",
                  "no running jail with jid " + std::to_string(r.jid))};
  }
  try {
    ZfsOps::jailDataset((int)r.jid, r.dataset);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatAttachZfsSuccess(r.jid, r.dataset)};
}

DispatchResult handleDetachZfs(const PrivOpsPure::DetachZfsReq &r) {
  auto jail = JailQuery::getJailByJid((int)r.jid);
  if (!jail) {
    return {404, PrivOpsWirePure::formatHandlerError(
                  "jail_not_found",
                  "no running jail with jid " + std::to_string(r.jid))};
  }
  try {
    ZfsOps::unjailDataset((int)r.jid, r.dataset);
  } catch (const std::exception &e) {
    return {500, PrivOpsWirePure::formatHandlerError("exec_failed", e.what())};
  }
  return {200, PrivOpsWirePure::formatDetachZfsSuccess(r.jid, r.dataset)};
}

// --- handleMountNullfs / handleUnmountNullfs ---

DispatchResult handleMountNullfs(const PrivOpsPure::MountNullfsReq &r) {
#ifndef __FreeBSD__
  return {500, PrivOpsWirePure::formatHandlerError(
                "platform_unsupported",
                "nullfs mount only supported on FreeBSD")};
#else
  // Mirror lib/mount.cpp's nmount(2) iov pattern. Names get
  // strdup'd so we can free them after the call (nmount documents
  // the iov is consumed but doesn't promise pointer ownership).
  std::vector<iovec> iov;
  auto add = [&iov](const char *name, void *value, size_t valLen) {
    iov.push_back({::strdup(name), ::strlen(name) + 1});
    iov.push_back({value, valLen});
  };
  char errmsg[256] = {0};
  add("fstype", (void*)"nullfs", 7);
  add("fspath", (void*)r.target.c_str(), r.target.size() + 1);
  add("target", (void*)r.source.c_str(), r.source.size() + 1);
  add("errmsg", errmsg, sizeof(errmsg));
  int flags = r.readOnly ? MNT_RDONLY : 0;
  int res = ::nmount(iov.data(), iov.size(), flags);
  int savedErrno = errno;
  for (size_t i = 0; i < iov.size(); i += 2)
    ::free(iov[i].iov_base);
  if (res != 0) {
    std::string msg = ::strerror(savedErrno);
    if (errmsg[0]) { msg += " ("; msg += errmsg; msg += ")"; }
    return {500, PrivOpsWirePure::formatHandlerError("nmount_failed", msg)};
  }
  return {200, PrivOpsWirePure::formatMountNullfsSuccess(r.source, r.target, r.readOnly)};
#endif
}

DispatchResult handleUnmountNullfs(const PrivOpsPure::UnmountNullfsReq &r) {
#ifndef __FreeBSD__
  return {500, PrivOpsWirePure::formatHandlerError(
                "platform_unsupported",
                "nullfs unmount only supported on FreeBSD")};
#else
  int flags = r.force ? MNT_FORCE : 0;
  int res = ::unmount(r.target.c_str(), flags);
  if (res == -1) {
    return {500, PrivOpsWirePure::formatHandlerError("unmount_failed",
                                                     ::strerror(errno))};
  }
  return {200, PrivOpsWirePure::formatUnmountNullfsSuccess(r.target)};
#endif
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
    case Verb::AttachZfs: {
      PrivOpsPure::AttachZfsReq r;
      if (auto e = PrivOpsWirePure::parseAttachZfs(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateAttachZfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleAttachZfs(r);
    }
    case Verb::DetachZfs: {
      PrivOpsPure::DetachZfsReq r;
      if (auto e = PrivOpsWirePure::parseDetachZfs(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateDetachZfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleDetachZfs(r);
    }
    case Verb::MountNullfs: {
      PrivOpsPure::MountNullfsReq r;
      if (auto e = PrivOpsWirePure::parseMountNullfs(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateMountNullfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleMountNullfs(r);
    }
    case Verb::UnmountNullfs: {
      PrivOpsPure::UnmountNullfsReq r;
      if (auto e = PrivOpsWirePure::parseUnmountNullfs(body, r); !e.empty())
        return {400, PrivOpsWirePure::formatParseError(e)};
      if (auto e = PrivOpsPure::validateUnmountNullfs(r); !e.empty())
        return {400, PrivOpsWirePure::formatValidateError(e)};
      return handleUnmountNullfs(r);
    }
    default:
      return PrivOpsWirePure::parseValidateAndDispatch(v, body);
  }
}

} // namespace Crated
