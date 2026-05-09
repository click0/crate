// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Unix-socket privops listener — kernel-blessed nvlist transport
// (0.9.14, rootless track).
//
// Background: 0.9.0-0.9.13 added an HTTP/JSON privops surface via
// cpp-httplib (POST /api/v1/privops/:verb). Good for remote
// clients (hub multi-host, CI), but cpp-httplib doesn't expose
// the connection fd, so getpeereid(2) for local clients is
// impossible without a fork. The 0.9.13 audit hook stayed
// dormant for that reason.
//
// 0.9.14 adds a SECOND transport — libnv over Unix socket — for
// local clients (crate(1) → crated). Pattern matches the
// existing daemon/control_socket.cpp listener (0.7.10) but with
// nvlist instead of hand-rolled HTTP.
//
// Protocol:
//   client connects → daemon accepts → daemon getpeereid(connFd)
//                  → client nvlist_send(req)
//                  → daemon nvlist_recv → walk into FieldMap
//                  → extractVerb + parse via PrivOpsNvPure
//                  → validate via PrivOpsPure
//                  → dispatch via privops_handlers (same handlers
//                    that serve HTTP path)
//                  → daemon packs response as nvlist
//                    {"status":<int>, "body":<json string>}
//                  → nvlist_send(resp) → close
//
// The response body is the same JSON shape the HTTP transport
// produces (formatHandlerError / formatSetRctlSuccess / etc.).
// Wrapping the JSON in an nvlist field is intentional — handlers
// keep returning DispatchResult{status, json-body}, no refactor.
// Native-typed nvlist responses are a future optimisation if
// motivated by traffic.
//
// Auth: filesystem perms (mode 0660 root:<group>) + getpeereid
// uid extraction. The peer uid feeds dispatchPrivOpFromMap as
// `operatorUid`, which lights up 0.9.13's per-user audit hook
// automatically.
//

#include "config.h"

namespace Crated {

// Lifecycle manager — same shape as ControlSocketsManager.
// Stored in main.cpp; one instance per daemon.
class PrivopsListener {
public:
  // Construct from config; doesn't open the socket yet.
  explicit PrivopsListener(const Config &config);
  ~PrivopsListener();

  // Open the socket, chmod/chown, start the accept thread.
  // Returns true if started, false if disabled by config or
  // platform doesn't support libnv (Linux dev builds).
  bool start();

  // Signal stop and join the accept thread. Idempotent.
  void stop();

  // Disable copy/move.
  PrivopsListener(const PrivopsListener &) = delete;
  PrivopsListener &operator=(const PrivopsListener &) = delete;

private:
  struct Impl;
  Impl *impl_;
};

} // namespace Crated
