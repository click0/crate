// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// WebSocket-based interactive console for crated. Runs an
// independent TCP listener (port from `console_ws_port` in
// crated.conf) so it doesn't have to share cpp-httplib's
// connection model. The handshake + frame protocol live in
// daemon/ws_pure.{h,cpp}.
//
// Authentication: the connecting client must present a valid
// `Authorization: Bearer <token>` header during the HTTP/1.1
// upgrade handshake. The token is checked against the daemon's
// admin tokens via the same `isAuthorized` helper used by other
// F2 endpoints.
//

#include "config.h"

#include <atomic>
#include <thread>

namespace Crated {

class WsConsole {
public:
  // Start the listener on `config.consoleWsPort`. A 0 port disables
  // the listener entirely (default — the feature is opt-in).
  static bool start(const Config &config);

  // Stop the listener and join the worker thread. Safe to call
  // multiple times; safe to call when start() returned false.
  static void stop();

private:
  static std::atomic<bool> g_running;
  static std::thread g_thread;
  static int g_listenFd;
};

} // namespace Crated
