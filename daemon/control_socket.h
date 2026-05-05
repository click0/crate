// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Runtime side of the crated control-socket plane.
// All policy / parsing lives in control_socket_pure.{h,cpp}; this
// module is the I/O glue: bind N Unix sockets with operator-supplied
// modes/groups, resolve groups via getgrnam(3), accept loop with
// peer-cred extraction via getpeereid(2), and route to the same
// pure decision module.
//

#include "config.h"

#include <memory>

namespace Crated {

class ControlSocketsManager {
public:
  explicit ControlSocketsManager(const Config &config);
  ~ControlSocketsManager();

  // Bind + listen on every configured control socket. Failure to
  // bring up an individual socket logs a warning and skips it
  // (per operator preference: don't fail-on-startup if one group
  // is missing). Returns the number of sockets actually started.
  int start();

  // Stop all listening threads and unlink all sockets.
  void stop();

private:
  Config config_;

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}
