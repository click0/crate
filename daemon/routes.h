// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// REST API route definitions for crated.
// F1 (minimal): GET /api/v1/containers, GET /api/v1/host, GET /metrics

#pragma once

#include "config.h"

namespace httplib { class Server; }

namespace Crated {

// 1.1.23: isUnixListener says which server instance this is — the
// Unix-socket listener (local, trusted) or the TCP listener (remote,
// token-gated). It is stamped onto every request as a non-spoofable
// marker so auth locality is decided from the accepting socket, not a
// client-supplyable REMOTE_ADDR header. Defaults to false (fail-closed:
// an un-flagged caller is treated as untrusted TCP).
void registerRoutes(httplib::Server &srv, const Config &config,
                    bool isUnixListener = false);

}
