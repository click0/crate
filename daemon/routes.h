// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// REST API route definitions for crated.
// F1 (minimal): GET /api/v1/containers, GET /api/v1/host, GET /metrics

#pragma once

#include "config.h"

namespace httplib { class Server; }

namespace Crated {

void registerRoutes(httplib::Server &srv, const Config &config);

}
