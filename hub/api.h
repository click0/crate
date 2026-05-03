// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Aggregated REST API routes for crate-hub.

#pragma once

#include "ha_pure.h"

#include <vector>

namespace httplib { class Server; }

namespace CrateHub {

class Store;
class Poller;

// Register all hub REST endpoints. `haSpecs` may be empty (HA
// disabled); `haThresholdSeconds` is ignored in that case.
void registerApiRoutes(httplib::Server &srv, Store &store, Poller &poller,
                       const std::vector<HaPure::HaSpec> &haSpecs,
                       long haThresholdSeconds);

}
