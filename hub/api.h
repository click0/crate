// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Aggregated REST API routes for crate-hub.

#pragma once

namespace httplib { class Server; }

namespace CrateHub {

class Store;
class Poller;

void registerApiRoutes(httplib::Server &srv, Store &store, Poller &poller);

}
