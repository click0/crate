// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

#include "util.h"

#include <string>
#include <vector>
#include <functional>

namespace RunServices {

// Set up DNS filtering via unbound (§4)
void setupDnsFilter(const class Spec &spec, const std::string &jailPath, bool logProgress);

// Set up socket proxy via socat (§15), returns cleanup callback
RunAtEnd setupSocketProxy(const class Spec &spec, const std::string &jailPath, bool logProgress);

// Generate rc.conf entries for managed services (§14)
void setupManagedServices(const class Spec &spec, const std::string &jailPath,
                          const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail,
                          bool logProgress);

// Start services listed in spec.runServices
void startServices(const class Spec &spec,
                   const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail,
                   const std::function<void(const char*)> &runScript);

// Stop services in reverse order
void stopServices(const class Spec &spec,
                  const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail);

// Stop managed services in reverse order (§14)
void stopManagedServices(const class Spec &spec,
                         const std::function<void(const std::vector<std::string>&, const std::string&)> &execInJail,
                         bool logProgress);

}
