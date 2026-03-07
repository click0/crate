// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Capsicum sandbox support using libcasper.
// Provides capability-mode sandboxing for crate processes.

#pragma once

#include <string>
#include <vector>

namespace CapsicumOps {

// Whether Capsicum/Casper support was compiled in.
bool available();

// Enter capability mode for the current process.
// After this call, no new file descriptors can be opened.
bool enterCapabilityMode();

// Casper service helpers (must be called BEFORE cap_enter).
// These open casper channels that remain usable in capability mode.

// Initialize DNS resolution through casper (cap_dns).
// Returns true if DNS casper channel was opened successfully.
bool initCapDns();

// Initialize syslog through casper (cap_syslog).
bool initCapSyslog();

// Resolve a hostname through the casper DNS channel.
// Only works after initCapDns().
std::string resolveDns(const std::string &hostname);

// Log a message through the casper syslog channel.
void logSyslog(int priority, const std::string &msg);

// Restrict file descriptor capabilities using cap_rights_limit.
bool limitFdRights(int fd, unsigned long long rights);

}
