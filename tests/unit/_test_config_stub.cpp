// Test-only stub for the Config:: namespace.
//
// lib/config.cpp depends on yaml-cpp (and on FreeBSD-specific paths via
// Util::Fs::getUserHomeDir()). The Linux unit-test workflow does not
// install yaml-cpp, so we cannot link tests against the real lib/config.cpp.
//
// Tests that exercise Spec::validate() (and any other code path calling
// Config::get) link this file instead. It returns a fixed empty
// Settings object — sufficient for tests that don't set
// optNet->networkName, and intentionally a "no networks defined"
// scenario for tests that do.

#include "config.h"

namespace Config {

static Settings &empty() {
  static Settings s;
  return s;
}

const Settings& load() { return empty(); }
const Settings& get()  { return empty(); }
std::string resolveCrateFile(const std::string &name) { return name; }

}
