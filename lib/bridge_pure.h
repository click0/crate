// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure decision helpers for auto-creation of bridge interfaces in
// `crate run`. The runtime side (`lib/run.cpp`) checks whether the
// requested bridge actually exists and, if not, decides whether the
// spec opts in to creating it on the fly.
//

#include <string>

namespace BridgePure {

// What the runtime should do given (existing, autoCreateOptIn) state.
enum class Action {
  // Bridge already up — proceed without touching it. The runtime
  // must NOT clean up a bridge it did not create.
  NoOp,

  // Bridge missing AND the spec opted into `auto_create_bridge:
  // true`. Runtime creates the interface and remembers to destroy
  // it on container teardown.
  Create,

  // Bridge missing AND no opt-in. The runtime should abort with a
  // diagnostic that points the user at the option.
  Error,
};

struct Inputs {
  bool exists;        // result of Util::interfaceExists(bridgeIface)
  bool autoCreate;    // value of spec.options.net.auto_create_bridge
};

Action chooseAction(const Inputs &in);
const char *actionName(Action a);

// Validate a bridge interface name as it appears in a spec. The
// FreeBSD kernel only accepts names matching <driver><N> (e.g.
// "bridge0", "bridge17"). We additionally forbid empty names,
// names longer than IFNAMSIZ-1 (15 chars), and names with
// shell-metacharacters or spaces — defense in depth, since the
// name is eventually fed to ifconfig(8) on the path that does not
// use libifconfig.
//
// Returns "" when the name is acceptable, otherwise a one-line
// reason suitable for the error message.
std::string validateBridgeName(const std::string &name);

} // namespace BridgePure
