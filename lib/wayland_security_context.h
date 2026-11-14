// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// 1.1.78: a Wayland socket for a jail that the compositor itself
// restricts (wp_security_context_v1).
//
// `gui: auto` / `gui.mode: wayland` used to bind the host compositor's
// own socket into the jail. That socket is the operator's: besides
// drawing windows, a client on it may ask for the compositor's
// privileged protocols — a virtual keyboard and pointer, screen capture,
// the clipboard of every other client, the list of all windows, a
// screen lock. A jail on it could type into, watch and drive every
// other window of the session, other jails' included.
//
// A security context is the compositor's answer: a client hands it a
// listening socket of its own, tagged with the name of the sandbox
// engine and of the application, and the compositor serves the clients
// that connect there without the privileged protocols (which ones is
// the compositor's policy: wlroots / sway 1.9+, KWin 6, Mutter 46 and
// later have it). crate makes that socket and mounts IT in the jail.
//
// The socket lives in a private 0700 directory under the operator's
// XDG_RUNTIME_DIR; the compositor stops listening when `keepFd` — the
// write end of a pipe whose read end the compositor holds — is closed,
// which also happens when crate dies.
//

#include <string>

namespace WaylandSecurityContext {

enum class Status {
  Ok,
  Unsupported,   // the compositor has no wp_security_context_manager_v1
  Failed         // could not talk to it, or it refused (see error)
};

struct Listener {
  Status status = Status::Failed;
  std::string error;        // Failed / Unsupported: what happened
  std::string dir;          // the private directory
  std::string socketPath;   // <dir>/<name>: what the jail gets
  int keepFd = -1;
};

// compositorSocket — the host compositor's socket
// ($XDG_RUNTIME_DIR/$WAYLAND_DISPLAY); dirTemplate — mkdtemp(3) template
// of the private directory; name — the socket's file name in it; appId /
// instanceId — what the compositor is told about the jail (sanitized
// here; "" leaves the request out). Does not throw.
Listener create(const std::string &compositorSocket, const std::string &dirTemplate,
                const std::string &name, const std::string &appId,
                const std::string &instanceId);

// Only ask: does the compositor at this socket make security contexts?
// (`crate doctor`.) err is set unless Ok.
Status probe(const std::string &compositorSocket, std::string &err);

// Close keepFd (the compositor stops listening) and remove the socket
// and its directory. Safe on a Listener that is not Ok.
void destroy(Listener &l);

}
