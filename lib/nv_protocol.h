// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// nvlist-based wire format for CLI↔daemon communication over Unix
// socket. Alternative to the HTTP+JSON REST API in daemon/server.cpp
// (cpp-httplib) and to the hand-rolled HTTP parser in
// daemon/control_socket_pure.cpp. Uses libnv from FreeBSD base.
//
// 0.8.27 status: scaffolding for a future control-plane v2 that
// bypasses cpp-httplib + the manual HTTP parser. Currently the
// only production caller is the `crate doctor` self-test, which
// validates the round-trip works on the host. Wiring this as the
// transport for control sockets (replacing daemon/control_socket
// _pure.cpp::parseHttpHead and ::buildHttpResponse) is tracked
// separately — it's a control-plane refactor, not an audit
// closure.
//
// Why kept around: the nvlist wire format is materially better
// than the manual HTTP parser for this use case:
//   - native framing (no Content-Length tracking)
//   - native peer-credential support over Unix sockets
//   - smaller on the wire
//   - no risk of misparsing HTTP edge cases (chunked, folded
//     headers, CRLF in values, etc.)
// Throwing this code away would lose the foundation for that
// refactor.

#pragma once

#include <string>
#include <vector>
#include <map>

namespace NvProtocol {

// Whether libnv support is compiled in (i.e. building on FreeBSD).
// Returns false on Linux dev builds; the rest of the API stubs
// out gracefully there.
bool available();

// Message structure for CLI↔daemon exchange.
struct Message {
  std::string action;                          // "start", "stop", "list", etc.
  std::map<std::string, std::string> params;   // key-value parameters
  int status = 0;                              // response status (0 = OK)
  std::string error;                           // error message if status != 0
};

// Send a message over a Unix socket fd using nvlist.
bool sendMessage(int fd, const Message &msg);

// Receive a message from a Unix socket fd.
bool recvMessage(int fd, Message &msg);

// Connect to the daemon Unix socket.
// Returns fd, or -1 on failure.
int connectToDaemon(const std::string &socketPath);

// Convenience: send a command and receive a response.
Message sendCommand(const std::string &socketPath, const Message &cmd);

// 0.8.27: in-process round-trip test. Opens a socketpair, sends a
// fixed test Message on one end, reads it back on the other.
// Returns true if both sides agreed on action/params. On Linux
// (no libnv) returns false without side effects so doctor can
// report the absence honestly.
bool selfTest();

}
