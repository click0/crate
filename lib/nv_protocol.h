// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// nvlist-based protocol for CLI↔daemon communication over Unix socket.
// Alternative to the HTTP REST API (daemon/server.cpp).
// Uses libnv from FreeBSD base.

#pragma once

#include <string>
#include <vector>
#include <map>

namespace NvProtocol {

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

}
