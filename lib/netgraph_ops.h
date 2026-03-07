// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Netgraph operations via PF_NETGRAPH socket. Replaces ngctl(8) calls.
// No external library needed — uses FreeBSD kernel socket API.

#pragma once

#include <string>

namespace NetgraphOps {

// Whether netgraph socket is available.
bool available();

// Create a netgraph node.
// Equivalent to: ngctl mkpeer <path> <type> <hook> <peerhook>
bool mkpeer(const std::string &path, const std::string &type,
            const std::string &hook, const std::string &peerhook);

// Name a netgraph node.
// Equivalent to: ngctl name <path> <name>
bool name(const std::string &path, const std::string &newName);

// Connect two netgraph nodes.
// Equivalent to: ngctl connect <path1>: <path2>: <hook1> <hook2>
bool connect(const std::string &path1, const std::string &path2,
             const std::string &hook1, const std::string &hook2);

// Send a message to a netgraph node.
bool msg(const std::string &path, const std::string &message);

// Shutdown (destroy) a netgraph node.
// Equivalent to: ngctl shutdown <path>:
bool shutdown(const std::string &path);

// Get the name of a netgraph node.
std::string show(const std::string &path);

}
