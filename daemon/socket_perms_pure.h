// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for crated's unix-socket permission configuration.
//
// 0.8.19 adds operator-controllable owner/group/mode on
// /var/run/crate/crated.sock so the filesystem-perm gate (the
// only gate today, see daemon/auth.cpp::isUnixSocketPeer) can be
// tightened from "root:wheel 0660" to whatever the operator
// wants. Pre-0.8.19 the only knob was the OS umask at bind time,
// which left the operator without a way to scope access to a
// custom group.
//
// Out of scope here: getpeereid(2) per-connection peer-credential
// verification. cpp-httplib's accept loop owns the connection fd
// and doesn't expose it to handlers, so getpeereid would require
// either forking httplib or replacing the unix-socket transport
// (the same pattern as daemon/control_socket.cpp from 0.7.11).
// Tracked separately as TODO low-priority security item.
//

#include <string>

namespace SocketPermsPure {

// Parse an octal mode literal like "0660", "660", or "0o660".
// Writes the parsed mode to *out and returns "" on success;
// otherwise returns an operator-readable error.
//
// We accept three spellings because operators come from different
// places: chmod(1) historically takes "660", crated YAML often
// has "0660", and YAML 1.2 parses "0o660" / "0660" inconsistently
// across loaders. parseUnixModeStr normalises all three.
//
// Range cap: 0..07777 (the standard sticky/setuid/setgid + rwx
// bits). Anything outside is rejected — operator typoed.
std::string parseUnixModeStr(const std::string &s, unsigned *out);

// Validate a Unix user name. Empty is accepted ("leave alone");
// non-empty must be 1..32 chars from [A-Za-z0-9_-] and not start
// with '-'. This matches FreeBSD's pw(8) name constraints and is
// stricter than the old SVR4 spec — fine for our use case.
std::string validateUserName(const std::string &s);

// Validate a Unix group name. Same alphabet/length as validateUserName.
std::string validateGroupName(const std::string &s);

// One-shot permission triple validator. Returns the first error
// found, or "" if all three pass.
std::string validateUnixSocketPerms(const std::string &owner,
                                    const std::string &group,
                                    unsigned mode);

// Predicate: is the configured mode "tight"?
//   true  if mode <= 0660 (rw-rw---- or stricter)
//   false otherwise
// Used to print a one-shot warning at startup when an operator
// loosens the socket past the conventional 0660. Same threshold
// as daemon/control_socket_pure.cpp::isModeSafe — keep them in
// sync if either changes.
bool isModeTight(unsigned mode);

} // namespace SocketPermsPure
