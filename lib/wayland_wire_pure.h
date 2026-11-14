// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// 1.1.78: the few messages of the Wayland wire protocol crate needs to
// ask a compositor for a security context (wp_security_context_v1,
// wayland-protocols staging/security-context). No libwayland: the
// exchange is seven requests and three kinds of events, and a build
// dependency on a GUI library is a lot for a jail manager to carry.
//
// The wire format (wayland.freedesktop.org/docs/html/ch04.html): every
// message is 32-bit words in the HOST byte order —
//   word 0: the object id the message is for
//   word 1: (size in bytes, header included) << 16 | opcode
//   then the arguments: uint / new_id / object as one word; a string as
//   its length INCLUDING the terminating NUL, the bytes, the NUL, padded
//   with zeros to a word; a new_id without an interface in the protocol
//   XML (wl_registry.bind) as string interface, uint version, uint id;
//   an fd as nothing at all — it travels beside the bytes (SCM_RIGHTS).
//
// Pure: bytes in, bytes out. lib/wayland_security_context.cpp does the
// socket I/O.
//

#include <cstdint>
#include <string>

namespace WaylandWirePure {

// Object ids are the client's to hand out, 1 is the display.
constexpr uint32_t kDisplayId = 1;

// The interface a compositor advertises when it can make security
// contexts, and the version crate speaks.
extern const char *const kSecurityContextManager;   // "wp_security_context_manager_v1"
constexpr uint32_t kSecurityContextVersion = 1;

// Limits: what crate will send as a string argument, and the largest
// message the protocol allows (the size field is 16 bits).
constexpr size_t kMaxString = 255;
constexpr size_t kMaxMessage = 65535;

// --- requests (each returns one complete message) ---

// wl_display.sync(new_id callback) — the compositor answers with
// wl_callback.done on that id once everything before it is processed.
std::string displaySync(uint32_t callbackId);
// wl_display.get_registry(new_id registry) — the compositor then sends a
// wl_registry.global for every global it offers this client.
std::string displayGetRegistry(uint32_t registryId);
// wl_registry.bind(name, interface, version, new_id)
std::string registryBind(uint32_t registryId, uint32_t name, const std::string &interface,
                         uint32_t version, uint32_t newId);
// wp_security_context_manager_v1.create_listener(new_id context, fd
// listen_fd, fd close_fd) — the two fds are sent with this message.
std::string managerCreateListener(uint32_t managerId, uint32_t contextId);
// wp_security_context_v1.set_sandbox_engine / set_app_id /
// set_instance_id (string), commit, destroy.
std::string contextSetSandboxEngine(uint32_t contextId, const std::string &name);
std::string contextSetAppId(uint32_t contextId, const std::string &appId);
std::string contextSetInstanceId(uint32_t contextId, const std::string &instanceId);
std::string contextCommit(uint32_t contextId);
std::string contextDestroy(uint32_t contextId);

// --- events ---

struct Event {
  uint32_t objectId = 0;
  uint16_t opcode = 0;
  std::string payload;   // the argument words
};

enum class Next { Event, NeedMore, Malformed };

// Take one message off the front of `buf` (bytes read from the socket so
// far) starting at `off`; on Event `off` moves past it. Malformed: a size
// below the header's 8 bytes or not a multiple of 4.
Next nextEvent(const std::string &buf, size_t &off, Event &ev);

// wl_registry.global (opcode 0): name, interface, version.
constexpr uint16_t kRegistryGlobal = 0;
bool parseRegistryGlobal(const std::string &payload, uint32_t &name, std::string &interface,
                         uint32_t &version);
// wl_display.error (opcode 0): object id, code, message — the compositor
// closes the connection after it. wl_display.delete_id is opcode 1.
constexpr uint16_t kDisplayError = 0;
constexpr uint16_t kDisplayDeleteId = 1;
bool parseDisplayError(const std::string &payload, uint32_t &objectId, uint32_t &code,
                       std::string &message);
// wl_callback.done (opcode 0): one uint crate does not look at.
constexpr uint16_t kCallbackDone = 0;

// --- what crate tells the compositor about the jail ---

// The sandbox engine name: reverse-DNS, as the protocol asks. A
// compositor can match on it (sway: `for_window [sandbox_engine=...]`)
// to mark or restrict the windows of crate jails.
extern const char *const kSandboxEngine;   // "io.github.click0.crate"

// An app / instance id made safe for the wire: printable ASCII other
// than space kept, anything else replaced by '_', cut to kMaxString.
// "" stays "" (the caller then leaves that request out).
std::string sanitizeId(const std::string &s);

}
