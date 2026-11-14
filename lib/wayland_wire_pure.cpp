// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "wayland_wire_pure.h"

#include <cstring>

namespace WaylandWirePure {

const char *const kSecurityContextManager = "wp_security_context_manager_v1";
const char *const kSandboxEngine = "io.github.click0.crate";

namespace {

// opcodes, in the order the protocol XML lists the requests
constexpr uint16_t kOpDisplaySync = 0;
constexpr uint16_t kOpDisplayGetRegistry = 1;
constexpr uint16_t kOpRegistryBind = 0;
constexpr uint16_t kOpManagerCreateListener = 1;   // 0 is destroy
constexpr uint16_t kOpContextDestroy = 0;
constexpr uint16_t kOpContextSetSandboxEngine = 1;
constexpr uint16_t kOpContextSetAppId = 2;
constexpr uint16_t kOpContextSetInstanceId = 3;
constexpr uint16_t kOpContextCommit = 4;

void putU32(std::string &out, uint32_t v) {
  char b[4];
  std::memcpy(b, &v, 4);
  out.append(b, 4);
}

void putString(std::string &out, const std::string &s) {
  const std::string cut = s.substr(0, kMaxString);
  putU32(out, (uint32_t)cut.size() + 1);
  out += cut;
  out.push_back('\0');
  while (out.size() % 4) out.push_back('\0');
}

// header + args; the size goes in once the args are known
std::string message(uint32_t objectId, uint16_t opcode, const std::string &args) {
  std::string out;
  putU32(out, objectId);
  putU32(out, ((uint32_t)(8 + args.size()) << 16) | opcode);
  out += args;
  return out;
}

uint32_t getU32(const std::string &buf, size_t off) {
  uint32_t v;
  std::memcpy(&v, buf.data() + off, 4);
  return v;
}

// a string argument at `off` of a payload; false when it does not fit or
// lacks its NUL
bool getString(const std::string &p, size_t &off, std::string &out) {
  if (off + 4 > p.size()) return false;
  const uint32_t len = getU32(p, off);
  off += 4;
  if (len == 0) { out.clear(); return true; }   // a null string
  const size_t padded = ((size_t)len + 3) & ~(size_t)3;
  if (padded < len || off + padded > p.size()) return false;
  if (p[off + len - 1] != '\0') return false;
  out.assign(p, off, len - 1);
  off += padded;
  return true;
}

}

std::string displaySync(uint32_t callbackId) {
  std::string a; putU32(a, callbackId);
  return message(kDisplayId, kOpDisplaySync, a);
}

std::string displayGetRegistry(uint32_t registryId) {
  std::string a; putU32(a, registryId);
  return message(kDisplayId, kOpDisplayGetRegistry, a);
}

std::string registryBind(uint32_t registryId, uint32_t name, const std::string &interface,
                         uint32_t version, uint32_t newId) {
  std::string a;
  putU32(a, name);
  putString(a, interface);
  putU32(a, version);
  putU32(a, newId);
  return message(registryId, kOpRegistryBind, a);
}

std::string managerCreateListener(uint32_t managerId, uint32_t contextId) {
  std::string a; putU32(a, contextId);
  return message(managerId, kOpManagerCreateListener, a);
}

std::string contextSetSandboxEngine(uint32_t contextId, const std::string &name) {
  std::string a; putString(a, name);
  return message(contextId, kOpContextSetSandboxEngine, a);
}

std::string contextSetAppId(uint32_t contextId, const std::string &appId) {
  std::string a; putString(a, appId);
  return message(contextId, kOpContextSetAppId, a);
}

std::string contextSetInstanceId(uint32_t contextId, const std::string &instanceId) {
  std::string a; putString(a, instanceId);
  return message(contextId, kOpContextSetInstanceId, a);
}

std::string contextCommit(uint32_t contextId) {
  return message(contextId, kOpContextCommit, "");
}

std::string contextDestroy(uint32_t contextId) {
  return message(contextId, kOpContextDestroy, "");
}

Next nextEvent(const std::string &buf, size_t &off, Event &ev) {
  if (off > buf.size() || buf.size() - off < 8) return Next::NeedMore;
  const uint32_t word1 = getU32(buf, off + 4);
  const size_t size = word1 >> 16;
  if (size < 8 || size % 4) return Next::Malformed;
  if (buf.size() - off < size) return Next::NeedMore;
  ev.objectId = getU32(buf, off);
  ev.opcode = (uint16_t)(word1 & 0xffff);
  ev.payload.assign(buf, off + 8, size - 8);
  off += size;
  return Next::Event;
}

bool parseRegistryGlobal(const std::string &payload, uint32_t &name, std::string &interface,
                         uint32_t &version) {
  if (payload.size() < 4) return false;
  name = getU32(payload, 0);
  size_t off = 4;
  if (!getString(payload, off, interface)) return false;
  if (off + 4 > payload.size()) return false;
  version = getU32(payload, off);
  return true;
}

bool parseDisplayError(const std::string &payload, uint32_t &objectId, uint32_t &code,
                       std::string &message) {
  if (payload.size() < 8) return false;
  objectId = getU32(payload, 0);
  code = getU32(payload, 4);
  size_t off = 8;
  return getString(payload, off, message);
}

std::string sanitizeId(const std::string &s) {
  std::string out;
  for (char c : s) {
    if (out.size() >= kMaxString) break;
    out.push_back((c > ' ' && c < 0x7f) ? c : '_');
  }
  return out;
}

}
