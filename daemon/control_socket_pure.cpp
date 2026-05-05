// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "control_socket_pure.h"
#include "../lib/pool_pure.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace ControlSocketPure {

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

bool hasShellMetachar(const std::string &s) {
  for (char c : s) {
    if (c == ';' || c == '`' || c == '$' || c == '|' || c == '&'
        || c == '<' || c == '>' || c == '\\' || c == '\n' || c == '\r'
        || c == '*' || c == '?' || c == '"' || c == '\''
        || c == ' ' || c == '\t')
      return true;
  }
  return false;
}

bool hasDotDot(const std::string &p) {
  size_t i = 0;
  while (i < p.size()) {
    auto slash = p.find('/', i);
    auto end = (slash == std::string::npos) ? p.size() : slash;
    if (p.substr(i, end - i) == "..") return true;
    if (slash == std::string::npos) break;
    i = slash + 1;
  }
  return false;
}

// Trim leading/trailing whitespace (ASCII).
std::string trim(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace((unsigned char)s[a])) a++;
  while (b > a && std::isspace((unsigned char)s[b-1])) b--;
  return s.substr(a, b - a);
}

// JSON-escape a string (same shape as audit_pure::escape).
std::string jsonEscape(const std::string &s) {
  std::ostringstream o;
  for (unsigned char c : s) {
    switch (c) {
    case '"':  o << "\\\""; break;
    case '\\': o << "\\\\"; break;
    case '\n': o << "\\n";  break;
    case '\r': o << "\\r";  break;
    case '\t': o << "\\t";  break;
    case '\b': o << "\\b";  break;
    case '\f': o << "\\f";  break;
    default:
      if (c < 0x20) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x", (int)c);
        o << buf;
      } else {
        o << (char)c;
      }
    }
  }
  return o.str();
}

// Minimal flat-JSON-object parser sufficient for ResourcesPatch:
// accepts {"k":"v","k2":"v2"} with quoted strings as both keys and
// values. Whitespace ignored. No nested objects/arrays/numbers/bools.
// Rejects anything else with a clear error.
//
// Returns "" on success and fills `out`. On parse error, returns
// the message and `out` is undefined.
std::string parseFlatJsonObject(const std::string &raw,
                                std::vector<std::pair<std::string, std::string>> &out) {
  out.clear();
  std::string s = trim(raw);
  if (s.empty()) return "JSON body is empty";
  if (s.front() != '{' || s.back() != '}')
    return "JSON body must be an object {...}";
  // Strip the braces and trim again.
  s = trim(s.substr(1, s.size() - 2));
  if (s.empty()) return "JSON object is empty (no fields)";

  size_t i = 0;
  auto skipWs = [&]() {
    while (i < s.size() && std::isspace((unsigned char)s[i])) i++;
  };
  auto readString = [&](std::string &out_str) -> std::string {
    skipWs();
    if (i >= s.size() || s[i] != '"')
      return "expected '\"' at position " + std::to_string(i);
    i++;  // skip opening quote
    std::ostringstream val;
    while (i < s.size() && s[i] != '"') {
      if (s[i] == '\\') {
        if (i + 1 >= s.size()) return "trailing backslash in string";
        char e = s[i+1];
        switch (e) {
        case '"':  val << '"';  break;
        case '\\': val << '\\'; break;
        case '/':  val << '/';  break;
        case 'n':  val << '\n'; break;
        case 'r':  val << '\r'; break;
        case 't':  val << '\t'; break;
        default:
          return std::string("unsupported escape '\\") + e + "'";
        }
        i += 2;
      } else {
        val << s[i];
        i++;
      }
    }
    if (i >= s.size()) return "unterminated string";
    i++;  // closing quote
    out_str = val.str();
    return "";
  };

  while (true) {
    std::string key, val;
    if (auto e = readString(key); !e.empty()) return e;
    skipWs();
    if (i >= s.size() || s[i] != ':')
      return "expected ':' after key '" + key + "'";
    i++;  // skip colon
    if (auto e = readString(val); !e.empty()) return e;
    out.emplace_back(key, val);
    skipWs();
    if (i >= s.size()) break;
    if (s[i] == ',') { i++; continue; }
    return "unexpected character '" + std::string(1, s[i]) + "' after value";
  }
  if (out.empty()) return "JSON object is empty (no fields)";
  return "";
}

} // anon

// --- Validation ---

std::string validateSocketSpec(const ControlSocketSpec &spec) {
  if (spec.path.empty())             return "control_socket: path is empty";
  if (spec.path.size() > 1024)       return "control_socket: path longer than 1024 chars";
  if (spec.path.front() != '/')      return "control_socket: path must be absolute";
  if (hasDotDot(spec.path))          return "control_socket: path must not contain '..' segments";
  if (hasShellMetachar(spec.path))   return "control_socket: path contains shell metacharacters or whitespace";

  static const char kRoot[] = "/var/run/crate/control/";
  const size_t kRootLen = sizeof(kRoot) - 1;
  if (spec.path.size() <= kRootLen
      || spec.path.compare(0, kRootLen, kRoot) != 0)
    return "control_socket: path must live under /var/run/crate/control/";

  if (spec.group.empty())            return "control_socket: group is empty";
  if (spec.group.size() > 32)        return "control_socket: group longer than 32 chars";
  for (char c : spec.group) {
    if (!(isAlnum(c) || c == '.' || c == '_' || c == '-'))
      return "control_socket: group contains invalid character '" + std::string(1, c) + "'";
  }

  if (spec.mode > 0777)              return "control_socket: mode out of range (must be 0..0777)";

  if (spec.role != "admin" && spec.role != "viewer")
    return "control_socket: role must be 'admin' or 'viewer', got '" + spec.role + "'";

  if (spec.pools.empty())
    return "control_socket: pools list is empty (use [\"*\"] for all-pools)";

  for (const auto &p : spec.pools) {
    if (p == "*") continue;
    if (p.empty() || p.size() > 64)
      return "control_socket: pool name out of length bounds (1..64)";
    for (char c : p) {
      if (!(isAlnum(c) || c == '.' || c == '_' || c == '-'))
        return "control_socket: pool '" + p + "' contains invalid character";
    }
  }
  return "";
}

bool isModeSafe(unsigned mode) {
  // 0660 or stricter: no other-bits, no group-write only if owner-write...
  // Practically: world bits (last 3) must be zero.
  return (mode & 0007u) == 0;
}

// --- Route parsing ---

namespace {

// Split path on '/' into non-empty components. Trailing slash drops the
// empty last component.
std::vector<std::string> splitPath(const std::string &p) {
  std::vector<std::string> out;
  std::string buf;
  for (char c : p) {
    if (c == '/') {
      if (!buf.empty()) { out.push_back(buf); buf.clear(); }
    } else {
      buf += c;
    }
  }
  if (!buf.empty()) out.push_back(buf);
  return out;
}

bool validContainerName(const std::string &n) {
  if (n.empty() || n.size() > 64) return false;
  for (char c : n) {
    if (!(isAlnum(c) || c == '.' || c == '_' || c == '-'))
      return false;
  }
  return true;
}

} // anon

ParsedRoute parseRoute(const std::string &method, const std::string &path) {
  ParsedRoute r;
  auto parts = splitPath(path);
  // Expected prefix: ["v1", "control", "containers", ...]
  if (parts.size() < 3) return r;
  if (parts[0] != "v1" || parts[1] != "control" || parts[2] != "containers")
    return r;

  // GET /v1/control/containers
  if (parts.size() == 3) {
    if (method == "GET") r.action = Action::ListContainers;
    return r;
  }

  // GET /v1/control/containers/:name
  if (parts.size() == 4) {
    if (!validContainerName(parts[3])) return r;
    r.container = parts[3];
    if (method == "GET") r.action = Action::GetContainer;
    return r;
  }

  // 5-part paths: /v1/control/containers/:name/{stats,resources}
  if (parts.size() == 5) {
    if (!validContainerName(parts[3])) return r;
    r.container = parts[3];
    if (parts[4] == "stats" && method == "GET")
      r.action = Action::GetContainerStats;
    else if (parts[4] == "resources" && method == "PATCH")
      r.action = Action::PatchResources;
    return r;
  }
  return r;
}

// --- Authorize ---

Decision authorize(const AuthorizeInput &in) {
  if (in.action == Action::Unknown)
    return Decision::DenyUnknownAction;

  // Layer 2: peer.gid must match socket-expected gid.
  if (in.peerGid < 0 || in.peerGid != in.socketExpectedGid)
    return Decision::DenyGidMismatch;

  // PATCH actions require admin role.
  if (in.action == Action::PatchResources && in.socketRole != "admin")
    return Decision::DenyRoleMismatch;

  // Per-container actions: pool ACL.
  if (in.action == Action::GetContainer
      || in.action == Action::GetContainerStats
      || in.action == Action::PatchResources) {
    auto pool = PoolPure::inferPool(in.container, in.poolSeparator);
    if (!poolVisibleOnSocket(pool, in.socketPools))
      return Decision::DenyPoolMismatch;
  }

  // ListContainers: filtering happens at render time.
  return Decision::Allow;
}

// --- PATCH body ---

std::string parseResourcesPatch(const std::string &body, ResourcesPatch &out) {
  out = ResourcesPatch{};
  std::vector<std::pair<std::string, std::string>> kv;
  if (auto e = parseFlatJsonObject(body, kv); !e.empty())
    return e;
  for (const auto &[k, v] : kv) {
    if      (k == "pcpu")      out.pcpu = v;
    else if (k == "memoryuse") out.memoryuse = v;
    else if (k == "readbps")   out.readbps = v;
    else if (k == "writebps")  out.writebps = v;
    else
      return "unsupported resource key '" + k + "' (allowed: pcpu, memoryuse, readbps, writebps)";
  }
  if (out.pcpu.empty() && out.memoryuse.empty()
      && out.readbps.empty() && out.writebps.empty())
    return "no recognised keys in patch body";
  return "";
}

// --- JSON ---

std::string renderContainersJson(const std::vector<ContainerSummary> &itemsIn) {
  auto items = itemsIn;
  std::sort(items.begin(), items.end(),
            [](const ContainerSummary &a, const ContainerSummary &b) {
              return a.name < b.name;
            });
  std::ostringstream o;
  o << "{\"containers\":[";
  for (size_t i = 0; i < items.size(); i++) {
    if (i > 0) o << ",";
    o << "{\"name\":\""  << jsonEscape(items[i].name)  << "\","
         "\"pool\":\""   << jsonEscape(items[i].pool)  << "\","
         "\"state\":\""  << jsonEscape(items[i].state) << "\","
         "\"jid\":"      << items[i].jid << "}";
  }
  o << "]}";
  return o.str();
}

std::string renderErrorJson(const std::string &msg) {
  return std::string("{\"error\":\"") + jsonEscape(msg) + "\"}";
}

std::string renderPatchOkJson(const ResourcesPatch &p) {
  std::ostringstream o;
  o << "{\"applied\":{";
  bool first = true;
  auto emit = [&](const char *k, const std::string &v) {
    if (v.empty()) return;
    if (!first) o << ",";
    o << "\"" << k << "\":\"" << jsonEscape(v) << "\"";
    first = false;
  };
  emit("pcpu",      p.pcpu);
  emit("memoryuse", p.memoryuse);
  emit("readbps",   p.readbps);
  emit("writebps",  p.writebps);
  o << "}}";
  return o.str();
}

// --- Helpers ---

int httpStatusFor(Decision d) {
  switch (d) {
  case Decision::Allow:               return 200;
  case Decision::DenyGidMismatch:     return 403;
  case Decision::DenyPoolMismatch:    return 403;
  case Decision::DenyRoleMismatch:    return 403;
  case Decision::DenyUnknownAction:   return 404;
  }
  return 500;
}

bool poolVisibleOnSocket(const std::string &pool,
                         const std::vector<std::string> &socketPools) {
  for (const auto &p : socketPools) {
    if (p == "*") return true;
    if (p == pool) return true;
  }
  // Pool-less containers (jail name without separator) are reachable
  // only through "*" sockets, which is handled above.
  return false;
}

} // namespace ControlSocketPure
