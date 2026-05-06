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

const char *actionLabel(Action a) {
  switch (a) {
  case Action::ListContainers:    return "list";
  case Action::GetContainer:      return "get";
  case Action::GetContainerStats: return "stats";
  case Action::PatchResources:    return "patch";
  case Action::Unknown:           return "unknown";
  }
  return "unknown";
}

bool actionIsMutating(Action a) {
  switch (a) {
  case Action::PatchResources:    return true;
  case Action::ListContainers:
  case Action::GetContainer:
  case Action::GetContainerStats:
  case Action::Unknown:           return false;
  }
  return false;
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

// --- HTTP wire parsing ---

namespace {

// Status reason phrases for the responses we actually emit.
const char *reasonForStatus(int status) {
  switch (status) {
  case 200: return "OK";
  case 400: return "Bad Request";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 411: return "Length Required";
  case 413: return "Payload Too Large";
  case 429: return "Too Many Requests";
  case 500: return "Internal Server Error";
  default:  return "Unknown";
  }
}

// Lowercase a copy.
std::string toLower(std::string s) {
  for (auto &c : s) {
    if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
  }
  return s;
}

bool methodLooksValid(const std::string &m) {
  if (m.empty() || m.size() > 16) return false;
  for (char c : m) {
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
      return false;
  }
  return true;
}

bool pathLooksValid(const std::string &p) {
  if (p.empty() || p.size() > 1024) return false;
  if (p.front() != '/') return false;
  for (char c : p) {
    // ASCII printable, no control chars, no whitespace mid-path.
    if (c < 0x21 || c > 0x7e) return false;
  }
  return true;
}

} // anon

ParsedHttp parseHttpHead(const std::string &head) {
  ParsedHttp out;
  // Locate the first CRLF (end of request line).
  auto eol = head.find("\r\n");
  if (eol == std::string::npos) {
    out.bad = true; out.error = "no CRLF after request line";
    return out;
  }
  std::string requestLine = head.substr(0, eol);
  if (requestLine.size() > 1024 + 32) {  // cap path + method + version + slack
    out.bad = true; out.error = "request line too long";
    return out;
  }

  // Split request line on single spaces. We require exactly two spaces:
  // METHOD SP PATH SP VERSION
  auto sp1 = requestLine.find(' ');
  if (sp1 == std::string::npos) {
    out.bad = true; out.error = "request line missing SP after method";
    return out;
  }
  auto sp2 = requestLine.find(' ', sp1 + 1);
  if (sp2 == std::string::npos) {
    out.bad = true; out.error = "request line missing SP after path";
    return out;
  }
  std::string method  = requestLine.substr(0, sp1);
  std::string path    = requestLine.substr(sp1 + 1, sp2 - sp1 - 1);
  std::string version = requestLine.substr(sp2 + 1);

  if (!methodLooksValid(method)) {
    out.bad = true; out.error = "invalid HTTP method";
    return out;
  }
  if (!pathLooksValid(path)) {
    out.bad = true; out.error = "invalid HTTP path";
    return out;
  }
  if (version != "HTTP/1.0" && version != "HTTP/1.1") {
    out.bad = true; out.error = "unsupported HTTP version (need 1.0 or 1.1)";
    return out;
  }

  out.method = method;
  out.path   = path;

  // Parse headers: each line `NAME: VALUE\r\n`, ending at empty CRLF.
  std::size_t i = eol + 2;
  while (i < head.size()) {
    auto e = head.find("\r\n", i);
    if (e == std::string::npos) {
      out.bad = true; out.error = "header block not terminated by CRLF";
      return out;
    }
    if (e == i) {
      // empty line — end of headers
      return out;
    }
    if (e - i > 4096) {
      out.bad = true; out.error = "header line too long";
      return out;
    }
    std::string line = head.substr(i, e - i);
    auto colon = line.find(':');
    if (colon == std::string::npos) {
      out.bad = true; out.error = "header missing ':'";
      return out;
    }
    std::string name = toLower(line.substr(0, colon));
    std::string value;
    // Skip optional whitespace after colon.
    std::size_t v = colon + 1;
    while (v < line.size() && (line[v] == ' ' || line[v] == '\t')) v++;
    value = line.substr(v);

    if (name == "content-length") {
      // Strict: digits only, fits in size_t, cap 64KB (control-socket bodies
      // are tiny JSON patches; anything bigger is hostile).
      if (value.empty()) {
        out.bad = true; out.error = "Content-Length empty";
        return out;
      }
      std::size_t n = 0;
      for (char c : value) {
        if (c < '0' || c > '9') {
          out.bad = true; out.error = "Content-Length not numeric";
          return out;
        }
        n = n * 10 + (std::size_t)(c - '0');
        if (n > 65536) {
          out.bad = true; out.error = "Content-Length over 64KB cap";
          return out;
        }
      }
      out.contentLength = n;
    }
    // All other headers ignored.
    i = e + 2;
  }
  // Reached end of input without seeing the empty terminator line.
  out.bad = true; out.error = "header block truncated";
  return out;
}

std::string buildHttpResponse(int status, const std::string &body,
                              const std::string &contentType) {
  std::ostringstream o;
  o << "HTTP/1.1 " << status << " " << reasonForStatus(status) << "\r\n"
    << "Content-Type: " << contentType << "\r\n"
    << "Content-Length: " << body.size() << "\r\n"
    << "Connection: close\r\n"
    << "\r\n"
    << body;
  return o.str();
}

} // namespace ControlSocketPure
