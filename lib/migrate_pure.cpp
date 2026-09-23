// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "migrate_pure.h"
#include "netaddr_pure.h"

#include <sstream>

namespace MigratePure {

namespace {

// 1.1.30: shared, verified-identical predicates (lib/netaddr_pure.h).
using NetAddrPure::isV4;
using NetAddrPure::isV6;
using NetAddrPure::looksLikeV4Shape;
using NetAddrPure::isHostname;

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

// Strip `https://` or `http://` prefix; populate hasScheme.
std::string stripScheme(const std::string &endpoint, bool *hasScheme = nullptr) {
  if (hasScheme) *hasScheme = false;
  static const char *prefixes[] = {"https://", "http://"};
  for (auto p : prefixes) {
    auto plen = std::string(p).size();
    if (endpoint.size() >= plen && endpoint.compare(0, plen, p) == 0) {
      if (hasScheme) *hasScheme = true;
      return endpoint.substr(plen);
    }
  }
  return endpoint;
}

std::string validatePort(const std::string &port) {
  if (port.empty()) return "port is empty";
  for (char c : port)
    if (c < '0' || c > '9') return "port must be numeric";
  long n = 0;
  for (char c : port) n = n * 10 + (c - '0');
  if (n < 1 || n > 65535) return "port out of range (1..65535)";
  return "";
}

} // anon

std::string validateEndpoint(const std::string &endpoint) {
  if (endpoint.empty()) return "endpoint is empty";
  auto rest = stripScheme(endpoint);
  if (rest.empty()) return "endpoint missing host:port";
  // Bracketed IPv6: [host]:port
  if (rest.front() == '[') {
    auto rb = rest.find(']');
    if (rb == std::string::npos) return "endpoint missing closing ']'";
    auto host = rest.substr(1, rb - 1);
    if (rb + 1 >= rest.size() || rest[rb + 1] != ':')
      return "endpoint missing ':' after ']'";
    auto port = rest.substr(rb + 2);
    if (!isV6(host)) return "endpoint IPv6 literal is malformed";
    return validatePort(port);
  }
  // host:port (IPv4 or hostname)
  auto colon = rest.rfind(':');
  if (colon == std::string::npos) return "endpoint must include :port";
  auto host = rest.substr(0, colon);
  auto port = rest.substr(colon + 1);
  // Dotted-numeric must validate as IPv4 — don't fall through to
  // hostname check (would accept 256.0.0.1 silently).
  if (looksLikeV4Shape(host)) {
    if (!isV4(host)) return "endpoint looks like IPv4 but has invalid octets";
    return validatePort(port);
  }
  if (!isHostname(host))
    return "endpoint host is neither IPv4 nor hostname";
  return validatePort(port);
}

std::string validateBearerToken(const std::string &t) {
  if (t.empty()) return "bearer token is empty";
  if (t.size() > 512) return "bearer token longer than 512 chars";
  for (unsigned char c : t) {
    if (c <= 0x20 || c == 0x7f) {
      // Control or whitespace — would corrupt the Authorization header.
      return "bearer token contains whitespace or control character";
    }
  }
  return "";
}

std::string validateContainerName(const std::string &name) {
  if (name.empty()) return "container name is empty";
  if (name.size() > 64) return "container name longer than 64 chars";
  if (name == "." || name == "..") return "container name is reserved";
  for (char c : name) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in container name";
      return os.str();
    }
  }
  return "";
}

// 1.1.21: the artifact filename comes from the SOURCE server's export
// JSON (`extractFileField`), i.e. a remote, less-trusted input. It is
// concatenated into `workDir + "/" + artifactFile` and used both as a
// `curl -o` target and an `unlink()` target. Without validation a
// hostile/compromised source could return `"../../../etc/cron.d/pwn"`
// and get arbitrary file write AND delete on the migrating host. Treat
// it as a single path COMPONENT: a plain filename — no slash, not the
// reserved "."/"..", no control bytes.
//
// 1.1.27: the 1.1.21 version also rejected ANY ".." substring. That was
// stricter than the server that produces the name (TransferPure::
// validateArtifactName and the jail-name validators allow '.' freely,
// only the exact "."/".." are reserved), so a container legitimately
// named e.g. `app..v2` exported fine server-side and then `crate migrate`
// refused its own artifact. With '/' excluded a single component cannot
// traverse whatever dots it contains, so the substring check bought
// nothing. Dropped.
std::string validateArtifactFile(const std::string &name) {
  if (name.empty()) return "artifact filename is empty";
  if (name.size() > 255) return "artifact filename longer than 255 chars";
  if (name == "." || name == "..") return "artifact filename is reserved";
  for (char c : name) {
    if (c == '/')
      return "artifact filename must not contain '/' (path traversal)";
    if (static_cast<unsigned char>(c) < 0x20 ||
        static_cast<unsigned char>(c) == 0x7f)
      return "artifact filename contains a control character";
  }
  return "";
}

std::string normalizeBaseUrl(const std::string &endpoint) {
  bool hasScheme = false;
  auto rest = stripScheme(endpoint, &hasScheme);
  if (hasScheme) return endpoint;
  return "https://" + rest;
}

Step buildExportStep(const Request &r) {
  Step s;
  s.kind = StepKind::Export;
  s.method = "POST";
  s.url = normalizeBaseUrl(r.fromEndpoint)
        + "/api/v1/containers/" + r.name + "/export";
  s.token = r.fromToken;
  return s;
}

std::vector<Step> buildRemainingSteps(const Request &r) {
  std::vector<Step> out;
  // 2. Download
  {
    Step s;
    s.kind = StepKind::Download;
    s.method = "GET";
    s.url = normalizeBaseUrl(r.fromEndpoint)
          + "/api/v1/exports/" + r.artifactFile;
    s.token = r.fromToken;
    s.filePath = r.workDir + "/" + r.artifactFile;
    out.push_back(s);
  }
  // 3. Upload to destination
  {
    Step s;
    s.kind = StepKind::Upload;
    s.method = "POST";
    s.url = normalizeBaseUrl(r.toEndpoint)
          + "/api/v1/imports/" + r.name;
    s.token = r.toToken;
    s.filePath = r.workDir + "/" + r.artifactFile;
    out.push_back(s);
  }
  // 4. Start on destination
  {
    Step s;
    s.kind = StepKind::StartTo;
    s.method = "POST";
    s.url = normalizeBaseUrl(r.toEndpoint)
          + "/api/v1/containers/" + r.name + "/start";
    s.token = r.toToken;
    out.push_back(s);
  }
  // 5. Stop source — only after dest is up.
  {
    Step s;
    s.kind = StepKind::StopFrom;
    s.method = "POST";
    s.url = normalizeBaseUrl(r.fromEndpoint)
          + "/api/v1/containers/" + r.name + "/stop";
    s.token = r.fromToken;
    out.push_back(s);
  }
  return out;
}

std::string describeStep(const Step &s) {
  std::ostringstream os;
  switch (s.kind) {
    case StepKind::Export:    os << "export source     "; break;
    case StepKind::Download:  os << "download artifact "; break;
    case StepKind::Upload:    os << "upload to dest    "; break;
    case StepKind::StartTo:   os << "start on dest     "; break;
    case StepKind::StopFrom:  os << "stop on source    "; break;
  }
  os << s.method << " " << s.url;
  return os.str();
}

std::string redactToken(const std::string &token) {
  std::ostringstream os;
  os << "<redacted: " << token.size() << " chars>";
  return os.str();
}

} // namespace MigratePure
