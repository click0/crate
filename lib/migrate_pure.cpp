// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "migrate_pure.h"

#include <sstream>

namespace MigratePure {

namespace {

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

bool isV4(const std::string &s) {
  size_t pos = 0;
  for (int i = 0; i < 4; i++) {
    auto dot = s.find('.', pos);
    auto end = (i == 3) ? s.size() : dot;
    if (i < 3 && dot == std::string::npos) return false;
    auto octet = s.substr(pos, end - pos);
    if (octet.empty() || octet.size() > 3) return false;
    int n = 0;
    for (char c : octet) {
      if (c < '0' || c > '9') return false;
      n = n * 10 + (c - '0');
    }
    if (n > 255) return false;
    pos = (i == 3) ? s.size() : (dot + 1);
  }
  return pos == s.size();
}

bool isV6(const std::string &s) {
  if (s.empty()) return false;
  bool sawDoubleColon = false;
  size_t i = 0;
  int groups = 0;
  while (i < s.size()) {
    if (i + 1 < s.size() && s[i] == ':' && s[i + 1] == ':') {
      if (sawDoubleColon) return false;
      sawDoubleColon = true;
      i += 2;
      continue;
    }
    if (s[i] == ':') {
      if (groups == 0) return false;
      i++;
      continue;
    }
    int hexLen = 0;
    while (i < s.size() && hexLen < 4 &&
           ((s[i] >= '0' && s[i] <= '9') ||
            (s[i] >= 'a' && s[i] <= 'f') ||
            (s[i] >= 'A' && s[i] <= 'F'))) {
      i++; hexLen++;
    }
    if (hexLen == 0) return false;
    groups++;
  }
  if (sawDoubleColon) return groups <= 7;
  return groups == 8;
}

// True iff `s` is a dotted-numeric string. Such strings must
// validate as IPv4 — they are never legal RFC 1123 hostnames (a
// label can't be all-digit) and accepting them as hostnames lets
// out-of-range octets like 256.0.0.1 through silently.
bool looksLikeV4Shape(const std::string &s) {
  if (s.empty()) return false;
  bool sawDot = false;
  for (char c : s) {
    if (c == '.') { sawDot = true; continue; }
    if (c < '0' || c > '9') return false;
  }
  return sawDot;
}

bool isHostname(const std::string &s) {
  if (s.empty() || s.size() > 253) return false;
  size_t i = 0;
  while (i < s.size()) {
    size_t labelStart = i;
    while (i < s.size() && s[i] != '.') i++;
    auto label = s.substr(labelStart, i - labelStart);
    if (label.empty() || label.size() > 63) return false;
    if (!isAlnum(label.front()) || !isAlnum(label.back())) return false;
    for (char c : label)
      if (!isAlnum(c) && c != '-') return false;
    if (i < s.size()) i++;
  }
  return true;
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
