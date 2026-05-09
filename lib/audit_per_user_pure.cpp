// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "audit_per_user_pure.h"

#include <sstream>

namespace AuditPerUserPure {

namespace {

// Conservative JSON-string escape — matches what other crate
// hand-rolled JSON does (privops_wire_pure, audit_pure). We
// stay strict on control chars: backslash + quote get escaped,
// newline / tab / CR become \\n \\t \\r. The verb token is
// constrained by parseVerb's snake_case alphabet so escapes
// never fire there in practice; defence in depth for future
// fields with looser charsets.
std::string escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 4);
  for (char c : s) {
    if (c == '\\' || c == '"') { out += '\\'; out += c; continue; }
    if (c == '\n') { out += "\\n"; continue; }
    if (c == '\r') { out += "\\r"; continue; }
    if (c == '\t') { out += "\\t"; continue; }
    out += c;
  }
  return out;
}

} // anon

const char *outcomeFor(int status) {
  if (status >= 200 && status < 300) return "ok";
  if (status == 400) return "parse_or_validate";
  if (status == 403) return "forbidden";
  if (status == 404) return "not_found";
  if (status == 429) return "rate_limit";
  if (status >= 500 && status < 600) return "server_error";
  return "other";
}

std::string formatLine(const Record &r) {
  std::ostringstream o;
  o << "{\"ts\":" << r.timestamp
    << ",\"uid\":" << r.uid
    << ",\"verb\":\"" << escape(r.verb) << "\""
    << ",\"status\":" << r.status
    << ",\"outcome\":\"" << outcomeFor(r.status) << "\""
    << "}";
  return o.str();
}

} // namespace AuditPerUserPure
