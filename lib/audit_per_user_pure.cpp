// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "audit_per_user_pure.h"
#include "json_pure.h"

#include <sstream>

namespace AuditPerUserPure {

namespace {

// JSON-string escape. The verb token is constrained by parseVerb's
// snake_case alphabet so escapes never fire there in practice; defence
// in depth for future fields with looser charsets. 1.1.29: delegates to
// the shared escaper — the former copy passed every control byte other
// than \n \r \t through RAW (invalid JSON); now all are escaped.
std::string escape(const std::string &s) { return JsonPure::escape(s); }

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
