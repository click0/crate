// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_wire_pure.h"

#include <cctype>
#include <cstdlib>
#include <sstream>

namespace PrivOpsWirePure {

const char *const kPresent = "PRESENT";

namespace {

// Skip whitespace at `i`, advancing `i` past it. Returns true if
// at least one character was consumed.
bool skipWs(const std::string &s, size_t &i) {
  size_t start = i;
  while (i < s.size()
         && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r'))
    i++;
  return i > start;
}

// Position `i` at the value following `"fieldName":`. Returns:
//   "absent"        if the field is not in the body
//   "after-colon"   on success — `i` points at first non-ws char of value
//   "malformed"     if `"fieldName"` was found but no `:` follows
//
// Mirrors routes_pure.cpp's quoted-field finder; we keep this
// inline because we need the position both for string and
// non-string values.
enum class LocateResult { Absent, AfterColon, Malformed };

LocateResult locateField(const std::string &body,
                         const std::string &fieldName,
                         size_t &i) {
  std::string needle = "\"" + fieldName + "\"";
  auto k = body.find(needle);
  if (k == std::string::npos) return LocateResult::Absent;
  k += needle.size();
  while (k < body.size()
         && (body[k] == ' ' || body[k] == '\t' || body[k] == '\n' || body[k] == '\r'))
    k++;
  if (k >= body.size() || body[k] != ':') return LocateResult::Malformed;
  k++;
  while (k < body.size()
         && (body[k] == ' ' || body[k] == '\t' || body[k] == '\n' || body[k] == '\r'))
    k++;
  i = k;
  return LocateResult::AfterColon;
}

// Decode a JSON string starting at the opening quote. Sets `i` past
// the closing quote on success. Returns true on success.
bool decodeJsonString(const std::string &body, size_t &i, std::string &out) {
  if (i >= body.size() || body[i] != '"') return false;
  i++;
  out.clear();
  while (i < body.size() && body[i] != '"') {
    if (body[i] == '\\' && i + 1 < body.size()) {
      char esc = body[i + 1];
      switch (esc) {
        case '"':  out += '"';  break;
        case '\\': out += '\\'; break;
        case '/':  out += '/';  break;
        case 'n':  out += '\n'; break;
        case 'r':  out += '\r'; break;
        case 't':  out += '\t'; break;
        case 'b':  out += '\b'; break;
        case 'f':  out += '\f'; break;
        default:   out += esc;  break;
      }
      i += 2;
    } else {
      out += body[i];
      i++;
    }
  }
  if (i >= body.size()) return false;
  i++; // past closing quote
  return true;
}

// Decode a JSON number (signed integer). Sets `i` past the last
// digit on success. Returns true on success.
bool decodeJsonInteger(const std::string &body, size_t &i, long &out) {
  if (i >= body.size()) return false;
  size_t start = i;
  if (body[i] == '-') i++;
  if (i >= body.size() || !std::isdigit((unsigned char)body[i])) return false;
  while (i < body.size() && std::isdigit((unsigned char)body[i])) i++;
  // No fractional part allowed for integers; let the caller decide
  // whether to error or accept-and-truncate. We reject to be strict.
  if (i < body.size() && body[i] == '.') return false;
  // Token must be terminated by whitespace, comma, or close brace.
  if (i < body.size()) {
    char c = body[i];
    if (c != ' ' && c != '\t' && c != '\n' && c != '\r'
        && c != ',' && c != '}' && c != ']') return false;
  }
  std::string token = body.substr(start, i - start);
  out = std::strtol(token.c_str(), nullptr, 10);
  return true;
}

// Decode a JSON boolean (`true` or `false`). Sets `i` past the
// last character on success.
bool decodeJsonBool(const std::string &body, size_t &i, bool &out) {
  if (body.compare(i, 4, "true") == 0) {
    i += 4;
    out = true;
    return true;
  }
  if (body.compare(i, 5, "false") == 0) {
    i += 5;
    out = false;
    return true;
  }
  return false;
}

} // anon

// --- Generic extractors ---

std::string extractStringField(const std::string &body,
                               const std::string &fieldName,
                               std::string &out) {
  size_t i = 0;
  auto r = locateField(body, fieldName, i);
  if (r == LocateResult::Absent) return "";
  if (r == LocateResult::Malformed) return "field '" + fieldName + "' malformed";
  if (i >= body.size() || body[i] != '"')
    return "field '" + fieldName + "' is not a string";
  if (!decodeJsonString(body, i, out))
    return "field '" + fieldName + "' has unterminated string";
  return kPresent;
}

std::string extractLongField(const std::string &body,
                             const std::string &fieldName,
                             long &out) {
  size_t i = 0;
  auto r = locateField(body, fieldName, i);
  if (r == LocateResult::Absent) return "";
  if (r == LocateResult::Malformed) return "field '" + fieldName + "' malformed";
  if (!decodeJsonInteger(body, i, out))
    return "field '" + fieldName + "' is not an integer";
  return kPresent;
}

std::string extractUnsignedField(const std::string &body,
                                 const std::string &fieldName,
                                 unsigned &out) {
  long v = 0;
  std::string r = extractLongField(body, fieldName, v);
  if (r != kPresent) return r;
  if (v < 0) return "field '" + fieldName + "' must be non-negative";
  if (v > 0xFFFFFFFFL) return "field '" + fieldName + "' overflows 32-bit unsigned";
  out = (unsigned)v;
  return kPresent;
}

std::string extractBoolField(const std::string &body,
                             const std::string &fieldName,
                             bool &out) {
  size_t i = 0;
  auto r = locateField(body, fieldName, i);
  if (r == LocateResult::Absent) return "";
  if (r == LocateResult::Malformed) return "field '" + fieldName + "' malformed";
  if (!decodeJsonBool(body, i, out))
    return "field '" + fieldName + "' is not a boolean";
  return kPresent;
}

// --- Required wrappers ---

std::string requireStringField(const std::string &body,
                               const std::string &fieldName,
                               std::string &out) {
  std::string r = extractStringField(body, fieldName, out);
  if (r.empty()) return "missing field '" + fieldName + "'";
  if (r != kPresent) return r;
  return "";
}

std::string requireLongField(const std::string &body,
                             const std::string &fieldName,
                             long &out) {
  std::string r = extractLongField(body, fieldName, out);
  if (r.empty()) return "missing field '" + fieldName + "'";
  if (r != kPresent) return r;
  return "";
}

std::string requireUnsignedField(const std::string &body,
                                 const std::string &fieldName,
                                 unsigned &out) {
  std::string r = extractUnsignedField(body, fieldName, out);
  if (r.empty()) return "missing field '" + fieldName + "'";
  if (r != kPresent) return r;
  return "";
}

// --- Per-verb parsers ---

std::string parseCreateJail(const std::string &body,
                            PrivOpsPure::CreateJailReq &out) {
  if (auto e = requireStringField(body, "name", out.name); !e.empty()) return e;
  if (auto e = requireStringField(body, "path", out.path); !e.empty()) return e;
  // hostname optional (empty = inherit)
  std::string r = extractStringField(body, "hostname", out.hostname);
  if (!r.empty() && r != kPresent) return r;
  // vnet optional, default false
  bool b = false;
  std::string br = extractBoolField(body, "vnet", b);
  if (!br.empty() && br != kPresent) return br;
  if (br == kPresent) out.vnet = b;
  // parameters optional
  std::string pr = extractStringField(body, "parameters", out.parameters);
  if (!pr.empty() && pr != kPresent) return pr;
  return "";
}

std::string parseDestroyJail(const std::string &body,
                             PrivOpsPure::DestroyJailReq &out) {
  if (auto e = requireStringField(body, "name", out.name); !e.empty()) return e;
  bool b = false;
  std::string br = extractBoolField(body, "force", b);
  if (!br.empty() && br != kPresent) return br;
  if (br == kPresent) out.force = b;
  return "";
}

std::string parseMountNullfs(const std::string &body,
                             PrivOpsPure::MountNullfsReq &out) {
  if (auto e = requireStringField(body, "source", out.source); !e.empty()) return e;
  if (auto e = requireStringField(body, "target", out.target); !e.empty()) return e;
  bool b = true;
  std::string br = extractBoolField(body, "read_only", b);
  if (!br.empty() && br != kPresent) return br;
  if (br == kPresent) out.readOnly = b;
  return "";
}

std::string parseUnmountNullfs(const std::string &body,
                               PrivOpsPure::UnmountNullfsReq &out) {
  if (auto e = requireStringField(body, "target", out.target); !e.empty()) return e;
  bool b = false;
  std::string br = extractBoolField(body, "force", b);
  if (!br.empty() && br != kPresent) return br;
  if (br == kPresent) out.force = b;
  return "";
}

std::string parseSetRctl(const std::string &body,
                         PrivOpsPure::SetRctlReq &out) {
  if (auto e = requireLongField(body, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireStringField(body, "key", out.key); !e.empty()) return e;
  if (auto e = requireStringField(body, "value", out.rawValue); !e.empty()) return e;
  return "";
}

std::string parseClearRctl(const std::string &body,
                           PrivOpsPure::ClearRctlReq &out) {
  if (auto e = requireLongField(body, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireStringField(body, "key", out.key); !e.empty()) return e;
  return "";
}

std::string parseAttachZfs(const std::string &body,
                           PrivOpsPure::AttachZfsReq &out) {
  if (auto e = requireLongField(body, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireStringField(body, "dataset", out.dataset); !e.empty()) return e;
  return "";
}

std::string parseDetachZfs(const std::string &body,
                           PrivOpsPure::DetachZfsReq &out) {
  if (auto e = requireLongField(body, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireStringField(body, "dataset", out.dataset); !e.empty()) return e;
  return "";
}

std::string parseConfigureIface(const std::string &body,
                                PrivOpsPure::ConfigureIfaceReq &out) {
  if (auto e = requireLongField(body, "jid", out.jid); !e.empty()) return e;
  if (auto e = requireStringField(body, "ifname", out.ifname); !e.empty()) return e;
  // bridge / ipv4_cidr / ipv6_cidr / mac_addr all optional
  std::string r;
  r = extractStringField(body, "bridge", out.bridge);
  if (!r.empty() && r != kPresent) return r;
  r = extractStringField(body, "ipv4_cidr", out.ipv4Cidr);
  if (!r.empty() && r != kPresent) return r;
  r = extractStringField(body, "ipv6_cidr", out.ipv6Cidr);
  if (!r.empty() && r != kPresent) return r;
  r = extractStringField(body, "mac_addr", out.macAddr);
  if (!r.empty() && r != kPresent) return r;
  return "";
}

std::string parseTeardownIface(const std::string &body,
                               PrivOpsPure::TeardownIfaceReq &out) {
  if (auto e = requireStringField(body, "ifname", out.ifname); !e.empty()) return e;
  return "";
}

std::string parseAddPfRule(const std::string &body,
                           PrivOpsPure::AddPfRuleReq &out) {
  if (auto e = requireStringField(body, "anchor", out.anchor); !e.empty()) return e;
  if (auto e = requireStringField(body, "rule", out.ruleText); !e.empty()) return e;
  return "";
}

std::string parseRemovePfRule(const std::string &body,
                              PrivOpsPure::RemovePfRuleReq &out) {
  if (auto e = requireStringField(body, "anchor", out.anchor); !e.empty()) return e;
  if (auto e = requireStringField(body, "rule", out.ruleText); !e.empty()) return e;
  return "";
}

std::string parseAddIpfwRule(const std::string &body,
                             PrivOpsPure::AddIpfwRuleReq &out) {
  if (auto e = requireUnsignedField(body, "set", out.set); !e.empty()) return e;
  if (auto e = requireUnsignedField(body, "number", out.number); !e.empty()) return e;
  if (auto e = requireStringField(body, "action", out.action); !e.empty()) return e;
  if (auto e = requireStringField(body, "body", out.body); !e.empty()) return e;
  return "";
}

std::string parseRemoveIpfwRule(const std::string &body,
                                PrivOpsPure::RemoveIpfwRuleReq &out) {
  if (auto e = requireUnsignedField(body, "set", out.set); !e.empty()) return e;
  if (auto e = requireUnsignedField(body, "number", out.number); !e.empty()) return e;
  return "";
}

// --- Verb routing helper ---

PrivOpsPure::Verb parseVerbFromPath(const std::string &path) {
  // Match "/api/v1/privops/<verb>" exactly (no trailing slash, no
  // query string). Reject anything else.
  static const std::string prefix = "/api/v1/privops/";
  if (path.compare(0, prefix.size(), prefix) != 0)
    return PrivOpsPure::Verb::Unknown;
  std::string verb = path.substr(prefix.size());
  if (verb.empty() || verb.find('/') != std::string::npos)
    return PrivOpsPure::Verb::Unknown;
  return PrivOpsPure::parseVerb(verb);
}

// --- Response body builders ---
//
// We keep these tiny so the daemon route handler in 0.9.1 doesn't
// need to know about JSON escaping rules. The error string is
// passed through as-is — callers must have already stripped any
// double quotes from validator output (they don't produce any
// today, but a future validator that did would need to escape).

namespace {

// Conservative escape: backslash + double-quote. Tab/newline are
// rejected outright since validators never produce them. Same
// shape as the audit_pure escape but inlined to avoid pulling in
// audit_pure.h here.
std::string escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    if (c == '\\' || c == '"') out += '\\';
    if (c == '\n') { out += "\\n"; continue; }
    if (c == '\r') { out += "\\r"; continue; }
    if (c == '\t') { out += "\\t"; continue; }
    out += c;
  }
  return out;
}

} // anon

std::string formatNotImplemented(PrivOpsPure::Verb v) {
  std::ostringstream o;
  o << "{\"error\":\"verb '" << PrivOpsPure::verbName(v)
    << "' not yet implemented (handler lands in a 0.9.x release)\"}";
  return o.str();
}

std::string formatParseError(const std::string &reason) {
  return std::string("{\"error\":\"parse: ") + escape(reason) + "\"}";
}

std::string formatValidateError(const std::string &reason) {
  return std::string("{\"error\":\"validate: ") + escape(reason) + "\"}";
}

// --- Combined parse + validate helper ---

namespace {

// Each block: parse(body, req) -> validate(req) -> dispatch(501).
//
// The repetition reflects the per-verb request-struct types — a
// std::variant or template approach would compress the source but
// drag in machinery the rest of the codebase doesn't use. The
// dispatcher disappears as handlers land verb-by-verb in 0.9.2..0.9.7.

template <typename Req,
          typename Parser,
          typename Validator>
DispatchResult runVerb(const std::string &body,
                       PrivOpsPure::Verb v,
                       Parser parse,
                       Validator validate) {
  Req r;
  std::string e = parse(body, r);
  if (!e.empty()) return {400, formatParseError(e)};
  e = validate(r);
  if (!e.empty()) return {400, formatValidateError(e)};
  return {501, formatNotImplemented(v)};
}

} // anon

// --- Per-verb success/error builders ---

std::string formatHandlerError(const std::string &kind,
                               const std::string &reason) {
  std::ostringstream o;
  o << "{\"error\":\"" << escape(kind) << ": " << escape(reason) << "\"}";
  return o.str();
}

std::string formatSetRctlSuccess(long jid,
                                 const std::string &key,
                                 const std::string &rawValue) {
  std::ostringstream o;
  o << "{\"set\":true"
    << ",\"jid\":" << jid
    << ",\"key\":\"" << escape(key) << "\""
    << ",\"value\":\"" << escape(rawValue) << "\""
    << "}";
  return o.str();
}

std::string formatClearRctlSuccess(long jid, const std::string &key) {
  std::ostringstream o;
  o << "{\"cleared\":true"
    << ",\"jid\":" << jid
    << ",\"key\":\"" << escape(key) << "\""
    << "}";
  return o.str();
}

std::string formatAttachZfsSuccess(long jid, const std::string &dataset) {
  std::ostringstream o;
  o << "{\"attached\":true"
    << ",\"jid\":" << jid
    << ",\"dataset\":\"" << escape(dataset) << "\""
    << "}";
  return o.str();
}

std::string formatDetachZfsSuccess(long jid, const std::string &dataset) {
  std::ostringstream o;
  o << "{\"detached\":true"
    << ",\"jid\":" << jid
    << ",\"dataset\":\"" << escape(dataset) << "\""
    << "}";
  return o.str();
}

std::string formatMountNullfsSuccess(const std::string &source,
                                     const std::string &target,
                                     bool readOnly) {
  std::ostringstream o;
  o << "{\"mounted\":true"
    << ",\"source\":\"" << escape(source) << "\""
    << ",\"target\":\"" << escape(target) << "\""
    << ",\"read_only\":" << (readOnly ? "true" : "false")
    << "}";
  return o.str();
}

std::string formatUnmountNullfsSuccess(const std::string &target) {
  std::ostringstream o;
  o << "{\"unmounted\":true"
    << ",\"target\":\"" << escape(target) << "\""
    << "}";
  return o.str();
}

DispatchResult parseValidateAndDispatch(PrivOpsPure::Verb v,
                                        const std::string &body) {
  using namespace PrivOpsPure;
  switch (v) {
    case Verb::CreateJail:
      return runVerb<CreateJailReq>(body, v, parseCreateJail, validateCreateJail);
    case Verb::DestroyJail:
      return runVerb<DestroyJailReq>(body, v, parseDestroyJail, validateDestroyJail);
    case Verb::MountNullfs:
      return runVerb<MountNullfsReq>(body, v, parseMountNullfs, validateMountNullfs);
    case Verb::UnmountNullfs:
      return runVerb<UnmountNullfsReq>(body, v, parseUnmountNullfs, validateUnmountNullfs);
    case Verb::SetRctl:
      return runVerb<SetRctlReq>(body, v, parseSetRctl, validateSetRctl);
    case Verb::ClearRctl:
      return runVerb<ClearRctlReq>(body, v, parseClearRctl, validateClearRctl);
    case Verb::AttachZfs:
      return runVerb<AttachZfsReq>(body, v, parseAttachZfs, validateAttachZfs);
    case Verb::DetachZfs:
      return runVerb<DetachZfsReq>(body, v, parseDetachZfs, validateDetachZfs);
    case Verb::ConfigureIface:
      return runVerb<ConfigureIfaceReq>(body, v, parseConfigureIface, validateConfigureIface);
    case Verb::TeardownIface:
      return runVerb<TeardownIfaceReq>(body, v, parseTeardownIface, validateTeardownIface);
    case Verb::AddPfRule:
      return runVerb<AddPfRuleReq>(body, v, parseAddPfRule, validateAddPfRule);
    case Verb::RemovePfRule:
      return runVerb<RemovePfRuleReq>(body, v, parseRemovePfRule, validateRemovePfRule);
    case Verb::AddIpfwRule:
      return runVerb<AddIpfwRuleReq>(body, v, parseAddIpfwRule, validateAddIpfwRule);
    case Verb::RemoveIpfwRule:
      return runVerb<RemoveIpfwRuleReq>(body, v, parseRemoveIpfwRule, validateRemoveIpfwRule);
    case Verb::Unknown:
      break;
  }
  return {404, std::string("{\"error\":\"unknown privops verb\"}")};
}

} // namespace PrivOpsWirePure
