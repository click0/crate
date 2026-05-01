// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "routes_pure.h"

#include <sstream>

namespace RoutesPure {

namespace {

bool isAllDigits(const std::string &s) {
  if (s.empty()) return false;
  for (auto c : s) if (c < '0' || c > '9') return false;
  return true;
}

bool looksLikeNumber(const std::string &s) {
  // Accept integers and decimals like "1234" or "1.5". RCTL emits ints
  // for everything we care about, but be lenient.
  if (s.empty()) return false;
  size_t i = 0;
  if (s[0] == '-') i++;
  bool sawDigit = false, sawDot = false;
  for (; i < s.size(); i++) {
    if (s[i] >= '0' && s[i] <= '9') { sawDigit = true; continue; }
    if (s[i] == '.' && !sawDot) { sawDot = true; continue; }
    return false;
  }
  return sawDigit;
}

void appendJsonEscaped(std::ostringstream &os, const std::string &s) {
  for (unsigned char c : s) {
    switch (c) {
      case '"':  os << "\\\""; break;
      case '\\': os << "\\\\"; break;
      case '\n': os << "\\n";  break;
      case '\r': os << "\\r";  break;
      case '\t': os << "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
          os << buf;
        } else {
          os << (char)c;
        }
    }
  }
}

} // anon

std::string formatStatsSseEvent(const StatsInput &in, long unixEpoch) {
  std::ostringstream os;
  os << "data: {";
  os << "\"ts\":" << unixEpoch;
  os << ",\"name\":\"";
  appendJsonEscaped(os, in.name);
  os << "\"";
  os << ",\"jid\":" << in.jid;
  os << ",\"ip\":\"";
  appendJsonEscaped(os, in.ip);
  os << "\"";
  for (auto &kv : in.usage) {
    os << ",\"";
    appendJsonEscaped(os, kv.first);
    os << "\":";
    if (looksLikeNumber(kv.second)) {
      os << kv.second;
    } else {
      os << "\"";
      appendJsonEscaped(os, kv.second);
      os << "\"";
    }
  }
  os << "}\n\n";
  (void)isAllDigits; // keep compiler happy if someday unused
  return os.str();
}

std::string validateSnapshotName(const std::string &name) {
  if (name.empty()) return "snapshot name is empty";
  if (name.size() > 64) return "snapshot name is longer than 64 chars";
  if (name == "." || name == "..") return "snapshot name is reserved";
  for (auto c : name) {
    bool ok = (c >= 'a' && c <= 'z')
           || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9')
           || c == '.' || c == '_' || c == '-';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in snapshot name";
      return os.str();
    }
  }
  return "";
}

std::string extractStringField(const std::string &body, const std::string &fieldName) {
  // Find "fieldName" (with surrounding double quotes)
  std::string needle = "\"" + fieldName + "\"";
  auto k = body.find(needle);
  if (k == std::string::npos) return "";
  k += needle.size();
  // Skip whitespace and exactly one ':'
  while (k < body.size() && (body[k] == ' ' || body[k] == '\t' || body[k] == '\n' || body[k] == '\r')) k++;
  if (k >= body.size() || body[k] != ':') return "";
  k++;
  while (k < body.size() && (body[k] == ' ' || body[k] == '\t' || body[k] == '\n' || body[k] == '\r')) k++;
  if (k >= body.size() || body[k] != '"') return "";
  k++; // past opening quote
  std::string out;
  while (k < body.size() && body[k] != '"') {
    if (body[k] == '\\' && k + 1 < body.size()) {
      char esc = body[k + 1];
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
      k += 2;
    } else {
      out += body[k];
      k++;
    }
  }
  // If we didn't find a closing quote, treat the field as malformed.
  if (k >= body.size()) return "";
  return out;
}

} // namespace RoutesPure
