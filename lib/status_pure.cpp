// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "status_pure.h"
#include "json_pure.h"

#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>

namespace StatusPure {

bool isTerminalEvent(const std::string &event) {
  return event == kExited || event == kFailed;
}

Field str(const std::string &key, const std::string &value) { return {key, value, false}; }
Field num(const std::string &key, long long value) { return {key, std::to_string(value), true}; }
Field boolean(const std::string &key, bool value) { return {key, value ? "true" : "false", true}; }

std::string renderLine(const std::string &event, long long epochSec,
                       const std::vector<Field> &fields) {
  std::string s = "{\"event\":" + JsonPure::quote(event) + ",\"ts\":" + std::to_string(epochSec);
  for (auto &f : fields) {
    if (f.key == "event" || f.key == "ts") continue;
    s += "," + JsonPure::quote(f.key) + ":";
    s += f.number ? f.value : JsonPure::quote(f.value);
  }
  s += "}\n";
  return s;
}

std::string Event::get(const std::string &key) const {
  auto it = fields.find(key);
  return it == fields.end() ? std::string() : it->second;
}

bool Event::getInt(const std::string &key, long long &out) const {
  auto it = fields.find(key);
  if (it == fields.end() || it->second.empty()) return false;
  const std::string &v = it->second;
  size_t i = (v[0] == '-') ? 1 : 0;
  if (i >= v.size()) return false;
  for (size_t k = i; k < v.size(); k++)
    if (!isdigit((unsigned char)v[k])) return false;
  errno = 0;
  char *end = nullptr;
  long long r = std::strtoll(v.c_str(), &end, 10);
  if (errno != 0 || !end || *end) return false;
  out = r;
  return true;
}

// --- a minimal reader for the flat objects renderLine() writes ---

namespace {

struct Cursor {
  const std::string &s;
  size_t i = 0;
  void ws() { while (i < s.size() && isspace((unsigned char)s[i])) i++; }
  bool eof() const { return i >= s.size(); }
  char peek() const { return i < s.size() ? s[i] : '\0'; }
};

bool hex4(const std::string &s, size_t at, unsigned &out) {
  if (at + 4 > s.size()) return false;
  out = 0;
  for (size_t k = 0; k < 4; k++) {
    char c = s[at + k];
    out <<= 4;
    if (c >= '0' && c <= '9') out |= (unsigned)(c - '0');
    else if (c >= 'a' && c <= 'f') out |= (unsigned)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') out |= (unsigned)(c - 'A' + 10);
    else return false;
  }
  return true;
}

void putUtf8(std::string &out, unsigned cp) {
  if (cp < 0x80) out += (char)cp;
  else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
  else { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
}

bool parseString(Cursor &c, std::string &out) {
  if (c.peek() != '"') return false;
  c.i++;
  out.clear();
  while (!c.eof()) {
    char ch = c.s[c.i++];
    if (ch == '"') return true;
    if ((unsigned char)ch < 0x20) return false;
    if (ch != '\\') { out += ch; continue; }
    if (c.eof()) return false;
    char e = c.s[c.i++];
    switch (e) {
      case '"': out += '"'; break;
      case '\\': out += '\\'; break;
      case '/': out += '/'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case 'n': out += '\n'; break;
      case 'r': out += '\r'; break;
      case 't': out += '\t'; break;
      case 'u': {
        unsigned cp = 0;
        if (!hex4(c.s, c.i, cp)) return false;
        c.i += 4;
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;   // surrogates: renderLine never writes them
        putUtf8(out, cp);
        break;
      }
      default: return false;
    }
  }
  return false;   // unterminated
}

// A bare value: integer, true, false, null. Kept as its spelling.
bool parseBare(Cursor &c, std::string &out) {
  size_t start = c.i;
  if (c.peek() == '-') c.i++;
  if (isdigit((unsigned char)c.peek())) {
    while (isdigit((unsigned char)c.peek())) c.i++;
    out = c.s.substr(start, c.i - start);
    return true;
  }
  for (const char *word : {"true", "false", "null"}) {
    std::string w(word);
    if (c.s.compare(start, w.size(), w) == 0) {
      c.i = start + w.size();
      out = w;
      return true;
    }
  }
  return false;
}

}   // namespace

bool parseLine(const std::string &line, Event &out) {
  Cursor c{line};
  c.ws();
  if (c.peek() != '{') return false;
  c.i++;
  Event ev;
  bool haveEvent = false, haveTs = false;
  c.ws();
  if (c.peek() == '}') return false;   // an empty object has no event
  for (;;) {
    c.ws();
    std::string key, value;
    if (!parseString(c, key)) return false;
    c.ws();
    if (c.peek() != ':') return false;
    c.i++;
    c.ws();
    bool isString = c.peek() == '"';
    if (isString) {
      if (!parseString(c, value)) return false;
    } else if (!parseBare(c, value)) {
      return false;
    }
    if (key == "event") {
      if (!isString || haveEvent) return false;
      ev.event = value;
      haveEvent = true;
    } else if (key == "ts") {
      if (isString || haveTs) return false;
      errno = 0;
      char *end = nullptr;
      long long t = std::strtoll(value.c_str(), &end, 10);
      if (errno != 0 || !end || *end) return false;
      ev.ts = t;
      haveTs = true;
    } else if (ev.fields.count(key)) {
      return false;
    } else {
      ev.fields[key] = value;
    }
    c.ws();
    if (c.peek() == ',') { c.i++; continue; }
    if (c.peek() == '}') { c.i++; break; }
    return false;
  }
  c.ws();
  if (!c.eof()) return false;
  if (!haveEvent || ev.event.empty()) return false;
  out = std::move(ev);
  return true;
}

void LineBuffer::feed(const char *data, size_t len) {
  for (size_t k = 0; k < len; k++) {
    char ch = data[k];
    if (ch == '\n') {
      if (overflow_) { overflow_ = false; buf_.clear(); }   // the oversize line ends here: dropped
      else buf_ += ch;
      continue;
    }
    if (overflow_) continue;
    // size of the line being assembled: bytes after the last '\n'
    size_t lastNl = buf_.rfind('\n');
    size_t cur = lastNl == std::string::npos ? buf_.size() : buf_.size() - lastNl - 1;
    if (cur >= kMaxLine) {
      buf_.erase(lastNl == std::string::npos ? 0 : lastNl + 1);
      overflow_ = true;
      continue;
    }
    buf_ += ch;
  }
}

bool LineBuffer::next(std::string &line) {
  size_t nl = buf_.find('\n');
  if (nl == std::string::npos) return false;
  line = buf_.substr(0, nl);
  buf_.erase(0, nl + 1);
  return true;
}

bool LineBuffer::flush(std::string &line) {
  if (next(line)) return true;
  if (buf_.empty() || overflow_) { buf_.clear(); overflow_ = false; return false; }
  line = buf_;
  buf_.clear();
  return true;
}

std::string parseStatusFd(const std::string &text, int &fdOut) {
  if (text.empty()) return "--status-fd needs a descriptor number";
  for (char ch : text)
    if (!isdigit((unsigned char)ch)) return "--status-fd: '" + text + "' is not a descriptor number";
  if (text.size() > 9) return "--status-fd: '" + text + "' is out of range";
  long v = std::strtol(text.c_str(), nullptr, 10);
  if (v < 3) return "--status-fd: descriptor " + text + " is stdin/stdout/stderr; use 3 or higher (e.g. `3>status.jsonl`)";
  if (v > INT_MAX) return "--status-fd: '" + text + "' is out of range";
  fdOut = (int)v;
  return "";
}

}
