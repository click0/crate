// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.65 (TODO §17.8, bwrap --json-status-fd): the machine-readable
// lifecycle `crate run --status-fd N` writes — one JSON object per line,
// one line per phase. This module is the format: the event names, how a
// line is rendered, and how a consumer (`crate stack up`, crated's
// spawned-jail owner watch, a CI harness) reads it back. No I/O here.
//
// The stream, in order, for a normal run:
//
//   {"event":"started","ts":T,"pid":P,"name":"<jail name>"}
//   {"event":"jail_created","ts":T,"jid":J,"name":"...","path":"/var/run/crate/jail-..."}
//   {"event":"net_ready","ts":T,"mode":"bridge","ip":"10.0.0.7"}       (ip when known)
//   {"event":"mounts_ready","ts":T}
//   {"event":"services_started","ts":T}
//   {"event":"healthy","ts":T}  |  {"event":"unhealthy","ts":T}       (healthcheck: only)
//   {"event":"exec_started","ts":T,"user":"alice","command":"/usr/local/bin/firefox"}
//   {"event":"exited","ts":T,"code":0,"reason":"exited normally","timed_out":false}
//   {"event":"teardown_done","ts":T}
//
// A run that throws before the command ran ends with
//   {"event":"failed","ts":T,"error":"..."} then teardown_done.
// `exited`, `failed` and end-of-stream are the terminal signals; a
// consumer waiting for the jail stops at the first of jail_created /
// exited / failed / EOF.
//
// Values are strings or integers (the booleans `timed_out` render as
// true/false); no nesting, so parseLine() below is a complete reader of
// what renderLine() writes and nothing more.

#pragma once

#include <map>
#include <string>
#include <vector>

namespace StatusPure {

// Event names, as written in the "event" field.
constexpr const char *kStarted         = "started";
constexpr const char *kJailCreated     = "jail_created";
constexpr const char *kNetReady        = "net_ready";
constexpr const char *kMountsReady     = "mounts_ready";
constexpr const char *kServicesStarted = "services_started";
constexpr const char *kHealthy         = "healthy";
constexpr const char *kUnhealthy       = "unhealthy";
constexpr const char *kExecStarted     = "exec_started";
constexpr const char *kExited          = "exited";
constexpr const char *kFailed          = "failed";
constexpr const char *kTeardownDone    = "teardown_done";

// true for the events after which nothing but teardown_done follows.
bool isTerminalEvent(const std::string &event);

// One field of an event. `number` renders the value bare (an integer
// or true/false); otherwise it is a JSON string.
struct Field {
  std::string key;
  std::string value;
  bool number = false;
};
Field str(const std::string &key, const std::string &value);
Field num(const std::string &key, long long value);
Field boolean(const std::string &key, bool value);

// Render one line: {"event":"<event>","ts":<epochSec>,<fields...>}\n.
// Field order is preserved; keys "event" and "ts" in `fields` are
// skipped so a caller cannot produce two of them.
std::string renderLine(const std::string &event, long long epochSec,
                       const std::vector<Field> &fields);

// A parsed line. `fields` holds every key but "event" as text (numbers
// and booleans as their bare spelling, strings unescaped).
struct Event {
  std::string event;
  long long ts = 0;
  std::map<std::string, std::string> fields;

  // "" when the key is absent
  std::string get(const std::string &key) const;
  // false when absent or not an integer
  bool getInt(const std::string &key, long long &out) const;
};

// Parse one line as written by renderLine(): a flat JSON object whose
// values are strings, integers, true/false or null. Leading/trailing
// whitespace and the newline are ignored. Returns false (and leaves
// `out` untouched) on anything else — nested values, trailing garbage,
// a missing "event".
bool parseLine(const std::string &line, Event &out);

// Byte-stream to lines. feed() appends what read(2) returned; next()
// pops one complete line (without its '\n') while there is one. A
// partial last line stays until more bytes arrive; flush() hands it
// out at EOF. Lines over kMaxLine bytes are dropped (a consumer
// reading a hostile fd must not buffer without bound).
class LineBuffer {
public:
  static constexpr size_t kMaxLine = 64 * 1024;
  void feed(const char *data, size_t len);
  bool next(std::string &line);
  bool flush(std::string &line);
private:
  std::string buf_;
  bool overflow_ = false;
};

// `--status-fd N`: an integer 3..INT_MAX (0-2 are the operator's stdio,
// which crate itself writes to). Returns "" when valid, else the reason.
std::string parseStatusFd(const std::string &text, int &fdOut);

}
