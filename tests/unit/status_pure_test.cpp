// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "status_pure.h"
#include "run_pure.h"

#include <atf-c++.hpp>

#include <cstring>
#include <string>

using namespace StatusPure;

ATF_TEST_CASE_WITHOUT_HEAD(render_line);
ATF_TEST_CASE_BODY(render_line) {
  ATF_REQUIRE_EQ(renderLine(kStarted, 1700000000, {num("pid", 4242)}),
                 std::string("{\"event\":\"started\",\"ts\":1700000000,\"pid\":4242}\n"));
  ATF_REQUIRE_EQ(renderLine(kJailCreated, 7, {num("jid", 12), str("name", "ff_pid4242"), str("path", "/var/run/crate/jail-ff-ab12")}),
                 std::string("{\"event\":\"jail_created\",\"ts\":7,\"jid\":12,\"name\":\"ff_pid4242\",\"path\":\"/var/run/crate/jail-ff-ab12\"}\n"));
  ATF_REQUIRE_EQ(renderLine(kExited, 1, {num("code", 124), str("reason", "timed out"), boolean("timed_out", true)}),
                 std::string("{\"event\":\"exited\",\"ts\":1,\"code\":124,\"reason\":\"timed out\",\"timed_out\":true}\n"));
  ATF_REQUIRE_EQ(renderLine(kTeardownDone, 2, {}), std::string("{\"event\":\"teardown_done\",\"ts\":2}\n"));
  // strings are escaped; a caller's "event"/"ts" cannot double the keys
  ATF_REQUIRE_EQ(renderLine(kFailed, 3, {str("error", "bad \"spec\"\n"), str("event", "x"), num("ts", 9)}),
                 std::string("{\"event\":\"failed\",\"ts\":3,\"error\":\"bad \\\"spec\\\"\\n\"}\n"));
  ATF_REQUIRE(isTerminalEvent(kExited));
  ATF_REQUIRE(isTerminalEvent(kFailed));
  ATF_REQUIRE(!isTerminalEvent(kJailCreated));
  ATF_REQUIRE(!isTerminalEvent(kTeardownDone));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_line_roundtrip);
ATF_TEST_CASE_BODY(parse_line_roundtrip) {
  Event ev;
  ATF_REQUIRE(parseLine(renderLine(kJailCreated, 1700000000, {num("jid", 12), str("name", "ff_pid4242"), str("path", "/var/run/crate/jail-ff-ab12")}), ev));
  ATF_REQUIRE_EQ(ev.event, std::string("jail_created"));
  ATF_REQUIRE_EQ(ev.ts, 1700000000LL);
  long long jid = 0;
  ATF_REQUIRE(ev.getInt("jid", jid));
  ATF_REQUIRE_EQ(jid, 12LL);
  ATF_REQUIRE_EQ(ev.get("name"), std::string("ff_pid4242"));
  ATF_REQUIRE_EQ(ev.get("path"), std::string("/var/run/crate/jail-ff-ab12"));
  ATF_REQUIRE_EQ(ev.get("missing"), std::string());
  ATF_REQUIRE(!ev.getInt("name", jid));
  ATF_REQUIRE(!ev.getInt("missing", jid));

  // escapes come back, booleans keep their spelling, null is accepted
  ATF_REQUIRE(parseLine(renderLine(kFailed, 3, {str("error", "bad \"spec\"\n\ttab \\ slash / \x01"), boolean("timed_out", false)}), ev));
  ATF_REQUIRE_EQ(ev.get("error"), std::string("bad \"spec\"\n\ttab \\ slash / \x01"));
  ATF_REQUIRE_EQ(ev.get("timed_out"), std::string("false"));
  ATF_REQUIRE(parseLine("  {\"event\":\"x\",\"ts\":0,\"a\":null,\"b\":-5,\"c\":\"\\u00e9\\u0041\"}  \n", ev));
  ATF_REQUIRE_EQ(ev.get("a"), std::string("null"));
  long long b = 0;
  ATF_REQUIRE(ev.getInt("b", b));
  ATF_REQUIRE_EQ(b, -5LL);
  ATF_REQUIRE_EQ(ev.get("c"), std::string("\xc3\xa9" "A"));
  // no ts is fine (0)
  ATF_REQUIRE(parseLine("{\"event\":\"exited\",\"code\":0}", ev));
  ATF_REQUIRE_EQ(ev.ts, 0LL);
  ATF_REQUIRE_EQ(ev.get("code"), std::string("0"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_line_rejects);
ATF_TEST_CASE_BODY(parse_line_rejects) {
  Event keep;
  keep.event = "untouched";
  for (const char *bad : {
         "",
         "{}",
         "not json",
         "{\"ts\":1}",                                   // no event
         "{\"event\":\"\"}",                             // empty event
         "{\"event\":1}",                                // event not a string
         "{\"event\":\"a\",\"ts\":\"1\"}",               // ts not a number
         "{\"event\":\"a\",\"event\":\"b\"}",            // duplicate
         "{\"event\":\"a\",\"k\":1,\"k\":2}",            // duplicate field
         "{\"event\":\"a\",\"k\":{\"n\":1}}",            // nested object
         "{\"event\":\"a\",\"k\":[1]}",                  // array
         "{\"event\":\"a\",\"k\":1.5}",                  // float
         "{\"event\":\"a\",\"k\":tru}",                  // bad literal
         "{\"event\":\"a\",\"k\":\"unterminated}",
         "{\"event\":\"a\",\"k\":\"bad \\x escape\"}",
         "{\"event\":\"a\",\"k\":\"\\ud800\"}",          // surrogate
         "{\"event\":\"a\",\"k\":\"ctl\x01\"}",          // raw control char
         "{\"event\":\"a\"} trailing",
         "{\"event\":\"a\",}",
         "{\"event\":\"a\" \"k\":1}",
         "[{\"event\":\"a\"}]",
       }) {
    ATF_REQUIRE(!parseLine(bad, keep));
    ATF_REQUIRE_EQ(keep.event, std::string("untouched"));
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(line_buffer);
ATF_TEST_CASE_BODY(line_buffer) {
  LineBuffer lb;
  std::string line;
  ATF_REQUIRE(!lb.next(line));
  const char *a = "{\"event\":\"started\"}\n{\"event\":\"jail_cr";
  lb.feed(a, strlen(a));
  ATF_REQUIRE(lb.next(line));
  ATF_REQUIRE_EQ(line, std::string("{\"event\":\"started\"}"));
  ATF_REQUIRE(!lb.next(line));                 // partial line waits
  const char *b = "eated\"}\n\n{\"event\":\"x\"}";
  lb.feed(b, strlen(b));
  ATF_REQUIRE(lb.next(line));
  ATF_REQUIRE_EQ(line, std::string("{\"event\":\"jail_created\"}"));
  ATF_REQUIRE(lb.next(line));
  ATF_REQUIRE_EQ(line, std::string());         // the empty line is a line
  ATF_REQUIRE(!lb.next(line));
  ATF_REQUIRE(lb.flush(line));                 // EOF hands out the tail
  ATF_REQUIRE_EQ(line, std::string("{\"event\":\"x\"}"));
  ATF_REQUIRE(!lb.flush(line));

  // an oversize line is dropped, the one after it survives
  std::string huge(LineBuffer::kMaxLine + 10, 'x');
  huge += "\n{\"event\":\"after\"}\n";
  lb.feed(huge.data(), huge.size());
  ATF_REQUIRE(lb.next(line));
  ATF_REQUIRE_EQ(line, std::string("{\"event\":\"after\"}"));
  ATF_REQUIRE(!lb.next(line));
  // oversize without a newline yet: flush gives nothing
  std::string huge2(LineBuffer::kMaxLine + 1, 'y');
  lb.feed(huge2.data(), huge2.size());
  ATF_REQUIRE(!lb.flush(line));
}

ATF_TEST_CASE_WITHOUT_HEAD(status_fd_option);
ATF_TEST_CASE_BODY(status_fd_option) {
  int fd = -1;
  ATF_REQUIRE_EQ(parseStatusFd("3", fd), std::string());
  ATF_REQUIRE_EQ(fd, 3);
  ATF_REQUIRE_EQ(parseStatusFd("17", fd), std::string());
  ATF_REQUIRE_EQ(fd, 17);
  fd = -1;
  for (const char *bad : {"", "0", "1", "2", "-3", "3x", "x", "abc", "1234567890"}) {
    ATF_REQUIRE(!parseStatusFd(bad, fd).empty());
    ATF_REQUIRE_EQ(fd, -1);
  }
  ATF_REQUIRE(parseStatusFd("2", fd).find("stdin/stdout/stderr") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(run_timeout);
ATF_TEST_CASE_BODY(run_timeout) {
  unsigned s = 0;
  ATF_REQUIRE_EQ(RunPure::parseRunTimeout("90", s), std::string());   ATF_REQUIRE_EQ(s, 90u);
  ATF_REQUIRE_EQ(RunPure::parseRunTimeout("90s", s), std::string());  ATF_REQUIRE_EQ(s, 90u);
  ATF_REQUIRE_EQ(RunPure::parseRunTimeout("15m", s), std::string());  ATF_REQUIRE_EQ(s, 900u);
  ATF_REQUIRE_EQ(RunPure::parseRunTimeout("2h", s), std::string());   ATF_REQUIRE_EQ(s, 7200u);
  ATF_REQUIRE_EQ(RunPure::parseRunTimeout("720h", s), std::string()); ATF_REQUIRE_EQ(s, RunPure::kRunTimeoutMax);
  s = 1;
  for (const char *bad : {"", "0", "0m", "-5", "5sec", "1d", "s", "1.5h", "9999999999", "721h", "99999m"}) {
    ATF_REQUIRE(!RunPure::parseRunTimeout(bad, s).empty());
    ATF_REQUIRE_EQ(s, 1u);   // untouched on error
  }

  ATF_REQUIRE(RunPure::runTimeoutPrefix(0).empty());
  auto p = RunPure::runTimeoutPrefix(90);
  ATF_REQUIRE_EQ(p.size(), 4u);
  ATF_REQUIRE_EQ(p[0], std::string("/usr/bin/timeout"));
  ATF_REQUIRE_EQ(p[1], std::string("-k"));
  ATF_REQUIRE_EQ(p[2], std::to_string(RunPure::kRunTimeoutKillAfter));
  ATF_REQUIRE_EQ(p[3], std::string("90"));

  ATF_REQUIRE(RunPure::runTimedOut(90, 124));
  ATF_REQUIRE(!RunPure::runTimedOut(90, 0));
  ATF_REQUIRE(!RunPure::runTimedOut(90, 1));
  ATF_REQUIRE(!RunPure::runTimedOut(0, 124));   // no timeout: 124 is the program's own code
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, render_line);
  ATF_ADD_TEST_CASE(tcs, parse_line_roundtrip);
  ATF_ADD_TEST_CASE(tcs, parse_line_rejects);
  ATF_ADD_TEST_CASE(tcs, line_buffer);
  ATF_ADD_TEST_CASE(tcs, status_fd_option);
  ATF_ADD_TEST_CASE(tcs, run_timeout);
}
