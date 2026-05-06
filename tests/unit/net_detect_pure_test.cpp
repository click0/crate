// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "net_detect_pure.h"

#include <atf-c++.hpp>

#include <string>

using NetDetectPure::parseRouteOutput;

ATF_TEST_CASE_WITHOUT_HEAD(typical_route_output);
ATF_TEST_CASE_BODY(typical_route_output) {
  // Exact output as `route -4 get default` produces on FreeBSD 14.
  std::string out =
    "   route to: default\n"
    "destination: default\n"
    "       mask: default\n"
    "    gateway: 192.168.1.1\n"
    "        fib: 0\n"
    "  interface: em0\n"
    "      flags: <UP,GATEWAY,DONE,STATIC>\n"
    "recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire\n"
    "     0         0         0         0      1500         1         0\n";
  ATF_REQUIRE_EQ(parseRouteOutput(out), std::string("em0"));
}

ATF_TEST_CASE_WITHOUT_HEAD(vlan_iface);
ATF_TEST_CASE_BODY(vlan_iface) {
  // VLAN interface (dotted form) accepted.
  std::string out = "  interface: vlan0.100\n";
  ATF_REQUIRE_EQ(parseRouteOutput(out), std::string("vlan0.100"));
}

ATF_TEST_CASE_WITHOUT_HEAD(no_interface_line);
ATF_TEST_CASE_BODY(no_interface_line) {
  // Default route exists but route(8) didn't print interface (e.g.
  // host-based blackhole route). Returns "" so caller falls back.
  std::string out =
    "   route to: default\n"
    "destination: default\n"
    "    gateway: 192.168.1.1\n";
  ATF_REQUIRE_EQ(parseRouteOutput(out), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(empty_input);
ATF_TEST_CASE_BODY(empty_input) {
  ATF_REQUIRE_EQ(parseRouteOutput(""), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(crlf_line_endings);
ATF_TEST_CASE_BODY(crlf_line_endings) {
  // Operator pipes the output through a tool that adds CRLF.
  std::string out = "  interface: em0\r\n";
  ATF_REQUIRE_EQ(parseRouteOutput(out), std::string("em0"));
}

ATF_TEST_CASE_WITHOUT_HEAD(rejects_garbage_value);
ATF_TEST_CASE_BODY(rejects_garbage_value) {
  // Defence in depth: if the value after "interface:" contains
  // shell metacharacters (which it shouldn't but parser is the
  // last line of defence before the value lands in pf rules),
  // return empty.
  ATF_REQUIRE_EQ(parseRouteOutput("  interface: em0;rm -rf /\n"),
                 std::string());
  ATF_REQUIRE_EQ(parseRouteOutput("  interface: em0`pwd`\n"),
                 std::string());
  ATF_REQUIRE_EQ(parseRouteOutput("  interface: em 0\n"),  // space
                 std::string());
  ATF_REQUIRE_EQ(parseRouteOutput("  interface: \n"),       // empty value
                 std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(takes_first_match);
ATF_TEST_CASE_BODY(takes_first_match) {
  // Multiple "interface:" lines (shouldn't happen with route(8),
  // but parser is robust). Takes the FIRST one.
  std::string out =
    "  interface: em0\n"
    "  interface: em1\n";
  ATF_REQUIRE_EQ(parseRouteOutput(out), std::string("em0"));
}

ATF_TEST_CASE_WITHOUT_HEAD(rejects_oversized_iface);
ATF_TEST_CASE_BODY(rejects_oversized_iface) {
  // > 15 chars (FreeBSD IFNAMSIZ - 1) — reject.
  std::string out = "  interface: " + std::string(16, 'a') + "\n";
  ATF_REQUIRE_EQ(parseRouteOutput(out), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(tab_separator_accepted);
ATF_TEST_CASE_BODY(tab_separator_accepted) {
  // Whitespace tolerance: tabs work too.
  std::string out = "\tinterface:\tem0\n";
  ATF_REQUIRE_EQ(parseRouteOutput(out), std::string("em0"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, typical_route_output);
  ATF_ADD_TEST_CASE(tcs, vlan_iface);
  ATF_ADD_TEST_CASE(tcs, no_interface_line);
  ATF_ADD_TEST_CASE(tcs, empty_input);
  ATF_ADD_TEST_CASE(tcs, crlf_line_endings);
  ATF_ADD_TEST_CASE(tcs, rejects_garbage_value);
  ATF_ADD_TEST_CASE(tcs, takes_first_match);
  ATF_ADD_TEST_CASE(tcs, rejects_oversized_iface);
  ATF_ADD_TEST_CASE(tcs, tab_separator_accepted);
}
