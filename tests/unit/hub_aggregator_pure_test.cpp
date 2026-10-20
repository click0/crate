// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "aggregator_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using AggregatorPure::NodeView;
using AggregatorPure::Summary;
using AggregatorPure::summarise;
using AggregatorPure::renderSummaryJson;
using AggregatorPure::countTopLevelObjects;

ATF_TEST_CASE_WITHOUT_HEAD(summarise_empty);
ATF_TEST_CASE_BODY(summarise_empty) {
  auto s = summarise({});
  ATF_REQUIRE_EQ(s.nodesTotal,      (unsigned)0);
  ATF_REQUIRE_EQ(s.nodesReachable,  (unsigned)0);
  ATF_REQUIRE_EQ(s.nodesDown,       (unsigned)0);
  ATF_REQUIRE_EQ(s.containersTotal, (unsigned)0);
}

ATF_TEST_CASE_WITHOUT_HEAD(summarise_mixed_reachability);
ATF_TEST_CASE_BODY(summarise_mixed_reachability) {
  std::vector<NodeView> nodes = {
    {"alpha", "10.0.0.1",  true,  3},
    {"beta",  "10.0.0.2",  false, 0},
    {"gamma", "10.0.0.3",  true,  5},
  };
  auto s = summarise(nodes);
  ATF_REQUIRE_EQ(s.nodesTotal,      (unsigned)3);
  ATF_REQUIRE_EQ(s.nodesReachable,  (unsigned)2);
  ATF_REQUIRE_EQ(s.nodesDown,       (unsigned)1);
  // Unreachable node's containerCount is ignored.
  ATF_REQUIRE_EQ(s.containersTotal, (unsigned)8);
}

ATF_TEST_CASE_WITHOUT_HEAD(summarise_unreachable_count_excluded_from_total);
ATF_TEST_CASE_BODY(summarise_unreachable_count_excluded_from_total) {
  // Even if an unreachable node has stale containerCount > 0 in its
  // NodeView (e.g. last-known value from cache), the summary must not
  // count it — those containers may already be gone.
  std::vector<NodeView> nodes = {
    {"alpha", "10.0.0.1", false, 999},
  };
  auto s = summarise(nodes);
  ATF_REQUIRE_EQ(s.containersTotal, (unsigned)0);
  ATF_REQUIRE_EQ(s.nodesDown,       (unsigned)1);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_summary_json_field_order);
ATF_TEST_CASE_BODY(render_summary_json_field_order) {
  Summary s{4, 3, 1, 17};
  auto j = renderSummaryJson(s);
  ATF_REQUIRE_EQ(j, std::string(
    "{\"nodes_total\":4"
    ",\"nodes_reachable\":3"
    ",\"nodes_down\":1"
    ",\"containers_total\":17}"));
}

// --- countTopLevelObjects ---

ATF_TEST_CASE_WITHOUT_HEAD(count_empty_array);
ATF_TEST_CASE_BODY(count_empty_array) {
  ATF_REQUIRE_EQ(countTopLevelObjects("[]"),       (unsigned)0);
  ATF_REQUIRE_EQ(countTopLevelObjects("  []  "),   (unsigned)0);
  ATF_REQUIRE_EQ(countTopLevelObjects("[\n]"),     (unsigned)0);
}

ATF_TEST_CASE_WITHOUT_HEAD(count_simple_objects);
ATF_TEST_CASE_BODY(count_simple_objects) {
  ATF_REQUIRE_EQ(countTopLevelObjects("[{},{}]"),                 (unsigned)2);
  ATF_REQUIRE_EQ(countTopLevelObjects("[{\"a\":1}]"),             (unsigned)1);
  ATF_REQUIRE_EQ(countTopLevelObjects("[{\"a\":1},{\"b\":2}]"),   (unsigned)2);
}

ATF_TEST_CASE_WITHOUT_HEAD(count_nested_objects_only_top_level);
ATF_TEST_CASE_BODY(count_nested_objects_only_top_level) {
  // 1 top-level object whose body contains 2 nested objects → still 1.
  ATF_REQUIRE_EQ(countTopLevelObjects("[{\"x\":{\"y\":{}}}]"),    (unsigned)1);
  // Two top-level objects each with a nested object → 2.
  ATF_REQUIRE_EQ(countTopLevelObjects("[{\"x\":{}},{\"y\":{}}]"), (unsigned)2);
}

ATF_TEST_CASE_WITHOUT_HEAD(count_ignores_braces_in_strings);
ATF_TEST_CASE_BODY(count_ignores_braces_in_strings) {
  // Curly braces inside a JSON string must not bump the count.
  ATF_REQUIRE_EQ(countTopLevelObjects("[{\"name\":\"ab{cd}ef\"}]"), (unsigned)1);
  ATF_REQUIRE_EQ(countTopLevelObjects("[{\"x\":\"\\\"{\"}]"),       (unsigned)1);
}

ATF_TEST_CASE_WITHOUT_HEAD(count_malformed_returns_zero);
ATF_TEST_CASE_BODY(count_malformed_returns_zero) {
  ATF_REQUIRE_EQ(countTopLevelObjects(""),           (unsigned)0);
  ATF_REQUIRE_EQ(countTopLevelObjects("not json"),   (unsigned)0);
  ATF_REQUIRE_EQ(countTopLevelObjects("[{"),         (unsigned)0);
  ATF_REQUIRE_EQ(countTopLevelObjects("[\"abc"),     (unsigned)0);
  // Object outside an array — not a top-level array, return 0.
  ATF_REQUIRE_EQ(countTopLevelObjects("{}"),         (unsigned)0);
}

// --- 1.1.49: crated envelope unwrapping + host:port splitting ---

ATF_TEST_CASE_WITHOUT_HEAD(extract_container_array_from_crated_envelope);
ATF_TEST_CASE_BODY(extract_container_array_from_crated_envelope) {
  using AggregatorPure::extractContainerArray;
  using AggregatorPure::countTopLevelObjects;
  // what crated actually returns: envelope + jls --libxo json object
  const std::string crated =
    R"({"status":"ok","data":{"__version":"2","jail-information":{"jail":[)"
    R"({"jid":3,"hostname":"web.local","path":"/var/run/crate/jail-web-1a2b","name":"web_pid100"},)"
    R"({"jid":4,"hostname":"db.local","path":"/var/run/crate/jail-db-3c4d","name":"db_pid200"}]}}})";
  auto arr = extractContainerArray(crated);
  ATF_REQUIRE_EQ(arr.front(), '[');
  ATF_REQUIRE_EQ(arr.back(), ']');
  ATF_REQUIRE_EQ(countTopLevelObjects(arr), 2u);     // used to be 0 on every node
  // data already an array
  ATF_REQUIRE_EQ(extractContainerArray(R"({"status":"ok","data":[{"a":1}]})"), std::string(R"([{"a":1}])"));
  // bare jls object, bare array, empty jail list
  ATF_REQUIRE_EQ(extractContainerArray(R"({"jail-information":{"jail":[{"jid":1}]}})"), std::string(R"([{"jid":1}])"));
  ATF_REQUIRE_EQ(extractContainerArray("  [ {\"x\":\"]\"} ]"), std::string("[ {\"x\":\"]\"} ]"));
  ATF_REQUIRE_EQ(extractContainerArray(R"({"status":"ok","data":{"jail-information":{"jail":[]}}})"), std::string("[]"));
  // garbage (reverse-proxy error page), empty, unbalanced -> []
  ATF_REQUIRE_EQ(extractContainerArray("<html>502 Bad Gateway</html>"), std::string("[]"));
  ATF_REQUIRE_EQ(extractContainerArray(""), std::string("[]"));
  ATF_REQUIRE_EQ(extractContainerArray(R"({"status":"ok","data":[{"a":1})"), std::string("[]"));
  ATF_REQUIRE_EQ(extractContainerArray(R"({"status":"error","error":"x"})"), std::string("[]"));
}

ATF_TEST_CASE_WITHOUT_HEAD(split_host_port_forms);
ATF_TEST_CASE_BODY(split_host_port_forms) {
  using AggregatorPure::splitHostPort;
  std::string h; int p = 0;
  ATF_REQUIRE(splitHostPort("alpha.example.com:9800", h, p)); ATF_REQUIRE_EQ(h, std::string("alpha.example.com")); ATF_REQUIRE_EQ(p, 9800);
  ATF_REQUIRE(splitHostPort("alpha", h, p, 9800));             ATF_REQUIRE_EQ(h, std::string("alpha")); ATF_REQUIRE_EQ(p, 9800);
  ATF_REQUIRE(splitHostPort("[::1]:9801", h, p));              ATF_REQUIRE_EQ(h, std::string("::1")); ATF_REQUIRE_EQ(p, 9801);
  ATF_REQUIRE(splitHostPort("[fd00::5]", h, p));               ATF_REQUIRE_EQ(h, std::string("fd00::5")); ATF_REQUIRE_EQ(p, 9800);
  ATF_REQUIRE(splitHostPort("fd00::5", h, p));                 ATF_REQUIRE_EQ(h, std::string("fd00::5")); ATF_REQUIRE_EQ(p, 9800);
  ATF_REQUIRE(splitHostPort("10.0.0.1:1", h, p));              ATF_REQUIRE_EQ(p, 1);
  ATF_REQUIRE(!splitHostPort("", h, p));
  ATF_REQUIRE(!splitHostPort("alpha:", h, p));                 // empty port
  ATF_REQUIRE(!splitHostPort("alpha:abc", h, p));
  ATF_REQUIRE(!splitHostPort("alpha:70000", h, p));
  ATF_REQUIRE(!splitHostPort("[::1", h, p));                   // unbalanced
  ATF_REQUIRE(!splitHostPort("[::1]9800", h, p));              // missing ':'
  ATF_REQUIRE(!splitHostPort(":9800", h, p));                  // empty host
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, summarise_empty);
  ATF_ADD_TEST_CASE(tcs, summarise_mixed_reachability);
  ATF_ADD_TEST_CASE(tcs, summarise_unreachable_count_excluded_from_total);
  ATF_ADD_TEST_CASE(tcs, render_summary_json_field_order);
  ATF_ADD_TEST_CASE(tcs, count_empty_array);
  ATF_ADD_TEST_CASE(tcs, count_simple_objects);
  ATF_ADD_TEST_CASE(tcs, count_nested_objects_only_top_level);
  ATF_ADD_TEST_CASE(tcs, count_ignores_braces_in_strings);
  ATF_ADD_TEST_CASE(tcs, count_malformed_returns_zero);
  ATF_ADD_TEST_CASE(tcs, extract_container_array_from_crated_envelope);
  ATF_ADD_TEST_CASE(tcs, split_host_port_forms);
}
