// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ha_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using HaPure::HaSpec;
using HaPure::MigrationOrder;
using HaPure::NodeView;
using HaPure::evaluateFailoverOrders;
using HaPure::renderOrdersJson;
using HaPure::validateSpecs;

// --- evaluateFailoverOrders ---

ATF_TEST_CASE_WITHOUT_HEAD(no_orders_when_primary_reachable);
ATF_TEST_CASE_BODY(no_orders_when_primary_reachable) {
  std::vector<HaSpec> specs = {
    {"foo", "alpha", {"beta", "gamma"}},
  };
  std::vector<NodeView> nodes = {
    {"alpha", true,  0},
    {"beta",  true,  0},
    {"gamma", true,  0},
  };
  ATF_REQUIRE(evaluateFailoverOrders(specs, nodes, 60).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(no_orders_below_threshold);
ATF_TEST_CASE_BODY(no_orders_below_threshold) {
  // Anti-flap: primary down 30s, threshold 60s → don't act yet.
  std::vector<HaSpec> specs = {
    {"foo", "alpha", {"beta"}},
  };
  std::vector<NodeView> nodes = {
    {"alpha", false, 30},
    {"beta",  true,  0},
  };
  ATF_REQUIRE(evaluateFailoverOrders(specs, nodes, 60).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(emit_order_at_threshold);
ATF_TEST_CASE_BODY(emit_order_at_threshold) {
  std::vector<HaSpec> specs = {
    {"foo", "alpha", {"beta"}},
  };
  std::vector<NodeView> nodes = {
    {"alpha", false, 60},  // exactly at threshold counts as down
    {"beta",  true,  0},
  };
  auto out = evaluateFailoverOrders(specs, nodes, 60);
  ATF_REQUIRE_EQ(out.size(), (size_t)1);
  ATF_REQUIRE_EQ(out[0].container, std::string("foo"));
  ATF_REQUIRE_EQ(out[0].fromNode,  std::string("alpha"));
  ATF_REQUIRE_EQ(out[0].toNode,    std::string("beta"));
  ATF_REQUIRE(!out[0].reason.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(picks_first_reachable_partner_in_order);
ATF_TEST_CASE_BODY(picks_first_reachable_partner_in_order) {
  // Order matters — partner list is operator-priority-ordered.
  std::vector<HaSpec> specs = {
    {"foo", "alpha", {"beta", "gamma", "delta"}},
  };
  std::vector<NodeView> nodes = {
    {"alpha", false, 120},
    {"beta",  false, 50},   // partner #1 also down
    {"gamma", true,  0},    // partner #2 picked
    {"delta", true,  0},    // partner #3 reachable but earlier wins
  };
  auto out = evaluateFailoverOrders(specs, nodes, 60);
  ATF_REQUIRE_EQ(out.size(), (size_t)1);
  ATF_REQUIRE_EQ(out[0].toNode, std::string("gamma"));
}

ATF_TEST_CASE_WITHOUT_HEAD(no_order_when_all_partners_down);
ATF_TEST_CASE_BODY(no_order_when_all_partners_down) {
  // Better to leave the container down than emit a half-order.
  std::vector<HaSpec> specs = {
    {"foo", "alpha", {"beta", "gamma"}},
  };
  std::vector<NodeView> nodes = {
    {"alpha", false, 120},
    {"beta",  false, 100},
    {"gamma", false, 50},
  };
  ATF_REQUIRE(evaluateFailoverOrders(specs, nodes, 60).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(missing_primary_node_skips_silently);
ATF_TEST_CASE_BODY(missing_primary_node_skips_silently) {
  // Operator typo or removed-from-config primary — don't crash;
  // just don't emit an order.
  std::vector<HaSpec> specs = {
    {"foo", "ghost", {"beta"}},
  };
  std::vector<NodeView> nodes = {
    {"beta", true, 0},
  };
  ATF_REQUIRE(evaluateFailoverOrders(specs, nodes, 60).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(multi_spec_orders_are_independent);
ATF_TEST_CASE_BODY(multi_spec_orders_are_independent) {
  std::vector<HaSpec> specs = {
    {"foo", "alpha", {"beta"}},
    {"bar", "alpha", {"gamma"}},
    {"baz", "delta", {"epsilon"}},   // delta is up — no order
  };
  std::vector<NodeView> nodes = {
    {"alpha",   false, 120},
    {"beta",    true,  0},
    {"gamma",   true,  0},
    {"delta",   true,  0},
    {"epsilon", true,  0},
  };
  auto out = evaluateFailoverOrders(specs, nodes, 60);
  ATF_REQUIRE_EQ(out.size(), (size_t)2);
  ATF_REQUIRE_EQ(out[0].container, std::string("foo"));
  ATF_REQUIRE_EQ(out[0].toNode,    std::string("beta"));
  ATF_REQUIRE_EQ(out[1].container, std::string("bar"));
  ATF_REQUIRE_EQ(out[1].toNode,    std::string("gamma"));
}

ATF_TEST_CASE_WITHOUT_HEAD(deterministic_no_thrash);
ATF_TEST_CASE_BODY(deterministic_no_thrash) {
  // Same input must give the same output across calls — the
  // poll-then-decide loop relies on this so consumers don't see
  // an order disappear and reappear when nothing actually changed.
  std::vector<HaSpec> specs = {
    {"foo", "alpha", {"beta", "gamma"}},
  };
  std::vector<NodeView> nodes = {
    {"alpha", false, 100},
    {"beta",  true,  0},
    {"gamma", true,  0},
  };
  auto a = evaluateFailoverOrders(specs, nodes, 60);
  auto b = evaluateFailoverOrders(specs, nodes, 60);
  ATF_REQUIRE_EQ(a.size(), b.size());
  for (size_t i = 0; i < a.size(); i++) {
    ATF_REQUIRE_EQ(a[i].container, b[i].container);
    ATF_REQUIRE_EQ(a[i].fromNode,  b[i].fromNode);
    ATF_REQUIRE_EQ(a[i].toNode,    b[i].toNode);
  }
}

// --- renderOrdersJson ---

ATF_TEST_CASE_WITHOUT_HEAD(render_empty_orders_yields_array);
ATF_TEST_CASE_BODY(render_empty_orders_yields_array) {
  ATF_REQUIRE_EQ(renderOrdersJson({}), std::string("[]"));
}

ATF_TEST_CASE_WITHOUT_HEAD(render_single_order_shape);
ATF_TEST_CASE_BODY(render_single_order_shape) {
  std::vector<MigrationOrder> orders = {
    {"foo", "alpha", "beta", "primary down for 120s"},
  };
  auto j = renderOrdersJson(orders);
  ATF_REQUIRE_EQ(j,
    std::string("[{\"container\":\"foo\","
                "\"from_node\":\"alpha\","
                "\"to_node\":\"beta\","
                "\"reason\":\"primary down for 120s\"}]"));
}

ATF_TEST_CASE_WITHOUT_HEAD(render_escapes_special_chars);
ATF_TEST_CASE_BODY(render_escapes_special_chars) {
  // Container/node names that pass validation can't contain `"`,
  // but `reason` is built by the runtime and should be safely
  // escaped against future formatting changes.
  std::vector<MigrationOrder> orders = {
    {"foo", "a", "b", "reason has \"quotes\" and\nnewline"},
  };
  auto j = renderOrdersJson(orders);
  ATF_REQUIRE(j.find("\\\"quotes\\\"") != std::string::npos);
  ATF_REQUIRE(j.find("\\n")             != std::string::npos);
}

// --- validateSpecs ---

ATF_TEST_CASE_WITHOUT_HEAD(validate_typical_spec_accepted);
ATF_TEST_CASE_BODY(validate_typical_spec_accepted) {
  std::vector<HaSpec> specs = {
    {"foo", "alpha", {"beta", "gamma"}},
    {"bar", "delta", {"epsilon"}},
  };
  ATF_REQUIRE_EQ(validateSpecs(specs), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(validate_invalid_specs_rejected);
ATF_TEST_CASE_BODY(validate_invalid_specs_rejected) {
  // Empty container.
  ATF_REQUIRE(!validateSpecs({{"", "alpha", {"beta"}}}).empty());
  // Invalid char in primary.
  ATF_REQUIRE(!validateSpecs({{"foo", "al pha", {"beta"}}}).empty());
  // No partners.
  ATF_REQUIRE(!validateSpecs({{"foo", "alpha", {}}}).empty());
  // Invalid partner.
  ATF_REQUIRE(!validateSpecs({{"foo", "alpha", {"be ta"}}}).empty());
  // Partner == primary.
  ATF_REQUIRE(!validateSpecs({{"foo", "alpha", {"alpha"}}}).empty());
  // Duplicate partners.
  ATF_REQUIRE(!validateSpecs({{"foo", "alpha", {"beta", "beta"}}}).empty());
  // Index in error.
  auto err = validateSpecs({{"ok", "alpha", {"beta"}},
                            {"",  "delta",  {"epsilon"}}});
  ATF_REQUIRE(err.find("ha[1]") != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, no_orders_when_primary_reachable);
  ATF_ADD_TEST_CASE(tcs, no_orders_below_threshold);
  ATF_ADD_TEST_CASE(tcs, emit_order_at_threshold);
  ATF_ADD_TEST_CASE(tcs, picks_first_reachable_partner_in_order);
  ATF_ADD_TEST_CASE(tcs, no_order_when_all_partners_down);
  ATF_ADD_TEST_CASE(tcs, missing_primary_node_skips_silently);
  ATF_ADD_TEST_CASE(tcs, multi_spec_orders_are_independent);
  ATF_ADD_TEST_CASE(tcs, deterministic_no_thrash);
  ATF_ADD_TEST_CASE(tcs, render_empty_orders_yields_array);
  ATF_ADD_TEST_CASE(tcs, render_single_order_shape);
  ATF_ADD_TEST_CASE(tcs, render_escapes_special_chars);
  ATF_ADD_TEST_CASE(tcs, validate_typical_spec_accepted);
  ATF_ADD_TEST_CASE(tcs, validate_invalid_specs_rejected);
}
