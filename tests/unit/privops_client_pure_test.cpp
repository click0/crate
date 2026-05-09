// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_client.h"
#include "privops_nv_pure.h"

#include <atf-c++.hpp>

#include <cstdlib>
#include <string>

using PrivOpsClient::buildSetRctl;
using PrivOpsClient::buildClearRctl;
using PrivOpsClient::buildAttachZfs;
using PrivOpsClient::buildDetachZfs;
using PrivOpsClient::buildMountNullfs;
using PrivOpsClient::buildUnmountNullfs;
using PrivOpsClient::buildConfigureIface;
using PrivOpsClient::buildTeardownIface;
using PrivOpsClient::buildAddPfRule;
using PrivOpsClient::buildRemovePfRule;
using PrivOpsClient::buildAddIpfwRule;
using PrivOpsClient::buildRemoveIpfwRule;
using PrivOpsClient::buildCreateJail;
using PrivOpsClient::buildDestroyJail;
using PrivOpsClient::detectSocketPath;
using PrivOpsClient::sendRequest;

// --- Builder shape ---

ATF_TEST_CASE_WITHOUT_HEAD(set_rctl_shape);
ATF_TEST_CASE_BODY(set_rctl_shape) {
  auto m = buildSetRctl(7, "pcpu", "20");
  ATF_REQUIRE_EQ(m["verb"],  std::string("set_rctl"));
  ATF_REQUIRE_EQ(m["jid"],   std::string("7"));
  ATF_REQUIRE_EQ(m["key"],   std::string("pcpu"));
  ATF_REQUIRE_EQ(m["value"], std::string("20"));
}

ATF_TEST_CASE_WITHOUT_HEAD(clear_rctl_shape);
ATF_TEST_CASE_BODY(clear_rctl_shape) {
  auto m = buildClearRctl(7, "pcpu");
  ATF_REQUIRE_EQ(m["verb"], std::string("clear_rctl"));
  ATF_REQUIRE_EQ(m["jid"],  std::string("7"));
  ATF_REQUIRE_EQ(m["key"],  std::string("pcpu"));
  // No 'value' field for clear
  ATF_REQUIRE(m.find("value") == m.end());
}

ATF_TEST_CASE_WITHOUT_HEAD(zfs_shapes);
ATF_TEST_CASE_BODY(zfs_shapes) {
  auto a = buildAttachZfs(3, "zroot/jails/x");
  ATF_REQUIRE_EQ(a["verb"], std::string("attach_zfs"));
  auto d = buildDetachZfs(3, "zroot/jails/x");
  ATF_REQUIRE_EQ(d["verb"], std::string("detach_zfs"));
}

ATF_TEST_CASE_WITHOUT_HEAD(mount_nullfs_readonly_default_explicit);
ATF_TEST_CASE_BODY(mount_nullfs_readonly_default_explicit) {
  auto ro = buildMountNullfs("/host", "/jail", true);
  ATF_REQUIRE_EQ(ro["read_only"], std::string("true"));
  auto rw = buildMountNullfs("/host", "/jail", false);
  ATF_REQUIRE_EQ(rw["read_only"], std::string("false"));
}

ATF_TEST_CASE_WITHOUT_HEAD(unmount_nullfs_force_field);
ATF_TEST_CASE_BODY(unmount_nullfs_force_field) {
  auto m = buildUnmountNullfs("/jail", true);
  ATF_REQUIRE_EQ(m["force"], std::string("true"));
}

ATF_TEST_CASE_WITHOUT_HEAD(configure_iface_all_fields);
ATF_TEST_CASE_BODY(configure_iface_all_fields) {
  auto m = buildConfigureIface(5, "epair0b", "bridge0",
                                "10.0.0.5/24", "fd00::5/64",
                                "02:00:11:22:33:44");
  ATF_REQUIRE_EQ(m["jid"],       std::string("5"));
  ATF_REQUIRE_EQ(m["ifname"],    std::string("epair0b"));
  ATF_REQUIRE_EQ(m["bridge"],    std::string("bridge0"));
  ATF_REQUIRE_EQ(m["ipv4_cidr"], std::string("10.0.0.5/24"));
  ATF_REQUIRE_EQ(m["ipv6_cidr"], std::string("fd00::5/64"));
  ATF_REQUIRE_EQ(m["mac_addr"],  std::string("02:00:11:22:33:44"));
}

ATF_TEST_CASE_WITHOUT_HEAD(configure_iface_empty_optionals_still_present);
ATF_TEST_CASE_BODY(configure_iface_empty_optionals_still_present) {
  // Empty optional fields are present (as empty strings) so the
  // wire shape is constant. Daemon-side parsers tolerate empty
  // optionals via the same path as JSON transport.
  auto m = buildConfigureIface(5, "epair0b", "", "10.0.0.5/24", "", "");
  ATF_REQUIRE(m.find("bridge")    != m.end());
  ATF_REQUIRE(m.find("ipv6_cidr") != m.end());
  ATF_REQUIRE(m.find("mac_addr")  != m.end());
  ATF_REQUIRE_EQ(m["bridge"],    std::string());
  ATF_REQUIRE_EQ(m["ipv6_cidr"], std::string());
  ATF_REQUIRE_EQ(m["mac_addr"],  std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(pf_rule_shapes);
ATF_TEST_CASE_BODY(pf_rule_shapes) {
  auto a = buildAddPfRule("crate", "pass on em0");
  ATF_REQUIRE_EQ(a["verb"],   std::string("add_pf_rule"));
  ATF_REQUIRE_EQ(a["anchor"], std::string("crate"));
  ATF_REQUIRE_EQ(a["rule"],   std::string("pass on em0"));
  auto r = buildRemovePfRule("crate", "");
  ATF_REQUIRE_EQ(r["verb"], std::string("remove_pf_rule"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipfw_rule_shapes);
ATF_TEST_CASE_BODY(ipfw_rule_shapes) {
  auto a = buildAddIpfwRule(0, 100, "allow", "ip from any to any");
  ATF_REQUIRE_EQ(a["verb"],   std::string("add_ipfw_rule"));
  ATF_REQUIRE_EQ(a["set"],    std::string("0"));
  ATF_REQUIRE_EQ(a["number"], std::string("100"));
  ATF_REQUIRE_EQ(a["action"], std::string("allow"));
  ATF_REQUIRE_EQ(a["body"],   std::string("ip from any to any"));
  auto r = buildRemoveIpfwRule(0, 100);
  ATF_REQUIRE_EQ(r["verb"], std::string("remove_ipfw_rule"));
  // No action/body on remove
  ATF_REQUIRE(r.find("action") == r.end());
}

ATF_TEST_CASE_WITHOUT_HEAD(create_jail_shape);
ATF_TEST_CASE_BODY(create_jail_shape) {
  auto m = buildCreateJail("alpine", "/zroot/jails/alpine",
                           "alpine.local", true, "allow.raw_sockets=1");
  ATF_REQUIRE_EQ(m["name"],       std::string("alpine"));
  ATF_REQUIRE_EQ(m["path"],       std::string("/zroot/jails/alpine"));
  ATF_REQUIRE_EQ(m["hostname"],   std::string("alpine.local"));
  ATF_REQUIRE_EQ(m["vnet"],       std::string("true"));
  ATF_REQUIRE_EQ(m["parameters"], std::string("allow.raw_sockets=1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(destroy_jail_force_default_off);
ATF_TEST_CASE_BODY(destroy_jail_force_default_off) {
  auto m = buildDestroyJail("alpine", false);
  ATF_REQUIRE_EQ(m["force"], std::string("false"));
}

// --- Round-trip with daemon-side parser ---

ATF_TEST_CASE_WITHOUT_HEAD(builder_set_rctl_round_trips_through_nv_parser);
ATF_TEST_CASE_BODY(builder_set_rctl_round_trips_through_nv_parser) {
  // Whatever the client builder emits MUST decode cleanly through
  // PrivOpsNvPure on the daemon side. This is the integration
  // contract: change the client field set and the daemon's
  // parser must keep accepting it (or this test fires).
  auto m = buildSetRctl(7, "pcpu", "20");
  PrivOpsPure::SetRctlReq req;
  ATF_REQUIRE_EQ(PrivOpsNvPure::parseSetRctl(m, req), std::string());
  ATF_REQUIRE_EQ(req.jid, 7);
  ATF_REQUIRE_EQ(req.key, std::string("pcpu"));
  ATF_REQUIRE_EQ(req.rawValue, std::string("20"));
}

ATF_TEST_CASE_WITHOUT_HEAD(builder_create_jail_round_trips);
ATF_TEST_CASE_BODY(builder_create_jail_round_trips) {
  auto m = buildCreateJail("alpine", "/zroot/jails/alpine",
                           "alpine.local", true, "");
  PrivOpsPure::CreateJailReq req;
  ATF_REQUIRE_EQ(PrivOpsNvPure::parseCreateJail(m, req), std::string());
  ATF_REQUIRE_EQ(req.name, std::string("alpine"));
  ATF_REQUIRE_EQ(req.path, std::string("/zroot/jails/alpine"));
  ATF_REQUIRE(req.vnet);
}

ATF_TEST_CASE_WITHOUT_HEAD(builder_configure_iface_round_trips);
ATF_TEST_CASE_BODY(builder_configure_iface_round_trips) {
  auto m = buildConfigureIface(5, "epair0b", "bridge0",
                                "10.0.0.5/24", "", "02:00:11:22:33:44");
  PrivOpsPure::ConfigureIfaceReq req;
  ATF_REQUIRE_EQ(PrivOpsNvPure::parseConfigureIface(m, req), std::string());
  ATF_REQUIRE_EQ(req.jid, 5);
  ATF_REQUIRE_EQ(req.ifname, std::string("epair0b"));
  ATF_REQUIRE_EQ(req.bridge, std::string("bridge0"));
  ATF_REQUIRE_EQ(req.ipv4Cidr, std::string("10.0.0.5/24"));
  ATF_REQUIRE_EQ(req.ipv6Cidr, std::string()); // empty → empty
  ATF_REQUIRE_EQ(req.macAddr, std::string("02:00:11:22:33:44"));
}

// --- detectSocketPath ---

ATF_TEST_CASE_WITHOUT_HEAD(detect_uses_env_var_when_set);
ATF_TEST_CASE_BODY(detect_uses_env_var_when_set) {
  ::setenv("CRATE_PRIVOPS_SOCKET", "/tmp/crate-test-priv.sock", 1);
  ATF_REQUIRE_EQ(detectSocketPath(),
                 std::string("/tmp/crate-test-priv.sock"));
  ::unsetenv("CRATE_PRIVOPS_SOCKET");
}

ATF_TEST_CASE_WITHOUT_HEAD(detect_empty_when_no_env_no_default);
ATF_TEST_CASE_BODY(detect_empty_when_no_env_no_default) {
  ::unsetenv("CRATE_PRIVOPS_SOCKET");
  // Default path /var/run/crate/crated-privops.sock won't exist
  // in the test env. detectSocketPath returns empty.
  // (If the test host happens to have crated running, the well-
  // known socket *would* exist and this test would fail; we
  // accept that fragility because it's the documented detection
  // logic.)
  std::string p = detectSocketPath();
  if (!p.empty()) {
    // Allow the well-known default to be present; only require
    // it's the documented one.
    ATF_REQUIRE_EQ(p, std::string("/var/run/crate/crated-privops.sock"));
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(detect_empty_env_treated_as_unset);
ATF_TEST_CASE_BODY(detect_empty_env_treated_as_unset) {
  // Explicit empty env var should NOT count as "use empty path".
  ::setenv("CRATE_PRIVOPS_SOCKET", "", 1);
  std::string p = detectSocketPath();
  // Either empty (default not present) or the default — but never
  // the empty string from the env var.
  ATF_REQUIRE(p.empty()
              || p == std::string("/var/run/crate/crated-privops.sock"));
  ::unsetenv("CRATE_PRIVOPS_SOCKET");
}

// --- sendRequest (transport stub on Linux) ---

ATF_TEST_CASE_WITHOUT_HEAD(send_returns_transport_error_when_no_socket);
ATF_TEST_CASE_BODY(send_returns_transport_error_when_no_socket) {
  // Empty path is "no socket configured"
  auto r = sendRequest("", buildSetRctl(7, "pcpu", "20"));
  ATF_REQUIRE_EQ(r.status, 0);
  ATF_REQUIRE(!r.transportError.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(send_returns_transport_error_when_unreachable);
ATF_TEST_CASE_BODY(send_returns_transport_error_when_unreachable) {
  // Path that can't possibly exist
  auto r = sendRequest("/nonexistent-path-for-test/socket",
                       buildSetRctl(7, "pcpu", "20"));
  ATF_REQUIRE(!r.transportError.empty());
  ATF_REQUIRE_EQ(r.status, 0);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, set_rctl_shape);
  ATF_ADD_TEST_CASE(tcs, clear_rctl_shape);
  ATF_ADD_TEST_CASE(tcs, zfs_shapes);
  ATF_ADD_TEST_CASE(tcs, mount_nullfs_readonly_default_explicit);
  ATF_ADD_TEST_CASE(tcs, unmount_nullfs_force_field);
  ATF_ADD_TEST_CASE(tcs, configure_iface_all_fields);
  ATF_ADD_TEST_CASE(tcs, configure_iface_empty_optionals_still_present);
  ATF_ADD_TEST_CASE(tcs, pf_rule_shapes);
  ATF_ADD_TEST_CASE(tcs, ipfw_rule_shapes);
  ATF_ADD_TEST_CASE(tcs, create_jail_shape);
  ATF_ADD_TEST_CASE(tcs, destroy_jail_force_default_off);
  ATF_ADD_TEST_CASE(tcs, builder_set_rctl_round_trips_through_nv_parser);
  ATF_ADD_TEST_CASE(tcs, builder_create_jail_round_trips);
  ATF_ADD_TEST_CASE(tcs, builder_configure_iface_round_trips);
  ATF_ADD_TEST_CASE(tcs, detect_uses_env_var_when_set);
  ATF_ADD_TEST_CASE(tcs, detect_empty_when_no_env_no_default);
  ATF_ADD_TEST_CASE(tcs, detect_empty_env_treated_as_unset);
  ATF_ADD_TEST_CASE(tcs, send_returns_transport_error_when_no_socket);
  ATF_ADD_TEST_CASE(tcs, send_returns_transport_error_when_unreachable);
}
