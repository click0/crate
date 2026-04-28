// ATF unit tests for Spec::validate() (lib/spec_pure.cpp).
//
// Spec::validate is the gate between user-supplied YAML and the rest of
// the program. A regression here can silently accept (or wrongly reject)
// any container spec.
//
// Tests use real Spec types and the real validate() linked from
// lib/spec_pure.cpp. The Config::get() singleton is stubbed in
// tests/unit/_test_config_stub.cpp to return an empty Settings object,
// so any networkName check naturally fails with "not found".

#include <atf-c++.hpp>

#include "spec.h"
#include "err.h"

// Build a minimal valid Spec — having a runCmdExecutable is enough.
static Spec mkValid() {
	Spec s;
	s.runCmdExecutable = "/bin/sh";
	return s;
}

// ===================================================================
// "must do something"
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(must_have_something_to_run);
ATF_TEST_CASE_BODY(must_have_something_to_run)
{
	Spec s;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(executable_only_ok);
ATF_TEST_CASE_BODY(executable_only_ok)
{
	auto s = mkValid();
	s.validate();
}

ATF_TEST_CASE_WITHOUT_HEAD(services_only_ok);
ATF_TEST_CASE_BODY(services_only_ok)
{
	Spec s;
	s.runServices.push_back("nginx");
	s.validate();
}

ATF_TEST_CASE_WITHOUT_HEAD(tor_only_ok);
ATF_TEST_CASE_BODY(tor_only_ok)
{
	Spec s;
	s.options["tor"] = std::make_shared<Spec::TorOptDetails>();
	s.validate();
}

// ===================================================================
// pkgLocalOverride
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(duplicate_local_overrides_throw);
ATF_TEST_CASE_BODY(duplicate_local_overrides_throw)
{
	auto s = mkValid();
	s.pkgLocalOverride.push_back({"pkgA", "/path/a.txz"});
	s.pkgLocalOverride.push_back({"pkgA", "/path/b.txz"});
	ATF_REQUIRE_THROW(Exception, s.validate());
}

// ===================================================================
// runCmdExecutable absolute-path check
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(executable_relative_path_throws);
ATF_TEST_CASE_BODY(executable_relative_path_throws)
{
	Spec s;
	s.runCmdExecutable = "bin/sh";
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(executable_empty_path_implicit_fallback);
ATF_TEST_CASE_BODY(executable_empty_path_implicit_fallback)
{
	// Empty exec but services or tor present is OK
	Spec s;
	s.runServices.push_back("nginx");
	s.validate();
}

// ===================================================================
// dirsShare / filesShare absolute-path check
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(dirsShare_relative_throws);
ATF_TEST_CASE_BODY(dirsShare_relative_throws)
{
	auto s = mkValid();
	s.dirsShare.push_back({"data", "/jail/data"});
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(filesShare_relative_throws);
ATF_TEST_CASE_BODY(filesShare_relative_throws)
{
	auto s = mkValid();
	s.filesShare.push_back({"/host/passwd", "etc/passwd"});
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(dirsShare_absolute_ok);
ATF_TEST_CASE_BODY(dirsShare_absolute_ok)
{
	auto s = mkValid();
	s.dirsShare.push_back({"/host/data", "/jail/data"});
	s.validate();
}

// ===================================================================
// options / scripts / unknown
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(unknown_option_throws);
ATF_TEST_CASE_BODY(unknown_option_throws)
{
	auto s = mkValid();
	s.options["nosuchopt"] = std::make_shared<Spec::NetOptDetails>();
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(known_options_ok);
ATF_TEST_CASE_BODY(known_options_ok)
{
	for (auto opt : {"x11", "ssl-certs", "video", "gl",
	                 "no-rm-static-libs", "dbg-ktrace"}) {
		auto s = mkValid();
		// Use NetOptDetails as a stand-in (validate only checks the key).
		s.options[opt] = std::make_shared<Spec::NetOptDetails>();
		s.validate();
	}
}

ATF_TEST_CASE_WITHOUT_HEAD(unknown_script_section_throws);
ATF_TEST_CASE_BODY(unknown_script_section_throws)
{
	auto s = mkValid();
	s.scripts["nosuch:section"] = {{"cmd", "echo hi"}};
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(empty_script_section_throws);
ATF_TEST_CASE_BODY(empty_script_section_throws)
{
	auto s = mkValid();
	s.scripts[""] = {{"cmd", "echo hi"}};
	ATF_REQUIRE_THROW(Exception, s.validate());
}

// ===================================================================
// net options — port range consistency
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(port_range_mismatched_span_throws);
ATF_TEST_CASE_BODY(port_range_mismatched_span_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Nat;
	// host:8080-8085 (span 5) → jail:9000-9001 (span 1) — inconsistent
	net->inboundPortsTcp.push_back({{8080, 8085}, {9000, 9001}});
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(port_range_consistent_ok);
ATF_TEST_CASE_BODY(port_range_consistent_ok)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Nat;
	net->inboundPortsTcp.push_back({{8080, 8085}, {9000, 9005}});
	s.options["net"] = net;
	s.validate();
}

// ===================================================================
// net options — networkName resolution (uses stub Config = empty)
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(network_name_with_empty_config_throws);
ATF_TEST_CASE_BODY(network_name_with_empty_config_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	// Need bridge mode for networkName test (NAT doesn't go through this path
	// in a meaningful way).
	net->mode = Spec::NetOptDetails::Mode::Bridge;
	net->bridgeIface = "bridge0";
	net->networkName = "lan";
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

// ===================================================================
// net options — mode-specific validation
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(bridge_without_iface_throws);
ATF_TEST_CASE_BODY(bridge_without_iface_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Bridge;
	// missing bridgeIface
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(passthrough_without_iface_throws);
ATF_TEST_CASE_BODY(passthrough_without_iface_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Passthrough;
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(netgraph_without_iface_throws);
ATF_TEST_CASE_BODY(netgraph_without_iface_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Netgraph;
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(nat_with_bridge_throws);
ATF_TEST_CASE_BODY(nat_with_bridge_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Nat;
	net->bridgeIface = "bridge0";
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(nat_with_dhcp_throws);
ATF_TEST_CASE_BODY(nat_with_dhcp_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Nat;
	net->ipMode = Spec::NetOptDetails::IpMode::Dhcp;
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(non_nat_with_inbound_throws);
ATF_TEST_CASE_BODY(non_nat_with_inbound_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Bridge;
	net->bridgeIface = "bridge0";
	net->inboundPortsTcp.push_back({{80, 80}, {80, 80}});
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(gateway_without_static_ip_throws);
ATF_TEST_CASE_BODY(gateway_without_static_ip_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Bridge;
	net->bridgeIface = "bridge0";
	net->ipMode = Spec::NetOptDetails::IpMode::Dhcp;
	net->gateway = "192.168.1.1";
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(vlan_with_nat_throws);
ATF_TEST_CASE_BODY(vlan_with_nat_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Nat;
	net->vlanId = 100;
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(static_mac_with_nat_throws);
ATF_TEST_CASE_BODY(static_mac_with_nat_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Nat;
	net->staticMac = true;
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(ip6_slaac_with_nat_throws);
ATF_TEST_CASE_BODY(ip6_slaac_with_nat_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Nat;
	net->ip6Mode = Spec::NetOptDetails::Ip6Mode::Slaac;
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(ip6_static_without_address_throws);
ATF_TEST_CASE_BODY(ip6_static_without_address_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Bridge;
	net->bridgeIface = "bridge0";
	net->ip6Mode = Spec::NetOptDetails::Ip6Mode::Static;
	// missing staticIp6
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(extra_iface_with_nat_primary_throws);
ATF_TEST_CASE_BODY(extra_iface_with_nat_primary_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Nat;
	Spec::NetOptDetails::ExtraInterface ex;
	ex.mode = Spec::NetOptDetails::Mode::Bridge;
	ex.bridgeIface = "bridge1";
	net->extraInterfaces.push_back(ex);
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(extra_iface_nat_mode_throws);
ATF_TEST_CASE_BODY(extra_iface_nat_mode_throws)
{
	auto s = mkValid();
	auto net = Spec::NetOptDetails::createDefault();
	net->mode = Spec::NetOptDetails::Mode::Bridge;
	net->bridgeIface = "bridge0";
	Spec::NetOptDetails::ExtraInterface ex;
	ex.mode = Spec::NetOptDetails::Mode::Nat;
	net->extraInterfaces.push_back(ex);
	s.options["net"] = net;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

// ===================================================================
// ZFS dataset names
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(zfs_empty_dataset_throws);
ATF_TEST_CASE_BODY(zfs_empty_dataset_throws)
{
	auto s = mkValid();
	s.zfsDatasets.push_back("");
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(zfs_absolute_dataset_throws);
ATF_TEST_CASE_BODY(zfs_absolute_dataset_throws)
{
	auto s = mkValid();
	s.zfsDatasets.push_back("/tank/foo");
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(zfs_traversal_dataset_throws);
ATF_TEST_CASE_BODY(zfs_traversal_dataset_throws)
{
	auto s = mkValid();
	s.zfsDatasets.push_back("tank/../etc");
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(zfs_valid_dataset_ok);
ATF_TEST_CASE_BODY(zfs_valid_dataset_ok)
{
	auto s = mkValid();
	s.zfsDatasets.push_back("tank/jails/web");
	s.validate();
}

// ===================================================================
// rctl limits — known/unknown
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(unknown_rctl_limit_throws);
ATF_TEST_CASE_BODY(unknown_rctl_limit_throws)
{
	auto s = mkValid();
	s.limits["nosuchlimit"] = "100";
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(known_rctl_limits_ok);
ATF_TEST_CASE_BODY(known_rctl_limits_ok)
{
	auto s = mkValid();
	s.limits["memoryuse"] = "1G";
	s.limits["cputime"]   = "60";
	s.limits["maxproc"]   = "200";
	s.validate();
}

// ===================================================================
// encryption
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(encryption_unknown_method_throws);
ATF_TEST_CASE_BODY(encryption_unknown_method_throws)
{
	auto s = mkValid();
	s.encrypted = true;
	s.encryptionMethod = "rot13";
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(encryption_unknown_keyformat_throws);
ATF_TEST_CASE_BODY(encryption_unknown_keyformat_throws)
{
	auto s = mkValid();
	s.encrypted = true;
	s.encryptionKeyformat = "morse";
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(encryption_unknown_cipher_throws);
ATF_TEST_CASE_BODY(encryption_unknown_cipher_throws)
{
	auto s = mkValid();
	s.encrypted = true;
	s.encryptionCipher = "des";
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(encryption_supported_cipher_ok);
ATF_TEST_CASE_BODY(encryption_supported_cipher_ok)
{
	auto s = mkValid();
	s.encrypted = true;
	s.encryptionCipher = "aes-256-gcm";
	s.validate();
}

// ===================================================================
// enforce_statfs range
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(enforce_statfs_negative_throws);
ATF_TEST_CASE_BODY(enforce_statfs_negative_throws)
{
	auto s = mkValid();
	s.enforceStatfs = -2;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(enforce_statfs_too_large_throws);
ATF_TEST_CASE_BODY(enforce_statfs_too_large_throws)
{
	auto s = mkValid();
	s.enforceStatfs = 3;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(enforce_statfs_valid_range_ok);
ATF_TEST_CASE_BODY(enforce_statfs_valid_range_ok)
{
	for (int v : {0, 1, 2}) {
		auto s = mkValid();
		s.enforceStatfs = v;
		s.validate();
	}
	// -1 is "not set" (default) — also OK
	auto s = mkValid();
	s.enforceStatfs = -1;
	s.validate();
}

// ===================================================================
// firewall policy port range
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(firewall_port_zero_throws);
ATF_TEST_CASE_BODY(firewall_port_zero_throws)
{
	auto s = mkValid();
	s.firewallPolicy = std::make_unique<Spec::FirewallPolicy>();
	s.firewallPolicy->allowTcp.push_back(0);
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(firewall_port_too_large_throws);
ATF_TEST_CASE_BODY(firewall_port_too_large_throws)
{
	auto s = mkValid();
	s.firewallPolicy = std::make_unique<Spec::FirewallPolicy>();
	s.firewallPolicy->allowUdp.push_back(70000);
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(firewall_valid_ports_ok);
ATF_TEST_CASE_BODY(firewall_valid_ports_ok)
{
	auto s = mkValid();
	s.firewallPolicy = std::make_unique<Spec::FirewallPolicy>();
	s.firewallPolicy->allowTcp.push_back(80);
	s.firewallPolicy->allowTcp.push_back(443);
	s.firewallPolicy->allowUdp.push_back(53);
	s.firewallPolicy->allowUdp.push_back(65535);
	s.validate();
}

// ===================================================================
// terminal devfs_ruleset
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(terminal_devfs_too_large_throws);
ATF_TEST_CASE_BODY(terminal_devfs_too_large_throws)
{
	auto s = mkValid();
	s.terminalOptions = std::make_unique<Spec::TerminalOptions>();
	s.terminalOptions->devfsRuleset = 70000;
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(terminal_devfs_default_ok);
ATF_TEST_CASE_BODY(terminal_devfs_default_ok)
{
	auto s = mkValid();
	s.terminalOptions = std::make_unique<Spec::TerminalOptions>();
	// devfsRuleset defaults to -1 (not set) — must validate.
	s.validate();
}

ATF_INIT_TEST_CASES(tcs)
{
	// must do something
	ATF_ADD_TEST_CASE(tcs, must_have_something_to_run);
	ATF_ADD_TEST_CASE(tcs, executable_only_ok);
	ATF_ADD_TEST_CASE(tcs, services_only_ok);
	ATF_ADD_TEST_CASE(tcs, tor_only_ok);

	// duplicate package overrides
	ATF_ADD_TEST_CASE(tcs, duplicate_local_overrides_throw);

	// path checks
	ATF_ADD_TEST_CASE(tcs, executable_relative_path_throws);
	ATF_ADD_TEST_CASE(tcs, executable_empty_path_implicit_fallback);
	ATF_ADD_TEST_CASE(tcs, dirsShare_relative_throws);
	ATF_ADD_TEST_CASE(tcs, filesShare_relative_throws);
	ATF_ADD_TEST_CASE(tcs, dirsShare_absolute_ok);

	// options + scripts
	ATF_ADD_TEST_CASE(tcs, unknown_option_throws);
	ATF_ADD_TEST_CASE(tcs, known_options_ok);
	ATF_ADD_TEST_CASE(tcs, unknown_script_section_throws);
	ATF_ADD_TEST_CASE(tcs, empty_script_section_throws);

	// net options
	ATF_ADD_TEST_CASE(tcs, port_range_mismatched_span_throws);
	ATF_ADD_TEST_CASE(tcs, port_range_consistent_ok);
	ATF_ADD_TEST_CASE(tcs, network_name_with_empty_config_throws);
	ATF_ADD_TEST_CASE(tcs, bridge_without_iface_throws);
	ATF_ADD_TEST_CASE(tcs, passthrough_without_iface_throws);
	ATF_ADD_TEST_CASE(tcs, netgraph_without_iface_throws);
	ATF_ADD_TEST_CASE(tcs, nat_with_bridge_throws);
	ATF_ADD_TEST_CASE(tcs, nat_with_dhcp_throws);
	ATF_ADD_TEST_CASE(tcs, non_nat_with_inbound_throws);
	ATF_ADD_TEST_CASE(tcs, gateway_without_static_ip_throws);
	ATF_ADD_TEST_CASE(tcs, vlan_with_nat_throws);
	ATF_ADD_TEST_CASE(tcs, static_mac_with_nat_throws);
	ATF_ADD_TEST_CASE(tcs, ip6_slaac_with_nat_throws);
	ATF_ADD_TEST_CASE(tcs, ip6_static_without_address_throws);
	ATF_ADD_TEST_CASE(tcs, extra_iface_with_nat_primary_throws);
	ATF_ADD_TEST_CASE(tcs, extra_iface_nat_mode_throws);

	// zfs
	ATF_ADD_TEST_CASE(tcs, zfs_empty_dataset_throws);
	ATF_ADD_TEST_CASE(tcs, zfs_absolute_dataset_throws);
	ATF_ADD_TEST_CASE(tcs, zfs_traversal_dataset_throws);
	ATF_ADD_TEST_CASE(tcs, zfs_valid_dataset_ok);

	// rctl limits
	ATF_ADD_TEST_CASE(tcs, unknown_rctl_limit_throws);
	ATF_ADD_TEST_CASE(tcs, known_rctl_limits_ok);

	// encryption
	ATF_ADD_TEST_CASE(tcs, encryption_unknown_method_throws);
	ATF_ADD_TEST_CASE(tcs, encryption_unknown_keyformat_throws);
	ATF_ADD_TEST_CASE(tcs, encryption_unknown_cipher_throws);
	ATF_ADD_TEST_CASE(tcs, encryption_supported_cipher_ok);

	// enforce_statfs
	ATF_ADD_TEST_CASE(tcs, enforce_statfs_negative_throws);
	ATF_ADD_TEST_CASE(tcs, enforce_statfs_too_large_throws);
	ATF_ADD_TEST_CASE(tcs, enforce_statfs_valid_range_ok);

	// firewall
	ATF_ADD_TEST_CASE(tcs, firewall_port_zero_throws);
	ATF_ADD_TEST_CASE(tcs, firewall_port_too_large_throws);
	ATF_ADD_TEST_CASE(tcs, firewall_valid_ports_ok);

	// terminal devfs
	ATF_ADD_TEST_CASE(tcs, terminal_devfs_too_large_throws);
	ATF_ADD_TEST_CASE(tcs, terminal_devfs_default_ok);
}
