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
#include "spec_pure.h"
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
	// 1.1.63: a read-only directory share is fine, a read-only file share is not
	s.dirsShare.push_back({"/jail/ro", "/host/ro", true});
	s.validate();
	s.filesShare.push_back({"/jail/f", "/host/f", true});
	ATF_REQUIRE_THROW(Exception, s.validate());
}

// 1.1.64: run/user
ATF_TEST_CASE_WITHOUT_HEAD(run_user_validation);
ATF_TEST_CASE_BODY(run_user_validation)
{
	for (const char *ok : {"", "root", "www", "git", "_tor", "john.doe", "app-1"}) {
		auto s = mkValid();
		s.runUser = ok;
		s.validate();
	}
	for (const char *bad : {"1www", "-x", "a b", "www;id", "../root"}) {
		auto s = mkValid();
		s.runUser = bad;
		ATF_REQUIRE_THROW(Exception, s.validate());
	}
	{
		auto s = mkValid();
		s.runUser = std::string(33, 'a');   // one over the pw(8) limit
		ATF_REQUIRE_THROW(Exception, s.validate());
	}
}

// 1.1.63: tmpfs and etc/keep
ATF_TEST_CASE_WITHOUT_HEAD(tmpfs_and_etc_keep_validation);
ATF_TEST_CASE_BODY(tmpfs_and_etc_keep_validation)
{
	// (Spec's copy constructor lives in the yaml-linked spec.cpp, so each
	// variant is built afresh.)
	auto base = [] {
		auto s = mkValid();
		s.tmpfs.push_back({"/tmp", ""});
		s.tmpfs.push_back({"$HOME/.cache", "512m"});
		s.etcKeep.push_back("localtime");
		return s;
	};
	base().validate();
	{ auto t = base(); t.tmpfs.push_back({"/tmp", "1g"});            ATF_REQUIRE_THROW(Exception, t.validate()); }   // twice
	{ auto t = base(); t.tmpfs.push_back({"/etc", ""});              ATF_REQUIRE_THROW(Exception, t.validate()); }   // hides /etc
	{ auto t = base(); t.tmpfs.push_back({"var/tmp", ""});           ATF_REQUIRE_THROW(Exception, t.validate()); }   // relative
	{ auto t = base(); t.tmpfs.push_back({"/var/tmp", "lots"});      ATF_REQUIRE_THROW(Exception, t.validate()); }   // bad size
	{ auto t = base(); t.dirsShare.push_back({"/tmp", "/host/tmp"}); ATF_REQUIRE_THROW(Exception, t.validate()); }   // tmpfs over a share
	{ auto t = base(); t.etcKeep.push_back("ssl/certs");             ATF_REQUIRE_THROW(Exception, t.validate()); }
	{ auto t = base(); t.etcKeep.push_back("../passwd");             ATF_REQUIRE_THROW(Exception, t.validate()); }
}

// ===================================================================
// pkg/add — paths must be absolute
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(pkg_add_relative_path_throws);
ATF_TEST_CASE_BODY(pkg_add_relative_path_throws)
{
	auto s = mkValid();
	s.pkgAdd.push_back("nginx-1.27.txz");
	ATF_REQUIRE_THROW(Exception, s.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(pkg_add_absolute_path_ok);
ATF_TEST_CASE_BODY(pkg_add_absolute_path_ok)
{
	auto s = mkValid();
	s.pkgAdd.push_back("/host/pkgs/nginx-1.27.txz");
	s.validate();
}

ATF_TEST_CASE_WITHOUT_HEAD(pkg_add_multiple_one_relative_throws);
ATF_TEST_CASE_BODY(pkg_add_multiple_one_relative_throws)
{
	auto s = mkValid();
	s.pkgAdd.push_back("/host/a.txz");
	s.pkgAdd.push_back("b.txz");  // relative — must reject
	ATF_REQUIRE_THROW(Exception, s.validate());
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

// ===================================================================
// 0.8.17: top-level `network:` shorthand validator
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(top_level_network_auto_accepted);
ATF_TEST_CASE_BODY(top_level_network_auto_accepted)
{
	ATF_REQUIRE_EQ(SpecPure::validateTopLevelNetwork("auto"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(top_level_network_empty_rejected);
ATF_TEST_CASE_BODY(top_level_network_empty_rejected)
{
	auto err = SpecPure::validateTopLevelNetwork("");
	ATF_REQUIRE(!err.empty());
	ATF_REQUIRE(err.find("auto") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(top_level_network_unsupported_value_rejected);
ATF_TEST_CASE_BODY(top_level_network_unsupported_value_rejected)
{
	// Reserved-for-future values must NOT silently work today —
	// "host", "none", a bridge name. Operators get a diagnostic
	// pointing at options.net for richer config.
	for (auto v : {"host", "none", "bridge0", "wireguard", "Auto"}) {
		auto err = SpecPure::validateTopLevelNetwork(v);
		ATF_REQUIRE(!err.empty());
		ATF_REQUIRE(err.find("options.net") != std::string::npos);
	}
}

// --- 1.1.44: options/net address validators ---

ATF_TEST_CASE_WITHOUT_HEAD(net_address_validators);
ATF_TEST_CASE_BODY(net_address_validators) {
	ATF_REQUIRE_EQ(SpecPure::validateStaticIp4("192.168.1.50"), std::string());
	ATF_REQUIRE_EQ(SpecPure::validateStaticIp4("192.168.1.50/24"), std::string());
	ATF_REQUIRE_EQ(SpecPure::validateStaticIp4("10.0.0.1/32"), std::string());
	ATF_REQUIRE(!SpecPure::validateStaticIp4("").empty());
	ATF_REQUIRE(!SpecPure::validateStaticIp4("192.168.1.256").empty());
	ATF_REQUIRE(!SpecPure::validateStaticIp4("192.168.1.50/33").empty());   // used to be UB in run_net
	ATF_REQUIRE(!SpecPure::validateStaticIp4("192.168.1.50/abc").empty());
	ATF_REQUIRE(!SpecPure::validateStaticIp4("fd00::1").empty());
	ATF_REQUIRE(!SpecPure::validateStaticIp4("10.0.0.1; rm -rf /").empty());

	ATF_REQUIRE_EQ(SpecPure::validateStaticIp6("fd00::50"), std::string());
	ATF_REQUIRE_EQ(SpecPure::validateStaticIp6("fd00::50/64"), std::string());
	ATF_REQUIRE(!SpecPure::validateStaticIp6("fd00::50/129").empty());
	ATF_REQUIRE(!SpecPure::validateStaticIp6("fd00::50/64x").empty());   // went to ifconfig verbatim
	ATF_REQUIRE(!SpecPure::validateStaticIp6("192.168.1.1").empty());
	ATF_REQUIRE(!SpecPure::validateStaticIp6("").empty());

	ATF_REQUIRE_EQ(SpecPure::validateGateway4("192.168.1.1"), std::string());
	ATF_REQUIRE(!SpecPure::validateGateway4("192.168.1.1/24").empty());
	ATF_REQUIRE(!SpecPure::validateGateway4("gw.local").empty());
	ATF_REQUIRE(!SpecPure::validateGateway4("").empty());
}

// --- 1.1.46: bounded integers, ports, port ranges ---

ATF_TEST_CASE_WITHOUT_HEAD(bounded_int_and_port_parsing);
ATF_TEST_CASE_BODY(bounded_int_and_port_parsing) {
	ATF_REQUIRE_EQ(SpecPure::parseIntInRange("-1", -1, 3, "securelevel"), -1);
	ATF_REQUIRE_EQ(SpecPure::parseIntInRange("3", -1, 3, "securelevel"), 3);
	ATF_REQUIRE_EQ(SpecPure::parseIntInRange("+2", -1, 3, "securelevel"), 2);
	ATF_REQUIRE_THROW(Exception, SpecPure::parseIntInRange("4", -1, 3, "securelevel"));
	ATF_REQUIRE_THROW(Exception, SpecPure::parseIntInRange("-2", -1, 3, "securelevel"));
	ATF_REQUIRE_THROW(Exception, SpecPure::parseIntInRange("abc", -1, 3, "securelevel"));
	ATF_REQUIRE_THROW(Exception, SpecPure::parseIntInRange("", -1, 3, "securelevel"));
	ATF_REQUIRE_THROW(Exception, SpecPure::parseIntInRange("-", -1, 3, "securelevel"));
	ATF_REQUIRE_THROW(Exception, SpecPure::parseIntInRange("1e3", 0, 10000, "x"));

	ATF_REQUIRE_EQ(SpecPure::parsePort("1", "p"), 1u);
	ATF_REQUIRE_EQ(SpecPure::parsePort("65535", "p"), 65535u);
	ATF_REQUIRE_THROW(Exception, SpecPure::parsePort("0", "p"));
	ATF_REQUIRE_THROW(Exception, SpecPure::parsePort("65536", "p"));
	ATF_REQUIRE_THROW(Exception, SpecPure::parsePort("-80", "p"));

	auto r = SpecPure::parsePortRange("80-90");
	ATF_REQUIRE_EQ(r.first, 80u); ATF_REQUIRE_EQ(r.second, 90u);
	auto one = SpecPure::parsePortRange("443");
	ATF_REQUIRE_EQ(one.first, 443u); ATF_REQUIRE_EQ(one.second, 443u);
	ATF_REQUIRE_THROW(Exception, SpecPure::parsePortRange("90-80"));     // reversed
	ATF_REQUIRE_THROW(Exception, SpecPure::parsePortRange("0-80"));      // port 0
	ATF_REQUIRE_THROW(Exception, SpecPure::parsePortRange("80-70000"));  // > 65535
}

ATF_INIT_TEST_CASES(tcs)
{
	// 0.8.17: top-level network shorthand
	ATF_ADD_TEST_CASE(tcs, top_level_network_auto_accepted);
	ATF_ADD_TEST_CASE(tcs, top_level_network_empty_rejected);
	ATF_ADD_TEST_CASE(tcs, top_level_network_unsupported_value_rejected);

	// must do something
	ATF_ADD_TEST_CASE(tcs, must_have_something_to_run);
	ATF_ADD_TEST_CASE(tcs, executable_only_ok);
	ATF_ADD_TEST_CASE(tcs, services_only_ok);
	ATF_ADD_TEST_CASE(tcs, tor_only_ok);

	// duplicate package overrides
	ATF_ADD_TEST_CASE(tcs, duplicate_local_overrides_throw);

	// pkg/add absolute-path validation
	ATF_ADD_TEST_CASE(tcs, pkg_add_relative_path_throws);
	ATF_ADD_TEST_CASE(tcs, pkg_add_absolute_path_ok);
	ATF_ADD_TEST_CASE(tcs, pkg_add_multiple_one_relative_throws);

	// path checks
	ATF_ADD_TEST_CASE(tcs, executable_relative_path_throws);
	ATF_ADD_TEST_CASE(tcs, executable_empty_path_implicit_fallback);
	ATF_ADD_TEST_CASE(tcs, dirsShare_relative_throws);
	ATF_ADD_TEST_CASE(tcs, filesShare_relative_throws);
	ATF_ADD_TEST_CASE(tcs, dirsShare_absolute_ok);
	ATF_ADD_TEST_CASE(tcs, tmpfs_and_etc_keep_validation);
	ATF_ADD_TEST_CASE(tcs, run_user_validation);

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
	ATF_ADD_TEST_CASE(tcs, net_address_validators);
	ATF_ADD_TEST_CASE(tcs, bounded_int_and_port_parsing);
}
