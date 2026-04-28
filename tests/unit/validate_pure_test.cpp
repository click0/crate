// ATF unit tests for ValidatePure::gatherWarnings (lib/validate_pure.cpp).
//
// Each warning branch in `crate validate <spec>` is now exercised by a
// dedicated test. The output gives the operator a security-aware
// summary; a regression that drops a warning ships silent risk.

#include <atf-c++.hpp>
#include <algorithm>
#include <string>
#include <vector>

#include "spec.h"
#include "validate_pure.h"

using ValidatePure::gatherWarnings;

// Helper: minimal Spec + a runCmd so spec.validate() (if ever called)
// would also pass — though we only test gatherWarnings here.
static Spec mkSpec() {
	Spec s;
	s.runCmdExecutable = "/bin/sh";
	return s;
}

static bool hasMatch(const std::vector<std::string> &v, const std::string &needle) {
	for (auto &s : v)
		if (s.find(needle) != std::string::npos) return true;
	return false;
}

ATF_TEST_CASE_WITHOUT_HEAD(no_warnings_for_minimal_spec);
ATF_TEST_CASE_BODY(no_warnings_for_minimal_spec)
{
	auto s = mkSpec();
	ATF_REQUIRE_EQ(gatherWarnings(s).size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(sysvipc_warns);
ATF_TEST_CASE_BODY(sysvipc_warns)
{
	auto s = mkSpec();
	s.allowSysvipc = true;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "sysvipc"));
}

ATF_TEST_CASE_WITHOUT_HEAD(net_lan_with_tor_warns);
ATF_TEST_CASE_BODY(net_lan_with_tor_warns)
{
	auto s = mkSpec();
	auto net = Spec::NetOptDetails::createDefault();
	net->outboundLan = true;
	s.options["net"] = net;
	s.options["tor"] = std::make_shared<Spec::TorOptDetails>();
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "LAN with tor"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_no_outbound_warns);
ATF_TEST_CASE_BODY(ipv6_no_outbound_warns)
{
	auto s = mkSpec();
	auto net = std::make_shared<Spec::NetOptDetails>();
	// no outbound flags set
	net->ipv6 = true;
	s.options["net"] = net;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "ipv6=true but no outbound"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_with_tor_warns);
ATF_TEST_CASE_BODY(ipv6_with_tor_warns)
{
	auto s = mkSpec();
	auto net = Spec::NetOptDetails::createDefault();
	net->ipv6 = true;
	s.options["net"] = net;
	s.options["tor"] = std::make_shared<Spec::TorOptDetails>();
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "ipv6=true with tor"));
}

ATF_TEST_CASE_WITHOUT_HEAD(limits_without_maxproc_warns);
ATF_TEST_CASE_BODY(limits_without_maxproc_warns)
{
	auto s = mkSpec();
	s.limits["memoryuse"] = "1G";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "maxproc not set"));
}

ATF_TEST_CASE_WITHOUT_HEAD(limits_with_maxproc_no_warn);
ATF_TEST_CASE_BODY(limits_with_maxproc_no_warn)
{
	auto s = mkSpec();
	s.limits["maxproc"] = "100";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(!hasMatch(w, "maxproc not set"));
}

ATF_TEST_CASE_WITHOUT_HEAD(encrypted_warns);
ATF_TEST_CASE_BODY(encrypted_warns)
{
	auto s = mkSpec();
	s.encrypted = true;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "encrypted=true"));
}

ATF_TEST_CASE_WITHOUT_HEAD(dns_filter_empty_rules_warns);
ATF_TEST_CASE_BODY(dns_filter_empty_rules_warns)
{
	auto s = mkSpec();
	s.dnsFilter = std::make_unique<Spec::DnsFilter>();
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "dns_filter section present but no allow/block"));
}

ATF_TEST_CASE_WITHOUT_HEAD(dns_filter_without_net_warns);
ATF_TEST_CASE_BODY(dns_filter_without_net_warns)
{
	auto s = mkSpec();
	s.dnsFilter = std::make_unique<Spec::DnsFilter>();
	s.dnsFilter->block.push_back("ads.example");
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "dns_filter requires networking"));
}

ATF_TEST_CASE_WITHOUT_HEAD(allow_chflags_warns);
ATF_TEST_CASE_BODY(allow_chflags_warns)
{
	auto s = mkSpec();
	s.allowChflags = true;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "allow_chflags"));
}

ATF_TEST_CASE_WITHOUT_HEAD(allow_mlock_warns);
ATF_TEST_CASE_BODY(allow_mlock_warns)
{
	auto s = mkSpec();
	s.allowMlock = true;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "allow_mlock"));
}

ATF_TEST_CASE_WITHOUT_HEAD(securelevel_below_default_warns);
ATF_TEST_CASE_BODY(securelevel_below_default_warns)
{
	for (int level : {0, 1}) {
		auto s = mkSpec();
		s.securelevel = level;
		auto w = gatherWarnings(s);
		ATF_REQUIRE(hasMatch(w, "securelevel"));
	}
}

ATF_TEST_CASE_WITHOUT_HEAD(securelevel_default_no_warn);
ATF_TEST_CASE_BODY(securelevel_default_no_warn)
{
	auto s = mkSpec();
	s.securelevel = 2;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(!hasMatch(w, "securelevel"));
}

ATF_TEST_CASE_WITHOUT_HEAD(children_max_warns);
ATF_TEST_CASE_BODY(children_max_warns)
{
	auto s = mkSpec();
	s.childrenMax = 10;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "children_max"));
}

ATF_TEST_CASE_WITHOUT_HEAD(cpuset_invalid_char_warns);
ATF_TEST_CASE_BODY(cpuset_invalid_char_warns)
{
	auto s = mkSpec();
	s.cpuset = "0,1,abc";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "cpuset"));
}

ATF_TEST_CASE_WITHOUT_HEAD(cpuset_valid_no_warn);
ATF_TEST_CASE_BODY(cpuset_valid_no_warn)
{
	auto s = mkSpec();
	s.cpuset = "0-3,5,7";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(!hasMatch(w, "cpuset"));
}

ATF_TEST_CASE_WITHOUT_HEAD(cow_zfs_backend_warns);
ATF_TEST_CASE_BODY(cow_zfs_backend_warns)
{
	auto s = mkSpec();
	s.cowOptions = std::make_unique<Spec::CowOptions>();
	s.cowOptions->backend = "zfs";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "cow/backend=zfs"));
}

ATF_TEST_CASE_WITHOUT_HEAD(cow_persistent_mode_warns);
ATF_TEST_CASE_BODY(cow_persistent_mode_warns)
{
	auto s = mkSpec();
	s.cowOptions = std::make_unique<Spec::CowOptions>();
	s.cowOptions->mode = "persistent";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "persistent"));
}

ATF_TEST_CASE_WITHOUT_HEAD(x11_nested_warns);
ATF_TEST_CASE_BODY(x11_nested_warns)
{
	auto s = mkSpec();
	s.x11Options = std::make_unique<Spec::X11Options>();
	s.x11Options->mode = "nested";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "Xephyr"));
}

ATF_TEST_CASE_WITHOUT_HEAD(clipboard_isolated_without_nested_warns);
ATF_TEST_CASE_BODY(clipboard_isolated_without_nested_warns)
{
	auto s = mkSpec();
	s.clipboardOptions = std::make_unique<Spec::ClipboardOptions>();
	s.clipboardOptions->mode = "isolated";
	// no x11Options at all
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "clipboard/mode=isolated"));
}

ATF_TEST_CASE_WITHOUT_HEAD(clipboard_isolated_with_nested_no_warn);
ATF_TEST_CASE_BODY(clipboard_isolated_with_nested_no_warn)
{
	auto s = mkSpec();
	s.clipboardOptions = std::make_unique<Spec::ClipboardOptions>();
	s.clipboardOptions->mode = "isolated";
	s.x11Options = std::make_unique<Spec::X11Options>();
	s.x11Options->mode = "nested";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(!hasMatch(w, "clipboard/mode=isolated"));
}

ATF_TEST_CASE_WITHOUT_HEAD(dbus_session_warns);
ATF_TEST_CASE_BODY(dbus_session_warns)
{
	auto s = mkSpec();
	s.dbusOptions = std::make_unique<Spec::DbusOptions>();
	s.dbusOptions->sessionBus = true;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "dbus/session=true"));
}

ATF_TEST_CASE_WITHOUT_HEAD(socket_proxy_empty_warns);
ATF_TEST_CASE_BODY(socket_proxy_empty_warns)
{
	auto s = mkSpec();
	s.socketProxy = std::make_unique<Spec::SocketProxy>();
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "socket_proxy section present but no"));
}

ATF_TEST_CASE_WITHOUT_HEAD(firewall_without_net_warns);
ATF_TEST_CASE_BODY(firewall_without_net_warns)
{
	auto s = mkSpec();
	s.firewallPolicy = std::make_unique<Spec::FirewallPolicy>();
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "firewall policy requires 'net'"));
}

ATF_TEST_CASE_WITHOUT_HEAD(firewall_block_no_allow_warns);
ATF_TEST_CASE_BODY(firewall_block_no_allow_warns)
{
	auto s = mkSpec();
	s.options["net"] = Spec::NetOptDetails::createDefault();
	s.firewallPolicy = std::make_unique<Spec::FirewallPolicy>();
	s.firewallPolicy->defaultPolicy = "block";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "default=block with no allow"));
}

ATF_TEST_CASE_WITHOUT_HEAD(capsicum_warns);
ATF_TEST_CASE_BODY(capsicum_warns)
{
	auto s = mkSpec();
	s.securityAdvanced = std::make_unique<Spec::SecurityAdvanced>();
	s.securityAdvanced->capsicum = true;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "capsicum"));
}

ATF_TEST_CASE_WITHOUT_HEAD(mac_rules_warns);
ATF_TEST_CASE_BODY(mac_rules_warns)
{
	auto s = mkSpec();
	s.securityAdvanced = std::make_unique<Spec::SecurityAdvanced>();
	s.securityAdvanced->macRules.push_back("uid 1000 read /etc");
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "mac_bsdextended"));
}

ATF_TEST_CASE_WITHOUT_HEAD(terminal_devfs_ruleset_warns);
ATF_TEST_CASE_BODY(terminal_devfs_ruleset_warns)
{
	auto s = mkSpec();
	s.terminalOptions = std::make_unique<Spec::TerminalOptions>();
	s.terminalOptions->devfsRuleset = 5;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "devfs_ruleset"));
}

// Sanity: combining multiple problems produces multiple warnings
ATF_TEST_CASE_WITHOUT_HEAD(multiple_warnings);
ATF_TEST_CASE_BODY(multiple_warnings)
{
	auto s = mkSpec();
	s.allowSysvipc = true;
	s.allowMlock = true;
	s.allowChflags = true;
	s.encrypted = true;
	auto w = gatherWarnings(s);
	ATF_REQUIRE(w.size() >= 4u);
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, no_warnings_for_minimal_spec);
	ATF_ADD_TEST_CASE(tcs, sysvipc_warns);
	ATF_ADD_TEST_CASE(tcs, net_lan_with_tor_warns);
	ATF_ADD_TEST_CASE(tcs, ipv6_no_outbound_warns);
	ATF_ADD_TEST_CASE(tcs, ipv6_with_tor_warns);
	ATF_ADD_TEST_CASE(tcs, limits_without_maxproc_warns);
	ATF_ADD_TEST_CASE(tcs, limits_with_maxproc_no_warn);
	ATF_ADD_TEST_CASE(tcs, encrypted_warns);
	ATF_ADD_TEST_CASE(tcs, dns_filter_empty_rules_warns);
	ATF_ADD_TEST_CASE(tcs, dns_filter_without_net_warns);
	ATF_ADD_TEST_CASE(tcs, allow_chflags_warns);
	ATF_ADD_TEST_CASE(tcs, allow_mlock_warns);
	ATF_ADD_TEST_CASE(tcs, securelevel_below_default_warns);
	ATF_ADD_TEST_CASE(tcs, securelevel_default_no_warn);
	ATF_ADD_TEST_CASE(tcs, children_max_warns);
	ATF_ADD_TEST_CASE(tcs, cpuset_invalid_char_warns);
	ATF_ADD_TEST_CASE(tcs, cpuset_valid_no_warn);
	ATF_ADD_TEST_CASE(tcs, cow_zfs_backend_warns);
	ATF_ADD_TEST_CASE(tcs, cow_persistent_mode_warns);
	ATF_ADD_TEST_CASE(tcs, x11_nested_warns);
	ATF_ADD_TEST_CASE(tcs, clipboard_isolated_without_nested_warns);
	ATF_ADD_TEST_CASE(tcs, clipboard_isolated_with_nested_no_warn);
	ATF_ADD_TEST_CASE(tcs, dbus_session_warns);
	ATF_ADD_TEST_CASE(tcs, socket_proxy_empty_warns);
	ATF_ADD_TEST_CASE(tcs, firewall_without_net_warns);
	ATF_ADD_TEST_CASE(tcs, firewall_block_no_allow_warns);
	ATF_ADD_TEST_CASE(tcs, capsicum_warns);
	ATF_ADD_TEST_CASE(tcs, mac_rules_warns);
	ATF_ADD_TEST_CASE(tcs, terminal_devfs_ruleset_warns);
	ATF_ADD_TEST_CASE(tcs, multiple_warnings);
}
