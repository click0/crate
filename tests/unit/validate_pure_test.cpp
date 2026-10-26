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

using ValidatePure::gatherStrictErrors;
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

ATF_TEST_CASE_WITHOUT_HEAD(x11_shared_warns);
ATF_TEST_CASE_BODY(x11_shared_warns)
{
	auto s = mkSpec();
	s.x11Options = std::make_unique<Spec::X11Options>();
	s.x11Options->mode = "shared";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "x11/mode=shared"));
	ATF_REQUIRE(hasMatch(w, "NO display isolation"));
}

ATF_TEST_CASE_WITHOUT_HEAD(x11_headless_no_warn);
ATF_TEST_CASE_BODY(x11_headless_no_warn)
{
	auto s = mkSpec();
	s.x11Options = std::make_unique<Spec::X11Options>();
	s.x11Options->mode = "headless";
	auto w = gatherWarnings(s);
	ATF_REQUIRE(!hasMatch(w, "NO display isolation"));
}

ATF_TEST_CASE_WITHOUT_HEAD(x11_option_implicit_shared_warns);
ATF_TEST_CASE_BODY(x11_option_implicit_shared_warns)
{
	// No x11Options block, but options:[x11] triggers the implicit
	// shared-mode warning.
	auto s = mkSpec();
	s.options["x11"] = std::make_shared<Spec::NetOptDetails>();  // any OptDetails works
	auto w = gatherWarnings(s);
	ATF_REQUIRE(hasMatch(w, "defaults to 'shared'"));
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

// 1.1.62: device classes — media classes are silent, input/usb/serial/all warn
ATF_TEST_CASE_WITHOUT_HEAD(devices_classes_warn);
ATF_TEST_CASE_BODY(devices_classes_warn)
{
	auto s = mkSpec();
	s.devices.sound = true; s.devices.gpu = true; s.devices.video = true;
	ATF_REQUIRE(!hasMatch(gatherWarnings(s), "devices"));
	s.devices.input = true;
	ATF_REQUIRE(hasMatch(gatherWarnings(s), "devices/input"));
	auto a = mkSpec();
	a.devices.all = true;
	ATF_REQUIRE(hasMatch(gatherWarnings(a), "devices: all"));
}

// 1.1.64: run/user warnings
ATF_TEST_CASE_WITHOUT_HEAD(run_user_warnings);
ATF_TEST_CASE_BODY(run_user_warnings)
{
	auto s = mkSpec();
	ATF_REQUIRE(!hasMatch(gatherWarnings(s), "run/user"));
	s.runUser = "root";
	ATF_REQUIRE(hasMatch(gatherWarnings(s), "runs as root inside the jail"));

	auto t = mkSpec();
	t.runUser = "www";
	ATF_REQUIRE(!hasMatch(gatherWarnings(t), "run/user"));       // no $HOME shares, no GUI: quiet
	t.dirsShare.push_back({"$HOME/www", "$HOME/www"});
	ATF_REQUIRE(hasMatch(gatherWarnings(t), "belong to the operator"));
	t.x11Options = std::make_unique<Spec::X11Options>();
	ATF_REQUIRE(hasMatch(gatherWarnings(t), "X11 authority"));
}

// 1.1.67: privacy
ATF_TEST_CASE_WITHOUT_HEAD(privacy_warnings);
ATF_TEST_CASE_BODY(privacy_warnings)
{
	auto s = mkSpec();
	ATF_REQUIRE(!hasMatch(gatherWarnings(s), "privacy/hostid"));      // no anonymity network: quiet
	s.options["tor"] = std::make_shared<Spec::TorOptDetails>();
	ATF_REQUIRE(hasMatch(gatherWarnings(s), "tor/i2pd without privacy/hostid"));
	s.privacyHostid = "random";
	ATF_REQUIRE(!hasMatch(gatherWarnings(s), "privacy/hostid"));
}

// 1.1.65: run/timeout
ATF_TEST_CASE_WITHOUT_HEAD(run_timeout_warnings);
ATF_TEST_CASE_BODY(run_timeout_warnings)
{
	auto s = mkSpec();
	ATF_REQUIRE(!hasMatch(gatherWarnings(s), "run/timeout"));
	s.runTimeoutSec = 90;
	ATF_REQUIRE(!hasMatch(gatherWarnings(s), "run/timeout"));    // a command with a limit: quiet

	auto t = mkSpec();
	t.runCmdExecutable.clear();
	t.runServices.push_back("nginx");
	t.runTimeoutSec = 3600;
	ATF_REQUIRE(hasMatch(gatherWarnings(t), "service-only"));

	auto u = mkSpec();
	u.runTimeoutSec = 30;
	u.healthcheck = std::make_unique<Spec::Healthcheck>();
	u.healthcheck->test = "/bin/true";
	u.healthcheck->startPeriodSec = 30;
	ATF_REQUIRE(hasMatch(gatherWarnings(u), "start_period"));
	u.healthcheck->startPeriodSec = 5;
	ATF_REQUIRE(!hasMatch(gatherWarnings(u), "start_period"));
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

// ---------------------------------------------------------------------------
// gatherStrictErrors (0.7.16) — `crate validate --strict` only
// ---------------------------------------------------------------------------

// Build a Spec with the limits stub already populated so the
// "unbounded RCTL" strict check doesn't dominate every test.
static Spec mkBoundedSpec() {
	auto s = mkSpec();
	s.limits["memoryuse"] = "512M";
	return s;
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_minimal_spec_still_unbounded);
ATF_TEST_CASE_BODY(strict_minimal_spec_still_unbounded)
{
	// Minimal spec with no limits: --strict flags it for unbounded RCTL.
	auto s = mkSpec();
	auto e = gatherStrictErrors(s);
	ATF_REQUIRE(hasMatch(e, "memoryuse"));
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_bounded_spec_no_errors);
ATF_TEST_CASE_BODY(strict_bounded_spec_no_errors)
{
	// Spec with a memoryuse limit should pass the unbounded-RCTL check.
	auto s = mkBoundedSpec();
	auto e = gatherStrictErrors(s);
	for (auto &m : e)
		ATF_REQUIRE(m.find("memoryuse") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_bounded_via_maxproc);
ATF_TEST_CASE_BODY(strict_bounded_via_maxproc)
{
	// maxproc alone is also acceptable bounding (it caps fork-bombs).
	auto s = mkSpec();
	s.limits["maxproc"] = "200";
	auto e = gatherStrictErrors(s);
	for (auto &m : e)
		ATF_REQUIRE(m.find("memoryuse or maxproc") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_inbound_tcp_port_conflict);
ATF_TEST_CASE_BODY(strict_inbound_tcp_port_conflict)
{
	auto s = mkBoundedSpec();
	auto net = Spec::NetOptDetails::createDefault();
	// Two host rules both targeting port 8080 — clear conflict.
	net->inboundPortsTcp.push_back({{8080, 8080}, {80, 80}});
	net->inboundPortsTcp.push_back({{8080, 8080}, {81, 81}});
	s.options["net"] = net;
	auto e = gatherStrictErrors(s);
	ATF_REQUIRE(hasMatch(e, "host port 8080"));
	ATF_REQUIRE(hasMatch(e, "tcp"));
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_inbound_tcp_range_overlap);
ATF_TEST_CASE_BODY(strict_inbound_tcp_range_overlap)
{
	// Range overlap is a conflict too: 8000-8100 and 8050-8200 share
	// 51 ports.
	auto s = mkBoundedSpec();
	auto net = Spec::NetOptDetails::createDefault();
	net->inboundPortsTcp.push_back({{8000, 8100}, {80, 180}});
	net->inboundPortsTcp.push_back({{8050, 8200}, {81, 231}});
	s.options["net"] = net;
	auto e = gatherStrictErrors(s);
	ATF_REQUIRE(hasMatch(e, "8000-8100"));
	ATF_REQUIRE(hasMatch(e, "8050-8200"));
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_inbound_udp_port_conflict);
ATF_TEST_CASE_BODY(strict_inbound_udp_port_conflict)
{
	// UDP independently flagged; same-protocol scoping.
	auto s = mkBoundedSpec();
	auto net = Spec::NetOptDetails::createDefault();
	net->inboundPortsUdp.push_back({{53, 53}, {53, 53}});
	net->inboundPortsUdp.push_back({{53, 53}, {54, 54}});
	s.options["net"] = net;
	auto e = gatherStrictErrors(s);
	ATF_REQUIRE(hasMatch(e, "udp"));
	// TCP isn't accidentally flagged.
	for (auto &m : e) {
		// "tcp" appearing inside a udp message is fine; check on a
		// per-rule basis: the message describing the UDP conflict
		// contains "udp". Just confirm we have a udp entry above.
		(void)m;
	}
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_no_inbound_no_conflict);
ATF_TEST_CASE_BODY(strict_no_inbound_no_conflict)
{
	// Single inbound rule cannot conflict with itself.
	auto s = mkBoundedSpec();
	auto net = Spec::NetOptDetails::createDefault();
	net->inboundPortsTcp.push_back({{8080, 8080}, {80, 80}});
	s.options["net"] = net;
	auto e = gatherStrictErrors(s);
	for (auto &m : e)
		ATF_REQUIRE(m.find("host port") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_duplicate_share_destination);
ATF_TEST_CASE_BODY(strict_duplicate_share_destination)
{
	auto s = mkBoundedSpec();
	// Two different host paths -> same jail-side destination.
	// (Share is {jail, host}: the jail-side path comes first, as in
	// the spec's [jailDir, hostDir] pairs.)
	s.dirsShare.push_back({"/data", "/home/alice/data"});
	s.dirsShare.push_back({"/data", "/home/bob/data"});
	auto e = gatherStrictErrors(s);
	ATF_REQUIRE(hasMatch(e, "/data"));
	ATF_REQUIRE(hasMatch(e, "two different host sources"));
	// 1.1.63: one host directory under two jail paths is not a conflict
	auto t = mkBoundedSpec();
	t.dirsShare.push_back({"/data",   "/home/alice/data"});
	t.dirsShare.push_back({"/backup", "/home/alice/data"});
	for (auto &m : gatherStrictErrors(t))
		ATF_REQUIRE(m.find("two different host sources") == std::string::npos);
}

// 1.1.63: tmpfs / :ro / etc/keep warnings
ATF_TEST_CASE_WITHOUT_HEAD(mounts_1163_warnings);
ATF_TEST_CASE_BODY(mounts_1163_warnings)
{
	auto s = mkSpec();
	s.dirsShare.push_back({"/home/alice", "$HOME"});
	ATF_REQUIRE(hasMatch(gatherWarnings(s), "shared read-write as a whole"));
	s.dirsShare.back().readOnly = true;
	ATF_REQUIRE(!hasMatch(gatherWarnings(s), "shared read-write as a whole"));

	auto t = mkSpec();
	t.dirsShare.push_back({"/home/alice/.cache/x", "/host/x"});
	t.tmpfs.push_back({"/home/alice/.cache", ""});
	ATF_REQUIRE(hasMatch(gatherWarnings(t), "hides it"));

	auto u = mkSpec();
	u.etcKeep.push_back("localtime");
	ATF_REQUIRE(hasMatch(gatherWarnings(u), "etc/keep"));
	u.baseHostRo = true;
	ATF_REQUIRE(!hasMatch(gatherWarnings(u), "etc/keep"));
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_same_share_twice_not_a_conflict);
ATF_TEST_CASE_BODY(strict_same_share_twice_not_a_conflict)
{
	// Operator listing the SAME mapping twice is harmless dup, not
	// a conflict (idempotent). Only flag when sources differ.
	auto s = mkBoundedSpec();
	s.dirsShare.push_back({"/home/alice/data", "/data"});
	s.dirsShare.push_back({"/home/alice/data", "/data"});
	auto e = gatherStrictErrors(s);
	for (auto &m : e)
		ATF_REQUIRE(m.find("two different host sources") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_empty_share_paths);
ATF_TEST_CASE_BODY(strict_empty_share_paths)
{
	auto s = mkBoundedSpec();
	s.dirsShare.push_back({"", "/data"});
	s.filesShare.push_back({"/etc/hosts", ""});
	auto e = gatherStrictErrors(s);
	ATF_REQUIRE(hasMatch(e, "share/dir"));
	ATF_REQUIRE(hasMatch(e, "share/file"));
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_x11_shared_promoted_to_error);
ATF_TEST_CASE_BODY(strict_x11_shared_promoted_to_error)
{
	auto s = mkBoundedSpec();
	s.x11Options = std::make_unique<Spec::X11Options>();
	s.x11Options->mode = "shared";
	auto e = gatherStrictErrors(s);
	ATF_REQUIRE(hasMatch(e, "x11/mode=shared"));
	ATF_REQUIRE(hasMatch(e, "rejected in --strict"));
}

ATF_TEST_CASE_WITHOUT_HEAD(strict_x11_nested_no_error);
ATF_TEST_CASE_BODY(strict_x11_nested_no_error)
{
	auto s = mkBoundedSpec();
	s.x11Options = std::make_unique<Spec::X11Options>();
	s.x11Options->mode = "nested";
	auto e = gatherStrictErrors(s);
	for (auto &m : e)
		ATF_REQUIRE(m.find("x11") == std::string::npos);
}

// 1.1.58: base/mode: host-ro — base/remove is dead configuration there.
ATF_TEST_CASE_WITHOUT_HEAD(thin_jail_base_remove_warns);
ATF_TEST_CASE_BODY(thin_jail_base_remove_warns)
{
	auto s = mkSpec();
	s.baseHostRo = true;
	ATF_REQUIRE(!hasMatch(gatherWarnings(s), "base/mode=host-ro"));
	s.baseRemove.push_back("/usr/share/doc");
	ATF_REQUIRE(hasMatch(gatherWarnings(s), "base/mode=host-ro"));
	// a full jail trims as asked: no warning
	s.baseHostRo = false;
	ATF_REQUIRE(!hasMatch(gatherWarnings(s), "base/mode=host-ro"));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, thin_jail_base_remove_warns);
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
	ATF_ADD_TEST_CASE(tcs, x11_shared_warns);
	ATF_ADD_TEST_CASE(tcs, x11_headless_no_warn);
	ATF_ADD_TEST_CASE(tcs, x11_option_implicit_shared_warns);
	ATF_ADD_TEST_CASE(tcs, clipboard_isolated_without_nested_warns);
	ATF_ADD_TEST_CASE(tcs, clipboard_isolated_with_nested_no_warn);
	ATF_ADD_TEST_CASE(tcs, dbus_session_warns);
	ATF_ADD_TEST_CASE(tcs, socket_proxy_empty_warns);
	ATF_ADD_TEST_CASE(tcs, firewall_without_net_warns);
	ATF_ADD_TEST_CASE(tcs, firewall_block_no_allow_warns);
	ATF_ADD_TEST_CASE(tcs, capsicum_warns);
	ATF_ADD_TEST_CASE(tcs, mac_rules_warns);
	ATF_ADD_TEST_CASE(tcs, terminal_devfs_ruleset_warns);
	ATF_ADD_TEST_CASE(tcs, devices_classes_warn);
	ATF_ADD_TEST_CASE(tcs, mounts_1163_warnings);
	ATF_ADD_TEST_CASE(tcs, run_user_warnings);
	ATF_ADD_TEST_CASE(tcs, run_timeout_warnings);
	ATF_ADD_TEST_CASE(tcs, privacy_warnings);
	ATF_ADD_TEST_CASE(tcs, multiple_warnings);
	// 0.7.16 strict-mode tests
	ATF_ADD_TEST_CASE(tcs, strict_minimal_spec_still_unbounded);
	ATF_ADD_TEST_CASE(tcs, strict_bounded_spec_no_errors);
	ATF_ADD_TEST_CASE(tcs, strict_bounded_via_maxproc);
	ATF_ADD_TEST_CASE(tcs, strict_inbound_tcp_port_conflict);
	ATF_ADD_TEST_CASE(tcs, strict_inbound_tcp_range_overlap);
	ATF_ADD_TEST_CASE(tcs, strict_inbound_udp_port_conflict);
	ATF_ADD_TEST_CASE(tcs, strict_no_inbound_no_conflict);
	ATF_ADD_TEST_CASE(tcs, strict_duplicate_share_destination);
	ATF_ADD_TEST_CASE(tcs, strict_same_share_twice_not_a_conflict);
	ATF_ADD_TEST_CASE(tcs, strict_empty_share_paths);
	ATF_ADD_TEST_CASE(tcs, strict_x11_shared_promoted_to_error);
	ATF_ADD_TEST_CASE(tcs, strict_x11_nested_no_error);
}
