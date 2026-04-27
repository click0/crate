// ATF unit tests for Spec::NetOptDetails methods.
//
// Uses real Spec types from lib/spec.h, methods linked from lib/spec_pure.cpp.

#include <atf-c++.hpp>
#include <memory>

#include "spec.h"

ATF_TEST_CASE_WITHOUT_HEAD(allowOutbound_all_false);
ATF_TEST_CASE_BODY(allowOutbound_all_false)
{
	Spec::NetOptDetails n;
	ATF_REQUIRE(!n.allowOutbound());
}

ATF_TEST_CASE_WITHOUT_HEAD(allowOutbound_wan_only);
ATF_TEST_CASE_BODY(allowOutbound_wan_only)
{
	Spec::NetOptDetails n;
	n.outboundWan = true;
	ATF_REQUIRE(n.allowOutbound());
}

ATF_TEST_CASE_WITHOUT_HEAD(allowOutbound_dns_only);
ATF_TEST_CASE_BODY(allowOutbound_dns_only)
{
	Spec::NetOptDetails n;
	n.outboundDns = true;
	ATF_REQUIRE(n.allowOutbound());
}

ATF_TEST_CASE_WITHOUT_HEAD(allowOutbound_all_true);
ATF_TEST_CASE_BODY(allowOutbound_all_true)
{
	Spec::NetOptDetails n;
	n.outboundWan = true;
	n.outboundLan = true;
	n.outboundHost = true;
	n.outboundDns = true;
	ATF_REQUIRE(n.allowOutbound());
}

ATF_TEST_CASE_WITHOUT_HEAD(allowInbound_empty);
ATF_TEST_CASE_BODY(allowInbound_empty)
{
	Spec::NetOptDetails n;
	ATF_REQUIRE(!n.allowInbound());
}

ATF_TEST_CASE_WITHOUT_HEAD(allowInbound_tcp);
ATF_TEST_CASE_BODY(allowInbound_tcp)
{
	Spec::NetOptDetails n;
	n.inboundPortsTcp.push_back({{80, 80}, {80, 80}});
	ATF_REQUIRE(n.allowInbound());
}

ATF_TEST_CASE_WITHOUT_HEAD(allowInbound_udp);
ATF_TEST_CASE_BODY(allowInbound_udp)
{
	Spec::NetOptDetails n;
	n.inboundPortsUdp.push_back({{53, 53}, {53, 53}});
	ATF_REQUIRE(n.allowInbound());
}

ATF_TEST_CASE_WITHOUT_HEAD(allowInbound_both);
ATF_TEST_CASE_BODY(allowInbound_both)
{
	Spec::NetOptDetails n;
	n.inboundPortsTcp.push_back({{443, 443}, {443, 443}});
	n.inboundPortsUdp.push_back({{5060, 5060}, {5060, 5060}});
	ATF_REQUIRE(n.allowInbound());
}

ATF_TEST_CASE_WITHOUT_HEAD(isNatMode_default);
ATF_TEST_CASE_BODY(isNatMode_default)
{
	Spec::NetOptDetails n;
	ATF_REQUIRE(n.isNatMode());
	ATF_REQUIRE(n.needsIpfw());
}

ATF_TEST_CASE_WITHOUT_HEAD(isNatMode_bridge);
ATF_TEST_CASE_BODY(isNatMode_bridge)
{
	Spec::NetOptDetails n;
	n.mode = Spec::NetOptDetails::Mode::Bridge;
	ATF_REQUIRE(!n.isNatMode());
	ATF_REQUIRE(!n.needsIpfw());
}

ATF_TEST_CASE_WITHOUT_HEAD(isNatMode_passthrough);
ATF_TEST_CASE_BODY(isNatMode_passthrough)
{
	Spec::NetOptDetails n;
	n.mode = Spec::NetOptDetails::Mode::Passthrough;
	ATF_REQUIRE(!n.isNatMode());
	ATF_REQUIRE(!n.needsIpfw());
}

ATF_TEST_CASE_WITHOUT_HEAD(isNatMode_netgraph);
ATF_TEST_CASE_BODY(isNatMode_netgraph)
{
	Spec::NetOptDetails n;
	n.mode = Spec::NetOptDetails::Mode::Netgraph;
	ATF_REQUIRE(!n.isNatMode());
	ATF_REQUIRE(!n.needsIpfw());
}

ATF_TEST_CASE_WITHOUT_HEAD(needsDhcp_auto);
ATF_TEST_CASE_BODY(needsDhcp_auto)
{
	Spec::NetOptDetails n;
	ATF_REQUIRE(!n.needsDhcp());
}

ATF_TEST_CASE_WITHOUT_HEAD(needsDhcp_dhcp);
ATF_TEST_CASE_BODY(needsDhcp_dhcp)
{
	Spec::NetOptDetails n;
	n.ipMode = Spec::NetOptDetails::IpMode::Dhcp;
	ATF_REQUIRE(n.needsDhcp());
}

ATF_TEST_CASE_WITHOUT_HEAD(needsDhcp_static);
ATF_TEST_CASE_BODY(needsDhcp_static)
{
	Spec::NetOptDetails n;
	n.ipMode = Spec::NetOptDetails::IpMode::Static;
	ATF_REQUIRE(!n.needsDhcp());
}

ATF_TEST_CASE_WITHOUT_HEAD(needsDhcp_none);
ATF_TEST_CASE_BODY(needsDhcp_none)
{
	Spec::NetOptDetails n;
	n.ipMode = Spec::NetOptDetails::IpMode::None;
	ATF_REQUIRE(!n.needsDhcp());
}

ATF_TEST_CASE_WITHOUT_HEAD(optionExists_empty);
ATF_TEST_CASE_BODY(optionExists_empty)
{
	Spec s;
	ATF_REQUIRE(!s.optionExists("net"));
	ATF_REQUIRE(!s.optionExists("tor"));
}

ATF_TEST_CASE_WITHOUT_HEAD(optionExists_present);
ATF_TEST_CASE_BODY(optionExists_present)
{
	Spec s;
	s.options["net"] = std::make_shared<Spec::NetOptDetails>();
	ATF_REQUIRE(s.optionExists("net"));
	ATF_REQUIRE(!s.optionExists("tor"));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, allowOutbound_all_false);
	ATF_ADD_TEST_CASE(tcs, allowOutbound_wan_only);
	ATF_ADD_TEST_CASE(tcs, allowOutbound_dns_only);
	ATF_ADD_TEST_CASE(tcs, allowOutbound_all_true);
	ATF_ADD_TEST_CASE(tcs, allowInbound_empty);
	ATF_ADD_TEST_CASE(tcs, allowInbound_tcp);
	ATF_ADD_TEST_CASE(tcs, allowInbound_udp);
	ATF_ADD_TEST_CASE(tcs, allowInbound_both);
	ATF_ADD_TEST_CASE(tcs, isNatMode_default);
	ATF_ADD_TEST_CASE(tcs, isNatMode_bridge);
	ATF_ADD_TEST_CASE(tcs, isNatMode_passthrough);
	ATF_ADD_TEST_CASE(tcs, isNatMode_netgraph);
	ATF_ADD_TEST_CASE(tcs, needsDhcp_auto);
	ATF_ADD_TEST_CASE(tcs, needsDhcp_dhcp);
	ATF_ADD_TEST_CASE(tcs, needsDhcp_static);
	ATF_ADD_TEST_CASE(tcs, needsDhcp_none);
	ATF_ADD_TEST_CASE(tcs, optionExists_empty);
	ATF_ADD_TEST_CASE(tcs, optionExists_present);
}
