// ATF unit tests for Spec::NetOptDetails pure methods
//
// Build:
//   c++ -std=c++17 -Ilib -o tests/unit/spec_netopt_test \
//       tests/unit/spec_netopt_test.cpp -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

// ===================================================================
// Minimal reproduction of Spec types needed for testing
// (avoids pulling in yaml-cpp, rang, and other heavy dependencies)
// ===================================================================

class Spec {
public:
	class OptDetails {
	public:
		virtual ~OptDetails() = 0;
	};
	class NetOptDetails : public OptDetails {
	public:
		typedef std::pair<unsigned,unsigned> PortRange;

		enum class Mode { Nat, Bridge, Passthrough, Netgraph };
		Mode mode = Mode::Nat;

		bool outboundWan = false;
		bool outboundLan = false;
		bool outboundHost = false;
		bool outboundDns = false;
		bool ipv6 = false;
		std::vector<std::pair<PortRange, PortRange>> inboundPortsTcp;
		std::vector<std::pair<PortRange, PortRange>> inboundPortsUdp;

		enum class IpMode { Auto, Static, Dhcp, None };
		IpMode ipMode = IpMode::Auto;

		bool allowOutbound() const {
			return outboundWan || outboundLan || outboundHost || outboundDns;
		}
		bool allowInbound() const {
			return !inboundPortsTcp.empty() || !inboundPortsUdp.empty();
		}
		bool isNatMode() const {
			return mode == Mode::Nat;
		}
		bool needsIpfw() const {
			return mode == Mode::Nat;
		}
		bool needsDhcp() const {
			return ipMode == IpMode::Dhcp;
		}
	};

	std::map<std::string, std::shared_ptr<OptDetails>> options;

	bool optionExists(const char *opt) const {
		return options.find(opt) != options.end();
	}
};

Spec::OptDetails::~OptDetails() {}

// ===================================================================
// Tests: allowOutbound
// ===================================================================

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

// ===================================================================
// Tests: allowInbound
// ===================================================================

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

// ===================================================================
// Tests: isNatMode / needsIpfw
// ===================================================================

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

// ===================================================================
// Tests: needsDhcp
// ===================================================================

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

// ===================================================================
// Tests: optionExists
// ===================================================================

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

// ===================================================================
// Registration
// ===================================================================

ATF_INIT_TEST_CASES(tcs)
{
	// allowOutbound
	ATF_ADD_TEST_CASE(tcs, allowOutbound_all_false);
	ATF_ADD_TEST_CASE(tcs, allowOutbound_wan_only);
	ATF_ADD_TEST_CASE(tcs, allowOutbound_dns_only);
	ATF_ADD_TEST_CASE(tcs, allowOutbound_all_true);

	// allowInbound
	ATF_ADD_TEST_CASE(tcs, allowInbound_empty);
	ATF_ADD_TEST_CASE(tcs, allowInbound_tcp);
	ATF_ADD_TEST_CASE(tcs, allowInbound_udp);
	ATF_ADD_TEST_CASE(tcs, allowInbound_both);

	// isNatMode / needsIpfw
	ATF_ADD_TEST_CASE(tcs, isNatMode_default);
	ATF_ADD_TEST_CASE(tcs, isNatMode_bridge);
	ATF_ADD_TEST_CASE(tcs, isNatMode_passthrough);
	ATF_ADD_TEST_CASE(tcs, isNatMode_netgraph);

	// needsDhcp
	ATF_ADD_TEST_CASE(tcs, needsDhcp_auto);
	ATF_ADD_TEST_CASE(tcs, needsDhcp_dhcp);
	ATF_ADD_TEST_CASE(tcs, needsDhcp_static);
	ATF_ADD_TEST_CASE(tcs, needsDhcp_none);

	// optionExists
	ATF_ADD_TEST_CASE(tcs, optionExists_empty);
	ATF_ADD_TEST_CASE(tcs, optionExists_present);
}
