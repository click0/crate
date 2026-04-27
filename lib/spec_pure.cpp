// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "spec_pure.h"
#include "spec.h"

#include "util.h"   // Util::toUInt

namespace SpecPure {

PortRange parsePortRange(const std::string &str) {
  auto hyphen = str.find('-');
  return hyphen == std::string::npos
    ? PortRange(Util::toUInt(str), Util::toUInt(str))
    : PortRange(Util::toUInt(str.substr(0, hyphen)),
                Util::toUInt(str.substr(hyphen + 1)));
}

}

// ===================================================================
// Pure method definitions for Spec / Spec::NetOptDetails / Spec::OptDetails.
// Originally lived in lib/spec.cpp; moved here so unit tests can link
// against them without dragging in yaml-cpp etc.
// ===================================================================

Spec::OptDetails::~OptDetails() {}

Spec::NetOptDetails::NetOptDetails()
: outboundWan(false),
  outboundLan(false),
  outboundHost(false),
  outboundDns(false),
  ipv6(false)
{ }

bool Spec::NetOptDetails::allowOutbound() const {
  return outboundWan || outboundLan || outboundHost || outboundDns;
}

bool Spec::NetOptDetails::allowInbound() const {
  return !inboundPortsTcp.empty() || !inboundPortsUdp.empty();
}

bool Spec::NetOptDetails::isNatMode() const {
  return mode == Mode::Nat;
}

bool Spec::NetOptDetails::needsIpfw() const {
  return mode == Mode::Nat;
}

bool Spec::NetOptDetails::needsDhcp() const {
  return ipMode == IpMode::Dhcp;
}

bool Spec::optionExists(const char* opt) const {
  return options.find(opt) != options.end();
}
