// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// 1.1.68: the member spec `crate stack up` builds — the yaml-cpp half.
//
// createCrate() copies the spec FILE it is given into +CRATE.SPEC, and
// the detached `crate run -f` reads that file. So everything the stack
// adds to a member (the template, the pool address, the /etc/hosts and
// resolv.conf scripts, the named volumes) has to land in a spec FILE at
// the YAML level, the way lib/profile.cpp merges a profile's .local —
// a Spec-level merge never reached the run (TODO §17, found in 1.1.59).
// `${VAR}` placeholders are kept as text: the stack passes its vars to
// the run with --var, and `crate run` substitutes them when it parses
// +CRATE.SPEC (also 1.1.68), so a `from_file` secret is not baked into
// the archive.
//

#include <yaml-cpp/yaml.h>

#include <map>
#include <string>
#include <vector>

namespace StackSpec {

// 1.1.70: a member's primary network as the spec parser will see it —
// read from the template-merged YAML with the member's vars substituted
// (`ip: ${DB_IP}` is an address, `mode: ${MODE}` a mode). `stack up`
// decides from this, before anything starts, which members are on a
// stack bridge (StackPure::poolEligible) and which have a static address
// of their own; until 1.1.69 that came from a Spec-level mergeSpecs that
// could disagree with the YAML-level merge the member is built from.
struct NetInfo {
  bool hasNet = false;     // a net option (net, tor, or top-level network:)
  std::string mode;        // options/net/mode; "auto" for `network: auto`; "nat" when unset; "" without hasNet
  std::string bridge;      // options/net/bridge
  std::string staticIp;    // options/net/ip when it is an address (not dhcp/none)
  bool ipSet = false;      // options/net/ip present at all (an address, dhcp or none)
};
NetInfo netInfo(const YAML::Node &spec, const std::map<std::string, std::string> &vars);

struct Share {
  std::string containerPath;
  std::string hostPath;
  bool        readOnly = false;
};

struct Injections {
  std::string ipCidr;     // pool address; applied only when the net option has no `ip`
  std::string gateway;    // with the address, when the spec names none
  std::string hostsCmd;   // StackPure::hostsCommand — "" for none
  std::string dnsCmd;     // StackPure::dnsCommand — "" for none
  std::vector<Share> shares;
};

// Does the spec have a networking option the pool can address? True for
// `net` or `tor` in any options form (tor implies a blank net) and for a
// top-level `network:` key — the shapes the parser materialises
// Spec::options["net"] from.
bool hasNetOption(const YAML::Node &spec);
// options/net/ip present (extended form).
bool hasStaticIp(const YAML::Node &spec);

// The member's final spec: `tpl` (when defined) under `spec`, then the
// injections. Neither argument is modified. Throws Exception when the
// spec's `scripts` or `dirs` block has a shape the parser would reject —
// the merge must not paper over it.
YAML::Node compose(const YAML::Node &spec, const YAML::Node &tpl, const Injections &inj);

// Write `node` to `outPath` with a "generated" header, atomically.
void writeSpec(const YAML::Node &node, const std::string &outPath, const std::string &header);

} // namespace StackSpec
