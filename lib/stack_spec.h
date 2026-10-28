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

#include <string>
#include <vector>

namespace StackSpec {

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
