// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "stack_spec.h"
#include "profile.h"   // Profile::mergeYaml — the same merge a profile's .local gets
#include "err.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fstream>
#include <sstream>

#define ERR(msg...) ERR2("stack", msg)

namespace StackSpec {

static const char *kSection = "run:before-start-services";

// Option names in any of the three `options` shapes (a name, a list of
// names or single-key maps, a map name -> details).
static bool optionsContain(const YAML::Node &options, const std::string &name) {
  if (!options.IsDefined() || options.IsNull()) return false;
  if (options.IsScalar()) return options.as<std::string>() == name;
  if (options.IsSequence()) {
    for (const auto &item : options) {
      if (item.IsScalar() && item.as<std::string>() == name) return true;
      if (item.IsMap() && item.size() == 1 && item.begin()->first.IsScalar()
          && item.begin()->first.as<std::string>() == name) return true;
    }
    return false;
  }
  if (options.IsMap()) return options[name].IsDefined();
  return false;
}

bool hasNetOption(const YAML::Node &spec) {
  if (!spec.IsDefined() || !spec.IsMap()) return false;
  if (spec["network"].IsDefined()) return true;
  const auto options = spec["options"];
  return optionsContain(options, "net") || optionsContain(options, "tor");
}

static YAML::Node netDetails(const YAML::Node &spec) {
  if (!spec.IsDefined() || !spec.IsMap()) return YAML::Node(YAML::NodeType::Undefined);
  const auto options = spec["options"];
  if (!options.IsDefined() || !options.IsMap()) return YAML::Node(YAML::NodeType::Undefined);
  return options["net"];
}

bool hasStaticIp(const YAML::Node &spec) {
  const auto net = netDetails(spec);
  return net.IsDefined() && net.IsMap() && net["ip"].IsDefined() && !net["ip"].IsNull();
}

static bool hasGateway(const YAML::Node &spec) {
  const auto net = netDetails(spec);
  return net.IsDefined() && net.IsMap() && net["gateway"].IsDefined() && !net["gateway"].IsNull();
}

// The parser accepts a scripts section as a scalar, a list of lines, a
// list of lists, or a map name -> script. Adding a named script needs the
// map form; the other shapes are rewritten to the names the parser would
// have given them ("" for the single script, "script#N" for a list of
// lists), so the jail runs exactly what the spec said.
static YAML::Node scriptsSectionAsMap(const YAML::Node &section) {
  if (!section.IsDefined() || section.IsNull()) return YAML::Node(YAML::NodeType::Map);
  if (section.IsMap()) return YAML::Clone(section);
  YAML::Node out(YAML::NodeType::Map);
  if (section.IsScalar()) { out[""] = YAML::Clone(section); return out; }
  if (section.IsSequence()) {
    bool allScalars = section.size() > 0;
    for (const auto &item : section) if (!item.IsScalar()) allScalars = false;
    if (allScalars) { out[""] = YAML::Clone(section); return out; }
    unsigned idx = 1;
    for (const auto &item : section) {
      if (!item.IsSequence())
        ERR("scripts/" << kSection << ": lists must hold lines or lists of lines")
      out["script#" + std::to_string(idx++)] = YAML::Clone(item);
    }
    return out;
  }
  ERR("scripts/" << kSection << ": unsupported shape")
}

YAML::Node compose(const YAML::Node &spec, const YAML::Node &tpl, const Injections &inj) {
  if (!spec.IsDefined() || !spec.IsMap())
    ERR("a member spec must be a YAML map")
  YAML::Node result = (tpl.IsDefined() && !tpl.IsNull()) ? Profile::mergeYaml(tpl, spec)
                                                          : YAML::Clone(spec);

  // pool address — only where the parsed spec would have had a net option
  // without a static address (the 1.1.45 rule, now at the YAML level)
  if (!inj.ipCidr.empty() && hasNetOption(result) && !hasStaticIp(result)) {
    YAML::Node overlay(YAML::NodeType::Map);
    overlay["options"]["net"]["ip"] = inj.ipCidr;
    if (!inj.gateway.empty() && !hasGateway(result))
      overlay["options"]["net"]["gateway"] = inj.gateway;
    // A top-level `network: auto` materialises the net option with mode
    // auto, but the parser handles the keys in file order and an
    // `options/net` map seen after it starts from fresh details — the
    // mode would depend on where `options` lands in the emitted file.
    // Spell the mode out so the result is the same in either order.
    const auto net = netDetails(result);
    const bool modeSet = net.IsDefined() && net.IsMap() && net["mode"].IsDefined() && !net["mode"].IsNull();
    if (!modeSet && result["network"].IsDefined() && result["network"].IsScalar()
        && result["network"].as<std::string>() == "auto")
      overlay["options"]["net"]["mode"] = "auto";
    result = Profile::mergeYaml(result, overlay);
  }

  // hosts / resolver scripts
  if (!inj.hostsCmd.empty() || !inj.dnsCmd.empty()) {
    if (result["scripts"].IsDefined() && !result["scripts"].IsNull() && !result["scripts"].IsMap())
      ERR("scripts must be a map")
    YAML::Node section = scriptsSectionAsMap(result["scripts"][kSection]);
    if (!inj.hostsCmd.empty()) section["__crate_stack_hosts"] = inj.hostsCmd;
    if (!inj.dnsCmd.empty())   section["__crate_stack_dns"]   = inj.dnsCmd;
    result["scripts"][kSection] = section;
  }

  // named volumes as dirs/share entries
  if (!inj.shares.empty()) {
    if (result["dirs"].IsDefined() && !result["dirs"].IsNull() && !result["dirs"].IsMap())
      ERR("dirs must be a map")
    YAML::Node share = result["dirs"]["share"];
    if (share.IsDefined() && !share.IsNull() && !share.IsSequence())
      ERR("dirs/share has to be a list")
    // A volume the spec already shares (same jail and host path, in the
    // scalar or the pair form) is not added a second time — the strict
    // validate rejects duplicate destinations.
    auto present = [&share](const Share &s) {
      if (!share.IsDefined() || !share.IsSequence()) return false;
      for (const auto &e : share) {
        std::string jail, host;
        if (e.IsScalar()) { jail = host = e.as<std::string>(); }
        else if (e.IsSequence() && e.size() >= 2 && e[0].IsScalar() && e[1].IsScalar()) {
          jail = e[0].as<std::string>(); host = e[1].as<std::string>();
        } else continue;
        if (jail == s.containerPath && host == s.hostPath) return true;
      }
      return false;
    };
    for (auto &s : inj.shares) {
      if (present(s)) continue;
      YAML::Node entry(YAML::NodeType::Sequence);
      entry.SetStyle(YAML::EmitterStyle::Flow);   // `- [/jail, /host, ro]`, the hand-written look
      entry.push_back(s.containerPath);
      entry.push_back(s.hostPath);
      if (s.readOnly) entry.push_back("ro");
      result["dirs"]["share"].push_back(entry);
    }
  }

  return result;
}

void writeSpec(const YAML::Node &node, const std::string &outPath, const std::string &header) {
  std::ostringstream out;
  if (!header.empty()) out << header << "\n";
  {
    YAML::Emitter em;
    em << node;
    if (!em.good()) ERR("cannot emit the member spec: " << em.GetLastError())
    out << em.c_str() << "\n";
  }
  const auto tmp = outPath + ".tmp";
  {
    std::ofstream f(tmp, std::ios::trunc);
    if (!f) ERR("cannot write " << tmp << ": " << strerror(errno))
    f << out.str();
    if (!f) ERR("cannot write " << tmp)
  }
  if (::rename(tmp.c_str(), outPath.c_str()) != 0) {
    int e = errno;
    ::unlink(tmp.c_str());
    ERR("cannot rename " << tmp << " to " << outPath << ": " << strerror(e))
  }
}

} // namespace StackSpec
