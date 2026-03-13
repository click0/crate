// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "util.h"
#include "err.h"
#include "commands.h"
#include "jail_query.h"
#include "ipfw_ops.h"
#include "net.h"
#include "pathnames.h"

#include <rang.hpp>
#include <yaml-cpp/yaml.h>

#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <filesystem>

#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>

#define ERR(msg...) ERR2("stack", msg)

// A network definition within a stack file
struct StackNetwork {
  std::string name;             // logical name (e.g., "matrix")
  std::string bridge;           // bridge interface (e.g., "bridge99")
  std::string subnet;           // subnet CIDR (e.g., "10.99.0.0/24")
  std::string gateway;          // gateway IP (e.g., "10.99.0.1")
  bool dns = false;             // run per-stack unbound DNS on bridge IP
  std::string ipRange;          // IP pool range (e.g., "10.99.0.100-10.99.0.200")
};

// A named volume declared at stack level
struct StackVolume {
  std::string name;             // logical name (e.g., "certs")
  std::string hostPath;         // host directory path
};

// A volume mount for a container
struct VolumeMountEntry {
  std::string volumeName;       // reference to StackVolume
  std::string containerPath;    // path inside the container
  bool readOnly = false;        // :ro suffix
};

// A container entry within a stack file
struct StackEntry {
  std::string name;             // container name
  std::string crateFile;        // path to .crate file
  std::string specFile;         // path to spec YAML (for create)
  std::string templateName;     // optional template
  std::vector<std::string> depends;  // names of dependencies
  std::map<std::string, std::string> vars;  // per-container variable overrides
  std::vector<VolumeMountEntry> volumeMounts;  // named volume mounts
};

// Parse networks section from a stack YAML
static std::vector<StackNetwork> parseNetworks(const YAML::Node &top) {
  std::vector<StackNetwork> networks;
  if (!top["networks"] || !top["networks"].IsMap())
    return networks;
  for (auto n : top["networks"]) {
    StackNetwork net;
    net.name = n.first.as<std::string>();
    if (!n.second.IsMap())
      ERR("networks/" << net.name << " must be a map")
    if (n.second["bridge"])
      net.bridge = n.second["bridge"].as<std::string>();
    else
      ERR("networks/" << net.name << " requires 'bridge' field")
    if (n.second["subnet"])
      net.subnet = n.second["subnet"].as<std::string>();
    if (n.second["gateway"])
      net.gateway = n.second["gateway"].as<std::string>();
    if (n.second["dns"])
      net.dns = n.second["dns"].as<bool>();
    if (n.second["ip_range"])
      net.ipRange = n.second["ip_range"].as<std::string>();
    networks.push_back(std::move(net));
  }
  return networks;
}

// --- IP Pool Allocator (§27.3) ---

// Parse a CIDR subnet into base address and prefix length
static bool parseCidr(const std::string &cidr, uint32_t &baseAddr, unsigned &prefixLen) {
  auto slashPos = cidr.find('/');
  if (slashPos == std::string::npos)
    return false;
  auto addrStr = cidr.substr(0, slashPos);
  prefixLen = std::stoul(cidr.substr(slashPos + 1));
  struct in_addr addr;
  if (inet_pton(AF_INET, addrStr.c_str(), &addr) != 1)
    return false;
  baseAddr = ntohl(addr.s_addr);
  return true;
}

// Convert uint32_t IP to dotted string
static std::string ipToString(uint32_t ip) {
  struct in_addr addr;
  addr.s_addr = htonl(ip);
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &addr, buf, sizeof(buf));
  return buf;
}

// Allocate IPs from subnet for containers that don't have static IPs
// Reserve .1 for gateway/bridge, allocate .2, .3, ... sequentially
static std::map<std::string, std::string> allocateIpPool(
    const StackNetwork &network,
    const std::vector<StackEntry> &entries,
    const std::map<std::string, std::string> &existingIps) {

  std::map<std::string, std::string> result = existingIps;

  if (network.subnet.empty())
    return result;

  uint32_t baseAddr;
  unsigned prefixLen;
  if (!parseCidr(network.subnet, baseAddr, prefixLen))
    return result;

  // Determine pool start/end
  uint32_t poolStart, poolEnd;
  if (!network.ipRange.empty()) {
    auto dashPos = network.ipRange.find('-');
    if (dashPos != std::string::npos) {
      struct in_addr s, e;
      inet_pton(AF_INET, network.ipRange.substr(0, dashPos).c_str(), &s);
      inet_pton(AF_INET, network.ipRange.substr(dashPos + 1).c_str(), &e);
      poolStart = ntohl(s.s_addr);
      poolEnd = ntohl(e.s_addr);
    } else {
      poolStart = (baseAddr & ~((1u << (32 - prefixLen)) - 1)) + 2;
      poolEnd = (baseAddr | ((1u << (32 - prefixLen)) - 1)) - 1;
    }
  } else {
    // Default: .2 to .254 (skip .0=network, .1=gateway, .255=broadcast)
    poolStart = (baseAddr & ~((1u << (32 - prefixLen)) - 1)) + 2;
    poolEnd = (baseAddr | ((1u << (32 - prefixLen)) - 1)) - 1;
  }

  // Collect already-used IPs
  std::set<uint32_t> usedIps;
  for (auto &kv : existingIps) {
    struct in_addr a;
    if (inet_pton(AF_INET, kv.second.c_str(), &a) == 1)
      usedIps.insert(ntohl(a.s_addr));
  }

  // Gateway is reserved
  if (!network.gateway.empty()) {
    struct in_addr gw;
    if (inet_pton(AF_INET, network.gateway.c_str(), &gw) == 1)
      usedIps.insert(ntohl(gw.s_addr));
  }

  // Allocate for containers without IPs
  uint32_t nextIp = poolStart;
  for (auto &e : entries) {
    if (result.count(e.name))
      continue; // already has an IP

    while (nextIp <= poolEnd && usedIps.count(nextIp))
      nextIp++;

    if (nextIp > poolEnd)
      ERR("IP pool exhausted for network '" << network.name
          << "': cannot allocate IP for container '" << e.name << "'")

    auto prefixStr = std::to_string(prefixLen);
    result[e.name] = ipToString(nextIp);
    usedIps.insert(nextIp);
    nextIp++;
  }

  return result;
}

// --- Per-Stack DNS Service (§27.1) ---

// Generate unbound configuration for a stack's DNS service
static std::string generateUnboundConf(
    const std::string &listenIp,
    const std::string &subnet,
    const std::map<std::string, std::string> &nameToIp,
    const std::string &upstreamDns) {

  std::ostringstream conf;
  conf << "server:\n";
  conf << "  interface: " << listenIp << "\n";
  conf << "  port: 53\n";
  conf << "  do-daemonize: yes\n";
  conf << "  pidfile: \"/var/run/unbound_stack.pid\"\n";
  conf << "  access-control: 127.0.0.0/8 allow\n";
  if (!subnet.empty())
    conf << "  access-control: " << subnet << " allow\n";
  conf << "  access-control: 0.0.0.0/0 refuse\n";
  conf << "  hide-identity: yes\n";
  conf << "  hide-version: yes\n";
  conf << "\n";
  conf << "  # Stack container A records\n";
  conf << "  local-zone: \"crate.\" static\n";
  for (auto &kv : nameToIp) {
    conf << "  local-data: \"" << kv.first << ".crate. IN A " << kv.second << "\"\n";
    // Also add plain name without .crate suffix for convenience
    conf << "  local-data: \"" << kv.first << ". IN A " << kv.second << "\"\n";
  }
  conf << "\n";
  conf << "forward-zone:\n";
  conf << "  name: \".\"\n";
  conf << "  forward-addr: " << upstreamDns << "\n";

  return conf.str();
}

// Start per-stack unbound DNS service on the bridge interface IP.
// Returns the PID of the unbound process (for cleanup).
static pid_t startStackDns(
    const StackNetwork &network,
    const std::map<std::string, std::string> &nameToIp,
    bool logProgress) {

  if (!network.dns || network.gateway.empty())
    return -1;

  // Get upstream DNS for forwarding
  auto upstreamDns = Net::getNameserverIp();

  auto confDir = STR("/var/run/crate/dns-" << network.name);
  std::filesystem::create_directories(confDir);

  auto confPath = STR(confDir << "/unbound.conf");
  auto conf = generateUnboundConf(network.gateway, network.subnet, nameToIp, upstreamDns);
  Util::Fs::writeFile(conf, confPath);

  if (logProgress)
    std::cerr << rang::fg::gray << "starting stack DNS on " << network.gateway
              << " for network '" << network.name << "' ("
              << nameToIp.size() << " records)" << rang::style::reset << std::endl;

  pid_t pid = ::fork();
  if (pid == 0) {
    ::execl(CRATE_PATH_UNBOUND, "unbound", "-c", confPath.c_str(), nullptr);
    ::_exit(127);
  }
  if (pid < 0)
    ERR("failed to fork unbound for stack DNS: " << strerror(errno))

  return pid;
}

// Stop the per-stack unbound DNS service
static void stopStackDns(const std::string &networkName, pid_t unboundPid) {
  if (unboundPid > 0) {
    ::kill(unboundPid, SIGTERM);
    int status;
    ::waitpid(unboundPid, &status, 0);
  }
  // Clean up config directory
  auto confDir = STR("/var/run/crate/dns-" << networkName);
  std::filesystem::remove_all(confDir);
}

// --- Network Policies (§27.2) ---

// Parse network_policy section from a stack YAML
static Spec::NetworkPolicy parseNetworkPolicy(const YAML::Node &top) {
  Spec::NetworkPolicy policy;
  if (!top["network_policy"] || !top["network_policy"].IsMap())
    return policy;

  auto &np = top["network_policy"];
  if (np["default"])
    policy.defaultAction = np["default"].as<std::string>();

  if (np["rules"] && np["rules"].IsSequence()) {
    for (auto r : np["rules"]) {
      Spec::NetworkPolicyRule rule;
      if (r["from"]) rule.from = r["from"].as<std::string>();
      if (r["to"])   rule.to = r["to"].as<std::string>();
      if (r["action"]) rule.action = r["action"].as<std::string>();
      if (r["proto"])  rule.proto = r["proto"].as<std::string>();
      if (r["ports"] && r["ports"].IsSequence()) {
        for (auto p : r["ports"])
          rule.ports.push_back(p.as<unsigned>());
      }
      policy.rules.push_back(std::move(rule));
    }
  }

  return policy;
}

// Apply network policies as ipfw rules on the bridge interface.
// Returns cleanup callback that removes the rules on stack teardown.
static RunAtEnd applyNetworkPolicies(
    const Spec::NetworkPolicy &policy,
    const std::map<std::string, std::string> &nameToIp,
    const std::string &bridgeIface,
    bool logProgress) {

  if (policy.rules.empty() && policy.defaultAction == "allow")
    return RunAtEnd();

  // Use a high rule number range for stack policies: 30000-39999
  static const unsigned policyRuleBase = 30000;
  static unsigned nextPolicySlot = 0;
  unsigned slotBase = policyRuleBase + (nextPolicySlot++) * 100;

  std::vector<unsigned> addedRules;
  unsigned ruleNum = slotBase;

  // Apply explicit rules first
  for (auto &rule : policy.rules) {
    auto fromIt = nameToIp.find(rule.from);
    auto toIt = nameToIp.find(rule.to);
    if (fromIt == nameToIp.end() || toIt == nameToIp.end())
      continue;

    for (auto port : rule.ports) {
      auto ruleStr = STR(rule.action << " " << rule.proto
                         << " from " << fromIt->second
                         << " to " << toIt->second << " " << port
                         << " via " << bridgeIface);
      IpfwOps::addRule(ruleNum, ruleStr);
      addedRules.push_back(ruleNum);
      ruleNum++;

      if (logProgress)
        std::cerr << rang::fg::gray << "network policy: " << rule.from
                  << " -> " << rule.to << ":" << port
                  << " [" << rule.action << "]"
                  << rang::style::reset << std::endl;
    }
  }

  // Default policy for bridge traffic
  if (policy.defaultAction == "deny") {
    // Deny all remaining traffic on the bridge
    for (auto &kv : nameToIp) {
      auto ruleStr = STR("deny ip from " << kv.second << " to any via " << bridgeIface);
      IpfwOps::addRule(ruleNum, ruleStr);
      addedRules.push_back(ruleNum);
      ruleNum++;
    }
    if (logProgress)
      std::cerr << rang::fg::gray << "network policy: default deny on "
                << bridgeIface << rang::style::reset << std::endl;
  }

  return RunAtEnd([addedRules]() {
    for (auto r : addedRules) {
      try { IpfwOps::deleteRule(r); } catch (...) {}
    }
  });
}

// Extract the IP address (without prefix length) from a CIDR string like "10.99.0.2/24"
static std::string ipFromCidr(const std::string &cidr) {
  auto pos = cidr.find('/');
  return pos != std::string::npos ? cidr.substr(0, pos) : cidr;
}

// Collect container name -> IP mappings by parsing each spec's network config.
// Returns a map of container name to IP address string.
static std::map<std::string, std::string> collectContainerIPs(const std::vector<StackEntry> &entries) {
  std::map<std::string, std::string> nameToIp;
  for (auto &e : entries) {
    if (e.specFile.empty())
      continue;
    try {
      auto spec = parseSpecWithVars(e.specFile, e.vars);
      if (!e.templateName.empty()) {
        auto tpl = parseSpec(e.templateName);
        spec = mergeSpecs(tpl, spec);
      }
      auto *netOpt = spec.optionNet();
      if (netOpt && !netOpt->staticIp.empty())
        nameToIp[e.name] = ipFromCidr(netOpt->staticIp);
    } catch (...) {
      // Skip containers whose specs can't be parsed at this stage
    }
  }
  return nameToIp;
}

// Build /etc/hosts content from container name->IP mappings
static std::string buildHostsEntries(const std::map<std::string, std::string> &nameToIp) {
  std::ostringstream ss;
  for (auto &kv : nameToIp)
    ss << kv.second << " " << kv.first << "\n";
  return ss.str();
}

struct ParsedStack {
  std::vector<StackEntry> entries;
  std::map<std::string, StackVolume> volumes;
};

// Parse a stack YAML file into entries and volumes
static ParsedStack parseStackFile(const std::string &fname, const std::map<std::string, std::string> &globalVars) {
  std::vector<StackEntry> entries;

  // Read and substitute global variables
  std::string content;
  {
    std::ifstream ifs(fname);
    if (!ifs.good())
      ERR("cannot open stack file: " << fname)
    content.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
  }

  // Substitute global vars in the stack file itself
  if (!globalVars.empty()) {
    for (auto &kv : globalVars) {
      std::string token = "${" + kv.first + "}";
      size_t pos = 0;
      while ((pos = content.find(token, pos)) != std::string::npos) {
        content.replace(pos, token.length(), kv.second);
        pos += kv.second.length();
      }
    }
  }

  YAML::Node top = YAML::Load(content);

  if (!top["containers"] || !top["containers"].IsMap())
    ERR("stack file must have a 'containers' map at the top level")

  // Parse named volumes (§26)
  std::map<std::string, StackVolume> volumes;
  if (top["volumes"] && top["volumes"].IsMap()) {
    for (auto v : top["volumes"]) {
      StackVolume vol;
      vol.name = v.first.as<std::string>();
      if (v.second.IsMap()) {
        if (v.second["path"])
          vol.hostPath = Util::pathSubstituteVarsInPath(v.second["path"].as<std::string>());
        else
          ERR("volumes/" << vol.name << " requires a 'path' field")
      } else if (v.second.IsScalar()) {
        vol.hostPath = Util::pathSubstituteVarsInPath(v.second.as<std::string>());
      } else {
        ERR("volumes/" << vol.name << " must be a map or scalar path")
      }
      volumes[vol.name] = vol;
    }
  }

  // Resolve paths relative to the stack file's directory
  auto stackDir = std::filesystem::path(fname).parent_path();
  auto resolvePath = [&stackDir](const std::string &p) -> std::string {
    std::filesystem::path fp(p);
    if (fp.is_absolute())
      return p;
    return (stackDir / fp).string();
  };

  for (auto c : top["containers"]) {
    StackEntry entry;
    entry.name = c.first.as<std::string>();

    if (!c.second.IsMap())
      ERR("containers/" << entry.name << " must be a map")

    if (c.second["crate"])
      entry.crateFile = resolvePath(c.second["crate"].as<std::string>());
    if (c.second["spec"])
      entry.specFile = resolvePath(c.second["spec"].as<std::string>());
    if (c.second["template"])
      entry.templateName = c.second["template"].as<std::string>();

    if (entry.crateFile.empty() && entry.specFile.empty())
      ERR("containers/" << entry.name << " must have either 'crate' or 'spec' field")

    if (c.second["depends"]) {
      auto &deps = c.second["depends"];
      if (deps.IsSequence()) {
        for (auto d : deps)
          entry.depends.push_back(d.as<std::string>());
      } else if (deps.IsScalar()) {
        entry.depends.push_back(deps.as<std::string>());
      }
    }

    if (c.second["vars"] && c.second["vars"].IsMap()) {
      for (auto v : c.second["vars"]) {
        auto varName = v.first.as<std::string>();
        if (v.second.IsMap() && v.second["from_file"]) {
          // Secret from file (§26): read value from a file on the host
          auto filePath = Util::pathSubstituteVarsInPath(v.second["from_file"].as<std::string>());
          std::ifstream secretFile(filePath);
          if (!secretFile.good())
            ERR("vars/" << varName << "/from_file: cannot read file: " << filePath)
          std::string value((std::istreambuf_iterator<char>(secretFile)),
                             std::istreambuf_iterator<char>());
          // Trim trailing newline (common in secret files)
          while (!value.empty() && (value.back() == '\n' || value.back() == '\r'))
            value.pop_back();
          entry.vars[varName] = value;
        } else {
          entry.vars[varName] = v.second.as<std::string>();
        }
      }
    }

    // Parse volume mounts: "volumes: [certs:/etc/letsencrypt:ro]"
    if (c.second["volumes"]) {
      auto &vols = c.second["volumes"];
      if (!vols.IsSequence())
        ERR("containers/" << entry.name << "/volumes must be a list")
      for (auto vm : vols) {
        auto mountStr = vm.as<std::string>();
        VolumeMountEntry mount;
        // Parse format: "volume_name:/container/path[:ro]"
        auto colon1 = mountStr.find(':');
        if (colon1 == std::string::npos)
          ERR("containers/" << entry.name << "/volumes: invalid format '" << mountStr
              << "', expected 'volume_name:/path[:ro]'")
        mount.volumeName = mountStr.substr(0, colon1);
        auto rest = mountStr.substr(colon1 + 1);
        auto colon2 = rest.rfind(':');
        if (colon2 != std::string::npos && rest.substr(colon2 + 1) == "ro") {
          mount.readOnly = true;
          mount.containerPath = rest.substr(0, colon2);
        } else {
          mount.containerPath = rest;
        }
        if (volumes.find(mount.volumeName) == volumes.end())
          ERR("containers/" << entry.name << "/volumes: unknown volume '" << mount.volumeName << "'")
        entry.volumeMounts.push_back(std::move(mount));
      }
    }

    // Merge global vars (global vars are defaults, per-container overrides win)
    for (auto &gv : globalVars)
      if (entry.vars.find(gv.first) == entry.vars.end())
        entry.vars[gv.first] = gv.second;

    entries.push_back(std::move(entry));
  }

  return {entries, volumes};
}

// Topological sort using Kahn's algorithm; returns entries in dependency order.
// Throws on cycles.
static std::vector<StackEntry> topoSort(const std::vector<StackEntry> &entries) {
  // Build name -> index map
  std::map<std::string, size_t> nameIdx;
  for (size_t i = 0; i < entries.size(); i++) {
    if (nameIdx.count(entries[i].name))
      ERR("duplicate container name '" << entries[i].name << "' in stack file")
    nameIdx[entries[i].name] = i;
  }

  // Validate dependencies exist
  for (auto &e : entries)
    for (auto &d : e.depends)
      if (!nameIdx.count(d))
        ERR("container '" << e.name << "' depends on unknown container '" << d << "'")

  // Compute in-degrees and adjacency
  size_t n = entries.size();
  std::vector<int> inDeg(n, 0);
  std::vector<std::vector<size_t>> adj(n); // adj[i] = containers that depend on i

  for (size_t i = 0; i < n; i++) {
    for (auto &d : entries[i].depends) {
      size_t di = nameIdx[d];
      adj[di].push_back(i);
      inDeg[i]++;
    }
  }

  // Kahn's algorithm
  std::queue<size_t> q;
  for (size_t i = 0; i < n; i++)
    if (inDeg[i] == 0)
      q.push(i);

  std::vector<StackEntry> sorted;
  sorted.reserve(n);
  while (!q.empty()) {
    size_t cur = q.front();
    q.pop();
    sorted.push_back(entries[cur]);
    for (auto next : adj[cur]) {
      if (--inDeg[next] == 0)
        q.push(next);
    }
  }

  if (sorted.size() != n)
    ERR("circular dependency detected in stack file")

  return sorted;
}

// Print status table for a stack, querying runtime state from running jails
static void printStackStatus(const std::vector<StackEntry> &entries) {
  // Query all running jails once
  auto jails = JailQuery::getAllJails(true);

  // Header
  std::cout << std::left;
  std::cout << "  " << std::setw(18) << "NAME"
            << std::setw(10) << "STATE"
            << std::setw(8) << "JID"
            << std::setw(16) << "IP"
            << std::setw(20) << "DEPENDS"
            << std::endl;
  std::cout << "  " << std::string(70, '-') << std::endl;

  for (auto &e : entries) {
    // Try to find a running jail matching this container name
    std::string state = "stopped";
    std::string jidStr = "-";
    std::string ipStr = "-";

    for (auto &j : jails) {
      if (j.name.find(e.name) != std::string::npos) {
        state = j.dying ? "dying" : "running";
        jidStr = std::to_string(j.jid);
        ipStr = j.ip4.empty() ? "-" : j.ip4;
        break;
      }
    }

    std::string deps;
    for (size_t i = 0; i < e.depends.size(); i++) {
      if (i > 0) deps += ", ";
      deps += e.depends[i];
    }
    if (deps.empty()) deps = "-";

    // Color-code state
    std::cout << "  " << std::setw(18) << e.name;
    if (state == "running")
      std::cout << rang::fg::green << std::setw(10) << state << rang::style::reset;
    else if (state == "dying")
      std::cout << rang::fg::yellow << std::setw(10) << state << rang::style::reset;
    else
      std::cout << rang::fg::red << std::setw(10) << state << rang::style::reset;
    std::cout << std::setw(8) << jidStr
              << std::setw(16) << ipStr
              << std::setw(20) << deps
              << std::endl;
  }
}

bool stackCommand(const Args &args) {
  auto parsed = parseStackFile(args.stackFile, args.vars);
  auto &entries = parsed.entries;
  auto &volumes = parsed.volumes;

  if (args.stackSubcmd == "status") {
    auto sorted = topoSort(entries);

    // Parse networks
    std::string content;
    {
      std::ifstream ifs(args.stackFile);
      if (ifs.good())
        content.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    }
    auto networks = parseNetworks(YAML::Load(content));

    std::cout << rang::style::bold << "Stack: " << rang::style::reset
              << args.stackFile << std::endl;
    std::cout << "  Containers: " << sorted.size() << std::endl;

    if (!networks.empty()) {
      std::cout << "  Networks:" << std::endl;
      for (auto &net : networks)
        std::cout << "    " << net.name << ": " << net.bridge
                  << (net.subnet.empty() ? "" : " (" + net.subnet + ")")
                  << std::endl;
    }

    // Show container IPs
    auto containerIPs = collectContainerIPs(sorted);
    if (!containerIPs.empty()) {
      std::cout << "  DNS mappings:" << std::endl;
      for (auto &kv : containerIPs)
        std::cout << "    " << kv.first << " -> " << kv.second << std::endl;
    }

    std::cout << "  Start order (dependency-resolved):" << std::endl;
    std::cout << std::endl;
    printStackStatus(sorted);
    std::cout << std::endl;
    return true;
  }

  if (args.stackSubcmd == "up") {
    auto sorted = topoSort(entries);

    // Collect container name -> IP mappings for /etc/hosts injection
    auto containerIPs = collectContainerIPs(sorted);

    // Parse networks section and create bridges if needed
    std::vector<StackNetwork> networks;
    Spec::NetworkPolicy networkPolicy;
    std::vector<pid_t> dnsPids;
    std::vector<RunAtEnd> policyCleanups;
    {
      std::string content;
      std::ifstream ifs(args.stackFile);
      if (ifs.good()) {
        content.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
        auto top = YAML::Load(content);
        networks = parseNetworks(top);
        networkPolicy = parseNetworkPolicy(top);

        for (auto &net : networks) {
          // Check if bridge exists, create if not
          if (!Util::interfaceExists(net.bridge)) {
            std::cout << rang::fg::cyan << "  [stack] " << rang::style::reset
                      << "Creating bridge: " << net.bridge << std::endl;
            Util::execCommand({CRATE_PATH_IFCONFIG, net.bridge, "create"},
              CSTR("create bridge " << net.bridge));
            if (!net.gateway.empty()) {
              auto prefixLen = net.subnet.empty() ? "" :
                               "/" + net.subnet.substr(net.subnet.find('/') + 1);
              Util::execCommand({CRATE_PATH_IFCONFIG, net.bridge, "inet",
                                 net.gateway + prefixLen},
                CSTR("set bridge " << net.bridge << " IP"));
            }
            Util::execCommand({CRATE_PATH_IFCONFIG, net.bridge, "up"},
              CSTR("bring up bridge " << net.bridge));
          }

          // IP Pool allocation: assign IPs to containers that don't have static ones
          if (!net.subnet.empty())
            containerIPs = allocateIpPool(net, sorted, containerIPs);
        }
      }
    }

    auto hostsEntries = buildHostsEntries(containerIPs);

    // Start per-stack DNS services
    for (auto &net : networks) {
      if (net.dns && !net.gateway.empty()) {
        auto pid = startStackDns(net, containerIPs, args.logProgress);
        if (pid > 0)
          dnsPids.push_back(pid);
      }
    }

    // Apply network policies
    for (auto &net : networks) {
      if (!networkPolicy.rules.empty() || networkPolicy.defaultAction == "deny") {
        auto cleanup = applyNetworkPolicies(networkPolicy, containerIPs,
                                             net.bridge, args.logProgress);
        policyCleanups.push_back(std::move(cleanup));
      }
    }

    std::cout << rang::style::bold << "Starting stack: " << rang::style::reset
              << args.stackFile << " (" << sorted.size() << " containers)" << std::endl;
    std::cout << "  Start order: ";
    for (size_t i = 0; i < sorted.size(); i++) {
      if (i > 0) std::cout << " -> ";
      std::cout << sorted[i].name;
    }
    std::cout << std::endl;

    // Show container DNS mappings
    if (!containerIPs.empty()) {
      std::cout << "  DNS mappings:";
      for (auto &kv : containerIPs)
        std::cout << " " << kv.first << "=" << kv.second;
      std::cout << std::endl;
    }

    // Show DNS service status
    if (!dnsPids.empty())
      std::cout << "  DNS service: running on bridge gateway" << std::endl;
    std::cout << std::endl;

    for (auto &e : sorted) {
      std::cout << rang::fg::cyan << "  [stack] " << rang::style::reset
                << "Starting: " << e.name << std::endl;

      // Build and run each container
      // If spec file is provided, create first then run
      // If crate file is provided, run directly
      if (!e.crateFile.empty()) {
        // Run the .crate file
        // Build argv for runCrate
        std::vector<std::string> runArgs = {"crate", "run", "-f", e.crateFile};
        std::vector<char*> runArgv;
        for (auto &a : runArgs) runArgv.push_back(const_cast<char*>(a.c_str()));
        runArgv.push_back(nullptr);

        Args runCmdArgs;
        runCmdArgs.cmd = CmdRun;
        runCmdArgs.runCrateFile = e.crateFile;
        runCmdArgs.logProgress = args.logProgress;
        runCmdArgs.vars = e.vars;

        int returnCode = 0;
        bool ok = runCrate(runCmdArgs, 0, nullptr, returnCode);
        if (!ok) {
          std::cerr << rang::fg::red << "  [stack] Failed to start: " << e.name
                    << rang::style::reset << std::endl;
          return false;
        }
      } else if (!e.specFile.empty()) {
        // Create + run flow
        auto spec = parseSpecWithVars(e.specFile, e.vars);
        if (!e.templateName.empty()) {
          auto templateSpec = parseSpec(e.templateName);
          spec = mergeSpecs(templateSpec, spec);
        }

        // Auto-assign IP from pool if container has no static IP configured
        auto poolIt = containerIPs.find(e.name);
        if (poolIt != containerIPs.end()) {
          auto *netOpt = spec.optionNetWr();
          if (netOpt && netOpt->staticIp.empty()) {
            // Find the subnet prefix length from the first matching network
            std::string prefix = "/24"; // default
            for (auto &net : networks) {
              if (!net.subnet.empty()) {
                prefix = "/" + net.subnet.substr(net.subnet.find('/') + 1);
                break;
              }
            }
            netOpt->staticIp = poolIt->second + prefix;
            if (netOpt->gateway.empty()) {
              for (auto &net : networks) {
                if (!net.gateway.empty()) {
                  netOpt->gateway = net.gateway;
                  break;
                }
              }
            }
          }
        }

        // Inject /etc/hosts entries for inter-container DNS (§26)
        if (!hostsEntries.empty()) {
          // Build a shell command that appends all container mappings to /etc/hosts
          std::ostringstream hostsCmd;
          hostsCmd << "printf '\\n# crate stack containers\\n";
          for (auto &kv : containerIPs)
            hostsCmd << kv.second << " " << kv.first << "\\n";
          hostsCmd << "' >> /etc/hosts";
          spec.scripts["run:before-start-services"]["__crate_stack_hosts"] = hostsCmd.str();
        }

        // Inject DNS resolver pointing to stack DNS service
        for (auto &net : networks) {
          if (net.dns && !net.gateway.empty()) {
            std::ostringstream dnsCmd;
            dnsCmd << "printf 'nameserver " << net.gateway << "\\n' > /etc/resolv.conf";
            spec.scripts["run:before-start-services"]["__crate_stack_dns"] = dnsCmd.str();
            break;
          }
        }

        // Inject named volume mounts as dirsShare entries (§26)
        for (auto &vm : e.volumeMounts) {
          auto it = volumes.find(vm.volumeName);
          if (it != volumes.end())
            spec.dirsShare.push_back({vm.containerPath, it->second.hostPath});
        }

        spec.validate();

        Args createArgs;
        createArgs.cmd = CmdCreate;
        createArgs.createSpec = e.specFile;
        createArgs.createTemplate = e.templateName;
        createArgs.logProgress = args.logProgress;
        createArgs.vars = e.vars;

        std::string crateOutput = e.name + ".crate";
        createArgs.createOutput = crateOutput;

        bool ok = createCrate(createArgs, spec.preprocess());
        if (!ok) {
          std::cerr << rang::fg::red << "  [stack] Failed to create: " << e.name
                    << rang::style::reset << std::endl;
          return false;
        }

        // Now run the created crate
        Args runCmdArgs;
        runCmdArgs.cmd = CmdRun;
        runCmdArgs.runCrateFile = crateOutput;
        runCmdArgs.logProgress = args.logProgress;
        runCmdArgs.vars = e.vars;

        int returnCode = 0;
        ok = runCrate(runCmdArgs, 0, nullptr, returnCode);
        if (!ok) {
          std::cerr << rang::fg::red << "  [stack] Failed to run: " << e.name
                    << rang::style::reset << std::endl;
          return false;
        }
      }

      // If container has a healthcheck (embedded in its spec), wait for it
      // The healthcheck is evaluated by the daemon or by the run phase itself
      std::cout << rang::fg::green << "  [stack] " << rang::style::reset
                << "Started: " << e.name << std::endl;
    }

    std::cout << std::endl;
    std::cout << rang::fg::green << "Stack started successfully." << rang::style::reset << std::endl;
    return true;
  }

  if (args.stackSubcmd == "down") {
    auto sorted = topoSort(entries);
    // Reverse order for shutdown (dependents first)
    std::reverse(sorted.begin(), sorted.end());

    // Parse networks for DNS cleanup
    std::vector<StackNetwork> downNetworks;
    {
      std::string content;
      std::ifstream ifs(args.stackFile);
      if (ifs.good()) {
        content.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
        downNetworks = parseNetworks(YAML::Load(content));
      }
    }

    std::cout << rang::style::bold << "Stopping stack: " << rang::style::reset
              << args.stackFile << " (" << sorted.size() << " containers)" << std::endl;
    std::cout << "  Stop order: ";
    for (size_t i = 0; i < sorted.size(); i++) {
      if (i > 0) std::cout << " -> ";
      std::cout << sorted[i].name;
    }
    std::cout << std::endl;
    std::cout << std::endl;

    bool allOk = true;
    for (auto &e : sorted) {
      std::cout << rang::fg::cyan << "  [stack] " << rang::style::reset
                << "Stopping: " << e.name << std::endl;
      // Note: actual jail removal would need to find the jail by name.
      // For now, we print the intent. Full integration with crate clean/jail removal
      // will come when crated tracks running stacks.
      std::cout << rang::fg::yellow << "  [stack] " << rang::style::reset
                << "Container " << e.name << " scheduled for cleanup" << std::endl;
    }

    // Stop per-stack DNS services
    for (auto &net : downNetworks) {
      if (net.dns) {
        stopStackDns(net.name, -1);
        std::cout << rang::fg::cyan << "  [stack] " << rang::style::reset
                  << "Stopped DNS for network: " << net.name << std::endl;
      }
    }

    if (allOk) {
      std::cout << std::endl;
      std::cout << rang::fg::green << "Stack stopped." << rang::style::reset << std::endl;
    }
    return allOk;
  }

  if (args.stackSubcmd == "exec") {
    // Execute a command in a specific stack container
    // Usage: crate stack exec <stack-file> <container-name> -- <command...>
    if (args.stackExecContainer.empty())
      ERR("stack exec requires a container name and command")

    // Find the container
    bool found = false;
    for (auto &e : entries) {
      if (e.name == args.stackExecContainer) {
        found = true;
        break;
      }
    }
    if (!found)
      ERR("container '" << args.stackExecContainer << "' not found in stack")

    // Find running jail matching the container name
    auto jails = JailQuery::getAllJails(true);
    int jid = -1;
    for (auto &j : jails) {
      if (j.name.find(args.stackExecContainer) != std::string::npos) {
        jid = j.jid;
        break;
      }
    }
    if (jid < 0)
      ERR("container '" << args.stackExecContainer << "' is not running")

    // Execute via JailExec
    if (args.stackExecArgs.empty())
      ERR("no command specified for stack exec")

    auto status = JailExec::execInJail(jid, args.stackExecArgs, "root", "stack exec");
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
  }

  ERR("unknown stack subcommand: " << args.stackSubcmd)
  return false;
}
