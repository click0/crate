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
#include "privops_client.h"
#include "runtime_paths_pure.h"
#include "stack_pure.h"
#include "stack_spec.h"  // 1.1.68: the member spec is composed at the YAML level
#include "status_fd.h"   // 1.1.65: detached `crate run --status-fd`

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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>   // 1.1.51: /dev/null for the detached supervisor
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <cstdlib>   // 1.1.68: mkdtemp for the composed member specs
#include <string.h>

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
  std::string templateName;     // optional template (a name or a path, see resolveTemplate)
  std::string stackDir;         // directory of the stack file (template lookup)
  std::vector<std::string> depends;  // names of dependencies
  std::map<std::string, std::string> vars;  // per-container variable overrides
  std::vector<VolumeMountEntry> volumeMounts;  // named volume mounts
};

// 1.1.51: start a container as a detached `crate run -f` child instead of
// calling runCrate() in-process. runCrate() is the jail's foreground
// supervisor and returns only when the jail exits — so a service-only
// first container meant the second was never started. The child is
// spawned like daemon/routes.cpp (setsid, stdio to /dev/null).
// 1.1.65: over a `--status-fd` pipe (StatusFd::spawnCrateRun); we then
// read its lifecycle stream until `jail_created` instead of polling
// jls(8) for a "<name>_pid<pid>" jail, so `depends:` ordering still
// means "the previous one is up" and a run that fails says why.
static StatusFd::Spawned spawnCrateRunDetached(const std::string &crateFile,
                                               const std::map<std::string, std::string> &vars,
                                               bool logProgress) {
  std::vector<std::string> argv;
  if (logProgress) argv.push_back("--log-progress");
  for (auto &kv : vars) { argv.push_back("--var"); argv.push_back(kv.first + "=" + kv.second); }
  argv.push_back("-f");
  argv.push_back(crateFile);
  return StatusFd::spawnCrateRun(argv);
}

// Wait up to `timeoutSec` for the jail of the container started as `s`
// to be created. False (with the reason in `why`) when the run ended or
// failed first, the child died, or the time ran out.
static bool waitForStackJail(const StatusFd::Spawned &s, unsigned timeoutSec, std::string &why) {
  StatusPure::Event ev;
  auto w = StatusFd::waitForJail(s.statusFd, s.pid, timeoutSec, ev);
  why = StatusFd::describe(w, ev);
  return w == StatusFd::Wait::JailCreated;
}

// Parse networks section from a stack YAML
static std::vector<StackNetwork> parseNetworks(const YAML::Node &top) {
  std::vector<StackNetwork> networks;
  if (!top["networks"] || !top["networks"].IsMap())
    return networks;
  for (auto n : top["networks"]) {
    StackNetwork net;
    net.name = n.first.as<std::string>();
    // 1.1.25: the network name becomes the `dns-<name>` config directory
    // that startStackDns create_directories/writes and stopStackDns
    // remove_all's as root — reject '/' and '..' (path traversal) and
    // shell/quote chars before it goes anywhere.
    if (auto e = StackPure::validateStackName(net.name); !e.empty())
      ERR("networks/" << net.name << ": " << e)
    if (!n.second.IsMap())
      ERR("networks/" << net.name << " must be a map")
    if (n.second["bridge"])
      net.bridge = n.second["bridge"].as<std::string>();
    else
      ERR("networks/" << net.name << " requires 'bridge' field")
    if (n.second["subnet"]) {
      net.subnet = n.second["subnet"].as<std::string>();
      // 1.1.45: a subnet without "/N" used to pass here and blow up
      // after the bridge was already created (find('/')+1 == 0 → the
      // whole subnet appended to the gateway).
      uint32_t base = 0; unsigned plen = 0;
      if (!StackPure::parseCidr(net.subnet, base, plen))
        ERR("networks/" << net.name << "/subnet: '" << net.subnet << "' is not an IPv4 CIDR (a.b.c.d/N)")
    }
    if (n.second["gateway"]) {
      net.gateway = n.second["gateway"].as<std::string>();
      // 1.1.25: the gateway is interpolated into a `printf 'nameserver …'`
      // shell fragment run as root — must be a bare IP literal.
      if (auto e = StackPure::validateStackIp(net.gateway); !e.empty())
        ERR("networks/" << net.name << "/gateway: " << e)
    }
    if (n.second["dns"])
      net.dns = n.second["dns"].as<bool>();
    if (n.second["ip_range"])
      net.ipRange = n.second["ip_range"].as<std::string>();
    networks.push_back(std::move(net));
  }
  return networks;
}

// --- IP Pool Allocator (§27.3) ---

// parseCidr, ipToString moved to lib/stack_pure.cpp; forward to keep
// existing call sites unchanged.
static inline bool parseCidr(const std::string &cidr, uint32_t &baseAddr, unsigned &prefixLen) {
  return StackPure::parseCidr(cidr, baseAddr, prefixLen);
}
static inline std::string ipToString(uint32_t ip) { return StackPure::ipToString(ip); }

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
    ERR("invalid CIDR subnet '" << network.subnet << "' in network '" << network.name << "'")
  if (prefixLen < 8 || prefixLen > 30)
    ERR("invalid prefix length " << prefixLen << " in network '" << network.name
        << "': must be between 8 and 30")

  // Determine pool start/end
  uint32_t poolStart, poolEnd;
  if (!network.ipRange.empty()) {
    auto dashPos = network.ipRange.find('-');
    if (dashPos != std::string::npos) {
      struct in_addr s, e;
      // 1.1.51: a malformed ip_range used to leave s/e uninitialised.
      if (inet_pton(AF_INET, network.ipRange.substr(0, dashPos).c_str(), &s) != 1 ||
          inet_pton(AF_INET, network.ipRange.substr(dashPos + 1).c_str(), &e) != 1)
        ERR("networks/" << network.name << "/ip_range '" << network.ipRange
            << "' must be a.b.c.d-a.b.c.d")
      poolStart = ntohl(s.s_addr);
      poolEnd = ntohl(e.s_addr);
      if (poolStart > poolEnd)
        ERR("networks/" << network.name << "/ip_range '" << network.ipRange << "' is reversed")
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
    // 1.1.45: a prebuilt `crate:` entry runs with the network its own
    // spec carries — the stack cannot inject an address into it. It
    // used to get a pool IP anyway, which only ever reached unbound and
    // /etc/hosts: every other container resolved the name to an address
    // nothing listened on.
    if (!e.crateFile.empty()) {
      WARN("stack network '" << network.name << "': container '" << e.name
           << "' is a prebuilt .crate — no pool IP assigned; it is not in stack DNS/hosts "
           "unless its own spec sets a static ip")
      continue;
    }

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

// Resolve the base directory for per-stack unbound config + pidfile.
// Legacy: /var/run/crate (shared across operators).
// Rootless (1.0.3+): /var/run/crate/<uid> when crated's privops socket
// is detected, so two operators on the same host don't fight over
// the same dns-<network> subdir or pidfile path.
static const std::string &dnsBaseDir() {
  static std::string cached;
  static bool computed = false;
  if (!computed) {
    if (!PrivOpsClient::detectSocketPath().empty())
      cached = RuntimePathsPure::perUserRoot((uint32_t)::getuid());
    else
      cached = "/var/run/crate";
    computed = true;
  }
  return cached;
}

// Generate unbound configuration for a stack's DNS service
static std::string generateUnboundConf(
    const std::string &listenIp,
    const std::string &subnet,
    const std::map<std::string, std::string> &nameToIp,
    const std::string &upstreamDns,
    const std::string &networkName = "") {

  std::ostringstream conf;
  conf << "server:\n";
  conf << "  interface: " << listenIp << "\n";
  conf << "  port: 53\n";
  // 1.1.26: run in the foreground. With `do-daemonize: yes` the process
  // we fork()ed was only the short-lived launcher: it exited within ms,
  // so the 200ms liveness check in startStackDns saw "exited
  // immediately" on SUCCESS, the returned pid never pointed at unbound,
  // and nothing could stop it. Now our child IS unbound (setsid'd in
  // startStackDns); `down` stops it via the pidfile below.
  conf << "  do-daemonize: no\n";
  // Use per-stack pidfile to avoid clashes when multiple stacks run DNS
  if (!networkName.empty())
    conf << "  pidfile: \"" << dnsBaseDir() << "/dns-" << networkName << "/unbound.pid\"\n";
  else
    conf << "  pidfile: \"" << dnsBaseDir() << "/dns-default/unbound.pid\"\n";
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

  auto confDir = STR(dnsBaseDir() << "/dns-" << network.name);
  std::filesystem::create_directories(confDir);

  auto confPath = STR(confDir << "/unbound.conf");
  auto conf = generateUnboundConf(network.gateway, network.subnet, nameToIp, upstreamDns, network.name);
  Util::Fs::writeFile(conf, confPath);

  if (logProgress)
    std::cerr << rang::fg::gray << "starting stack DNS on " << network.gateway
              << " for network '" << network.name << "' ("
              << nameToIp.size() << " records)" << rang::style::reset << std::endl;

  pid_t pid = ::fork();
  if (pid == 0) {
    // 1.1.26: own session so unbound (now foreground, see the conf)
    // survives `crate stack up` exiting / the terminal hanging up. It
    // logs to syslog and never uses stdio, so stdio is left as-is.
    ::setsid();
    ::execl(CRATE_PATH_UNBOUND, "unbound", "-c", confPath.c_str(), nullptr);
    ::_exit(127);
  }
  if (pid < 0)
    ERR("failed to fork unbound for stack DNS: " << strerror(errno))

  // Brief wait to verify unbound didn't exit immediately (e.g. config error)
  ::usleep(200000); // 200ms
  int status;
  pid_t ret = ::waitpid(pid, &status, WNOHANG);
  if (ret > 0) {
    // Child already exited — unbound failed to start
    WARN("stack DNS (unbound) for network '" << network.name
         << "' exited immediately ("
         << (WIFEXITED(status) ? "status=" + std::to_string(WEXITSTATUS(status))
             : WIFSIGNALED(status) ? "signal=" + std::to_string(WTERMSIG(status))
             : std::string("unknown wait status")) << ")")
    return -1;
  }

  return pid;
}

// Stop the per-stack unbound DNS service
static void stopStackDns(const std::string &networkName, pid_t unboundPid) {
  auto confDir = STR(dnsBaseDir() << "/dns-" << networkName);
  // 1.1.26: `stack down` runs in a DIFFERENT process from `stack up`, so
  // the pid `up` got from fork() is unavailable here (the caller passes
  // -1) — and under the old `do-daemonize: yes` that pid was the
  // short-lived launcher anyway, never unbound itself. Net effect: DNS
  // was NEVER stopped; an orphan unbound stayed bound to <gateway>:53
  // and the next `up` failed to bind ("exited immediately"). Read the
  // pidfile unbound writes into confDir (set in generateUnboundConf)
  // and signal that; fall back to the passed pid.
  pid_t target = -1;
  {
    std::ifstream pf(confDir + "/unbound.pid");
    long v = 0;
    if ((pf >> v) && v > 1) target = static_cast<pid_t>(v);
  }
  if (target <= 1) target = unboundPid;
  if (target > 1) {
    ::kill(target, SIGTERM);
    // Not our child when called from `down` — reap only if it is.
    int status;
    ::waitpid(target, &status, WNOHANG);
  }
  // Clean up config directory
  std::filesystem::remove_all(confDir);
}

// --- Network Policies (§27.2) ---

// Parse network_policy section from a stack YAML
static Spec::NetworkPolicy parseNetworkPolicy(const YAML::Node &top) {
  Spec::NetworkPolicy policy;
  if (!top["network_policy"] || !top["network_policy"].IsMap())
    return policy;

  auto np = top["network_policy"];
  if (np["default"])
    policy.defaultAction = np["default"].as<std::string>();

  if (np["rules"] && np["rules"].IsSequence()) {
    for (auto r : np["rules"]) {
      Spec::NetworkPolicyRule rule;
      if (r["from"]) rule.from = r["from"].as<std::string>();
      if (r["to"])   rule.to = r["to"].as<std::string>();
      if (r["action"]) {
        rule.action = r["action"].as<std::string>();
        if (rule.action != "allow" && rule.action != "deny")
          ERR("network_policy rule: invalid action '" << rule.action
              << "', must be 'allow' or 'deny'")
      }
      if (r["proto"]) {
        rule.proto = r["proto"].as<std::string>();
        if (rule.proto != "tcp" && rule.proto != "udp")
          ERR("network_policy rule: invalid proto '" << rule.proto
              << "', must be 'tcp' or 'udp'")
      }
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
// When default policy is "deny", also blocks traffic from other stacks' subnets
// (otherStackSubnets) to enforce inter-stack network isolation -- containers in
// one stack cannot reach containers in another stack's subnet unless explicitly allowed.
// Returns cleanup callback that removes the rules on stack teardown.
static RunAtEnd applyNetworkPolicies(
    const Spec::NetworkPolicy &policy,
    const std::map<std::string, std::string> &nameToIp,
    const std::string &bridgeIface,
    bool logProgress,
    const std::vector<std::string> &otherStackSubnets = {}) {

  if (policy.rules.empty() && policy.defaultAction == "allow")
    return RunAtEnd();

  // Use a high rule number range for stack policies: 30000-39999.
  // 1.1.45: the block is chosen from the LIVE rule list, not from a
  // per-process counter (which restarted at 30000 in every `stack up`,
  // so two stacks shared numbers and one's cleanup deleted the other's).
  unsigned slotBase = 0;
  try {
    auto listing = Util::execCommandGetOutput({CRATE_PATH_IPFW, "list"}, "ipfw list");
    slotBase = StackPure::freePolicySlot(StackPure::ipfwRuleNumbers(listing));
  } catch (const std::exception &e) {
    ERR("network_policy: cannot read the ipfw rule list to pick a free slot: " << e.what())
  }
  if (slotBase == 0)
    ERR("network_policy: no free 100-rule block in 30000..39999 — run `crate stack down` "
        "for stacks that are gone, or `ipfw list` and clean up by hand")

  // Host ipfw only sees bridged (L2) traffic when the bridge hands it
  // to the firewall; otherwise every `via bridgeN` rule below is dead.
  try {
    if (Util::getSysctlInt("net.link.bridge.ipfw") == 0) {
      if (logProgress)
        std::cerr << rang::fg::gray
                  << "network policy: enabling net.link.bridge.ipfw=1 (bridge traffic through ipfw)"
                  << rang::style::reset << std::endl;
      Util::setSysctlInt("net.link.bridge.ipfw", 1);
    }
  } catch (const std::exception &e) {
    WARN("network_policy: could not set net.link.bridge.ipfw=1: " << e.what()
         << " — policy rules may not see jail<->jail traffic")
  }

  // Rules already added are cleaned up even if a later addRule throws
  // (the RunAtEnd used to be built only after the loop).
  auto addedRules = std::make_shared<std::vector<unsigned>>();
  RunAtEnd cleanup([addedRules]() {
    for (auto r : *addedRules) {
      try { IpfwOps::deleteRule(r); } catch (...) {}
    }
  });
  unsigned ruleNum = slotBase;

  // Apply explicit rules first
  for (auto &rule : policy.rules) {
    auto fromIt = nameToIp.find(rule.from);
    auto toIt = nameToIp.find(rule.to);
    if (fromIt == nameToIp.end()) {
      WARN("network_policy rule: 'from' container '" << rule.from
           << "' not found in stack, skipping rule")
      continue;
    }
    if (toIt == nameToIp.end()) {
      WARN("network_policy rule: 'to' container '" << rule.to
           << "' not found in stack, skipping rule")
      continue;
    }

    for (auto port : rule.ports) {
      auto ruleStr = STR(rule.action << " " << rule.proto
                         << " from " << fromIt->second
                         << " to " << toIt->second << " " << port
                         << " via " << bridgeIface);
      IpfwOps::addRule(ruleNum, ruleStr);
      addedRules->push_back(ruleNum);
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
      addedRules->push_back(ruleNum);
      ruleNum++;
    }

    // Inter-stack isolation: block traffic from other stacks' subnets into this bridge.
    // This prevents containers in foreign stacks from reaching our containers even if
    // they share a common host network path.
    for (auto &foreignSubnet : otherStackSubnets) {
      auto ruleStr = STR("deny ip from " << foreignSubnet << " to any via " << bridgeIface);
      IpfwOps::addRule(ruleNum, ruleStr);
      addedRules->push_back(ruleNum);
      ruleNum++;
      if (logProgress)
        std::cerr << rang::fg::gray << "network policy: blocking foreign subnet "
                  << foreignSubnet << " on " << bridgeIface
                  << rang::style::reset << std::endl;
    }

    if (logProgress)
      std::cerr << rang::fg::gray << "network policy: default deny on "
                << bridgeIface << rang::style::reset << std::endl;
  }

  return cleanup;
}

// ipFromCidr moved to lib/stack_pure.cpp
static inline std::string ipFromCidr(const std::string &cidr) { return StackPure::ipFromCidr(cidr); }

// 1.1.68: `containers/<name>/template` used to be opened as given, i.e.
// relative to the current directory, although crate.5 shows a template
// NAME there (`template: web-base`). Resolve it the way `crate create
// --template` does (StackPure::templateCandidates): a path is relative
// to the stack file like `spec:`, a name is searched in the template
// directories.
static std::string resolveTemplate(const StackEntry &e) {
  const auto candidates = StackPure::templateCandidates(e.templateName, e.stackDir,
                                                        Util::Fs::getUserHomeDir());
  for (auto &c : candidates)
    if (Util::Fs::fileExists(c)) return c;
  std::ostringstream searched;
  for (size_t i = 0; i < candidates.size(); i++) searched << (i ? ", " : "") << candidates[i];
  ERR("containers/" << e.name << ": template '" << e.templateName << "' not found (searched "
      << searched.str() << ")")
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
        auto tpl = parseSpec(resolveTemplate(e));
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

// buildHostsEntries moved to lib/stack_pure.cpp
static inline std::string buildHostsEntries(const std::map<std::string, std::string> &nameToIp) {
  return StackPure::buildHostsEntries(nameToIp);
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
    // 1.1.25: the container name is interpolated into a `printf '…' >>
    // /etc/hosts` shell fragment run via `sh -c` as root — reject
    // quotes/metachars/newlines before it can close the quote.
    if (auto e = StackPure::validateStackName(entry.name); !e.empty())
      ERR("containers/" << entry.name << ": " << e)

    if (!c.second.IsMap())
      ERR("containers/" << entry.name << " must be a map")

    if (c.second["crate"])
      entry.crateFile = resolvePath(c.second["crate"].as<std::string>());
    if (c.second["spec"])
      entry.specFile = resolvePath(c.second["spec"].as<std::string>());
    if (c.second["template"])
      entry.templateName = c.second["template"].as<std::string>();
    entry.stackDir = stackDir.string();

    if (entry.crateFile.empty() && entry.specFile.empty())
      ERR("containers/" << entry.name << " must have either 'crate' or 'spec' field")

    if (c.second["depends"]) {
      auto deps = c.second["depends"];
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
      auto vols = c.second["volumes"];
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

// Topological sort delegated to StackPure::topoSort<StackEntry>
// (template lives in lib/stack_pure.h; works for any T with .name + .depends).
static inline std::vector<StackEntry> topoSort(const std::vector<StackEntry> &entries) {
  return StackPure::topoSort(entries);
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
      if (StackPure::jailNameMatchesContainer(j.name, e.name)) {   // 1.1.45: exact, not substring
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

  // 1.1.56: `stack up`/`down` create bridges, start the stack resolver on
  // :53 and write /etc/hosts inside the jails as root — the stack path is
  // root-only today (TODO §1). Refuse up front with the reason instead of
  // failing on the first privileged step with half a stack running.
  if ((args.stackSubcmd == "up" || args.stackSubcmd == "down") && ::geteuid() != 0)
    ERR("stack " << args.stackSubcmd << " needs root: it creates bridges, runs the "
        "stack DNS resolver and edits /etc/hosts inside the containers "
        "(rootless stacks are tracked in TODO §1)")

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
        // 1.1.45: the other networks of this stack are the "foreign"
        // subnets a default-deny bridge must not accept traffic from
        // (the parameter was never passed, so the isolation was dead code).
        std::vector<std::string> otherSubnets;
        for (auto &o : networks)
          if (&o != &net && !o.subnet.empty()) otherSubnets.push_back(o.subnet);
        auto cleanup = applyNetworkPolicies(networkPolicy, containerIPs,
                                             net.bridge, args.logProgress, otherSubnets);
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

    // 1.1.68: the composed member specs (template + stack injections) are
    // written to a private directory and handed to createCrate as the
    // spec FILE, because that file — not the parsed Spec — is what
    // becomes +CRATE.SPEC and what the detached `crate run -f` reads.
    struct SpecDir {
      std::string path;
      ~SpecDir() { if (!path.empty()) { try { Util::Fs::rmdirHier(path); } catch (...) {} } }
      const std::string &get() {
        if (path.empty()) {
          char tmpl[] = "/tmp/crate-stack-XXXXXX";
          if (::mkdtemp(tmpl) == nullptr)
            ERR("mkdtemp for the stack's member specs: " << strerror(errno))
          path = tmpl;
        }
        return path;
      }
    } specDir;

    for (auto &e : sorted) {
      std::cout << rang::fg::cyan << "  [stack] " << rang::style::reset
                << "Starting: " << e.name << std::endl;

      // Build and run each container
      // If spec file is provided, create first then run
      // If crate file is provided, run directly
      if (!e.crateFile.empty()) {
        // Run the .crate file as a detached supervisor
        auto s = spawnCrateRunDetached(e.crateFile, e.vars, args.logProgress);
        std::string why = "fork failed";
        if (s.pid < 0 || !waitForStackJail(s, 120, why)) {
          std::cerr << rang::fg::red << "  [stack] Failed to start: " << e.name << " — " << why
                    << rang::style::reset << std::endl;
          return false;
        }
      } else if (!e.specFile.empty()) {
        // Create + run flow. 1.1.68: everything the stack adds is composed
        // at the YAML level (StackSpec::compose) and written to a file;
        // until now it was applied to the parsed Spec only, and createCrate
        // copied e.specFile into +CRATE.SPEC verbatim, so the template, the
        // pool address, the hosts/DNS scripts and the named volumes never
        // reached the detached `crate run -f` — the member ran its bare
        // spec. `${VAR}` stays as text in the file: the run gets the vars
        // with --var and substitutes them itself.
        StackSpec::Injections inj;

        // Auto-assign IP from pool if container has no static IP configured
        auto poolIt = containerIPs.find(e.name);
        if (poolIt != containerIPs.end()) {
          std::vector<std::string> subnets;
          for (auto &net : networks) subnets.push_back(net.subnet);
          inj.ipCidr = StackPure::poolCidr(poolIt->second, subnets);
          for (auto &net : networks)
            if (!net.gateway.empty()) { inj.gateway = net.gateway; break; }
        }

        // Inject /etc/hosts entries for inter-container DNS (§26). 1.1.25:
        // sink-guard — every name/IP is re-validated at the point it enters
        // a `sh -c` string (StackPure::hostsCommand).
        if (!hostsEntries.empty()) {
          std::string err;
          inj.hostsCmd = StackPure::hostsCommand(containerIPs, err);
          if (!err.empty()) ERR(err)
        }

        // Inject DNS resolver pointing to stack DNS service
        for (auto &net : networks) {
          if (net.dns && !net.gateway.empty()) {
            std::string err;
            inj.dnsCmd = StackPure::dnsCommand(net.gateway, err);
            if (!err.empty()) ERR("network '" << net.name << "': " << err)
            break;
          }
        }

        // Inject named volume mounts as dirs/share entries (§26)
        for (auto &vm : e.volumeMounts) {
          auto it = volumes.find(vm.volumeName);
          if (it != volumes.end())
            inj.shares.push_back({vm.containerPath, it->second.hostPath, vm.readOnly});   // 1.1.63: :ro reaches the mount
        }

        YAML::Node specNode, tplNode;
        try {
          specNode = YAML::LoadFile(e.specFile);
        } catch (const YAML::Exception &ex) {
          ERR("containers/" << e.name << ": cannot parse " << e.specFile << ": " << ex.what())
        }
        std::string templatePath;
        if (!e.templateName.empty()) {
          templatePath = resolveTemplate(e);
          try {
            tplNode = YAML::LoadFile(templatePath);
          } catch (const YAML::Exception &ex) {
            ERR("containers/" << e.name << ": cannot parse template " << templatePath << ": " << ex.what())
          }
        }
        const auto memberSpec = specDir.get() + "/" + e.name + ".yml";
        {
          std::ostringstream header;
          header << "# generated by crate stack up from " << e.specFile;
          if (!templatePath.empty()) header << " + template " << templatePath;
          header << "\n# do not edit: change the stack or spec file and run again";
          StackSpec::writeSpec(StackSpec::compose(specNode, tplNode, inj), memberSpec, header.str());
        }
        if (args.logProgress)
          std::cerr << rang::fg::gray << Util::tmSecMs() << ": [stack] " << e.name
                    << ": composed spec at " << memberSpec << rang::style::reset << std::endl;

        auto spec = parseSpecWithVars(memberSpec, e.vars);
        spec.validate();

        Args createArgs;
        createArgs.cmd = CmdCreate;
        createArgs.createSpec = memberSpec;
        createArgs.createTemplate = templatePath;
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

        // Now run the created crate (detached supervisor, 1.1.51)
        auto s = spawnCrateRunDetached(crateOutput, e.vars, args.logProgress);
        std::string why = "fork failed";
        if (s.pid < 0 || !waitForStackJail(s, 120, why)) {
          std::cerr << rang::fg::red << "  [stack] Failed to run: " << e.name << " — " << why
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
    // 1.1.45: actually stop the containers (this printed "scheduled for
    // cleanup" and did nothing). Each entry's jail is "<name>_pid<N>";
    // stopCrate signals it, waits, force-destroys on timeout, and the
    // supervisor's RunAtEnd chain cleans up behind it.
    {
      auto jails = JailQuery::getAllJails(true);
      for (auto &e : sorted) {
        std::cout << rang::fg::cyan << "  [stack] " << rang::style::reset
                  << "Stopping: " << e.name << std::endl;
        bool any = false;
        for (auto &j : jails) {
          if (!StackPure::jailNameMatchesContainer(j.name, e.name)) continue;
          any = true;
          Args stopArgs;
          stopArgs.cmd = CmdStop;
          stopArgs.stopTarget = j.name;
          try {
            if (!stopCrate(stopArgs)) {
              std::cerr << rang::fg::red << "  [stack] stop returned failure for " << j.name
                        << rang::style::reset << std::endl;
              allOk = false;
            }
          } catch (const std::exception &ex) {
            std::cerr << rang::fg::red << "  [stack] stop failed for " << j.name << ": "
                      << ex.what() << rang::style::reset << std::endl;
            allOk = false;
          }
        }
        if (!any)
          std::cout << rang::fg::gray << "  [stack] " << rang::style::reset
                    << e.name << " is not running" << std::endl;
      }
    }

    // 1.1.45: network_policy rules of this stack's bridges. They are
    // deleted by `stack up`'s own exit path, but a killed `stack up`
    // (or one from a previous boot's layout) leaves them behind.
    for (auto &net : downNetworks) {
      if (net.bridge.empty()) continue;
      try {
        auto listing = Util::execCommandGetOutput({CRATE_PATH_IPFW, "list"}, "ipfw list");
        for (auto r : StackPure::policyRulesForBridge(listing, net.bridge)) {
          try { IpfwOps::deleteRule(r); } catch (...) {}
          std::cout << rang::fg::cyan << "  [stack] " << rang::style::reset
                    << "Removed network_policy rule " << r << " (via " << net.bridge << ")" << std::endl;
        }
      } catch (const std::exception &ex) {
        std::cerr << rang::fg::yellow << "  [stack] could not read ipfw rules for "
                  << net.bridge << ": " << ex.what() << rang::style::reset << std::endl;
      }
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
      // 1.1.45: exact "<name>_pid<N>" match — a substring search made
      // `stack exec db` run the command (as root) in jail "mydb_pid…".
      if (StackPure::jailNameMatchesContainer(j.name, args.stackExecContainer)) {
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
