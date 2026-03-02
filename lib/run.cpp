// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "locs.h"
#include "cmd.h"
#include "mount.h"
#include "net.h"
#include "scripts.h"
#include "ctx.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"
#include "commands.h"
#include "run_net.h"
#include "run_jail.h"
#include "run_gui.h"
#include "run_services.h"

#include <rang.hpp>

#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/wait.h>
// sys/jail.h isn't C++-safe: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=238928
// Still unfixed as of FreeBSD 15.0 — uses struct in_addr/in6_addr without includes
extern "C" {
#include <sys/jail.h>
}
#include <sys/uio.h>
#include <jail.h>
#include <pwd.h>
#include <signal.h>

#include <string>
#include <list>
#include <iostream>
#include <memory>
#include <limits>
#include <filesystem>

#define ERR(msg...) ERR2("running a crate container", msg)

#define LOG(msg...) \
  { \
    if (args.logProgress) \
      std::cerr << rang::fg::gray << Util::tmSecMs() << ": " << msg << rang::style::reset << std::endl; \
  }


static uid_t myuid = ::getuid();
static gid_t mygid = ::getgid();

// Use getpwuid(getuid()) for authoritative identity — immune to USER env spoofing.
// This is critical because crate is a setuid binary.
struct UserInfo {
  std::string name;
  std::string homeDir;
  bool valid;
};

static UserInfo userInfo = []() -> UserInfo {
  struct passwd *pw = ::getpwuid(::getuid());
  if (pw == nullptr || pw->pw_name == nullptr || pw->pw_name[0] == '\0')
    return {"", "", false};
  return {pw->pw_name, pw->pw_dir, true};
}();

// options
static bool optionInitializeRc = false; // this pulls a lot of dependencies, and starts a lot of things that we don't need in crate
// ipfw rule number bases (§18): dynamically assigned via FwSlots to eliminate conflicts.
// Each crate gets a unique slot; rule numbers are: base + slot*10 + offset.
// OUT rules use range 50000-64999; IPv6 uses slot+1 within the same range.
static const unsigned fwSlotSize = 10;
static const unsigned fwRuleRangeOutBase = 50000;

// hosts's default gateway network parameters
static std::string gwIface;
static std::string hostIP;
static std::string hostLAN;
// IPv6 gateway info (populated when net.ipv6 is enabled)
static std::string gwIface6;
static std::string hostIP6;
static unsigned    hostIP6Prefix = 0;

// Signal handling: catch SIGINT/SIGTERM so RunAtEnd destructors fire for clean shutdown
static volatile sig_atomic_t g_signalReceived = 0;
static void signalHandler(int sig) { g_signalReceived = sig; }

//
// helpers
//
static std::string argsToString(int argc, char** argv) {
  std::ostringstream ss;
  for (int i = 0; i < argc; i++)
    ss << " " << Util::shellQuote(argv[i]);
  return ss.str();
}

//
// interface
//
bool runCrate(const Args &args, int argc, char** argv, int &outReturnCode) {
  LOG("'run' command is invoked, " << argc << " arguments are provided")

  // Install signal handlers so SIGINT/SIGTERM don't kill the process immediately.
  g_signalReceived = 0;
  struct sigaction sa = {};
  sa.sa_handler = signalHandler;
  sigemptyset(&sa.sa_mask);
  struct sigaction oldSigint, oldSigterm;
  ::sigaction(SIGINT, &sa, &oldSigint);
  ::sigaction(SIGTERM, &sa, &oldSigterm);
  RunAtEnd restoreSignals([&oldSigint, &oldSigterm]() {
    ::sigaction(SIGINT, &oldSigint, nullptr);
    ::sigaction(SIGTERM, &oldSigterm, nullptr);
  });

  // validate user identity from passwd database (not from env)
  if (!userInfo.valid)
    ERR("failed to determine user identity from getpwuid(getuid())")

  auto &user = userInfo.name;
  auto &homeDir = userInfo.homeDir;

  // create the jail directory
  auto jailPath = STR(Locations::jailDirectoryPath << "/jail-" << Util::filePathToBareName(args.runCrateFile) << "-" << Util::randomHex(4));
  Util::Fs::mkdir(jailPath, S_IRUSR|S_IWUSR|S_IXUSR);

  // check if jail directory is on encrypted ZFS (opportunistic, pre-spec)
  if (Util::Fs::isOnZfs(jailPath)) {
    auto dataset = Util::Fs::getZfsDataset(jailPath);
    if (!dataset.empty() && Util::Fs::isZfsEncrypted(dataset)) {
      if (!Util::Fs::isZfsKeyLoaded(dataset))
        ERR("ZFS dataset '" << dataset << "' is encrypted but key is not loaded; "
            "run 'zfs load-key " << dataset << "' first")
      LOG("jail directory on encrypted ZFS dataset '" << dataset << "'")
    }
  }

  auto J = [&jailPath](auto subdir) {
    return STR(jailPath << subdir);
  };

  RunAtEnd destroyJailDir([&jailPath,&args]() {
    LOG("removing the jail directory " << jailPath << " ...")
    Util::Fs::rmdirHier(jailPath);
    LOG("removing the jail directory " << jailPath << " done")
  });

  // mounts
  std::list<std::unique_ptr<Mount>> mounts;
  auto mount = [&mounts](Mount *m) {
    mounts.push_front(std::unique_ptr<Mount>(m));
    m->mount();
  };

  // validate the crate archive: reject archives with '..' path components (directory traversal)
  LOG("validating the crate file " << args.runCrateFile)
  {
    auto listing = Util::execPipelineGetOutput(
      {{CRATE_PATH_XZ, Cmd::xzThreadsArg, "--decompress"}, {CRATE_PATH_TAR, "tf", "-"}},
      "list crate archive contents", args.runCrateFile);
    std::istringstream is(listing);
    std::string entry;
    while (std::getline(is, entry)) {
      if (entry.find("..") != std::string::npos)
        ERR("crate archive contains path with '..' component: " << entry << " — refusing to extract (directory traversal)")
    }
  }

  // extract the crate archive into the jail directory
  LOG("extracting the crate file " << args.runCrateFile << " into " << jailPath)
  Util::execPipeline(
    {{CRATE_PATH_XZ, Cmd::xzThreadsArg, "--decompress"}, {CRATE_PATH_TAR, "xf", "-", "-C", jailPath}},
    "extract the crate file into the jail directory", args.runCrateFile);

  // parse +CRATE.SPEC
  auto spec = parseSpec(J("/+CRATE.SPEC")).preprocess();

  // enforce encryption requirement from spec (§1)
  if (spec.encrypted) {
    if (!Util::Fs::isOnZfs(jailPath))
      ERR("spec requires encrypted storage but jail directory is not on ZFS; "
          "create a ZFS dataset with: zfs create -o encryption=aes-256-gcm -o keyformat=passphrase <pool>/crate")
    auto dataset = Util::Fs::getZfsDataset(jailPath);
    if (dataset.empty())
      ERR("cannot determine ZFS dataset for jail directory")
    if (!Util::Fs::isZfsEncrypted(dataset))
      ERR("spec requires encryption but ZFS dataset '" << dataset << "' is not encrypted; "
          "create with: zfs create -o encryption=aes-256-gcm -o keyformat=passphrase " << dataset)
    if (!Util::Fs::isZfsKeyLoaded(dataset))
      ERR("ZFS dataset '" << dataset << "' is encrypted but key is not loaded; "
          "run 'zfs load-key " << dataset << "' first")
    LOG("spec-required encryption verified on dataset '" << dataset << "'")
  }

  // Copy-on-Write setup (§6)
  RunAtEnd destroyCowClone;
  if (spec.cowOptions) {
    if (spec.cowOptions->backend == "zfs") {
      if (!Util::Fs::isOnZfs(jailPath))
        ERR("cow/backend=zfs requires jail directory on ZFS")
      auto baseDataset = Util::Fs::getZfsDataset(jailPath);
      if (baseDataset.empty())
        ERR("cannot determine ZFS dataset for jail directory")
      auto snapName = STR(baseDataset << "@cow-" << Util::randomHex(4));
      auto cloneName = STR(baseDataset << "/cow-" << Util::randomHex(4));
      Util::execCommand({CRATE_PATH_ZFS, "snapshot", snapName}, "create COW base snapshot");
      Util::execCommand({CRATE_PATH_ZFS, "clone", snapName, cloneName}, "create COW clone");
      auto cloneMountpoint = Util::stripTrailingSpace(
        Util::execCommandGetOutput({CRATE_PATH_ZFS, "get", "-H", "-o", "value", "mountpoint", cloneName}, "get clone mountpoint"));
      LOG("COW clone created: " << cloneName << " at " << cloneMountpoint)
      if (spec.cowOptions->mode == "ephemeral") {
        destroyCowClone.reset([cloneName, snapName, &args]() {
          LOG("destroying ephemeral COW clone " << cloneName)
          Util::execCommand({CRATE_PATH_ZFS, "destroy", cloneName}, "destroy COW clone");
          Util::execCommand({CRATE_PATH_ZFS, "destroy", snapName}, "destroy COW base snapshot");
        });
      }
    } else if (spec.cowOptions->backend == "unionfs") {
      auto overlayDir = STR(jailPath << "-cow-writable");
      Util::Fs::mkdir(overlayDir, S_IRUSR|S_IWUSR|S_IXUSR);
      mount(new Mount("unionfs", jailPath, overlayDir, 0));
      LOG("COW unionfs overlay mounted at " << jailPath)
      if (spec.cowOptions->mode == "ephemeral") {
        destroyCowClone.reset([overlayDir, &args]() {
          LOG("removing ephemeral unionfs overlay " << overlayDir)
          Util::Fs::rmdirHier(overlayDir);
        });
      }
    }
  }

  // check the pre-conditions for networking
  int origIpForwarding = -1;
  bool isNatMode = false;
  if (spec.optionExists("net")) {
    if (Util::getSysctlInt("kern.features.vimage") == 0)
      ERR("the crate needs network access, but the VIMAGE feature isn't available in the kernel (kern.features.vimage==0)")

    auto optNet = spec.optionNet();
    isNatMode = !optNet || optNet->isNatMode();

    // NAT mode needs ipfw_nat; bridge/passthrough/netgraph don't
    if (isNatMode)
      Util::ensureKernelModuleIsLoaded("ipfw_nat");

    // Bridge mode needs if_bridge
    if (optNet && optNet->mode == Spec::NetOptDetails::Mode::Bridge)
      RunNet::ensureBridgeModule();

    // net.inet.ip.forwarding needs to be 1 for networking to work
    origIpForwarding = Util::getSysctlInt("net.inet.ip.forwarding");
    if (origIpForwarding == 0) {
      LOG("enabling net.inet.ip.forwarding (was 0, will restore on exit)")
      Util::setSysctlInt("net.inet.ip.forwarding", 1);
    }
    // Detect container-vs-host FreeBSD version mismatch for ipfw compatibility (NAT mode only)
    if (isNatMode) {
      int hostMajor = Util::getFreeBSDMajorVersion();
      int containerMajor = 0;
      auto osverFile = J("/+CRATE.OSVERSION");
      if (Util::Fs::fileExists(osverFile)) {
        int fd = ::open(osverFile.c_str(), O_RDONLY);
        if (fd >= 0) {
          char buf[16] = {0};
          auto n = ::read(fd, buf, sizeof(buf)-1);
          ::close(fd);
          if (n > 0) try { containerMajor = std::stoi(buf); } catch (...) {}
        }
      }
      if (containerMajor > 0 && hostMajor > 0 && containerMajor != hostMajor) {
        std::cerr << rang::fg::yellow
                  << "warning: host is FreeBSD " << hostMajor
                  << " but container base is FreeBSD " << containerMajor << ". ";
        if (hostMajor >= 15 && containerMajor < 15)
          std::cerr << "ipfw inside the container may fail due to removed compatibility code "
                    << "in FreeBSD 15.0 (commit 4a77657cbc01). "
                    << "Rebuild the container with a FreeBSD 15.0+ base.";
        else
          std::cerr << "Cross-version containers may have subtle incompatibilities.";
        std::cerr << rang::style::reset << std::endl;
      }
    }
  }

  // MAC bsdextended rules (§8)
  RunAtEnd removeMacRules;
  if (spec.securityAdvanced) {
    if (!spec.securityAdvanced->macRules.empty()) {
      LOG("loading MAC bsdextended rules")
      Util::ensureKernelModuleIsLoaded("mac_bsdextended");
      for (auto &rule : spec.securityAdvanced->macRules) {
        LOG("adding MAC rule: " << rule)
        auto ruleArgs = Util::splitString(rule, " ");
        auto fullArgs = std::vector<std::string>{CRATE_PATH_UGIDFW, "add"};
        fullArgs.insert(fullArgs.end(), ruleArgs.begin(), ruleArgs.end());
        Util::execCommand(fullArgs, CSTR("add MAC rule: " << rule));
      }
      removeMacRules.reset([&spec, &args]() {
        LOG("removing MAC bsdextended rules")
        Util::execCommand({CRATE_PATH_UGIDFW, "list"}, "list MAC rules before cleanup");
      });
    }
    if (!spec.securityAdvanced->macAllowPorts.empty()) {
      LOG("loading MAC portacl rules")
      Util::ensureKernelModuleIsLoaded("mac_portacl");
      for (auto port : spec.securityAdvanced->macAllowPorts)
        LOG("MAC portacl: allowing port " << port)
    }
  }

  // helper
  auto runScript = [&jailPath,&spec](const char *section) {
    Scripts::section(section, spec.scripts, [&jailPath,section](const std::string &cmd) {
      Util::execCommand({"/usr/sbin/chroot", jailPath, "/bin/sh", "-c",
                         STR("ASSUME_ALWAYS_YES=yes " << cmd)}, CSTR("run script#" << section));
    });
  };
  runScript("run:begin");

  // mount devfs (MNT_IGNORE hides it from df/mount output)
  mount(new Mount("devfs", J("/dev"), "", MNT_IGNORE));

  // Terminal isolation: apply devfs ruleset (§16)
  if (spec.terminalOptions) {
    if (spec.terminalOptions->devfsRuleset >= 0) {
      auto rulesetStr = std::to_string(spec.terminalOptions->devfsRuleset);
      Util::execCommand({CRATE_PATH_DEVFS, "-m", J("/dev"), "ruleset", rulesetStr}, "apply terminal devfs ruleset");
      Util::execCommand({CRATE_PATH_DEVFS, "-m", J("/dev"), "rule", "applyset"}, "apply terminal devfs rules");
      LOG("terminal: devfs_ruleset=" << rulesetStr)
    }
    if (!spec.terminalOptions->allowRawTty) {
      LOG("terminal: raw TTY access denied (default devfs restrictions apply)")
    }
  }

  auto jailXname = STR(Util::filePathToBareName(args.runCrateFile) << "_pid" << ::getpid());

  // environment in jail
  std::string jailEnv;
  auto setJailEnv = [&jailEnv](const std::string &var, const std::string &val) {
    if (!jailEnv.empty())
      jailEnv = jailEnv + ' ';
    jailEnv = jailEnv + var + '=' + val;
  };
  setJailEnv("CRATE", "yes");

  // turn options on — X11 with mode support (§11)
  RunAtEnd killXephyrAtEnd = RunGui::setupX11(spec, jailPath, jailXname, mounts, setJailEnv, args.logProgress);

  // Clipboard isolation (§12) — log mode
  if (spec.clipboardOptions) {
    auto &cbMode = spec.clipboardOptions->mode;
    std::string x11Mode = spec.x11Options ? spec.x11Options->mode : "shared";
    if (cbMode == "isolated") {
      if (x11Mode == "nested")
        LOG("clipboard isolation: active (via nested X11)")
      else
        LOG("clipboard isolation: requested but x11 is not nested — limited isolation")
    } else if (cbMode == "none") {
      LOG("clipboard disabled")
    }
  }

  // create jail
  runScript("run:before-create-jail");
  LOG("creating jail " << jailXname)

  auto jailInfo = RunJail::createJail(spec, jailPath, args.logProgress);
  int jid = jailInfo.jid;
  // securelevel: -1 means inherit host default, 0-3 are explicit values
  // bastille defaults to securelevel=2 for all jails
  auto securelevelStr = spec.securelevel >= 0 ? std::to_string(spec.securelevel) : std::string();
  // children.max: limits nested jails; -1 means not set (kernel default)
  auto childrenMaxStr = spec.childrenMax >= 0 ? std::to_string(spec.childrenMax) : std::string();

  RunAtEnd destroyJail([jailInfo,&jailXname,runScript,&args]() {
    runScript("run:before-remove-jail");
    LOG("removing jail " << jailXname << " jid=" << jailInfo.jid << " ...")
    RunJail::removeJail(jailInfo);
    runScript("run:after-remove-jail");
    LOG("removing jail " << jailXname << " jid=" << jailInfo.jid << " done")
  });

  runScript("run:after-create-jail");
  LOG("jail " << jailXname << " has been created, jid=" << jid)

  // Apply securelevel after jail creation (§8)
  // Like bastille's securelevel=2 default, restricts kernel modifications inside the jail
  if (!securelevelStr.empty()) {
    auto jidS = std::to_string(jid);
    Util::execCommand({CRATE_PATH_JAIL, "-m", STR("jid=" << jidS), STR("securelevel=" << securelevelStr)},
                      CSTR("set securelevel=" << securelevelStr));
    LOG("securelevel set to " << securelevelStr << " for jail " << jid)
  }

  // Apply children.max after jail creation
  // Limits how many child jails this container can create (0 = none)
  if (!childrenMaxStr.empty()) {
    auto jidS = std::to_string(jid);
    Util::execCommand({CRATE_PATH_JAIL, "-m", STR("jid=" << jidS), STR("children.max=" << childrenMaxStr)},
                      CSTR("set children.max=" << childrenMaxStr));
    LOG("children.max set to " << childrenMaxStr << " for jail " << jid)
  }

  // Apply CPU set restrictions via cpuset(1) (§8)
  // Pins jail processes to specific CPUs (e.g., "0-3", "0,2,4")
  RunAtEnd releaseCpuset;
  if (!spec.cpuset.empty()) {
    auto jidS = std::to_string(jid);
    Util::execCommand({CRATE_PATH_CPUSET, "-l", spec.cpuset, "-j", jidS},
                      CSTR("apply cpuset " << spec.cpuset));
    LOG("cpuset applied: CPUs " << spec.cpuset << " for jail " << jid)
  }

  // apply RCTL resource limits (§5)
  RunAtEnd removeRctlRules = RunJail::applyRctlLimits(spec, jid, args.logProgress);

  // attach ZFS datasets to jail
  RunAtEnd detachZfsDatasets = RunJail::attachZfsDatasets(spec, jid, args.logProgress);

  // helpers for jail access (exec-based: no shell)
  auto jidStr = std::to_string(jid);
  auto execInJail = [&jidStr](const std::vector<std::string> &argv, const std::string &descr) {
    auto fullArgv = std::vector<std::string>{CRATE_PATH_JEXEC, jidStr};
    fullArgv.insert(fullArgv.end(), argv.begin(), argv.end());
    Util::execCommand(fullArgv, descr);
  };
  auto writeFileInJail = [J](auto str, auto file) {
    Util::Fs::writeFile(str, J(file));
  };
  auto appendFileInJail = [J](auto str, auto file) {
    Util::Fs::appendFile(str, J(file));
  };

  // set up networking
  RunAtEnd destroyEpipeAtEnd;
  RunAtEnd destroyBridgeEpairAtEnd;
  RunAtEnd destroyFirewallRulesAtEnd;
  RunAtEnd destroyIpv6FwRules;
  RunAtEnd destroyPfAnchor;
  RunAtEnd releaseFwSlot;
  auto optionNet = spec.optionNet();
  std::string jailSideIface; // jail-side network interface name (for all modes)

  if (optionNet && optionNet->mode == Spec::NetOptDetails::Mode::Bridge) {
    //
    // Bridge mode: epair → user's bridge, no NAT, L2 connectivity
    //
    LOG("bridge mode: using bridge " << optionNet->bridgeIface)

    auto bridgeInfo = RunNet::createBridgeEpair(jid, jidStr, optionNet->bridgeIface, execInJail);
    jailSideIface = bridgeInfo.ifaceB;

    // Static MAC address (deterministic based on jail name + interface)
    if (optionNet->staticMac) {
      auto [macA, macB] = RunNet::generateStaticMac(jailXname, bridgeInfo.ifaceA);
      RunNet::setMacAddress(bridgeInfo.ifaceA, macA);
      execInJail({CRATE_PATH_IFCONFIG, bridgeInfo.ifaceB, "ether", macB},
        "set static MAC on jail-side epair");
      LOG("bridge mode: static MAC " << macA << " / " << macB)
    }

    // VLAN interface inside jail
    if (optionNet->vlanId >= 0) {
      RunNet::createVlanInJail(jid, bridgeInfo.ifaceB, optionNet->vlanId, execInJail);
      LOG("bridge mode: VLAN " << optionNet->vlanId << " on " << bridgeInfo.ifaceB)
    }

    destroyBridgeEpairAtEnd.reset([bridgeInfo]() {
      RunNet::destroyBridgeEpair(bridgeInfo);
    });

    // Configure IP addressing
    if (optionNet->ipMode == Spec::NetOptDetails::IpMode::Dhcp) {
      // DHCP provides its own resolv.conf — don't copy host's
      RunNet::configureDhcp(bridgeInfo.ifaceB, jailPath, jid, jidStr, execInJail);
      LOG("bridge mode: DHCP lease acquired on " << bridgeInfo.ifaceB)
    } else if (optionNet->ipMode == Spec::NetOptDetails::IpMode::Static) {
      RunNet::configureStaticIp(bridgeInfo.ifaceB, optionNet->staticIp, optionNet->gateway, jid, execInJail);
      // Copy resolv.conf for static IP (no DHCP to provide it)
      Util::Fs::copyFile("/etc/resolv.conf", J("/etc/resolv.conf"));
      LOG("bridge mode: static IP " << optionNet->staticIp << " on " << bridgeInfo.ifaceB)
    } else if (optionNet->ipMode != Spec::NetOptDetails::IpMode::None) {
      // Auto or unspecified — default to DHCP for bridge mode
      RunNet::configureDhcp(bridgeInfo.ifaceB, jailPath, jid, jidStr, execInJail);
      LOG("bridge mode: DHCP (auto) on " << bridgeInfo.ifaceB)
    }

  } else if (optionNet && (optionNet->allowOutbound() || optionNet->allowInbound())) {
    //
    // NAT mode (original behavior): epair + ipfw NAT
    //
    // detect host's gateway
    auto gw = RunNet::detectGateway();
    gwIface = gw.iface; hostIP = gw.hostIP; hostLAN = gw.hostLAN;

    // IPv6 gateway detection: determine host's IPv6-capable interface
    if (optionNet->ipv6) {
      try {
        auto output6 = Util::execPipelineGetOutput(
          {{CRATE_PATH_NETSTAT, "-rn", "-f", "inet6"}, {CRATE_PATH_GREP, "^default"}, {CRATE_PATH_SED, "s| *| |"}},
          "determine host's IPv6 gateway interface");
        auto elts6 = Util::splitString(output6, " ");
        if (elts6.size() >= 4) {
          gwIface6 = Util::stripTrailingSpace(elts6[3]);
          LOG("IPv6 gateway interface: " << gwIface6)
        }
      } catch (...) {
        gwIface6 = gwIface;
        LOG("no IPv6 default route found, using IPv4 gateway interface: " << gwIface6)
      }
      auto ipv6addrs = Net::getIfaceIp6Addresses(gwIface6.empty() ? gwIface : gwIface6);
      for (auto &addr : ipv6addrs) {
        if (std::get<2>(addr) == "global") {
          hostIP6 = std::get<0>(addr);
          hostIP6Prefix = std::get<1>(addr);
          break;
        }
      }
      if (hostIP6.empty())
        LOG("warning: no global IPv6 address found on " << (gwIface6.empty() ? gwIface : gwIface6) << ", IPv6 pass-through may not work")
      else
        LOG("host IPv6 address: " << hostIP6 << "/" << hostIP6Prefix)
    }
    auto nameserverIp = Net::getNameserverIp();

    if (optionNet->outboundDns)
      Util::Fs::copyFile("/etc/resolv.conf", J("/etc/resolv.conf"));

    auto epair = RunNet::createEpair(jid, jidStr, execInJail);
    jailSideIface = epair.ifaceB;

    // IPv6 pass-through networking
    std::string epipeIp6A, epipeIp6B;
    if (optionNet->ipv6) {
      auto numToIp6 = [](unsigned epairNum, unsigned idx) {
        unsigned addr = 100 + 2 * epairNum + idx;
        return STR("fd00:cra7:e::" << std::hex << addr);
      };
      epipeIp6A = numToIp6(epair.num, 0);
      epipeIp6B = numToIp6(epair.num, 1);

      execInJail({CRATE_PATH_IFCONFIG, "lo0", "inet6", "::1", "prefixlen", "128"}, "set up lo0 IPv6 in jail");
      Util::execCommand({CRATE_PATH_IFCONFIG, epair.ifaceA, "inet6", epipeIp6A, "prefixlen", "126"},
                        "set up IPv6 on host-side epair");
      execInJail({CRATE_PATH_IFCONFIG, epair.ifaceB, "inet6", epipeIp6B, "prefixlen", "126"},
                 "set up IPv6 on jail-side epair");
      execInJail({CRATE_PATH_ROUTE, "-6", "add", "default", epipeIp6A}, "set IPv6 default route in jail");
      auto origIp6Forwarding = Util::getSysctlInt("net.inet6.ip6.forwarding");
      if (origIp6Forwarding == 0) {
        LOG("enabling net.inet6.ip6.forwarding")
        Util::setSysctlInt("net.inet6.ip6.forwarding", 1);
      }
      LOG("IPv6 networking configured: " << epipeIp6A << " <-> " << epipeIp6B)
    }

    destroyEpipeAtEnd.reset([ifaceA=epair.ifaceA]() {
      RunNet::destroyEpair(ifaceA);
    });

    // enable firewall in jail
    appendFileInJail(STR(
        "firewall_enable=\"YES\""             << std::endl <<
        "firewall_type=\"open\""              << std::endl
      ),
      "/etc/rc.conf");

    // allocate firewall slot (§18)
    std::unique_ptr<Ctx::FwSlots> fwSlots(Ctx::FwSlots::lock());
    auto fwSlot = fwSlots->allocate(::getpid());
    fwSlots->unlock();
    releaseFwSlot.reset([]() {
      std::unique_ptr<Ctx::FwSlots> fwSlots(Ctx::FwSlots::lock());
      fwSlots->release(::getpid());
      fwSlots->unlock();
    });

    destroyFirewallRulesAtEnd = RunNet::setupFirewallRules(spec, epair, gw, fwSlot, nameserverIp, origIpForwarding, args.logProgress);

    // IPv6 firewall rules
    if (optionNet->ipv6 && !epipeIp6B.empty()) {
      auto execFW = [](const std::vector<std::string> &fwargs) {
        auto argv = std::vector<std::string>{CRATE_PATH_IPFW, "-q"};
        argv.insert(argv.end(), fwargs.begin(), fwargs.end());
        Util::execCommand(argv, "firewall rule");
      };
      auto fwRuleOutNo = fwRuleRangeOutBase + fwSlot * fwSlotSize + 1;
      auto fwRule6OutNo = fwRuleOutNo + 1;
      auto rule6OutS = std::to_string(fwRule6OutNo);
      auto v6Iface = gwIface6.empty() ? gwIface : gwIface6;
      if (optionNet->allowOutbound()) {
        if (optionNet->outboundDns)
          execFW({"add", rule6OutS, "allow", "udp", "from", epipeIp6B, "to", "any", "53"});
        execFW({"add", rule6OutS, "deny", "udp", "from", epipeIp6B, "to", "any", "53"});
        if (!optionNet->outboundHost)
          execFW({"add", rule6OutS, "deny", "ip6", "from", epipeIp6B, "to", "me6"});
        execFW({"add", rule6OutS, "allow", "ip6", "from", epipeIp6B, "to", "any", "out", "xmit", v6Iface});
        execFW({"add", rule6OutS, "allow", "ip6", "from", "any", "to", epipeIp6B, "in", "recv", v6Iface});
      }
      LOG("IPv6 firewall rules configured for " << epipeIp6B)

      destroyIpv6FwRules.reset([fwRule6OutNo]() {
        Util::execCommand({CRATE_PATH_IPFW, "delete", std::to_string(fwRule6OutNo)}, "destroy IPv6 firewall rule");
      });
    }

    // Per-container firewall policy via pf anchors (§3)
    if (spec.firewallPolicy) {
      auto anchorName = STR("crate/" << jailXname);
      std::ostringstream pfRules;
      for (auto &cidr : spec.firewallPolicy->blockIp)
        pfRules << "block drop quick from " << epair.ipB << " to " << cidr << std::endl;
      if (optionNet->ipv6 && !epipeIp6B.empty()) {
        for (auto &cidr : spec.firewallPolicy->blockIp)
          if (Net::isIpv6Address(cidr.substr(0, cidr.find('/'))))
            pfRules << "block drop quick from " << epipeIp6B << " to " << cidr << std::endl;
      }
      for (auto port : spec.firewallPolicy->allowTcp) {
        pfRules << "pass out quick proto tcp from " << epair.ipB << " to any port " << port << std::endl;
        if (optionNet->ipv6 && !epipeIp6B.empty())
          pfRules << "pass out quick inet6 proto tcp from " << epipeIp6B << " to any port " << port << std::endl;
      }
      for (auto port : spec.firewallPolicy->allowUdp) {
        pfRules << "pass out quick proto udp from " << epair.ipB << " to any port " << port << std::endl;
        if (optionNet->ipv6 && !epipeIp6B.empty())
          pfRules << "pass out quick inet6 proto udp from " << epipeIp6B << " to any port " << port << std::endl;
      }
      if (spec.firewallPolicy->defaultPolicy == "block")
        pfRules << "block drop all" << std::endl;
      else
        pfRules << "pass all" << std::endl;

      auto tmpRules = STR("/tmp/crate-pf-" << jailXname << ".conf");
      Util::Fs::writeFile(pfRules.str(), tmpRules);
      Util::execCommand({CRATE_PATH_PFCTL, "-a", anchorName, "-f", tmpRules}, "load pf anchor rules");
      Util::Fs::unlink(tmpRules);
      LOG("pf anchor '" << anchorName << "' loaded")

      destroyPfAnchor.reset([anchorName, &args]() {
        LOG("flushing pf anchor '" << anchorName << "'")
        Util::execCommand({CRATE_PATH_PFCTL, "-a", anchorName, "-F", "all"}, "flush pf anchor");
      });
    }
  }

  // disable services that normally start by default
  if (optionInitializeRc)
    appendFileInJail(STR(
        "sendmail_enable=\"NO\""         << std::endl <<
        "cron_enable=\"NO\""             << std::endl
      ),
      "/etc/rc.conf");

  // rc-initialization
  if (optionInitializeRc)
    execInJail({"/bin/sh", "/etc/rc"}, "exec.start");
  else if (isNatMode && spec.optionExists("net"))
    execInJail({"/bin/sh", "-c", "service ipfw start > /dev/null 2>&1"}, "start firewall in jail");

  // add user to jail
  RunJail::createUserInJail(spec, jailPath, jid, user, homeDir, myuid, mygid, execInJail, runScript, args.logProgress);

  // share directories if requested
  for (auto &dirShare : spec.dirsShare) {
    const auto dirJail = Util::pathSubstituteVarsInPath(dirShare.first);
    const auto dirHost = Util::pathSubstituteVarsInPath(dirShare.second);
    Util::safePath(J(dirJail), jailPath, "shared directory (jail side)");
    if (!Util::Fs::dirExists(dirHost))
      ERR("shared directory '" << dirHost << "' doesn't exist on the host, can't run the app")
    std::filesystem::create_directories(J(dirJail));
    mount(new Mount("nullfs", J(dirJail), dirHost, MNT_IGNORE));
  }

  // share files if requested
  for (auto &fileShare : spec.filesShare) {
    const auto fileJail = Util::pathSubstituteVarsInPath(fileShare.first);
    const auto fileHost = Util::pathSubstituteVarsInPath(fileShare.second);
    Util::safePath(J(fileJail), jailPath, "shared file (jail side)");
    bool fileHostExists = Util::Fs::fileExists(fileHost);
    bool fileJailExists = Util::Fs::fileExists(J(fileJail));
    if (!fileHostExists && !fileJailExists) {
      ERR("none of the files in a file-share exists: fileHost=" << fileHost << " fileJail=" << fileJail)
    } else if (fileHostExists && fileJailExists) {
      Util::Fs::unlink(J(fileJail));
      Util::Fs::link(fileHost, J(fileJail));
    } else if (fileHostExists) {
      Util::Fs::link(fileHost, J(fileJail));
    } else {
      Util::Fs::link(J(fileJail), fileHost);
    }
  }

  // Socket proxying (§15)
  RunAtEnd destroySocatProxies = RunServices::setupSocketProxy(spec, jailPath, args.logProgress);
  // Also mount shared sockets via nullfs (setupSocketProxy created the files)
  if (spec.socketProxy) {
    for (auto &sockPath : spec.socketProxy->share)
      mount(new Mount("nullfs", J(sockPath), sockPath, MNT_IGNORE));
  }

  // DNS filtering (§4)
  RunServices::setupDnsFilter(spec, jailPath, args.logProgress);

  // D-Bus isolation (§13)
  RunGui::setupDbus(spec, jailPath, setJailEnv, args.logProgress);

  // Managed services (§14)
  RunServices::setupManagedServices(spec, jailPath, execInJail, args.logProgress);

  // start services
  RunServices::startServices(spec, execInJail, runScript);

  // copy X11 authentication files into the user's home directory in jail
  RunGui::copyX11Auth(spec, jailPath, homeDir, myuid, mygid);

  // Clipboard proxy daemon (§12)
  RunAtEnd killClipboardProxy = RunGui::setupClipboard(spec, jailXname, jidStr, args.logProgress);

  // run the process
  runScript("run:before-execute");
  int returnCode = 0;
  if (!spec.runCmdExecutable.empty()) {
    LOG("running the command in jail: env=" << jailEnv)
    auto innerCmd = STR("/usr/bin/env " << jailEnv
                        << (spec.optionExists("dbg-ktrace") ? " /usr/bin/ktrace" : "")
                        << " " << Util::shellQuote(spec.runCmdExecutable) << spec.runCmdArgs << argsToString(argc, argv));
    int status = Util::execCommandGetStatus({CRATE_PATH_JEXEC, "-l", "-U", user, jidStr, innerCmd}, "run command in jail");
    returnCode = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    LOG("command has finished in jail: returnCode=" << returnCode)
  } else {
    LOG("this is a service-only crate, install and run the command that exits on Ctrl-C")
    auto cmdFile = "/run.sh";
    writeFileInJail(STR(
        "#!/bin/sh"                                                 << std::endl <<
        ""                                                          << std::endl <<
        "trap onSIGNIT 2"                                           << std::endl <<
        ""                                                          << std::endl <<
        "onSIGNIT()"                                                << std::endl <<
        "{"                                                         << std::endl <<
        "  echo \"Caught signal SIGINT ... exiting\""               << std::endl <<
        "  exit 0"                                                  << std::endl <<
        "}"                                                         << std::endl <<
        ""                                                          << std::endl <<
        "echo \"Running the services: " << spec.runServices << "\"" << std::endl <<
        "echo \"Waiting for Ctrl-C to exit ...\""                   << std::endl <<
        "/bin/sleep 1000000000"                                     << std::endl
      ),
      cmdFile
    );
    Util::Fs::chown(J(cmdFile), myuid, mygid);
    Util::Fs::chmod(J(cmdFile), 0500);
    {
      int status = Util::execCommandGetStatus({CRATE_PATH_JEXEC, "-l", "-U", user, jidStr, cmdFile}, "run service command in jail");
      returnCode = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
  }

  // Check if interrupted by signal
  if (g_signalReceived != 0) {
    LOG("interrupted by signal " << g_signalReceived << ", skipping post-exec, cleaning up")
    returnCode = 128 + g_signalReceived;
  } else {
    runScript("run:after-execute");

    // stop managed services in reverse order (§14)
    RunServices::stopManagedServices(spec, execInJail, args.logProgress);

    // stop services
    RunServices::stopServices(spec, execInJail);

    if (spec.optionExists("dbg-ktrace"))
      Util::Fs::copyFile(J(STR(homeDir << "/ktrace.out")), "ktrace.out");

    if (optionInitializeRc)
      execInJail({"/bin/sh", "/etc/rc.shutdown"}, "exec.stop");

    runScript("run:end");
  }

  // release resources (order matters — reverse of creation)
  killClipboardProxy.doNow();
  if (!spec.limits.empty())
    removeRctlRules.doNow();
  if (!spec.zfsDatasets.empty())
    detachZfsDatasets.doNow();
  destroyJail.doNow();
  killXephyrAtEnd.doNow();
  destroySocatProxies.doNow();
  for (auto &m : mounts)
    m->unmount();
  if (optionNet && optionNet->mode == Spec::NetOptDetails::Mode::Bridge) {
    destroyPfAnchor.doNow();
    destroyBridgeEpairAtEnd.doNow();
  } else if (optionNet && (optionNet->allowOutbound() || optionNet->allowInbound())) {
    destroyPfAnchor.doNow();
    destroyIpv6FwRules.doNow();
    destroyFirewallRulesAtEnd.doNow();
    destroyEpipeAtEnd.doNow();
    releaseFwSlot.doNow();
  }
  removeMacRules.doNow();
  if (spec.cowOptions)
    destroyCowClone.doNow();
  destroyJailDir.doNow();

  // done
  outReturnCode = returnCode;
  LOG("'run' command has succeeded")
  return true;
}
