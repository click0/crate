// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "args.h"
#include "spec.h"
#include "locs.h"
#include "cmd.h"
#include "mount.h"
#include "net.h"
#include "scripts.h"
#include "ctx.h"
#include "util.h"
#include "err.h"
#include "commands.h"

#include <rang.hpp>

#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/param.h>
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
static unsigned fwRuleBaseIn = 19000;  // ipfw rule number base for in rules: in rules should be before out rules because of rule conflicts
static unsigned fwRuleBaseOut = 59000; // ipfw rule number base TODO Need to investigate how to eliminate rule conflicts.

// hosts's default gateway network parameters
static std::string gwIface;
static std::string hostIP;
static std::string hostLAN;

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
  // Instead, set a flag and let RunAtEnd destructors clean up jail/mount/firewall/epair.
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

  // variables
  int res;

  // create the jail directory
  auto jailPath = STR(Locations::jailDirectoryPath << "/jail-" << Util::filePathToBareName(args.runCrateFile) << "-" << Util::randomHex(4));
  Util::Fs::mkdir(jailPath, S_IRUSR|S_IWUSR|S_IXUSR);

  // check if jail directory is on encrypted ZFS
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
    // remove the jail directory
    LOG("removing the jail directory " << jailPath << " ...")
    Util::Fs::rmdirHier(jailPath);
    LOG("removing the jail directory " << jailPath << " done")
  });

  // mounts
  std::list<std::unique_ptr<Mount>> mounts;
  auto mount = [&mounts](Mount *m) {
    mounts.push_front(std::unique_ptr<Mount>(m)); // push_front so that the last added is also the last removed
    m->mount();
  };

  // validate the crate archive: reject archives with '..' path components (directory traversal)
  LOG("validating the crate file " << args.runCrateFile)
  {
    auto listing = Util::execPipelineGetOutput(
      {{"xz", Cmd::xzThreadsArg, "--decompress"}, {"tar", "tf", "-"}},
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
    {{"xz", Cmd::xzThreadsArg, "--decompress"}, {"tar", "xf", "-", "-C", jailPath}},
    "extract the crate file into the jail directory", args.runCrateFile);

  // parse +CRATE.SPEC
  auto spec = parseSpec(J("/+CRATE.SPEC")).preprocess();

  // check the pre-conditions
  int origIpForwarding = -1; // -1 = not modified; 0 = was off and we turned it on
  if (spec.optionExists("net")) {
    // we need to create vnet jails
    if (Util::getSysctlInt("kern.features.vimage") == 0)
      ERR("the crate needs network access, but the VIMAGE feature isn't available in the kernel (kern.features.vimage==0)")
    // ipfw needs the ipfw_nat kernel module in order to function
    Util::ensureKernelModuleIsLoaded("ipfw_nat");
    // net.inet.ip.forwarding needs to be 1 for networking to work
    // Save original value so we can restore it when the last crate exits.
    // NOTE: on FreeBSD 15.0+ this can be pre-set in /boot/loader.conf: net.inet.ip.forwarding=1
    origIpForwarding = Util::getSysctlInt("net.inet.ip.forwarding");
    if (origIpForwarding == 0) {
      LOG("enabling net.inet.ip.forwarding (was 0, will restore on exit)")
      Util::setSysctlInt("net.inet.ip.forwarding", 1);
    }
    // warn about ipfw binary incompatibility on FreeBSD 15.0+
    if (Util::getFreeBSDMajorVersion() >= 15)
      std::cerr << rang::fg::yellow
                << "warning: FreeBSD " << Util::getSysctlString("kern.osrelease") << " detected. "
                << "Containers created on FreeBSD <15.0 may have ipfw binary incompatibility. "
                << "Rebuild containers with a FreeBSD 15.0+ base if networking fails."
                << rang::style::reset << std::endl;
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

  auto jailXname = STR(Util::filePathToBareName(args.runCrateFile) << "_pid" << ::getpid());

  // environment in jail
  std::string jailEnv;
  auto setJailEnv = [&jailEnv](auto var, auto val) {
    if (!jailEnv.empty())
      jailEnv = jailEnv + ' ';
    jailEnv = jailEnv + var + '=' + val;
  };
  setJailEnv("CRATE", "yes"); // let the app know that it runs from the crate. CAVEAT if you remove this, the env(1) command below needs to be removed when there is no env

  // turn options on
  if (spec.optionExists("x11")) {
    LOG("x11 option is requested: mount the X11 socket in jail")
    // create the X11 socket directory (sticky bit like standard /tmp/.X11-unix)
    Util::Fs::mkdir(J("/tmp/.X11-unix"), 01777);
    // mount the X11 socket directory in jail
    mount(new Mount("nullfs", J("/tmp/.X11-unix"), "/tmp/.X11-unix", MNT_IGNORE));
    // DISPLAY variable copied to jail
    auto *display = ::getenv("DISPLAY");
    if (display == nullptr)
      ERR("DISPLAY environment variable is not set")
    setJailEnv("DISPLAY", display);
  }

  // create jail // also see https://www.cyberciti.biz/faq/how-to-configure-a-freebsd-jail-with-vnet-and-zfs/
  runScript("run:before-create-jail");
  LOG("creating jail " << jailXname)
  const char *optNet = spec.optionExists("net") ? "true" : "false";
  const bool hasZfsDatasets = !spec.zfsDatasets.empty();
  const char *optZfsMount = hasZfsDatasets ? "true" : "false";
  const char *optEnforceStatfs = hasZfsDatasets ? "1" : "2";
  int jid;
  int jailFd = -1; // jail descriptor for race-free removal (FreeBSD 15.0+)
#ifdef JAIL_OWN_DESC
  if (Util::getFreeBSDMajorVersion() >= 15) {
    // Use owning jail descriptor: eliminates TOCTOU race in jail_remove(),
    // and auto-removes jail if crate crashes (kernel closes the owning fd)
    char descBuf[32] = {0};
    res = ::jail_setv(JAIL_CREATE | JAIL_OWN_DESC,
      "path", jailPath.c_str(),
      "host.hostname", Util::gethostname().c_str(),
      "persist", nullptr,
      "allow.raw_sockets", optNet, // allow ping-pong
      "allow.socket_af", optNet,
      "allow.mount", optZfsMount,
      "allow.mount.zfs", optZfsMount,
      "enforce_statfs", optEnforceStatfs,
      "vnet", nullptr/*"new"*/, // possible values are: nullptr, { "disable", "new", "inherit" }, see lib/libjail/jail.c
      "desc", descBuf,
      nullptr);
    if (res == -1)
      ERR("failed to create jail: " << jail_errmsg)
    jid = res;
    jailFd = std::atoi(descBuf);
    LOG("jail descriptor fd=" << jailFd)
  } else
#endif
  {
    res = ::jail_setv(JAIL_CREATE,
      "path", jailPath.c_str(),
      "host.hostname", Util::gethostname().c_str(),
      "persist", nullptr,
      "allow.raw_sockets", optNet, // allow ping-pong
      "allow.socket_af", optNet,
      "allow.mount", optZfsMount,
      "allow.mount.zfs", optZfsMount,
      "enforce_statfs", optEnforceStatfs,
      "vnet", nullptr/*"new"*/, // possible values are: nullptr, { "disable", "new", "inherit" }, see lib/libjail/jail.c
      nullptr);
    if (res == -1)
      ERR("failed to create jail: " << jail_errmsg)
    jid = res;
  }

  RunAtEnd destroyJail([jid,jailFd,&jailXname,runScript,&args]() {
    (void)jailFd; // used only when JAIL_OWN_DESC is defined
    // stop and remove jail
    runScript("run:before-remove-jail");
    LOG("removing jail " << jailXname << " jid=" << jid << " ...")
#ifdef JAIL_OWN_DESC
    if (jailFd >= 0) {
      // Race-free removal via jail descriptor
      if (::jail_remove_jd(jailFd) == -1)
        ERR("failed to remove jail: " << strerror(errno))
      ::close(jailFd);
    } else
#endif
    {
      if (::jail_remove(jid) == -1)
        ERR("failed to remove jail: " << strerror(errno))
    }
    runScript("run:after-remove-jail");
    LOG("removing jail " << jailXname << " jid=" << jid << " done")
  });

  runScript("run:after-create-jail");
  LOG("jail " << jailXname << " has been created, jid=" << jid)

  // attach ZFS datasets to jail
  RunAtEnd detachZfsDatasets;
  if (hasZfsDatasets) {
    auto jidStr = std::to_string(jid);
    for (auto &dataset : spec.zfsDatasets) {
      LOG("attaching ZFS dataset " << dataset << " to jail " << jid)
      Util::execCommand({"zfs", "jail", jidStr, dataset},
        CSTR("attach ZFS dataset " << dataset));
    }
    detachZfsDatasets.reset([&spec, jid, &args]() {
      auto jidStr = std::to_string(jid);
      for (auto &dataset : Util::reverseVector(spec.zfsDatasets)) {
        LOG("detaching ZFS dataset " << dataset << " from jail " << jid)
        Util::execCommand({"zfs", "unjail", jidStr, dataset},
          CSTR("detach ZFS dataset " << dataset));
      }
    });
  }

  // helpers for jail access (exec-based: no shell)
  auto jidStr = std::to_string(jid);
  auto execInJail = [&jidStr](const std::vector<std::string> &argv, const std::string &descr) {
    auto fullArgv = std::vector<std::string>{"jexec", jidStr};
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
  RunAtEnd destroyFirewallRulesAtEnd;
  auto optionNet = spec.optionNet();
  if (optionNet && (optionNet->allowOutbound() || optionNet->allowInbound())) {
    { // determine host's gateway interface
      auto elts = Util::splitString(
                    Util::execPipelineGetOutput(
                      {{"netstat", "-rn"}, {"grep", "^default"}, {"sed", "s| *| |"}},
                      "determine host's gateway interface"),
                    " "
                  );
      if (elts.size() != 4)
        ERR("Unable to determine host's gateway IP and interface");
      elts[3] = Util::stripTrailingSpace(elts[3]);
      gwIface = elts[3];
    }
    { // determine host's gateway interface IP and network
      auto ipv4 = Net::getIfaceIp4Addresses(gwIface);
      if (ipv4.empty())
        ERR("Failed to determine host's gateway interface IP: no IPv4 addresses found")
      hostIP  = std::get<0>(ipv4[0]);
      hostLAN = std::get<2>(ipv4[0]);
    }
    // determine the hosts's nameserver
    auto nameserverIp = Net::getNameserverIp();
    // copy /etc/resolv.conf into jail
    if (optionNet->outboundDns)
      Util::Fs::copyFile("/etc/resolv.conf", J("/etc/resolv.conf"));
    // create the epipe
    // set the lo0 IP address (lo0 is always automatically present in vnet jails)
    execInJail({"ifconfig", "lo0", "inet", "127.0.0.1"}, "set up the lo0 interface in jail");
    // create networking interface
    std::string epipeIfaceA = Util::stripTrailingSpace(Util::execCommandGetOutput({"ifconfig", "epair", "create"}, "create the jail epipe"));
    std::string epipeIfaceB = STR(epipeIfaceA.substr(0, epipeIfaceA.size()-1) << "b"); // jail side
    unsigned epairNum = std::stoul(epipeIfaceA.substr(5/*skip epair*/, epipeIfaceA.size()-5-1));
    auto numToIp = [](unsigned epairNum, unsigned ipIdx2) {
      // XXX use 10.0.0.0/8 network for this purpose because number of containers can be large, and we need to have that many IP addresses available
      unsigned ip = 100 + 2*epairNum + ipIdx2; // 100 to avoid the addresses .0 and .1
      unsigned ip1 = ip % 256;
      ip /= 256;
      unsigned ip2 = ip % 256;
      ip /= 256;
      unsigned ip3 = ip;
      return STR("10." << ip3 << "." << ip2 << "." << ip1);
    };
    auto epipeIpA = numToIp(epairNum, 0), epipeIpB = numToIp(epairNum, 1);
    // disable checksum offload on epair interfaces to work around FreeBSD 15.0 bug
    // where packets between jails/host get dropped due to uncomputed checksums
    Util::execCommand({"ifconfig", epipeIfaceA, "-txcsum", "-txcsum6"}, "disable checksum offload on epair (host side)");
    Util::execCommand({"ifconfig", epipeIfaceB, "-txcsum", "-txcsum6"}, "disable checksum offload on epair (jail side)");
    // transfer the interface into jail
    Util::execCommand({"ifconfig", epipeIfaceB, "vnet", jidStr}, "transfer the network interface into jail");
    // set the IP addresses on the jail epipe
    execInJail({"ifconfig", epipeIfaceB, "inet", epipeIpB, "netmask", "0xfffffffe"}, "set up IP jail epipe addresses");
    Util::execCommand({"ifconfig", epipeIfaceA, "inet", epipeIpA, "netmask", "0xfffffffe"}, "set up IP jail epipe addresses");
    // enable firewall in jail
    //if (optionInitializeRc)
      appendFileInJail(STR(
          "firewall_enable=\"YES\""             << std::endl <<
          "firewall_type=\"open\""              << std::endl
        ),
        "/etc/rc.conf");
    // set default route in jail
    execInJail({"route", "add", "default", epipeIpA}, "set default route in jail");
    // destroy the epipe when finished
    destroyEpipeAtEnd.reset([epipeIfaceA]() {
      Util::execCommand({"ifconfig", epipeIfaceA, "destroy"}, CSTR("destroy the jail epipe (" << epipeIfaceA << ")"));
    });
    // add firewall rules to NAT and route packets from jails to host's default GW
    {
      // exec-based ipfw wrapper: no shell, argv array passed directly
      auto execFW = [](const std::vector<std::string> &fwargs) {
        auto argv = std::vector<std::string>{"ipfw", "-q"};
        argv.insert(argv.end(), fwargs.begin(), fwargs.end());
        Util::execCommand(argv, "firewall rule");
      };
      auto fwRuleInNo  = fwRuleBaseIn + 1/*common rules*/ + epairNum/*per-crate rules*/;
      auto fwNatInNo = fwRuleInNo;
      auto fwNatOutCommonNo = fwRuleBaseOut;
      auto fwRuleOutCommonNo = fwRuleBaseOut;
      auto fwRuleOutNo = fwRuleBaseOut + 1/*common rules*/ + epairNum/*per-crate rules*/;

      auto ruleInS  = std::to_string(fwRuleInNo);
      auto natInS   = std::to_string(fwNatInNo);
      auto ruleOutS = std::to_string(fwRuleOutNo);
      auto ruleOutCommonS = std::to_string(fwRuleOutCommonNo);
      auto natOutCommonS  = std::to_string(fwNatOutCommonNo);

      // IN rules for this epipe
      if (optionNet->allowInbound()) {
        // create the NAT instance
        auto rangeToStr = [](const Spec::NetOptDetails::PortRange &range) {
          return range.first == range.second ? STR(range.first) : STR(range.first << "-" << range.second);
        };
        // build nat config argv incrementally
        std::vector<std::string> natConfig = {"nat", natInS, "config"};
        for (auto &rangePair : optionNet->inboundPortsTcp) {
          natConfig.insert(natConfig.end(), {"redirect_port", "tcp",
            epipeIpB + ":" + rangeToStr(rangePair.second),
            hostIP + ":" + rangeToStr(rangePair.first)});
        }
        for (auto &rangePair : optionNet->inboundPortsUdp) {
          natConfig.insert(natConfig.end(), {"redirect_port", "udp",
            epipeIpB + ":" + rangeToStr(rangePair.second),
            hostIP + ":" + rangeToStr(rangePair.first)});
        }
        execFW(natConfig);
        // create firewall rules: one per port range
        for (auto &rangePair : optionNet->inboundPortsTcp) {
          execFW({"add", ruleInS, "nat", natInS, "tcp", "from", "any", "to", hostIP, rangeToStr(rangePair.first), "in", "recv", gwIface});
          execFW({"add", ruleInS, "nat", natInS, "tcp", "from", epipeIpB, rangeToStr(rangePair.second), "to", "any", "out", "xmit", gwIface});
        }
        for (auto &rangePair : optionNet->inboundPortsUdp) {
          execFW({"add", ruleInS, "nat", natInS, "udp", "from", "any", "to", hostIP, rangeToStr(rangePair.first), "in", "recv", gwIface});
          execFW({"add", ruleInS, "nat", natInS, "udp", "from", epipeIpB, rangeToStr(rangePair.second), "to", "any", "out", "xmit", gwIface});
        }
      }

      // OUT common rules
      if (optionNet->allowOutbound()) {
        std::unique_ptr<Ctx::FwUsers> fwUsers(Ctx::FwUsers::lock());
        if (fwUsers->isEmpty()) {
          execFW({"nat", natOutCommonS, "config", "ip", hostIP});
          execFW({"add", ruleOutCommonS, "nat", natOutCommonS, "all", "from", "any", "to", hostIP, "in", "recv", gwIface});
        }
        fwUsers->add(::getpid());
        fwUsers->unlock();
      }

      // OUT per-epipe rules: 1. whitewashes, 2. bans, 3. nats
      if (optionNet->allowOutbound()) {
        // allow DNS requests if required
        if (optionNet->outboundDns) {
          execFW({"add", ruleOutS, "nat", natOutCommonS, "udp", "from", epipeIpB, "to", nameserverIp, "53", "out", "xmit", gwIface});
          execFW({"add", ruleOutS, "allow", "udp", "from", epipeIpB, "to", nameserverIp, "53"});
        }
        execFW({"add", ruleOutS, "deny", "udp", "from", epipeIpB, "to", "any", "53"});
        // bans
        if (!optionNet->outboundHost)
          execFW({"add", ruleOutS, "deny", "ip", "from", epipeIpB, "to", "me"});
        if (!optionNet->outboundLan)
          execFW({"add", ruleOutS, "deny", "ip", "from", epipeIpB, "to", hostLAN});
        // nat the rest of the traffic
        execFW({"add", ruleOutS, "nat", natOutCommonS, "all", "from", epipeIpB, "to", "any", "out", "xmit", gwIface});
      }
      // destroy rules
      destroyFirewallRulesAtEnd.reset([fwRuleInNo, fwRuleOutNo, fwRuleOutCommonNo, optionNet, origIpForwarding, &args]() {
        auto ruleInS  = std::to_string(fwRuleInNo);
        auto ruleOutS = std::to_string(fwRuleOutNo);
        auto ruleOutCommonS = std::to_string(fwRuleOutCommonNo);
        // delete the rule(s) for this epipe
        if (optionNet->allowInbound())
          Util::execCommand({"ipfw", "delete", ruleInS}, "destroy firewall rule");
        if (optionNet->allowOutbound()) {
          Util::execCommand({"ipfw", "delete", ruleOutS}, "destroy firewall rule");
          { // possibly delete the common rules if this is the last firewall
            std::unique_ptr<Ctx::FwUsers> fwUsers(Ctx::FwUsers::lock());
            fwUsers->del(::getpid());
            if (fwUsers->isEmpty()) {
              Util::execCommand({"ipfw", "delete", ruleOutCommonS}, "destroy firewall rule");
              // restore ip.forwarding to its original value if we changed it
              if (origIpForwarding == 0) {
                LOG("restoring net.inet.ip.forwarding to 0")
                Util::setSysctlInt("net.inet.ip.forwarding", 0);
              }
            }
            fwUsers->unlock();
          }
        }
      });
    }
  }

  // disable services that normally start by default, but aren't desirable in crates
  if (optionInitializeRc)
    appendFileInJail(STR(
        "sendmail_enable=\"NO\""         << std::endl <<
        "cron_enable=\"NO\""             << std::endl
      ),
      "/etc/rc.conf");

  // rc-initializion (is this really needed?) This depends on the executables /bin/kenv, /sbin/sysctl, /bin/date which need to be kept during the 'create' phase
  if (optionInitializeRc)
    execInJail({"/bin/sh", "/etc/rc"}, "exec.start");
  else
    execInJail({"/bin/sh", "-c", "service ipfw start > /dev/null 2>&1"}, "start firewall in jail");

  // add the same user to jail, make group=user for now
  {
    LOG("create user's home directory " << homeDir << ", uid=" << myuid << " gid=" << mygid)
    Util::Fs::mkdir(J("/home"), 0755);
    Util::Fs::mkdir(J(homeDir), 0755);
    Util::Fs::chown(J(homeDir), myuid, mygid);
    runScript("run:before-create-users");
    LOG("add group " << user << " in jail")
    execInJail({"/usr/sbin/pw", "groupadd", user, "-g", std::to_string(mygid)}, "add the group in jail");
    LOG("add user " << user << " in jail")
    execInJail({"/usr/sbin/pw", "useradd", user, "-u", std::to_string(myuid), "-g", std::to_string(mygid), "-s", "/bin/sh", "-d", homeDir}, "add the user in jail");
    execInJail({"/usr/sbin/pw", "usermod", user, "-G", "wheel"}, "add the group to the user");
    // Verify group membership — setgroups(2)/getgroups(2) behavior changed in FreeBSD 15.0:
    // effective group ID is no longer included in the supplemental groups array
    LOG("verify user " << user << " group membership")
    execInJail({"/usr/bin/id", user}, "verify user group membership");
    // "video" option requires the corresponding user/group: create the identical user/group to jail
    if (spec.optionExists("video")) {
      static const char *devName = "/dev/video";
      static unsigned devNameLen = ::strlen(devName);
      uid_t videoUid = std::numeric_limits<uid_t>::max();
      gid_t videoGid = std::numeric_limits<gid_t>::max();
      for (const auto &entry : std::filesystem::directory_iterator("/dev")) {
        auto cpath = entry.path().native();
        if (cpath.size() >= devNameLen+1 && cpath.substr(0, devNameLen) == devName && ::isdigit(cpath[devNameLen])) {
          struct stat sb;
          if (::stat(cpath.c_str(), &sb) != 0)
            ERR("can't stat the video device '" << cpath << "'");
          if (videoUid == std::numeric_limits<uid_t>::max()) {
            videoUid = sb.st_uid;
            videoGid = sb.st_gid;
          } else if (sb.st_uid != videoUid || sb.st_gid != videoGid) {
            WARN("video devices have different uid/gid combinations")
          }
        }
      }

      // add video users and group, and add our user to this group
      if (videoUid != std::numeric_limits<uid_t>::max()) {
        // CAVEAT we assume that videoUid/videoGid aren't the same UID/GID that the user has
        execInJail({"/usr/sbin/pw", "groupadd", "videoops", "-g", std::to_string(videoGid)}, "add the videoops group");
        execInJail({"/usr/sbin/pw", "groupmod", "videoops", "-m", user}, "add the main user to the videoops group");
        execInJail({"/usr/sbin/pw", "useradd", "video", "-u", std::to_string(videoUid), "-g", std::to_string(videoGid)}, "add the video user in jail");
      } else {
        WARN("the app expects video, but no video devices are present")
      }
    }
    runScript("run:after-create-users");
  }

  // share directories if requested
  for (auto &dirShare : spec.dirsShare) {
    const auto dirJail = Util::pathSubstituteVarsInPath(dirShare.first);
    const auto dirHost = Util::pathSubstituteVarsInPath(dirShare.second);
    // Validate: jail-side path must resolve within jail (prevent ../../ traversal)
    Util::safePath(J(dirJail), jailPath, "shared directory (jail side)");
    // does the host directory exist?
    if (!Util::Fs::dirExists(dirHost))
      ERR("shared directory '" << dirHost << "' doesn't exist on the host, can't run the app")
    // create the directory in jail
    std::filesystem::create_directories(J(dirJail));
    // mount it as nullfs
    mount(new Mount("nullfs", J(dirJail), dirHost, MNT_IGNORE));
  }

  // share files if requested
  for (auto &fileShare : spec.filesShare) {
    const auto fileJail = Util::pathSubstituteVarsInPath(fileShare.first);
    const auto fileHost = Util::pathSubstituteVarsInPath(fileShare.second);
    // Validate: jail-side path must resolve within jail (prevent ../../ traversal)
    Util::safePath(J(fileJail), jailPath, "shared file (jail side)");
    // do files exist?
    bool fileHostExists = Util::Fs::fileExists(fileHost);
    bool fileJailExists = Util::Fs::fileExists(J(fileJail));
    if (!fileHostExists && !fileJailExists) {
      ERR("none of the files in a file-share exists: fileHost=" << fileHost << " fileJail=" << fileJail) // alternatively, we can create an empty file (?)
    } else if (fileHostExists && fileJailExists) {
      Util::Fs::unlink(J(fileJail));
      Util::Fs::link(fileHost, J(fileJail));
    } else if (fileHostExists) { // fileHost exists, but fileJail doesn't
      Util::Fs::link(fileHost, J(fileJail));
    } else { // fileJail exists, but fileHost doesn't
      Util::Fs::link(J(fileJail), fileHost);
    }
  }

  // start services, if any
  runScript("run:before-start-services");
  if (!spec.runServices.empty())
    for (auto &service : spec.runServices)
      execInJail({"/usr/sbin/service", service, "onestart"}, "start the service in jail");
  runScript("run:after-start-services");

  // copy X11 authentication files into the user's home directory in jail
  if (spec.optionExists("x11")) {
    // copy the .Xauthority and .ICEauthority files if they are present
    for (auto &file : {STR(homeDir << "/.Xauthority"), STR(homeDir << "/.ICEauthority")})
      if (Util::Fs::fileExists(file)) {
        Util::Fs::copyFile(file, J(file));
        Util::Fs::chown(J(file), myuid, mygid);
      }
  }

  // run the process
  runScript("run:before-execute");
  int returnCode = 0;
  if (!spec.runCmdExecutable.empty()) {
    LOG("running the command in jail: env=" << jailEnv)
    // Build inner command for jexec -l (login shell parses this string)
    auto innerCmd = STR("/usr/bin/env " << jailEnv
                        << (spec.optionExists("dbg-ktrace") ? " /usr/bin/ktrace" : "")
                        << " " << Util::shellQuote(spec.runCmdExecutable) << spec.runCmdArgs << argsToString(argc, argv));
    int status = Util::execCommandGetStatus({"jexec", "-l", "-U", user, jidStr, innerCmd}, "run command in jail");
    returnCode = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    LOG("command has finished in jail: returnCode=" << returnCode)
  } else {
    // No command is specified to be run.
    // This means that this is a service-only crate. We have to run some command, otherwise the crate would just exit immediately.
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
    // set ownership/permissions
    Util::Fs::chown(J(cmdFile), myuid, mygid);
    Util::Fs::chmod(J(cmdFile), 0500); // User-RX
    // run it the same way as we would any other command
    {
      int status = Util::execCommandGetStatus({"jexec", "-l", "-U", user, jidStr, cmdFile}, "run service command in jail");
      returnCode = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
  }
  // Check if interrupted by signal — skip post-exec scripts, go straight to cleanup
  if (g_signalReceived != 0) {
    LOG("interrupted by signal " << g_signalReceived << ", skipping post-exec, cleaning up")
    returnCode = 128 + g_signalReceived;
  } else {
    runScript("run:after-execute");

    // stop services, if any
    if (!spec.runServices.empty())
      for (auto &service : Util::reverseVector(spec.runServices))
        execInJail({"/usr/sbin/service", service, "onestop"}, "stop the service in jail");

    if (spec.optionExists("dbg-ktrace"))
      Util::Fs::copyFile(J(STR(homeDir << "/ktrace.out")), "ktrace.out");

    // rc-uninitializion (is this really needed?)
    if (optionInitializeRc)
      execInJail({"/bin/sh", "/etc/rc.shutdown"}, "exec.stop");

    runScript("run:end");
  }

  // release resources
  if (hasZfsDatasets)
    detachZfsDatasets.doNow();
  destroyJail.doNow();
  for (auto &m : mounts)
    m->unmount();
  if (optionNet && (optionNet->allowOutbound() || optionNet->allowInbound())) {
    destroyFirewallRulesAtEnd.doNow();
    destroyEpipeAtEnd.doNow();
  }
  destroyJailDir.doNow();

  // done
  outReturnCode = returnCode;
  LOG("'run' command has succeeded")
  return true;
}
