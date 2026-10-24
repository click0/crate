// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "locs.h"
#include "cmd.h"
#include "mount.h"
#include "net.h"
#include "run_pure.h"
#include "share_pure.h"
#include "bridge_pure.h"
#include "wireguard_runtime_pure.h"
#include "ipsec_runtime_pure.h"
#include "warm_pure.h"
#include "config.h"
#include "ip_alloc_pure.h"
#include "network_lease.h"
#include "ip6_alloc_pure.h"
#include "network_lease6.h"
#include "ipfw_ops.h"
#include "spec_registry.h"
#include "auto_fw_pure.h"
#include "net_detect.h"
#include "ifconfig_ops.h"
#include "scripts.h"
#include "ctx.h"
#include "jail_query.h"
#include "zfs_ops.h"
#include "mac_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"
#include "commands.h"
#include "run_net.h"
#include "run_jail.h"
#include "run_gui.h"
#include "compositor_pure.h"
#include "run_services.h"
#include "pfctl_ops.h"
#include "privops_client.h"
#include "privops_wire_pure.h"
#include "per_user_net_pure.h"
#include "runtime_paths_pure.h"
#include "thin_jail_pure.h"   // 1.1.58: base/mode: host-ro
#include "mounts_pure.h"      // 1.1.63: tmpfs
#include "passwd_pure.h"      // 1.1.64: run/user account lookup
#include "status_fd.h"        // 1.1.65: --status-fd lifecycle stream
#include "status_pure.h"

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
#include <fstream>    // 1.1.58: +CRATE.THIN
#include <sstream>
#include <memory>
#include <limits>
#include <filesystem>
#include <thread>
#include <atomic>
#include <chrono>

#define ERR(msg...) ERR2("running a crate container", msg)

#define LOG(msg...) \
  { \
    if (args.logProgress) \
      std::cerr << rang::fg::gray << Util::tmSecMs() << ": " << msg << rang::style::reset << std::endl; \
  }


static uid_t myuid = ::getuid();
static gid_t mygid = ::getgid();

// Use getpwuid(getuid()) for authoritative identity — immune to USER env spoofing.
// Critical in the legacy setuid `crate.x` build (euid 0 with a caller-controlled
// environment); kept everywhere so identity never depends on $USER. crate(1)
// itself has been unprivileged (mode 0755) since 1.0.0.
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
// ipfw rule numbering is now managed by setupFirewallRules() in run_net.cpp.
// IPv6 outbound is also handled there (Phase C9 consolidation).

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
// 1.1.41: under rootless the in-jail command is crated's child (pdfork
// behind exec_in_jail), not ours, so a terminal SIGINT never reaches it
// and nothing in the jail would notice Ctrl-C. Forward the signal
// through the process descriptors JailExec is currently waiting on
// (pdkill is a plain syscall — async-signal-safe). In the root path
// the children are in our process group and get the signal directly.
static void signalHandler(int sig) {
  g_signalReceived = sig;
  JailExec::forwardSignalToPrivopsChildren(sig);
}

//
// helpers
//
// argsToString moved to lib/run_pure.cpp (RunPure::argsToString).
static inline std::string argsToString(int argc, char** argv) {
  return RunPure::argsToString(argc, argv);
}

// 1.1.0: pfctl privops-routing wrappers. Same shape as the
// IfconfigOps wrappers in lib/run_net.cpp. Without these, the
// non-root `crate(1)` from 1.0.0+ fails to open /dev/pf when
// composing the per-jail anchor. Falls back to the bare PfctlOps
// primitive when no socket is available (legacy setuid builds).
static void addPfRulePrivopsOrLocal(const std::string &anchor,
                                    const std::string &rulesText) {
  std::string sock = PrivOpsClient::detectSocketPath();
  if (!sock.empty()) {
    auto resp = PrivOpsClient::sendRequest(sock,
        PrivOpsClient::buildAddPfRule(anchor, rulesText));
    if (!resp.transportError.empty())
      ERR2("run", "privops add_pf_rule '" << anchor
           << "' transport error: " << resp.transportError)
    if (resp.status >= 400)
      ERR2("run", "privops add_pf_rule '" << anchor
           << "' failed (status " << resp.status << "): " << resp.body)
    return;
  }
  PfctlOps::addRules(anchor, rulesText);
}

// 1.1.38: before loading our rdr rules, look at what the other crate
// anchors already forward. pf evaluates rdr first-match across the
// nested anchors, so a second jail claiming an already-forwarded host
// port silently never receives traffic — and until 1.1.38 every
// bridge/auto run left its anchor behind, so the "other" anchor is
// often a dead one. Listing needs /dev/pf; when that fails (rootless
// crate(1)) the check is skipped, not failed.
static void warnOnRdrHostPortCollision(const Spec::NetOptDetails *optionNet,
                                       const std::string &ownAnchor) {
  if (optionNet->inboundPortsTcp.empty() && optionNet->inboundPortsUdp.empty())
    return;
  std::string out;
  try {
    out = Util::execCommandGetOutput({CRATE_PATH_PFCTL, "-a", "crate/*", "-sn"},
                                     "list crate rdr rules");
  } catch (...) {
    return;
  }
  auto taken = AutoFwPure::parseRdrHostPorts(out);
  auto check = [&](const char *proto, const auto &ports) {
    for (const auto &[host, jail] : ports) {
      (void)jail;
      if (AutoFwPure::rdrHostPortTaken(taken, proto, host.first, host.second)) {
        std::cerr << rang::fg::yellow
                  << "auto-fw[pf]: host " << proto << " port "
                  << host.first << (host.first != host.second ? ":" + std::to_string(host.second) : "")
                  << " is already forwarded by another crate anchor — this jail's rdr "
                     "(anchor " << ownAnchor << ") will not receive that traffic. If the other "
                     "jail is gone, `crate clean` flushes its stale anchor."
                  << rang::style::reset << std::endl;
      }
    }
  };
  check("tcp", optionNet->inboundPortsTcp);
  check("udp", optionNet->inboundPortsUdp);
}

static void flushPfAnchorPrivopsOrLocal(const std::string &anchor) {
  std::string sock = PrivOpsClient::detectSocketPath();
  if (!sock.empty()) {
    auto resp = PrivOpsClient::sendRequest(sock,
        PrivOpsClient::buildFlushPfAnchor(anchor));
    if (!resp.transportError.empty()) {
      // Teardown-path: warn-only. Operator can clean the anchor
      // manually via pfctl(8) if needed.
      WARN("privops flush_pf_anchor '" << anchor
           << "' transport error: " << resp.transportError)
      return;
    }
    if (resp.status >= 400) {
      WARN("privops flush_pf_anchor '" << anchor
           << "' failed (status " << resp.status << "): " << resp.body)
    }
    return;
  }
  PfctlOps::flushRules(anchor);
}

// Healthcheck (§20): run test command inside jail, return true if exit code == 0
static bool runHealthcheckOnce(const std::string &jidStr, const std::string &user,
                               const Spec::Healthcheck &hc, unsigned timeoutSec) {
  try {
    // 1.1.39: through JailExec like every other in-jail command (was a
    // raw jexec argv, and the shell line was passed as ONE argv token).
    // The deadline is enforced by timeout(1) INSIDE the jail (base
    // ships /usr/bin/timeout).
    std::vector<std::string> argv;
    if (timeoutSec > 0)
      argv = {"/usr/bin/timeout", std::to_string(timeoutSec), "/bin/sh", "-c", hc.test};
    else
      argv = {"/bin/sh", "-c", hc.test};
    int status = JailExec::execInJail(std::stoi(jidStr), argv, user, "healthcheck");
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
  } catch (...) {
    return false;
  }
}

// Wait until healthcheck passes or retries exhausted. Returns true if healthy.
static bool waitForHealthy(const std::string &jidStr, const std::string &user,
                           const Spec::Healthcheck &hc, bool logProgress) {
  if (hc.startPeriodSec > 0) {
    if (logProgress)
      std::cerr << rang::fg::gray << "healthcheck: waiting " << hc.startPeriodSec
                << "s start period" << rang::style::reset << std::endl;
    ::sleep(hc.startPeriodSec);
  }

  unsigned failures = 0;
  // First check + up to hc.retries retries = retries+1 total attempts
  unsigned maxAttempts = hc.retries + 1;
  for (unsigned attempt = 0; attempt < maxAttempts; attempt++) {
    if (attempt > 0)
      ::sleep(hc.intervalSec);

    bool ok = runHealthcheckOnce(jidStr, user, hc, hc.timeoutSec);
    if (ok) {
      if (logProgress)
        std::cerr << rang::fg::green << "healthcheck: healthy"
                  << rang::style::reset << std::endl;
      return true;
    }
    failures++;
    if (logProgress)
      std::cerr << rang::fg::yellow << "healthcheck: failed (" << failures
                << "/" << maxAttempts << ")" << rang::style::reset << std::endl;
  }

  std::cerr << rang::fg::red << "healthcheck: unhealthy after " << maxAttempts
            << " attempts" << rang::style::reset << std::endl;
  return false;
}

// Background healthcheck monitor thread: periodically runs healthcheck and logs failures
// 1.1.65: `status` gets healthy/unhealthy on every transition (and the
// first verdict).
static void healthcheckMonitorLoop(const std::string jidStr, const std::string user,
                                   Spec::Healthcheck hc, bool logProgress,
                                   std::atomic<bool> &stopFlag, StatusFd::Writer *status) {
  int lastVerdict = -1;   // -1 none yet, 0 unhealthy, 1 healthy
  auto report = [&](bool healthy) {
    int v = healthy ? 1 : 0;
    if (v == lastVerdict || !status) return;
    lastVerdict = v;
    status->emit(healthy ? StatusPure::kHealthy : StatusPure::kUnhealthy);
  };
  if (hc.startPeriodSec > 0) {
    for (unsigned i = 0; i < hc.startPeriodSec && !stopFlag.load(); i++)
      ::sleep(1);
  }

  unsigned consecutiveFailures = 0;
  while (!stopFlag.load()) {
    for (unsigned i = 0; i < hc.intervalSec && !stopFlag.load(); i++)
      ::sleep(1);
    if (stopFlag.load()) break;

    bool ok = runHealthcheckOnce(jidStr, user, hc, hc.timeoutSec);
    if (ok) {
      if (consecutiveFailures > 0 && logProgress)
        std::cerr << rang::fg::green << "healthcheck: recovered"
                  << rang::style::reset << std::endl;
      consecutiveFailures = 0;
      report(true);
    } else {
      consecutiveFailures++;
      if (logProgress)
        std::cerr << rang::fg::yellow << "healthcheck: failed ("
                  << consecutiveFailures << "/" << hc.retries << ")"
                  << rang::style::reset << std::endl;
      if (consecutiveFailures >= hc.retries) {
        std::cerr << rang::fg::red << "healthcheck: UNHEALTHY — "
                  << consecutiveFailures << " consecutive failures"
                  << rang::style::reset << std::endl;
        consecutiveFailures = 0; // reset and keep monitoring
        report(false);
      }
    }
  }
}

// 1.1.65: the network mode name for the net_ready event
static const char *netModeName(const Spec::NetOptDetails *n) {
  if (!n) return "none";
  switch (n->mode) {
    case Spec::NetOptDetails::Mode::Nat:         return "nat";
    case Spec::NetOptDetails::Mode::Bridge:      return "bridge";
    case Spec::NetOptDetails::Mode::Passthrough: return "passthrough";
    case Spec::NetOptDetails::Mode::Netgraph:    return "netgraph";
    case Spec::NetOptDetails::Mode::Auto:        return "auto";
  }
  return "unknown";
}

//
// interface
//
static bool runCrateInner(const Args &args, int argc, char** argv, int &outReturnCode,
                          StatusFd::Writer &status);

// 1.1.65: the --status-fd stream wraps the whole run: `started` before
// anything, and after runCrateInner returned or threw — i.e. after every
// RunAtEnd has run — `failed` (with the error) and `teardown_done`.
bool runCrate(const Args &args, int argc, char** argv, int &outReturnCode) {
  StatusFd::Writer status(args.runStatusFd);
  if (auto e = status.open(); !e.empty())
    ERR(e)
  status.emit(StatusPure::kStarted, {StatusPure::num("pid", (long long)::getpid())});
  bool ok = false;
  try {
    ok = runCrateInner(args, argc, argv, outReturnCode, status);
  } catch (const std::exception &e) {
    status.emit(StatusPure::kFailed, {StatusPure::str("error", e.what())});
    status.emit(StatusPure::kTeardownDone);
    throw;
  }
  status.emit(StatusPure::kTeardownDone);
  return ok;
}

static bool runCrateInner(const Args &args, int argc, char** argv, int &outReturnCode,
                          StatusFd::Writer &status) {
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

  // ------------------------------------------------------------------
  // Warm-base mode (0.7.9): operator gives `--warm-base <dataset>
  // --name <name>` instead of `-f <file.crate>`. We snapshot+clone the
  // warm dataset (on-disk state captured by `crate template warm`) and
  // let ZFS auto-mount it as the jail directory, skipping the
  // tar-extract entirely. The cloned dataset still has +CRATE.SPEC
  // because the source jail had it from when it was first extracted.
  // ------------------------------------------------------------------
  const bool warmBase = !args.runWarmBase.empty();
  const std::string runHex = Util::randomHex(4);
  const std::string nameComponent = warmBase
    ? args.runName
    : Util::filePathToBareName(args.runCrateFile);

  // 1.1.33: the name becomes the jail directory, the network-lease key and
  // the kernel jail name, so it must obey one rule on BOTH paths — and be
  // checked before anything below creates a directory or clones a dataset.
  // The cold path used to take the .crate file stem unchecked.
  if (warmBase) {
    if (auto e = WarmPure::validateJailName(args.runName); !e.empty())
      ERR("--name: " << e)
  } else if (auto e = RunPure::validateCrateFileJailName(args.runCrateFile); !e.empty()) {
    ERR(e)
  }

  // 1.1.39: under rootless the jail directory lives in the operator's
  // per-user root (/var/run/crate/<uid>/, RuntimePathsPure) — the same
  // tree the lease file and spec registry already use — not in the
  // root-owned /var/run/crate, where an unprivileged mkdir fails. The
  // daemon creates and chowns that root (ensure_user_root).
  std::string jailBaseDir = Locations::jailDirectoryPath;
  {
    std::string sock = PrivOpsClient::detectSocketPath();
    if (!sock.empty()) {
      auto resp = PrivOpsClient::sendRequest(sock, PrivOpsClient::buildEnsureUserRoot());
      if (!resp.transportError.empty())
        ERR("privops ensure_user_root transport error: " << resp.transportError)
      if (resp.status >= 400)
        ERR("privops ensure_user_root failed (status " << resp.status << "): " << resp.body)
      std::string p;
      if (PrivOpsWirePure::extractStringField(resp.body, "path", p) == PrivOpsWirePure::kPresent
          && !p.empty())
        jailBaseDir = p;
      else
        jailBaseDir = RuntimePathsPure::perUserRoot((uint32_t)::getuid());
      LOG("rootless: jail directories under " << jailBaseDir)
    }
  }
  auto jailPath = STR(jailBaseDir << "/jail-" << nameComponent << "-" << runHex);

  // For warm-base we let ZFS create + mount the directory by setting
  // mountpoint inheritance on the clone. For the cold path we mkdir
  // up front so tar can extract into it.
  if (!warmBase) {
    Util::Fs::mkdir(jailPath, S_IRUSR|S_IWUSR|S_IXUSR);
  }

  // Warm-base prep: validate inputs, snapshot the warm template, clone
  // it under the jails parent dataset so the clone's mountpoint
  // inherits to <Locations::jailDirectoryPath>/jail-<name>-<hex> = jailPath.
  std::string warmCloneName, warmSnapName;
  RunAtEnd destroyWarmClone;
  if (warmBase) {
    if (auto e = WarmPure::validateTemplateDataset(args.runWarmBase); !e.empty())
      ERR("--warm-base: " << e)
    // (--name is validated up front, right after nameComponent, since 1.1.33.)

    if (!Util::Fs::isOnZfs(jailBaseDir))
      ERR("--warm-base requires the jails directory to live on ZFS; "
          << jailBaseDir << " is not")
    auto parentDataset = Util::Fs::getZfsDataset(jailBaseDir);
    if (parentDataset.empty())
      ERR("--warm-base: cannot determine ZFS dataset of " << jailBaseDir)

    warmSnapName = WarmPure::fullSnapshotName(
      args.runWarmBase, WarmPure::warmRunSnapshotSuffix(::time(nullptr)));
    warmCloneName = WarmPure::warmRunCloneName(parentDataset, args.runName, runHex);

    LOG("warm-base: snapshot " << warmSnapName)
    ZfsOps::snapshot(warmSnapName);
    LOG("warm-base: clone -> " << warmCloneName << " (auto-mounts at " << jailPath << ")")
    ZfsOps::clone(warmSnapName, warmCloneName);

    // Teardown: zfs destroy the clone (auto-unmounts) and then the
    // marker snapshot. Best-effort — we never want a teardown failure
    // to mask the real error from the run.
    destroyWarmClone.reset([warmCloneName, warmSnapName, &args]() {
      LOG("warm-base: destroy clone " << warmCloneName)
      try { ZfsOps::destroy(warmCloneName); } catch (...) {}
      LOG("warm-base: destroy snapshot " << warmSnapName)
      try { ZfsOps::destroy(warmSnapName); } catch (...) {}
    });
  }

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

  // The cold path uses Util::Fs::rmdirHier to clean up the extracted
  // tree on teardown. The warm path uses `zfs destroy <clone>` instead
  // (registered above as destroyWarmClone) — recursive rmdir on a
  // mounted clone would either fail or wipe through the mount.
  RunAtEnd destroyJailDir;
  if (!warmBase) {
    destroyJailDir.reset([&jailPath, &args]() {
      LOG("removing the jail directory " << jailPath << " ...")
      Util::Fs::rmdirHier(jailPath);
      LOG("removing the jail directory " << jailPath << " done")
    });
  }

  // mounts
  std::list<std::unique_ptr<Mount>> mounts;
  auto mount = [&mounts](Mount *m) {
    mounts.push_front(std::unique_ptr<Mount>(m));
    m->mount();
  };

  // For the cold path, validate + extract the .crate archive. For
  // warm-base, the rootfs is already in place from the ZFS clone.
  if (!warmBase) {
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
  } else {
    LOG("warm-base: rootfs comes from ZFS clone — skipping tar extraction")
    // Sanity check: the warm dataset must contain +CRATE.SPEC. Warm
    // templates produced by `crate template warm` always do (the source
    // jail was extracted from a .crate that put it there) but a
    // hand-rolled template might not.
    if (!Util::Fs::fileExists(J("/+CRATE.SPEC")))
      ERR("--warm-base: cloned dataset is missing +CRATE.SPEC at " << J("/+CRATE.SPEC")
          << " — was it produced by `crate template warm` of a `crate run` jail?")
  }

  // parse +CRATE.SPEC
  auto spec = parseSpec(J("/+CRATE.SPEC")).preprocess();

  // 1.1.58: thin jail (base/mode: host-ro). The archive holds the
  // writable layer only; mount the host's userland read-only now, before
  // anything chroots into the tree (run:begin scripts) or the jail
  // starts. The list comes from the +CRATE.THIN manifest `crate create`
  // froze, not from the spec, so a hand-edited spec cannot widen it.
  // Same `mount` list as every other nullfs mount: unmounted in reverse
  // order at teardown, routed through crated's mount_nullfs (read_only)
  // under rootless.
  {
    auto manifestPath = J(STR("/" << ThinJailPure::kManifestFile));
    const bool haveManifest = Util::Fs::fileExists(manifestPath);
    if (spec.baseHostRo && !haveManifest)
      ERR("the spec says base/mode: host-ro but the crate has no " << ThinJailPure::kManifestFile
          << " — it was created by an older crate or by hand; re-create it with `crate create`")
    if (haveManifest) {
      std::string content;
      {
        std::ifstream f(manifestPath, std::ios::binary);
        std::ostringstream ss;
        ss << f.rdbuf();
        content = ss.str();
      }
      ThinJailPure::Manifest manifest;
      std::string e;
      if (!ThinJailPure::parseManifest(content, manifest, e))
        ERR("thin jail: invalid " << ThinJailPure::kManifestFile << ": " << e)
      if (auto w = ThinJailPure::releaseMismatchWarning(manifest.osrelease,
                                                       Util::getSysctlString("kern.osrelease")); !w.empty())
        std::cerr << rang::fg::yellow << "warning: " << w << rang::style::reset << std::endl;
      LOG("thin jail: writable layer from FreeBSD " << manifest.osrelease << "; mounting "
          << manifest.hostDirs.size() << " host directories read-only")
      for (auto &[target, source] : ThinJailPure::mountPlan(jailPath, manifest.hostDirs)) {
        if (!Util::Fs::dirExists(source)) {
          if (ThinJailPure::isOptionalHostDir(source)) {
            LOG("thin jail: host directory " << source << " does not exist — skipped")
            continue;
          }
          ERR("thin jail: host directory '" << source << "' does not exist on this host")
        }
        Util::Fs::mkdirIfNotExists(target, 0755);
        mount(new Mount("nullfs", target, source, MNT_RDONLY|MNT_IGNORE));
      }
    }
  }

  // WireGuard tunnel: if the spec opts in via options.wireguard.config,
  // bring the tunnel up *before* the jail starts and register a
  // RunAtEnd handler so a teardown (clean exit, exception, signal)
  // tears it down in the reverse order. The actual command is
  // wg-quick(8) — no kernel touchpoints in this binary.
  RunAtEnd wgDownAtEnd;
  if (auto *wg = spec.optionWireguard()) {
    if (WireguardRuntimePure::isEnabled(wg->configPath)) {
      auto upArgv = WireguardRuntimePure::buildUpArgv(wg->configPath);
      LOG("wireguard: bringing tunnel up via " << upArgv[0] << " up " << wg->configPath)
      Util::execCommand(upArgv, "wg-quick up");
      auto downConfig = wg->configPath;
      wgDownAtEnd.reset([downConfig]() {
        try {
          Util::execCommand(WireguardRuntimePure::buildDownArgv(downConfig),
                            "wg-quick down");
        } catch (...) {
          // teardown is best-effort — log but don't propagate.
        }
      });
    }
  }

  // 0.8.4: IPsec / strongSwan tunnel. Same lifecycle pattern as
  // wireguard above, via `ipsec auto --add/--up` before jail start
  // and `--down/--delete` on teardown. Operator preconfigures the
  // strongSwan conn (via ipsec.conf or include); we only toggle it
  // around the jail's lifetime.
  //
  // 0.8.10: optional `conf:` field auto-installs the conn snippet
  // into /usr/local/etc/strongswan.d/crate-<jail>.conf at jail
  // start (then `ipsec reread`) and removes it on teardown.
  RunAtEnd ipsecDownAtEnd;
  RunAtEnd ipsecConfCleanup;
  if (auto *ip = spec.optionIpsec()) {
    if (IpsecRuntimePure::isEnabled(ip->connName)) {
      // 0.8.10: install conf snippet first if provided.
      std::string installedPath;
      if (!ip->confPath.empty()) {
        if (!Util::Fs::fileExists(ip->confPath))
          ERR("options/ipsec/conf: file not found: " << ip->confPath)
        installedPath = "/usr/local/etc/strongswan.d/crate-"
                      + nameComponent + ".conf";
        Util::Fs::copyFile(ip->confPath, installedPath);
        LOG("ipsec: installed conn snippet at " << installedPath)
        try {
          Util::execCommand({"/usr/local/sbin/ipsec", "reread"},
                            "ipsec reread");
        } catch (const std::exception &ex) {
          std::cerr << rang::fg::yellow
                    << "ipsec: reread failed: " << ex.what()
                    << " — strongSwan may not pick up the new conn"
                    << rang::style::reset << std::endl;
        }
        ipsecConfCleanup.reset([installedPath]() {
          try { Util::Fs::unlink(installedPath); } catch (...) {}
          try {
            Util::execCommand({"/usr/local/sbin/ipsec", "reread"},
                              "ipsec reread (cleanup)");
          } catch (...) {}
        });
      }

      LOG("ipsec: adding + bringing up conn '" << ip->connName << "'")
      Util::execCommand(IpsecRuntimePure::buildAddArgv(ip->connName),
                        "ipsec auto --add");
      Util::execCommand(IpsecRuntimePure::buildUpArgv(ip->connName),
                        "ipsec auto --up");
      auto connName = ip->connName;
      ipsecDownAtEnd.reset([connName]() {
        try {
          Util::execCommand(IpsecRuntimePure::buildDownArgv(connName),
                            "ipsec auto --down");
        } catch (...) {}
        try {
          Util::execCommand(IpsecRuntimePure::buildDeleteArgv(connName),
                            "ipsec auto --delete");
        } catch (...) {}
      });
    }
  }

  // Base container cloning (§22): if spec references a running jail, ZFS-clone its filesystem
  RunAtEnd destroyBaseClone;
  if (spec.baseContainer) {
    LOG("base_container: cloning from jail '" << spec.baseContainer->name << "'")
    if (!Util::Fs::isOnZfs(jailPath))
      ERR("base_container requires ZFS (jail directory must be on ZFS)")

    // Find source jail path via libjail API
    std::string srcJailPath;
    {
      auto srcJail = JailQuery::getJailByName(spec.baseContainer->name);
      if (srcJail)
        srcJailPath = srcJail->path;
      else
        ERR("base_container: source jail '" << spec.baseContainer->name << "' not found (is it running?)")
    }
    if (srcJailPath.empty())
      ERR("base_container: could not determine path of jail '" << spec.baseContainer->name << "'")

    if (!Util::Fs::isOnZfs(srcJailPath))
      ERR("base_container: source jail must be on ZFS for cloning")

    auto srcDataset = Util::Fs::getZfsDataset(srcJailPath);
    if (srcDataset.empty())
      ERR("base_container: cannot determine ZFS dataset of source jail")

    auto snapName = STR(srcDataset << "@base-clone-" << Util::randomHex(4));
    auto dstDataset = Util::Fs::getZfsDataset(jailPath);
    auto cloneName = STR(dstDataset << "/base-" << Util::randomHex(4));

    ZfsOps::snapshot(snapName);
    ZfsOps::clone(snapName, cloneName);

    auto cloneMountpoint = ZfsOps::getMountpoint(cloneName);

    // Overlay the clone's content into our jail directory
    // Use nullfs mount so the jail sees the cloned filesystem
    LOG("base_container: clone mounted at " << cloneMountpoint << ", overlaying into jail")

    destroyBaseClone.reset([cloneName, snapName, &args]() {
      LOG("destroying base_container clone " << cloneName)
      try { ZfsOps::destroy(cloneName); } catch (...) {}
      try { ZfsOps::destroy(snapName); } catch (...) {}
    });

    LOG("base_container: ZFS clone '" << cloneName << "' ready from jail '" << spec.baseContainer->name << "'")
  }

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
      ZfsOps::snapshot(snapName);
      ZfsOps::clone(snapName, cloneName);
      auto cloneMountpoint = ZfsOps::getMountpoint(cloneName);
      LOG("COW clone created: " << cloneName << " at " << cloneMountpoint)
      if (spec.cowOptions->mode == "ephemeral") {
        destroyCowClone.reset([cloneName, snapName, &args]() {
          LOG("destroying ephemeral COW clone " << cloneName)
          ZfsOps::destroy(cloneName);
          ZfsOps::destroy(snapName);
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
    // VNET/VIMAGE is a loader tunable: set kern.features.vimage=1 in loader.conf
    // or compile a VIMAGE-enabled kernel. Cannot be toggled at runtime.
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
      // 1.1.57: unprivileged crate cannot set sysctls; the daemon takes a
      // forwarding reference for us in acquire_fw_lease once the jail
      // exists (bridge/passthrough/netgraph too — this line used to fail
      // with EACCES for every rootless `net:` on a host with forwarding=0).
      if (!PrivOpsClient::detectSocketPath().empty()) {
        LOG("net.inet.ip.forwarding is 0; crated will enable it for this jail (acquire_fw_lease)")
      } else {
        LOG("enabling net.inet.ip.forwarding (was 0, will restore on exit)")
        Util::setSysctlInt("net.inet.ip.forwarding", 1);
      }
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
  // 0.8.31: cleanup handler now actually REMOVES the rules at
  // teardown (pre-0.8.31 it just listed them — the rules
  // accumulated across runs in /dev/ugidfw, eventually filling
  // the kernel's rule table). The handler captures a shared
  // jid pointer because the jid isn't known until later in this
  // function (RunJail::createJail). Pre-init value -1 means
  // "no jail created yet, nothing scoped to remove".
  auto macJidShared = std::make_shared<int>(-1);
  RunAtEnd removeMacRules;
  RunAtEnd removePortaclRulesAtEnd;   // 1.1.44
  if (spec.securityAdvanced) {
    if (!spec.securityAdvanced->macRules.empty()) {
      LOG("loading MAC bsdextended rules")
      Util::ensureKernelModuleIsLoaded("mac_bsdextended");
      for (auto &rule : spec.securityAdvanced->macRules) {
        LOG("adding MAC rule: " << rule)
        MacOps::addUgidfwRuleRaw(rule);
      }
      removeMacRules.reset([macJidShared, &args]() {
        if (*macJidShared <= 0) {
          // Jail never came up; rules were added without a jailid
          // scope so we can't selectively remove them. Operator
          // sees a warning. (mac_bsdextended rules without jailid
          // apply host-wide — a separate pre-existing bug.)
          LOG("MAC bsdextended cleanup: jail never created; rules "
              "left in place — run `ugidfw list` and clean by hand")
          return;
        }
        LOG("removing MAC bsdextended rules for jid " << *macJidShared)
        try {
          MacOps::removeUgidfwRules(*macJidShared);
        } catch (const std::exception &ex) {
          std::cerr << rang::fg::yellow
                    << "MAC bsdextended cleanup failed: " << ex.what()
                    << " — leftover rules may persist; run "
                    << "`ugidfw list` and clean by hand"
                    << rang::style::reset << std::endl;
        }
      });
    }
    if (!spec.securityAdvanced->macAllowPorts.empty()) {
      LOG("loading MAC portacl rules")
      Util::ensureKernelModuleIsLoaded("mac_portacl");
      // 0.8.31: actually install the portacl rules. Pre-0.8.31
      // this loop only LOG'd each port and called
      // ensureKernelModuleIsLoaded but never reached
      // MacOps::setPortaclRules — the operator's allow-list was
      // silently dropped. Bug found by 0.8.30 audit follow-up.
      // Build the rule list with uid=0 (rules apply to anyone
      // running inside the jail by default) for tcp+udp on each
      // configured port; setPortaclRules writes the
      // security.mac.portacl.rules sysctl atomically.
      std::vector<MacOps::PortaclRule> portaclRules;
      for (auto port : spec.securityAdvanced->macAllowPorts) {
        LOG("MAC portacl: allowing port " << port)
        portaclRules.push_back({0, "tcp", (int)port});
        portaclRules.push_back({0, "udp", (int)port});
      }
      // 1.1.44: MERGE into the host-wide list and take our rules back
      // out at exit. setPortaclRules overwrote security.mac.portacl.rules
      // wholesale — every other container's and the operator's rules
      // vanished on each run — and nothing restored them.
      try {
        MacOps::addPortaclRules(portaclRules);
        removePortaclRulesAtEnd.reset([portaclRules]() {
          try { MacOps::removePortaclRules(portaclRules); }
          catch (const std::exception &ex) {
            std::cerr << rang::fg::yellow << "MAC portacl: could not remove this container's rules: "
                      << ex.what() << rang::style::reset << std::endl;
          }
        });
      } catch (const std::exception &ex) {
        std::cerr << rang::fg::yellow
                  << "MAC portacl: addPortaclRules failed: " << ex.what()
                  << " — port restrictions NOT applied; check that "
                  << "mac_portacl is loaded and crate has root."
                  << rang::style::reset << std::endl;
      }
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

  // 1.1.62: the jail's devfs view. The devfs mounted a moment ago came
  // from the host with NO ruleset — every host device visible (the
  // pre-1.1.62 state of every jail without terminal/devfs_ruleset).
  // Build a PRIVATE ruleset for this jail: the operator's
  // terminal/devfs_ruleset (included) or the built-in hide-all + basic
  // nodes, then the device classes the spec enables plus the ones its
  // options imply — `gl` and the gui gpu/auto/compositor modes need
  // /dev/dri, `video` the camera, the compositor's drm backend the
  // evdev nodes. Rootless: one apply_devfs_rules privops round trip;
  // root: devfs(8) directly. `devices: all` keeps the full host view
  // (a custom ruleset is then applied the 1.1.10 way).
  {
    std::string devMount = J("/dev");
    DevicesPure::Devices eff = spec.devices;
    if (spec.optionExists("gl"))    eff.gpu = true;
    if (spec.optionExists("video")) eff.video = true;
    if (spec.guiOptions) {
      const auto &mode = spec.guiOptions->mode;
      if (mode == "gpu" || mode == "auto" || mode == "compositor") eff.gpu = true;
      if (mode == "compositor") {
        CompositorPure::Backend cbk;
        if (!CompositorPure::parseBackend(spec.guiOptions->backend, cbk))
          ERR("gui.backend: unknown backend '" << spec.guiOptions->backend << "'")
        if (cbk == CompositorPure::Backend::Drm) eff.input = true;
      }
    }
    int custom = spec.terminalOptions ? spec.terminalOptions->devfsRuleset : -1;
    std::string sock = PrivOpsClient::detectSocketPath();

    if (eff.all) {
      if (custom >= 0) {
        auto rulesetStr = std::to_string(custom);
        if (!sock.empty()) {
          auto resp = PrivOpsClient::sendRequest(sock,
              PrivOpsClient::buildApplyDevfsRuleset(devMount, (unsigned)custom));
          if (!resp.transportError.empty())
            ERR("privops apply_devfs_ruleset transport error: " << resp.transportError)
          if (resp.status >= 400)
            ERR("privops apply_devfs_ruleset failed (status " << resp.status
                << "): " << resp.body)
        } else {
          Util::execCommand({CRATE_PATH_DEVFS, "-m", devMount, "ruleset", rulesetStr}, "apply terminal devfs ruleset");
          Util::execCommand({CRATE_PATH_DEVFS, "-m", devMount, "rule", "applyset"}, "apply terminal devfs rules");
        }
        LOG("terminal: devfs_ruleset=" << rulesetStr << " (devices: all)")
      } else {
        LOG("devices: all — the host's /dev is visible in the jail")
      }
    } else {
      auto rules = DevicesPure::buildRules(eff, custom, spec.optionExists("net"));
      unsigned rs = DevicesPure::rulesetNumberFor((long)::getpid());
      try {
        if (!sock.empty()) {
          auto resp = PrivOpsClient::sendRequest(sock,
              PrivOpsClient::buildApplyDevfsRules(devMount, rs, rules));
          if (!resp.transportError.empty())
            ERR("privops apply_devfs_rules transport error: " << resp.transportError)
          if (resp.status >= 400)
            ERR("privops apply_devfs_rules failed (status " << resp.status << "): " << resp.body)
        } else {
          std::string rsStr = std::to_string(rs);
          // a stale set with this number (an old crate(1) with the same pid)
          try {
            Util::execCommand({CRATE_PATH_DEVFS, "rule", "-s", rsStr, "delset"}, "devices: delete a stale devfs ruleset");
          } catch (...) {}
          for (const auto &rule : rules) {
            std::vector<std::string> argv = {CRATE_PATH_DEVFS, "rule", "-s", rsStr, "add"};
            for (const auto &tok : Util::splitString(rule, " "))
              if (!tok.empty()) argv.push_back(tok);
            Util::execCommand(argv, "devices: add a devfs rule");
          }
          Util::execCommand({CRATE_PATH_DEVFS, "-m", devMount, "ruleset", rsStr}, "devices: associate the devfs ruleset");
          Util::execCommand({CRATE_PATH_DEVFS, "-m", devMount, "rule", "applyset"}, "devices: apply the devfs ruleset");
        }
        LOG("devices: " << DevicesPure::describe(eff) << " (private devfs ruleset " << rs
            << (custom >= 0 ? ", on top of terminal/devfs_ruleset " + std::to_string(custom) : "") << ")")
      } catch (const std::exception &ex) {
        std::cerr << rang::fg::yellow
                  << "devices: devfs rules failed: " << ex.what()
                  << " — the jail sees the host's /dev unfiltered; `crate audit <name>` shows what, "
                     "`devices: all` in the spec silences this warning"
                  << rang::style::reset << std::endl;
      }
    }
    if (spec.terminalOptions && !spec.terminalOptions->allowRawTty)
      LOG("terminal: raw TTY access denied (default devfs restrictions apply)")
  }

  // (0.8.11's auto-gui /dev/dri unhide and 0.8.45's compositor unhide
  // are part of the device-class block above since 1.1.62.)

  // 1.1.42: suffix via RunPure so crated (which knows our pid after
  // spawning us) can find this jail and record its owner.
  auto jailXname = STR(nameComponent << RunPure::jailXnamePidSuffix(::getpid()));

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

  auto jailInfo = RunJail::createJail(spec, jailPath, jailXname, args.logProgress);
  int jid = jailInfo.jid;

  // 0.8.31: publish jid to the MAC bsdextended cleanup handler so
  // it can scope removeUgidfwRules() to this jail. See the
  // RunAtEnd removeMacRules block earlier in this function for
  // the rationale (cleanup needed jid which wasn't yet available
  // when the handler was wired).
  *macJidShared = jid;

  // 0.8.21: register the {jail-name -> .crate path} pair so the
  // daemon's control-plane PostStart can find the spec on a later
  // `start <name>` request. Skipped for warm-base runs (no .crate
  // file path to register). Best-effort: a registry write failure
  // logs but doesn't abort the jail start.
  if (!warmBase && !args.runCrateFile.empty()) {
    try {
      auto absPath = std::filesystem::absolute(args.runCrateFile).string();
      SpecRegistry::upsert(nameComponent, absPath);
    } catch (const std::exception &ex) {
      WARN("spec-registry: failed to register " << nameComponent
           << " -> " << args.runCrateFile << ": " << ex.what())
    }
  }

  // securelevel: -1 means inherit host default, 0-3 are explicit values
  // bastille defaults to securelevel=2 for all jails
  // 1.1.46: crate.yml `securelevel` / `children_max` are the defaults
  // for specs that leave these at -1 (auto); unset in crate.yml (-1) keeps
  // the kernel/host default exactly as before.
  const int effSecurelevel = spec.securelevel >= 0 ? spec.securelevel : Config::get().securelevel;
  const int effChildrenMax = spec.childrenMax >= 0 ? spec.childrenMax : Config::get().childrenMax;
  auto securelevelStr = effSecurelevel >= 0 ? std::to_string(effSecurelevel) : std::string();
  // children.max: limits nested jails; -1 means not set (kernel default)
  auto childrenMaxStr = effChildrenMax >= 0 ? std::to_string(effChildrenMax) : std::string();

  // 1.1.51: host-side network teardown handlers are declared BEFORE
  // destroyJail on purpose. On the success path run.cpp calls doNow() in
  // an explicit order (jail -> mounts -> net -> fw slot); on an exception
  // the RunAtEnd destructors fire in reverse declaration order, and
  // these used to be declared after destroyJail — so a failing run tore
  // the network down while the jail still existed and unmounted last.
  // Declared here (empty) and .reset() right after each acquisition.
  RunAtEnd destroyEpipeAtEnd;
  RunAtEnd destroyBridgeEpairAtEnd;
  RunAtEnd destroyAutoBridgeAtEnd;      // 1.1.51: bridge we auto-created
  // 0.7.17: release the network-pool lease on teardown if we allocated
  // one. 0.8.20: same for the IPv6 pool lease (network_pool6).
  RunAtEnd releaseLeaseAtEnd;
  RunAtEnd releaseLease6AtEnd;
  RunAtEnd destroyNetgraphAtEnd;
  RunAtEnd destroyFirewallRulesAtEnd;
  RunAtEnd destroyPfAnchor;
  RunAtEnd releaseFwSlot;
  // 1.1.38: put net.inet6.ip6.forwarding back the way we found it.
  RunAtEnd restoreIp6ForwardingAtEnd;
  // 1.1.57: rootless — the shared firewall state (ipfw slot, forwarding
  // refcount) lives in crated, keyed by this jid. Acquired here, as soon
  // as the jid exists; released after the rules are gone. destroy_jail
  // also returns it, so a killed `crate run` leaks nothing.
  RunAtEnd releaseFwLeaseAtEnd;
  int      fwLeaseSlot = -1;
  unsigned fwLeaseFwd4Users = 0;
  const bool rootlessNet = spec.optionExists("net") && !PrivOpsClient::detectSocketPath().empty();
  if (rootlessNet) {
    auto optNet = spec.optionNet();
    const bool wantSlot = isNatMode;
    const bool want6 = isNatMode && optNet && optNet->ipv6;
    std::string sock = PrivOpsClient::detectSocketPath();
    auto resp = PrivOpsClient::sendRequest(sock,
        PrivOpsClient::buildAcquireFwLease((unsigned)jid, wantSlot, /*fwd4=*/true, want6));
    if (!resp.transportError.empty())
      ERR("privops acquire_fw_lease transport error: " << resp.transportError)
    if (resp.status >= 400)
      ERR("privops acquire_fw_lease failed (status " << resp.status << "): " << resp.body)
    long slotL = -1, users4 = 0;
    if (PrivOpsWirePure::extractLongField(resp.body, "slot", slotL) != PrivOpsWirePure::kPresent
        || PrivOpsWirePure::extractLongField(resp.body, "fwd4_users", users4) != PrivOpsWirePure::kPresent)
      ERR("privops acquire_fw_lease: malformed response: " << resp.body)
    fwLeaseSlot = (int)slotL;
    fwLeaseFwd4Users = users4 < 0 ? 0u : (unsigned)users4;
    if (wantSlot && fwLeaseSlot < 0)
      ERR("privops acquire_fw_lease returned no firewall slot")
    LOG("fw lease: slot=" << fwLeaseSlot << " fwd4_users=" << fwLeaseFwd4Users)
    releaseFwLeaseAtEnd.reset([jid, isNatMode, &args]() {
      std::string sock = PrivOpsClient::detectSocketPath();
      if (sock.empty()) return;
      auto resp = PrivOpsClient::sendRequest(sock, PrivOpsClient::buildReleaseFwLease((unsigned)jid));
      if (!resp.transportError.empty() || resp.status >= 400) {
        WARN("privops release_fw_lease failed: "
             << (resp.transportError.empty() ? "status " + std::to_string(resp.status) + " " + resp.body
                                             : resp.transportError))
        return;
      }
      long users4 = 1;
      PrivOpsWirePure::extractLongField(resp.body, "fwd4_users", users4);
      if (isNatMode && users4 == 0) {
        LOG("fw lease: last NAT user, removing the shared outbound rule")
        try { RunNet::removeCommonOutRule(); }
        catch (const std::exception &e) { WARN("remove shared outbound rule: " << e.what()) }
      }
    });
  }

  RunAtEnd destroyJail([jailInfo,&jailXname,runScript,&args]() {
    runScript("run:before-remove-jail");
    LOG("removing jail " << jailXname << " jid=" << jailInfo.jid << " ...")
    RunJail::removeJail(jailInfo);
    runScript("run:after-remove-jail");
    LOG("removing jail " << jailXname << " jid=" << jailInfo.jid << " done")
  });

  runScript("run:after-create-jail");
  LOG("jail " << jailXname << " has been created, jid=" << jid)
  status.emit(StatusPure::kJailCreated, {StatusPure::num("jid", jid),
                                         StatusPure::str("name", jailXname),
                                         StatusPure::str("path", jailPath)});

  // 1.1.5: securelevel + children.max are applied at jail creation
  // when the privops path is used (RunJail::createJail packs them
  // into the verb's `parameters` string). Skip the post-create
  // `jail -m` step in that case — under rootless mode it would
  // EACCES anyway, and the values are already in effect.
  bool privopsActive = !PrivOpsClient::detectSocketPath().empty();

  // Apply securelevel after jail creation (§8)
  // Like bastille's securelevel=2 default, restricts kernel modifications inside the jail
  if (!securelevelStr.empty() && !privopsActive) {
    auto jidS = std::to_string(jid);
    Util::execCommand({CRATE_PATH_JAIL, "-m", STR("jid=" << jidS), STR("securelevel=" << securelevelStr)},
                      CSTR("set securelevel=" << securelevelStr));
    LOG("securelevel set to " << securelevelStr << " for jail " << jid)
  }

  // Apply children.max after jail creation
  // Limits how many child jails this container can create (0 = none)
  if (!childrenMaxStr.empty() && !privopsActive) {
    auto jidS = std::to_string(jid);
    Util::execCommand({CRATE_PATH_JAIL, "-m", STR("jid=" << jidS), STR("children.max=" << childrenMaxStr)},
                      CSTR("set children.max=" << childrenMaxStr));
    LOG("children.max set to " << childrenMaxStr << " for jail " << jid)
  }

  // Apply CPU set restrictions via cpuset(1) (§8)
  // Pins jail processes to specific CPUs (e.g., "0-3", "0,2,4").
  // No RunAtEnd needed — cpuset is jail-scoped, the kernel drops
  // the binding when the jail dies (which destroyJail handles
  // unconditionally above). Pre-0.8.22 this declared a stray
  // RunAtEnd that was never reset; harmless but misleading.
  //
  // 1.1.9: routes through SetJailCpuset privops verb when the
  // socket is detected; falls back to direct cpuset(8) for legacy
  // setuid mode. Under 1.0.0+ rootless the direct call would
  // EACCES and silently drop the binding (same shape as
  // securelevel/children.max pre-1.1.5).
  if (!spec.cpuset.empty()) {
    auto jidS = std::to_string(jid);
    std::string sock = PrivOpsClient::detectSocketPath();
    if (!sock.empty()) {
      auto resp = PrivOpsClient::sendRequest(sock,
          PrivOpsClient::buildSetJailCpuset((unsigned)jid, spec.cpuset));
      if (!resp.transportError.empty())
        ERR("privops set_jail_cpuset transport error: " << resp.transportError)
      if (resp.status >= 400)
        ERR("privops set_jail_cpuset failed (status " << resp.status
            << "): " << resp.body)
    } else {
      Util::execCommand({CRATE_PATH_CPUSET, "-l", spec.cpuset, "-j", jidS},
                        CSTR("apply cpuset " << spec.cpuset));
    }
    LOG("cpuset applied: CPUs " << spec.cpuset << " for jail " << jid)
  }

  // apply RCTL resource limits (§5)
  RunAtEnd removeRctlRules = RunJail::applyRctlLimits(spec, jid, args.logProgress);

  // 0.8.31: apply ZFS refquota from spec.diskQuota. Pre-0.8.31 the
  // YAML key parsed and validated cleanly (lib/spec.cpp:805) but
  // applyDiskQuota was never invoked — operator's quota was
  // silently dropped. Bug found by 0.8.30 audit follow-up. Set
  // before attachZfsDatasets so a delegated dataset inherits the
  // quota at attach time.
  RunJail::applyDiskQuota(spec, jailPath, args.logProgress);

  // attach ZFS datasets to jail
  RunAtEnd detachZfsDatasets = RunJail::attachZfsDatasets(spec, jid, args.logProgress);

  // helpers for jail access (uses jail_attach with jexec fallback)
  auto jidStr = std::to_string(jid);
  auto execInJail = [&jid](const std::vector<std::string> &argv, const std::string &descr) {
    JailExec::execInJailChecked(jid, argv, "root", descr);
  };
  auto writeFileInJail = [J](auto str, auto file) {
    Util::Fs::writeFile(str, J(file));
  };
  auto appendFileInJail = [J](auto str, auto file) {
    Util::Fs::appendFile(str, J(file));
  };

  // set up networking
  // 0.8.2: ipfw NAT rule + instance cleanup. Only used on hosts
  // running ipfw (not pf). Declared next to the other auto-fw
  // teardown so the destruction ordering matches.
  RunAtEnd ipfwAutoFwCleanup;
  RunAtEnd reclaimPassthroughAtEnd;
  std::vector<RunAtEnd> destroyExtraInterfaces;
  auto optionNet = spec.optionNet();
  std::string jailSideIface; // jail-side network interface name (for all modes)
  std::string statusJailIp;  // 1.1.65: the jail's IPv4 when known, for the net_ready event

  if (optionNet && optionNet->mode == Spec::NetOptDetails::Mode::Bridge) {
    //
    // Bridge mode: epair → user's bridge, no NAT, L2 connectivity
    //
    LOG("bridge mode: using bridge " << optionNet->bridgeIface)

    // Auto-create the bridge if the spec opted in and it's missing.
    bool weCreatedBridge = false;
    {
      auto reason = BridgePure::validateBridgeName(optionNet->bridgeIface);
      if (!reason.empty())
        ERR("bridge mode: " << reason << " (got '" << optionNet->bridgeIface << "')")
      bool exists = Util::interfaceExists(optionNet->bridgeIface);
      auto act = BridgePure::chooseAction({exists, optionNet->autoCreateBridge});
      if (act == BridgePure::Action::Error) {
        ERR("bridge mode: bridge '" << optionNet->bridgeIface
            << "' does not exist; create it manually or set 'auto_create_bridge: true' in the spec")
      } else if (act == BridgePure::Action::Create) {
        // 1.1.41: create_bridge verb under rootless (the daemon only
        // accepts cloner names, bridge<N>); root creates it directly.
        std::string sock = PrivOpsClient::detectSocketPath();
        if (!sock.empty()) {
          auto resp = PrivOpsClient::sendRequest(sock,
              PrivOpsClient::buildCreateBridge(optionNet->bridgeIface));
          if (!resp.transportError.empty())
            ERR("bridge mode: privops create_bridge transport error: " << resp.transportError)
          if (resp.status != 200)
            ERR("bridge mode: privops create_bridge '" << optionNet->bridgeIface
                << "' failed (status " << resp.status << "): " << resp.body
                << " — create it once as root (`ifconfig " << optionNet->bridgeIface
                << " create up`, or cloned_interfaces in rc.conf)")
        } else {
          IfconfigOps::createNamedInterface(optionNet->bridgeIface);
          IfconfigOps::setUp(optionNet->bridgeIface);
        }
        weCreatedBridge = true;
        // 1.1.51: registered immediately — a throw in createBridgeEpair /
        // static-mac / VLAN below used to leak the bridge.
        destroyAutoBridgeAtEnd.reset([optionNet]() {
          try { RunNet::teardownIface(optionNet->bridgeIface); }   // 1.1.39: privops-aware
          catch (...) { /* best-effort while possibly unwinding */ }
        });
        LOG("bridge mode: auto-created bridge " << optionNet->bridgeIface)
      }
    }

    auto bridgeInfo = RunNet::createBridgeEpair(jid, jidStr, optionNet->bridgeIface, execInJail);
    jailSideIface = bridgeInfo.ifaceB;
    // 1.1.51: epair teardown armed right here, not after MAC/VLAN/IP
    // configuration — any throw in between leaked an epair pair per run.
    destroyBridgeEpairAtEnd.reset([bridgeInfo]() {
      RunNet::destroyBridgeEpair(bridgeInfo);
    });

    // Static MAC address (deterministic based on jail name + interface).
    // 1.1.38: hashed from nameComponent, not jailXname — jailXname is
    // "<name>_pid<pid>" and changed on every run, so the MAC changed on
    // every run and DHCP reservations never matched. crate.5 promised a
    // stable MAC all along.
    if (optionNet->staticMac) {
      auto [macA, macB] = RunNet::generateStaticMac(nameComponent, bridgeInfo.ifaceA);
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

    (void)weCreatedBridge;   // 1.1.51: bridge + epair teardown are armed above, at acquisition

    // 1.1.38: the jail's IPv4 address once known (static or pool) —
    // feeds the per-container firewall policy below. Empty for DHCP
    // (address not known at this point) and for ip: none.
    std::string bridgeJailIp;

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
      bridgeJailIp = optionNet->staticIp.substr(0, optionNet->staticIp.find('/'));
    } else if (optionNet->ipMode != Spec::NetOptDetails::IpMode::None) {
      // Auto / unspecified.
      // 0.7.17: if Settings.networkPool is configured, allocate from
      // the pool and configure as a static IP — gives operators
      // bridged jails without running DHCP. Falls back to DHCP if
      // no pool is configured (preserves pre-0.7.17 behaviour).
      const auto &cfg = Config::get();
      if (!cfg.networkPool.empty()) {
        IpAllocPure::Network pool;
        if (auto e = IpAllocPure::parseCidr(cfg.networkPool, pool); !e.empty())
          ERR("network_pool '" << cfg.networkPool << "': " << e)
        // Lease key = jail directory basename ("jail-<name>-<hex>"),
        // unique per jail instance and stable for its lifetime.
        auto leaseName = std::filesystem::path(jailPath).filename().string();
        // 1.1.39: under rootless each operator has its OWN lease file,
        // so two operators allocating from the same host-wide pool got
        // the same address (both start at base+2). Carve a per-uid
        // sub-block (PerUserNetPure::composeIpv4, network_pool_user_bits
        // below the pool prefix) and allocate from it; the address is
        // still configured with the POOL's prefix length and gateway so
        // routing on the shared bridge is unchanged.
        IpAllocPure::Network allocPool = pool;
        if (!PrivOpsClient::detectSocketPath().empty() && cfg.networkPoolUserBits > 0) {
          unsigned sub = pool.prefixLen + cfg.networkPoolUserBits;
          if (sub > 28) {
            std::cerr << rang::fg::yellow
                      << "network_pool " << cfg.networkPool << " is too small to split per user ("
                      << cfg.networkPoolUserBits << " bits -> /" << sub
                      << "); sharing one pool — two operators may receive the same address. "
                         "Use a wider pool or set network_pool_user_bits: 0 to silence."
                      << rang::style::reset << std::endl;
          } else {
            auto r = PerUserNetPure::composeIpv4(cfg.networkPool, sub, (uint32_t)::getuid());
            if (!r.error.empty())
              ERR("network_pool per-user split: " << r.error)
            if (auto e = IpAllocPure::parseCidr(r.cidr, allocPool); !e.empty())
              ERR("network_pool per-user split '" << r.cidr << "': " << e)
            LOG("network_pool: uid " << ::getuid() << " allocates from " << r.cidr)
          }
        }
        uint32_t addr = NetworkLease::allocateFor(leaseName, allocPool);
        // 1.1.51: release armed right after the allocation succeeds —
        // configureStaticIp / copyFile throwing below used to leave the
        // lease row forever.
        releaseLeaseAtEnd.reset([leaseName, &args]() {
          LOG("network: releasing lease for " << leaseName)
          try { NetworkLease::releaseFor(leaseName); } catch (...) {}
        });
        auto ipBare = IpAllocPure::formatIp(addr);
        auto ip = ipBare + "/" + std::to_string(pool.prefixLen);
        auto gw = IpAllocPure::formatIp(IpAllocPure::gatewayFor(pool));
        RunNet::configureStaticIp(bridgeInfo.ifaceB, ip, gw, jid, execInJail);
        Util::Fs::copyFile("/etc/resolv.conf", J("/etc/resolv.conf"));
        LOG("bridge mode: auto-allocated IP " << ip
            << " (gw " << gw << ") on " << bridgeInfo.ifaceB)
        bridgeJailIp = ipBare;

        // 0.8.20: IPv6 pool allocation. If network_pool6 is
        // configured in crate.yml, allocate a v6 from it and
        // configure as a static address alongside the v4. Same
        // lease-store pattern as v4 but in a separate file
        // (/var/run/crate/network-leases6.txt) so v4-only tooling
        // doesn't choke on v6 lines.
        //
        // No SNAT/NAT66/NPTv6 yet: this release just gets the
        // address onto the jail interface so operators can verify
        // ULA reachability from the jail. Egress translation is
        // tracked for a future release.
        if (!cfg.networkPool6.empty()) {
          Ip6AllocPure::Network6 pool6;
          if (auto e = Ip6AllocPure::parseCidr6(cfg.networkPool6, pool6); !e.empty())
            ERR("network_pool6 '" << cfg.networkPool6 << "': " << e)
          Ip6AllocPure::Network6 allocPool6 = pool6;
          if (!PrivOpsClient::detectSocketPath().empty() && cfg.networkPool6UserBits > 0) {
            unsigned sub6 = pool6.prefixLen + cfg.networkPool6UserBits;
            if (sub6 > 120) {
              std::cerr << rang::fg::yellow
                        << "network_pool6 " << cfg.networkPool6 << " is too small to split per user"
                        << rang::style::reset << std::endl;
            } else {
              auto r6 = PerUserNetPure::composeIpv6(cfg.networkPool6, sub6, (uint32_t)::getuid());
              if (!r6.error.empty())
                ERR("network_pool6 per-user split: " << r6.error)
              if (auto e = Ip6AllocPure::parseCidr6(r6.cidr, allocPool6); !e.empty())
                ERR("network_pool6 per-user split '" << r6.cidr << "': " << e)
              LOG("network_pool6: uid " << ::getuid() << " allocates from " << r6.cidr)
            }
          }
          auto addr6 = NetworkLease6::allocateFor(leaseName, allocPool6);
          releaseLease6AtEnd.reset([leaseName]() {   // 1.1.51: armed at acquisition
            try { NetworkLease6::releaseFor(leaseName); } catch (...) {}
          });
          auto ip6Bare = Ip6AllocPure::formatIp6(addr6);
          auto ip6 = ip6Bare + "/" + std::to_string(pool6.prefixLen);
          RunNet::configureStaticIp6(bridgeInfo.ifaceB, ip6, jid, execInJail);
          LOG("bridge mode: auto-allocated IPv6 " << ip6
              << " on " << bridgeInfo.ifaceB)
        }

        // 0.8.0: SNAT auto-rule. Without this, packets from the jail
        // leave the host with a 10.66.0.x source addr that never
        // gets translated and replies can't be routed back.
        // We emit one nat rule per jail (scoped by jail's IP) into
        // the jail's existing pf anchor crate/<jailXname>; the
        // anchor is flushed at teardown by the existing destroyPfAnchor
        // RunAtEnd, so cleanup is automatic.
        //
        // 0.8.6: if network_interface is unset in crate.yml, fall
        // back to NetDetect::defaultIfaceCached() which parses
        // `route -4 get default`. Only auto-detect once per daemon
        // lifetime (cached). Operator can still override by
        // setting network_interface explicitly.
        std::string externalIface = cfg.networkInterface;
        if (externalIface.empty()) {
          externalIface = NetDetect::defaultIfaceCached();
          if (!externalIface.empty()) {
            LOG("auto-fw: network_interface not set in crate.yml; "
                "auto-detected default route via " << externalIface);
          }
        }
        if (!externalIface.empty()) {
          if (auto e = AutoFwPure::validateExternalIface(externalIface); !e.empty())
            ERR("network_interface '" << externalIface << "': " << e)
          if (auto e = AutoFwPure::validateRuleAddress(ipBare); !e.empty())
            ERR("auto-fw: jail IP failed validation: " << e)
          auto rule = AutoFwPure::formatSnatAnchorLine(externalIface, ipBare);

          // 0.8.1: also emit per-port rdr rules from the spec's
          // inbound: declarations. Same anchor as SNAT — both
          // flushed together at jail teardown.
          for (const auto &[host, jail] : optionNet->inboundPortsTcp) {
            if (AutoFwPure::validatePort(host.first).empty()
                && AutoFwPure::validatePort(host.second).empty()
                && AutoFwPure::validatePort(jail.first).empty()
                && AutoFwPure::validatePort(jail.second).empty()) {
              rule += AutoFwPure::formatRdrAnchorLine(
                externalIface, "tcp",
                host.first, host.second,
                ipBare,
                jail.first, jail.second);
            }
          }
          for (const auto &[host, jail] : optionNet->inboundPortsUdp) {
            if (AutoFwPure::validatePort(host.first).empty()
                && AutoFwPure::validatePort(host.second).empty()
                && AutoFwPure::validatePort(jail.first).empty()
                && AutoFwPure::validatePort(jail.second).empty()) {
              rule += AutoFwPure::formatRdrAnchorLine(
                externalIface, "udp",
                host.first, host.second,
                ipBare,
                jail.first, jail.second);
            }
          }

          // 0.8.2: detect firewall backend. pf preferred (matches
          // 0.8.0/0.8.1 behaviour). If only ipfw loaded, use the
          // ipfw NAT path. If neither, warn and skip.
          //
          // 0.8.7: operator can override via firewall_backend in
          // crate.yml — "pf"/"ipfw" forces that path, "none" skips
          // auto-fw entirely (operator owns pf/ipfw rules), ""
          // keeps the kldstat-based auto-detect.
          int pfStatus = 1, ipfwStatus = 1;
          if (cfg.firewallBackend == "pf") {
            pfStatus = 0;  // force pf path
          } else if (cfg.firewallBackend == "ipfw") {
            ipfwStatus = 0;  // force ipfw path
          } else if (cfg.firewallBackend == "none") {
            // Skip both branches; the existing else clause warns.
          } else {
            // "" or unset — auto-detect via kldstat.
            try {
              pfStatus   = Util::execCommandGetStatus({"/sbin/kldstat", "-n", "pf"},   "kldstat pf");
            } catch (...) { pfStatus = 1; }
            try {
              ipfwStatus = Util::execCommandGetStatus({"/sbin/kldstat", "-n", "ipfw"}, "kldstat ipfw");
            } catch (...) { ipfwStatus = 1; }
          }

          if (cfg.firewallBackend == "none") {
            LOG("auto-fw: firewall_backend=none in crate.yml; "
                "skipping SNAT/rdr auto-rules per operator request")
          } else if (pfStatus == 0) {
            auto anchor = std::string("crate/") + jailXname;
            // 1.1.38: warn when another crate anchor already forwards
            // one of our host ports — pf takes the first match, so the
            // second rdr silently never fires. Best-effort: listing
            // anchors needs /dev/pf, so under rootless this is skipped.
            warnOnRdrHostPortCollision(optionNet, anchor);
            try {
              addPfRulePrivopsOrLocal(anchor, rule);
              LOG("auto-fw[pf]: rules added to anchor " << anchor
                  << " (" << ipBare << " -> " << externalIface << ")")
              // 1.1.38: flush the anchor at teardown. The comment above
              // always claimed destroyPfAnchor did this, but it was only
              // ever armed in the NAT branch — every bridge/auto run left
              // its crate/<name>_pid<pid> anchor (SNAT + rdr) behind for
              // good, and once the lease handed the IP to the next jail
              // the stale rdr forwarded the host port into it.
              if (!destroyPfAnchor) {
                destroyPfAnchor.reset([anchor, &args]() {
                  LOG("flushing pf anchor '" << anchor << "'")
                  flushPfAnchorPrivopsOrLocal(anchor);
                });
              }
            } catch (const std::exception &ex) {
              std::cerr << rang::fg::yellow
                        << "auto-fw[pf]: SNAT/rdr load failed: " << ex.what()
                        << " — outbound traffic may not work; configure pf manually"
                        << rang::style::reset << std::endl;
            }
          } else if (ipfwStatus == 0 && !AutoFwPure::validateIpfwIdsForJid(jid).empty()) {
            // 1.1.38: the ipfw id layout covers jids 1..9999; beyond
            // that the NAT instance id would run into the rule range.
            std::cerr << rang::fg::yellow
                      << "auto-fw[ipfw]: " << AutoFwPure::validateIpfwIdsForJid(jid)
                      << " — skipping SNAT/redir auto-rules for this jail; "
                         "reboot (resets jids) or configure ipfw manually"
                      << rang::style::reset << std::endl;
          } else if (ipfwStatus == 0) {
            // 0.8.2 + 0.8.3: ipfw alternative. SNAT (always) plus
            // redir_port clauses for each inbound: declaration.
            unsigned natId  = AutoFwPure::natIdForJail(jid);
            unsigned ruleId = AutoFwPure::ruleIdForJail(jid);
            // Build redirs from spec inbound declarations.
            std::vector<AutoFwPure::RedirPort> redirs;
            for (const auto &[host, jail] : optionNet->inboundPortsTcp) {
              if (AutoFwPure::validatePort(host.first).empty()
                  && AutoFwPure::validatePort(host.second).empty()
                  && AutoFwPure::validatePort(jail.first).empty()
                  && AutoFwPure::validatePort(jail.second).empty()) {
                redirs.push_back({"tcp",
                  host.first, host.second, ipBare,
                  jail.first, jail.second});
              }
            }
            for (const auto &[host, jail] : optionNet->inboundPortsUdp) {
              if (AutoFwPure::validatePort(host.first).empty()
                  && AutoFwPure::validatePort(host.second).empty()
                  && AutoFwPure::validatePort(jail.first).empty()
                  && AutoFwPure::validatePort(jail.second).empty()) {
                redirs.push_back({"udp",
                  host.first, host.second, ipBare,
                  jail.first, jail.second});
              }
            }
            try {
              // 0.8.30: route NAT config through IpfwOps::configureNat
              // instead of inline Util::execCommand so the (currently
              // shell-only) implementation has a single replacement
              // point when the native IP_FW3 path lands. configureNat
              // also warns if the natInstance is already in use,
              // catching cross-tool ID collisions early. The argv
              // builder still produces the canonical "ipfw nat <id>
              // config <…>" tokenization; we strip the
              // ["/sbin/ipfw", "nat", "<id>", "config"] prefix and
              // pass the rest as a single config string.
              auto natArgv = AutoFwPure::buildIpfwNatConfigWithRedirsArgv(
                natId, externalIface, redirs);
              std::string natConfig;
              for (size_t i = 4; i < natArgv.size(); i++) {
                if (!natConfig.empty()) natConfig += ' ';
                natConfig += natArgv[i];
              }
              // 1.1.39: through privops when unprivileged (was a direct
              // ipfw exec that EACCES'd under rootless).
              RunNet::ipfwExec({"nat", std::to_string(natId), "config", natConfig},
                               "ipfw nat config");
              {
                auto a = AutoFwPure::buildIpfwNatRuleArgv(ruleId, natId, ipBare, externalIface);
                RunNet::ipfwExec(std::vector<std::string>(a.begin() + 1, a.end()), "ipfw add nat rule");
              }
              // 0.8.39 (bug#239590): hairpin rule so connections
              // from the host itself to its own LAN address reach
              // the jail. Best-effort — soft-warn if it fails;
              // the SNAT/redir for external clients still works.
              unsigned loopbackId = AutoFwPure::loopbackRuleIdForJail(jid);
              bool loopbackInstalled = false;
              try {
                auto a = AutoFwPure::buildIpfwHostLoopbackNatArgv(loopbackId, natId);
                RunNet::ipfwExec(std::vector<std::string>(a.begin() + 1, a.end()),
                                 "ipfw add host-loopback nat rule");
                loopbackInstalled = true;
              } catch (const std::exception &ex) {
                std::cerr << rang::fg::yellow
                          << "auto-fw[ipfw]: host-loopback rule install failed: "
                          << ex.what()
                          << " — `nc <host-LAN-IP> <port>` from the host "
                             "itself may be rejected; external LAN clients "
                             "still work"
                          << rang::style::reset << std::endl;
              }
              LOG("auto-fw[ipfw]: NAT instance " << natId << " + rule " << ruleId
                  << (loopbackInstalled ? " + loopback " + std::to_string(loopbackId) : "")
                  << " (" << ipBare << " -> " << externalIface << ", "
                  << redirs.size() << " redir_port clauses)")
              // Cleanup: delete loopback rule, main rule, NAT instance.
              ipfwAutoFwCleanup.reset([natId, ruleId, loopbackId,
                                       loopbackInstalled, &args]() {
                LOG("auto-fw[ipfw]: cleanup rule " << ruleId
                    << (loopbackInstalled ? " + loopback " + std::to_string(loopbackId) : "")
                    << " + nat " << natId)
                if (loopbackInstalled) {
                  try {
                    RunNet::ipfwExec({"delete", std::to_string(loopbackId)},
                                     "ipfw delete host-loopback rule");
                  } catch (...) {}
                }
                try {
                  RunNet::ipfwExec({"delete", std::to_string(ruleId)}, "ipfw delete rule");
                } catch (...) {}
                // 0.8.30: ditto for the cleanup path. deleteNat
                // already swallows its own exceptions and warns,
                // so the outer try/catch is now redundant — kept
                // for safety in case a future implementation
                // changes behaviour.
                // 1.1.41: delete_ipfw_nat verb under rootless (1.1.39
                // left the instance in place with a warning).
                std::string sock = PrivOpsClient::detectSocketPath();
                if (!sock.empty()) {
                  auto resp = PrivOpsClient::sendRequest(sock,
                      PrivOpsClient::buildDeleteIpfwNat(natId));
                  if (!resp.transportError.empty() || resp.status != 200)
                    WARN("auto-fw[ipfw]: privops delete_ipfw_nat " << natId << " failed: "
                         << (resp.transportError.empty()
                               ? "status " + std::to_string(resp.status) + " " + resp.body
                               : resp.transportError))
                } else {
                  try {
                    IpfwOps::deleteNat(natId);
                  } catch (...) {}
                }
              });
            } catch (const std::exception &ex) {
              std::cerr << rang::fg::yellow
                        << "auto-fw[ipfw]: SNAT/redir setup failed: " << ex.what()
                        << " — outbound + port-forward traffic may not work"
                        << rang::style::reset << std::endl;
            }
          } else {
            std::cerr << rang::fg::yellow
                      << "auto-fw: neither pf nor ipfw loaded; skipping "
                         "SNAT/rdr auto-rules — outbound traffic from "
                      << ipBare << " will require manual firewall config"
                      << rang::style::reset << std::endl;
          }
        } else {
          std::cerr << rang::fg::yellow
                    << "auto-fw: network_interface unset in crate.yml AND "
                       "default-route auto-detection failed (no `route -4 get "
                       "default` interface line); skipping SNAT auto-rule — "
                       "outbound traffic from "
                    << ipBare << " will require operator-written pf/ipfw rules"
                    << rang::style::reset << std::endl;
        }
      } else {
        // No pool configured -- fall back to DHCP (pre-0.7.17 default).
        RunNet::configureDhcp(bridgeInfo.ifaceB, jailPath, jid, jidStr, execInJail);
        LOG("bridge mode: DHCP (auto) on " << bridgeInfo.ifaceB)
      }
    }

    // IPv6 configuration
    if (optionNet->ip6Mode == Spec::NetOptDetails::Ip6Mode::Slaac) {
      RunNet::configureSlaac(bridgeInfo.ifaceB, jailPath, jid, jidStr, execInJail);
      LOG("bridge mode: IPv6 SLAAC on " << bridgeInfo.ifaceB)
    } else if (optionNet->ip6Mode == Spec::NetOptDetails::Ip6Mode::Static) {
      RunNet::configureStaticIp6(bridgeInfo.ifaceB, optionNet->staticIp6, jid, execInJail);
      LOG("bridge mode: static IPv6 " << optionNet->staticIp6 << " on " << bridgeInfo.ifaceB)
    }

    statusJailIp = bridgeJailIp;

    // 1.1.38: per-container firewall policy in bridge/auto mode. It
    // was composed only in the NAT branch, so a bridge jail with
    // `firewall: {default: block}` ran wide open while crate.5 promised
    // the policy for every mode. Needs the jail's IPv4 (static or
    // pool); with DHCP the address is not known here, so say so.
    if (spec.firewallPolicy) {
      if (bridgeJailIp.empty()) {
        std::cerr << rang::fg::yellow
                  << "firewall: policy NOT applied — bridge mode with DHCP/none "
                     "addressing gives no jail IP to anchor the rules on; use a "
                     "static IP or network_pool"
                  << rang::style::reset << std::endl;
      } else {
        std::string v6 = (optionNet->ip6Mode == Spec::NetOptDetails::Ip6Mode::Static)
                           ? optionNet->staticIp6.substr(0, optionNet->staticIp6.find('/'))
                           : std::string();
        auto composed = PfctlOps::composeContainerPolicy(spec, jailXname, bridgeJailIp, v6);
        if (!composed.anchor.empty()) {
          try {
            addPfRulePrivopsOrLocal(composed.anchor, composed.rulesText);
            LOG("pf anchor '" << composed.anchor << "' policy loaded (bridge mode)")
            if (!destroyPfAnchor) {
              auto anchorName = composed.anchor;
              destroyPfAnchor.reset([anchorName, &args]() {
                LOG("flushing pf anchor '" << anchorName << "'")
                flushPfAnchorPrivopsOrLocal(anchorName);
              });
            }
          } catch (const std::exception &ex) {
            std::cerr << rang::fg::yellow
                      << "firewall: policy load failed: " << ex.what()
                      << " — the jail runs WITHOUT its firewall policy"
                      << rang::style::reset << std::endl;
          }
        }
      }
    }

  } else if (optionNet && optionNet->mode == Spec::NetOptDetails::Mode::Passthrough) {
    //
    // Passthrough mode: physical interface directly into jail
    //
    LOG("passthrough mode: using interface " << optionNet->passthroughIface)

    auto ptInfo = RunNet::passthroughInterface(jid, jidStr, optionNet->passthroughIface, execInJail);
    jailSideIface = ptInfo.iface;

    // Static MAC
    if (optionNet->staticMac) {
      auto [macA, macB] = RunNet::generateStaticMac(nameComponent, ptInfo.iface);
      // For passthrough, there's only one interface — set MAC inside jail
      execInJail({CRATE_PATH_IFCONFIG, ptInfo.iface, "ether", macB},
        "set static MAC on passthrough interface");
      LOG("passthrough mode: static MAC " << macB)
    }

    // VLAN
    if (optionNet->vlanId >= 0) {
      RunNet::createVlanInJail(jid, ptInfo.iface, optionNet->vlanId, execInJail);
      LOG("passthrough mode: VLAN " << optionNet->vlanId << " on " << ptInfo.iface)
    }

    // CRITICAL: reclaim MUST happen before jail destruction
    reclaimPassthroughAtEnd.reset([ptInfo, jailXname]() {
      RunNet::reclaimPassthroughInterface(ptInfo, jailXname);
    });

    // Configure IP addressing
    if (optionNet->ipMode == Spec::NetOptDetails::IpMode::Dhcp) {
      RunNet::configureDhcp(ptInfo.iface, jailPath, jid, jidStr, execInJail);
      LOG("passthrough mode: DHCP lease acquired on " << ptInfo.iface)
    } else if (optionNet->ipMode == Spec::NetOptDetails::IpMode::Static) {
      RunNet::configureStaticIp(ptInfo.iface, optionNet->staticIp, optionNet->gateway, jid, execInJail);
      Util::Fs::copyFile("/etc/resolv.conf", J("/etc/resolv.conf"));
      LOG("passthrough mode: static IP " << optionNet->staticIp)
    } else if (optionNet->ipMode != Spec::NetOptDetails::IpMode::None) {
      RunNet::configureDhcp(ptInfo.iface, jailPath, jid, jidStr, execInJail);
      LOG("passthrough mode: DHCP (auto) on " << ptInfo.iface)
    }

    // IPv6 configuration
    if (optionNet->ip6Mode == Spec::NetOptDetails::Ip6Mode::Slaac) {
      RunNet::configureSlaac(ptInfo.iface, jailPath, jid, jidStr, execInJail);
      LOG("passthrough mode: IPv6 SLAAC on " << ptInfo.iface)
    } else if (optionNet->ip6Mode == Spec::NetOptDetails::Ip6Mode::Static) {
      RunNet::configureStaticIp6(ptInfo.iface, optionNet->staticIp6, jid, execInJail);
      LOG("passthrough mode: static IPv6 " << optionNet->staticIp6)
    }

  } else if (optionNet && optionNet->mode == Spec::NetOptDetails::Mode::Netgraph) {
    //
    // Netgraph mode: ng_bridge + eiface, alternative to if_bridge
    //
    LOG("netgraph mode: using interface " << optionNet->netgraphIface)
    RunNet::ensureNetgraphModules();

    auto ngInfo = RunNet::createNetgraphInterface(jid, jidStr, optionNet->netgraphIface, jailXname, execInJail);
    jailSideIface = ngInfo.ngIface;

    // Static MAC
    if (optionNet->staticMac) {
      auto [macA, macB] = RunNet::generateStaticMac(nameComponent, ngInfo.ngIface);
      execInJail({CRATE_PATH_IFCONFIG, ngInfo.ngIface, "ether", macB},
        "set static MAC on netgraph eiface");
      LOG("netgraph mode: static MAC " << macB)
    }

    // VLAN
    if (optionNet->vlanId >= 0) {
      RunNet::createVlanInJail(jid, ngInfo.ngIface, optionNet->vlanId, execInJail);
      LOG("netgraph mode: VLAN " << optionNet->vlanId)
    }

    destroyNetgraphAtEnd.reset([ngInfo]() {
      RunNet::destroyNetgraphInterface(ngInfo);
    });

    // Configure IP addressing
    if (optionNet->ipMode == Spec::NetOptDetails::IpMode::Dhcp) {
      RunNet::configureDhcp(ngInfo.ngIface, jailPath, jid, jidStr, execInJail);
      LOG("netgraph mode: DHCP lease acquired on " << ngInfo.ngIface)
    } else if (optionNet->ipMode == Spec::NetOptDetails::IpMode::Static) {
      RunNet::configureStaticIp(ngInfo.ngIface, optionNet->staticIp, optionNet->gateway, jid, execInJail);
      Util::Fs::copyFile("/etc/resolv.conf", J("/etc/resolv.conf"));
      LOG("netgraph mode: static IP " << optionNet->staticIp)
    } else if (optionNet->ipMode != Spec::NetOptDetails::IpMode::None) {
      RunNet::configureDhcp(ngInfo.ngIface, jailPath, jid, jidStr, execInJail);
      LOG("netgraph mode: DHCP (auto) on " << ngInfo.ngIface)
    }

    // IPv6 configuration
    if (optionNet->ip6Mode == Spec::NetOptDetails::Ip6Mode::Slaac) {
      RunNet::configureSlaac(ngInfo.ngIface, jailPath, jid, jidStr, execInJail);
      LOG("netgraph mode: IPv6 SLAAC on " << ngInfo.ngIface)
    } else if (optionNet->ip6Mode == Spec::NetOptDetails::Ip6Mode::Static) {
      RunNet::configureStaticIp6(ngInfo.ngIface, optionNet->staticIp6, jid, execInJail);
      LOG("netgraph mode: static IPv6 " << optionNet->staticIp6)
    }

  } else if (optionNet && (optionNet->allowOutbound() || optionNet->allowInbound())) {
    //
    // NAT mode (original behavior): epair + ipfw NAT
    //
    // 1.1.39 refused NAT mode under rootless (slots + sysctls lived in
    // root-owned files). 1.1.57: both come from crated through
    // acquire_fw_lease (taken above, right after the jail was created),
    // the host-side IPv6 address goes through set_iface_inet_addr and
    // the shared NAT rule is created by whoever the daemon says is first.
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
      // 1.1.44: one /126 per pair (RunPure::epairIp6); the old
      // 100+2*num layout shared a /126 between pairs n and n+1.
      epipeIp6A = RunPure::epairIp6(epair.num, 0);
      epipeIp6B = RunPure::epairIp6(epair.num, 1);

      execInJail({CRATE_PATH_IFCONFIG, "lo0", "inet6", "::1", "prefixlen", "128"}, "set up lo0 IPv6 in jail");
      RunNet::setInet6AddrPrivopsOrLocal(epair.ifaceA, epipeIp6A, 126);   // 1.1.57: privops-aware
      execInJail({CRATE_PATH_IFCONFIG, epair.ifaceB, "inet6", epipeIp6B, "prefixlen", "126"},
                 "set up IPv6 on jail-side epair");
      execInJail({CRATE_PATH_ROUTE, "-6", "add", "default", epipeIp6A}, "set IPv6 default route in jail");
      auto origIp6Forwarding = Util::getSysctlInt("net.inet6.ip6.forwarding");
      if (origIp6Forwarding == 0 && !rootlessNet) {   // 1.1.57: rootless -> fwd6 reference in the lease
        LOG("enabling net.inet6.ip6.forwarding")
        Util::setSysctlInt("net.inet6.ip6.forwarding", 1);
        restoreIp6ForwardingAtEnd.reset([&args]() {
          LOG("restoring net.inet6.ip6.forwarding=0")
          try { Util::setSysctlInt("net.inet6.ip6.forwarding", 0); } catch (...) {}
        });
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

    // allocate firewall slot (§18). 1.1.57: rootless gets it from the
    // daemon's lease (taken above); root keeps the /var/run/crate file.
    unsigned fwSlot = 0;
    int sharedMode = 0;
    if (rootlessNet) {
      fwSlot = (unsigned)fwLeaseSlot;
      sharedMode = fwLeaseFwd4Users == 1 ? 1 : 2;
    } else {
      std::unique_ptr<Ctx::FwSlots> fwSlots(Ctx::FwSlots::lock());
      fwSlot = fwSlots->allocate(::getpid());
      fwSlots->unlock();
      releaseFwSlot.reset([]() {
        std::unique_ptr<Ctx::FwSlots> fwSlots(Ctx::FwSlots::lock());
        fwSlots->release(::getpid());
        fwSlots->unlock();
      });
    }

    {
      auto v6addr  = (optionNet->ipv6 && !epipeIp6B.empty()) ? epipeIp6B : std::string();
      auto v6iface = (optionNet->ipv6 && !epipeIp6B.empty()) ? (gwIface6.empty() ? gwIface : gwIface6) : std::string();
      destroyFirewallRulesAtEnd = RunNet::setupFirewallRules(spec, epair, gw, fwSlot, nameserverIp,
                                                             origIpForwarding, args.logProgress,
                                                             v6addr, v6iface, sharedMode);
      if (!v6addr.empty())
        LOG("IPv6 firewall rules configured for " << v6addr)
    }

    // Per-container firewall policy via pf anchors (§3).
    // 1.1.0: compose rules locally (pure), then push them via privops
    // when the rootless socket is detected so `crate(1)` doesn't need
    // /dev/pf access. Teardown likewise routes through flush_pf_anchor.
    if (spec.firewallPolicy) {
      auto v6addr = (optionNet->ipv6 && !epipeIp6B.empty()) ? epipeIp6B : std::string();
      auto composed = PfctlOps::composeContainerPolicy(
                          spec, jailXname, epair.ipB, v6addr);
      if (!composed.anchor.empty()) {
        addPfRulePrivopsOrLocal(composed.anchor, composed.rulesText);
        auto anchorName = composed.anchor;
        LOG("pf anchor '" << anchorName << "' loaded")
        destroyPfAnchor.reset([anchorName, &args]() {
          LOG("flushing pf anchor '" << anchorName << "'")
          flushPfAnchorPrivopsOrLocal(anchorName);
        });
      }
    }
  }

  // Set up extra interfaces (multi-interface containers)
  if (optionNet && !optionNet->extraInterfaces.empty()) {
    for (size_t i = 0; i < optionNet->extraInterfaces.size(); i++) {
      auto &ex = optionNet->extraInterfaces[i];
      std::string extraIface; // jail-side interface for this extra

      if (ex.mode == Spec::NetOptDetails::Mode::Bridge) {
        // 1.1.24: validate the extra-interface bridge name like the
        // primary bridge path (run.cpp ~1081). Without this, ex.bridgeIface
        // flows straight into `ifconfig <bridge> addm <member>` — a
        // leading-'-' value is taken as an ifconfig option (argument
        // injection). The primary path validated; this loop did not.
        if (auto reason = BridgePure::validateBridgeName(ex.bridgeIface);
            !reason.empty())
          ERR("extra[" << i << "] bridge mode: " << reason
              << " (got '" << ex.bridgeIface << "')")
        RunNet::ensureBridgeModule();
        auto bi = RunNet::createBridgeEpair(jid, jidStr, ex.bridgeIface, execInJail);
        extraIface = bi.ifaceB;
        if (ex.staticMac) {
          auto [macA, macB] = RunNet::generateStaticMac(nameComponent, bi.ifaceA);
          RunNet::setMacAddress(bi.ifaceA, macA);
          execInJail({CRATE_PATH_IFCONFIG, bi.ifaceB, "ether", macB}, "set static MAC on extra bridge epair");
        }
        if (ex.vlanId >= 0)
          RunNet::createVlanInJail(jid, bi.ifaceB, ex.vlanId, execInJail);
        destroyExtraInterfaces.emplace_back([bi]() { RunNet::destroyBridgeEpair(bi); });
        LOG("extra[" << i << "]: bridge " << ex.bridgeIface << " via " << bi.ifaceB)

      } else if (ex.mode == Spec::NetOptDetails::Mode::Passthrough) {
        auto pi = RunNet::passthroughInterface(jid, jidStr, ex.passthroughIface, execInJail);
        extraIface = pi.iface;
        if (ex.staticMac) {
          auto [macA, macB] = RunNet::generateStaticMac(nameComponent, pi.iface);
          execInJail({CRATE_PATH_IFCONFIG, pi.iface, "ether", macB}, "set static MAC on extra passthrough");
        }
        if (ex.vlanId >= 0)
          RunNet::createVlanInJail(jid, pi.iface, ex.vlanId, execInJail);
        destroyExtraInterfaces.emplace_back([pi, jailXname]() { RunNet::reclaimPassthroughInterface(pi, jailXname); });
        LOG("extra[" << i << "]: passthrough " << pi.iface)

      } else if (ex.mode == Spec::NetOptDetails::Mode::Netgraph) {
        RunNet::ensureNetgraphModules();
        auto ni = RunNet::createNetgraphInterface(jid, jidStr, ex.netgraphIface, jailXname, execInJail);
        extraIface = ni.ngIface;
        if (ex.staticMac) {
          auto [macA, macB] = RunNet::generateStaticMac(nameComponent, ni.ngIface);
          execInJail({CRATE_PATH_IFCONFIG, ni.ngIface, "ether", macB}, "set static MAC on extra netgraph");
        }
        if (ex.vlanId >= 0)
          RunNet::createVlanInJail(jid, ni.ngIface, ex.vlanId, execInJail);
        destroyExtraInterfaces.emplace_back([ni]() { RunNet::destroyNetgraphInterface(ni); });
        LOG("extra[" << i << "]: netgraph via " << ni.ngIface)
      }

      // Configure IPv4
      if (ex.ipMode == Spec::NetOptDetails::IpMode::Dhcp) {
        RunNet::configureDhcp(extraIface, jailPath, jid, jidStr, execInJail);
      } else if (ex.ipMode == Spec::NetOptDetails::IpMode::Static) {
        RunNet::configureStaticIp(extraIface, ex.staticIp, ex.gateway, jid, execInJail);
      } else if (ex.ipMode != Spec::NetOptDetails::IpMode::None) {
        RunNet::configureDhcp(extraIface, jailPath, jid, jidStr, execInJail);
      }

      // Configure IPv6
      if (ex.ip6Mode == Spec::NetOptDetails::Ip6Mode::Slaac) {
        RunNet::configureSlaac(extraIface, jailPath, jid, jidStr, execInJail);
      } else if (ex.ip6Mode == Spec::NetOptDetails::Ip6Mode::Static) {
        RunNet::configureStaticIp6(extraIface, ex.staticIp6, jid, execInJail);
      }
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

  // 1.1.65: every network mode has set the jail up by here (NAT: epair +
  // ipfw; bridge/passthrough/netgraph: the interface, address, pf
  // anchor). The IP is the bridge-family address when one is known.
  {
    if (statusJailIp.empty() && optionNet && !optionNet->staticIp.empty())
      statusJailIp = optionNet->staticIp.substr(0, optionNet->staticIp.find('/'));
    std::vector<StatusPure::Field> f = {StatusPure::str("mode", spec.optionExists("net") ? netModeName(optionNet) : "none")};
    if (!statusJailIp.empty()) f.push_back(StatusPure::str("ip", statusJailIp));
    status.emit(StatusPure::kNetReady, f);
  }

  // add user to jail
  RunJail::createUserInJail(spec, jailPath, jid, user, homeDir, myuid, mygid, execInJail, runScript, args.logProgress);

  // 1.1.64: the account the command runs as (run/user). The mirrored
  // operator is what createUserInJail just made; root is root; any other
  // name must exist in the jail's passwd — a package's account, one
  // `crate create` added, or one made here (warm templates and crates
  // from before 1.1.64 have none).
  const RunPure::RunUser runUser = RunPure::effectiveRunUser(spec.runUser, user, (unsigned)myuid);
  if (RunPure::runUserNeedsAccount(runUser)) {
    std::string passwd;
    {
      std::ifstream f(J("/etc/master.passwd"), std::ios::binary);
      std::ostringstream ss; ss << f.rdbuf(); passwd = ss.str();
    }
    PasswdPure::User found;
    if (!PasswdPure::lookupUser(passwd, runUser.name, found)) {
      LOG("run/user: creating the account '" << runUser.name << "' in the jail")
      execInJail({"/usr/sbin/pw", "useradd", runUser.name, "-m", "-s", "/bin/sh", "-c", "crate run/user"},
                 "create the run/user account in jail");
    }
  }
  LOG("run/user: the command runs as '" << runUser.name << "'"
      << (runUser.root ? " (root inside the jail, run/user: root)"
          : runUser.dedicated ? " (operator is root: dedicated unprivileged account)"
          : runUser.mirrored ? " (the operator's mirrored account)" : ""))

  // share directories if requested (1.1.63: `:ro` -> MNT_RDONLY)
  for (auto &dirShare : spec.dirsShare) {
    const auto dirJail = Util::pathSubstituteVarsInPath(dirShare.jail);
    const auto dirHost = Util::pathSubstituteVarsInPath(dirShare.host);
    Util::safePath(J(dirJail), jailPath, "shared directory (jail side)");
    if (!Util::Fs::dirExists(dirHost))
      ERR("shared directory '" << dirHost << "' doesn't exist on the host, can't run the app")
    std::filesystem::create_directories(J(dirJail));
    mount(new Mount("nullfs", J(dirJail), dirHost, MNT_IGNORE | (dirShare.readOnly ? MNT_RDONLY : 0)));
    if (dirShare.readOnly)
      LOG("dirs/share: " << dirHost << " -> " << dirJail << " read-only")
  }

  // share files if requested
  for (auto &fileShare : spec.filesShare) {
    const auto fileJail = Util::pathSubstituteVarsInPath(fileShare.jail);
    const auto fileHost = Util::pathSubstituteVarsInPath(fileShare.host);
    Util::safePath(J(fileJail), jailPath, "shared file (jail side)");
    SharePure::FileShareInputs inp{
      Util::Fs::fileExists(fileHost),
      Util::Fs::fileExists(J(fileJail)),
      Util::Fs::sameDevice(fileHost, J(fileJail)),
    };
    switch (SharePure::chooseFileStrategy(inp)) {
      case SharePure::FileStrategy::Error:
        ERR("none of the files in a file-share exists: fileHost=" << fileHost << " fileJail=" << fileJail)
      case SharePure::FileStrategy::HardLinkHostToJail:
        Util::Fs::unlink(J(fileJail));
        Util::Fs::link(fileHost, J(fileJail));
        break;
      case SharePure::FileStrategy::HardLinkHostToJailNew:
        Util::Fs::link(fileHost, J(fileJail));
        break;
      case SharePure::FileStrategy::HardLinkJailToHost:
        Util::Fs::link(J(fileJail), fileHost);
        break;
      case SharePure::FileStrategy::CopyJailToHostThenBind:
        Util::Fs::copyFile(J(fileJail), fileHost);
        // fall through into NullfsBindHostToJail
        [[fallthrough]];
      case SharePure::FileStrategy::NullfsBindHostToJail:
        if (Util::Fs::fileExists(J(fileJail)))
          Util::Fs::unlink(J(fileJail));
        Util::Fs::touchFile(J(fileJail));
        mount(new Mount("nullfs", J(fileJail), fileHost, MNT_IGNORE));
        LOG("file-share: cross-device path '" << fileHost << "' bound onto '" << J(fileJail) << "' via nullfs")
        break;
    }
  }

  // 1.1.63: tmpfs mounts (`tmpfs:`), after the shares so a tmpfs listed
  // above a share is what the spec asked for (crate validate warns).
  // Inside the user's home the tmpfs belongs to the user (0700), else
  // to root with the sticky 01777 of a shared /tmp. Root: nmount(2);
  // rootless: the mount_tmpfs privops verb, path-gated by the target.
  for (auto &t : spec.tmpfs) {
    const auto p = Util::pathSubstituteVarsInPath(t.path);
    Util::safePath(J(p), jailPath, "tmpfs mount point");
    std::filesystem::create_directories(J(p));
    auto *m = new Mount("tmpfs", J(p), "", MNT_IGNORE);
    const bool underHome = !homeDir.empty() && MountsPure::isUnder(p, homeDir);
    for (auto &kv : MountsPure::tmpfsParams(t.size, underHome, (unsigned)myuid, (unsigned)mygid))
      m->addParam(kv.first, kv.second);
    mount(m);
    LOG("tmpfs: " << p << (t.size.empty() ? "" : " (size " + t.size + ")") << (underHome ? " owned by the user" : ""))
  }
  status.emit(StatusPure::kMountsReady);

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

  // Cron jobs (§25): generate crontab and enable cron inside the container
  if (!spec.cronJobs.empty()) {
    // 1.1.51: one crontab PER USER. All jobs used to land in the first
    // job's user's crontab and a later `user:` was silently ignored.
    std::map<std::string, std::vector<const Spec::CronJob*>> byUser;
    for (auto &job : spec.cronJobs) {
      // 1.1.27: an explicit `user: ""` in the spec used to reach
      // `/var/cron/tabs/` (a directory) — apply the documented default.
      std::string u = job.user.empty() ? "root" : job.user;
      // 1.1.22: the user is a spec field that flows into a root-run file
      // path AND a `sh -c` string below — validate it as a username.
      if (auto e = RunPure::validateCronUser(u); !e.empty())
        ERR("cron/user rejected: " << e)
      byUser[u].push_back(&job);
    }
    for (auto &kv : byUser) {
      const std::string &cronUser = kv.first;
      std::ostringstream crontab;
      crontab << "# Generated by crate\n";
      crontab << "SHELL=/bin/sh\n";
      crontab << "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin\n";
      for (auto *job : kv.second)
        crontab << job->schedule << "\t" << job->command << std::endl;
      Util::Fs::writeFile(crontab.str(), J(STR("/var/cron/tabs/" << cronUser)));
      // Ensure correct ownership and permissions (cron requires 0600)
      Util::execCommand({"/usr/sbin/chroot", jailPath, "/bin/sh", "-c",
        STR("chmod 0600 /var/cron/tabs/" << cronUser)}, "set crontab permissions");
    }
    // Enable cron in rc.conf
    Util::Fs::appendFile("cron_enable=\"YES\"\n", J("/etc/rc.conf"));
    LOG("cron: " << spec.cronJobs.size() << " jobs configured for " << byUser.size() << " user(s)")
  }

  // Init scripts (§26): run only on first start, skip on subsequent runs.
  // Uses a marker file to track whether init has already been performed.
  {
    auto initMarker = J("/.crate-initialized");
    if (!spec.scripts.empty() && spec.scripts.count("init") && !Util::Fs::fileExists(initMarker)) {
      LOG("running init scripts (first start)")
      runScript("init");
      Util::Fs::writeFile("", initMarker);
      LOG("init scripts completed, marker created")
    }
  }

  // start services
  RunServices::startServices(spec, execInJail, runScript);
  status.emit(StatusPure::kServicesStarted);

  // Healthcheck: wait for container to become healthy after services start (§20)
  if (spec.healthcheck) {
    LOG("waiting for healthcheck to pass")
    if (!waitForHealthy(jidStr, user, *spec.healthcheck, args.logProgress)) {
      std::cerr << rang::fg::red << "container failed healthcheck — proceeding anyway"
                << rang::style::reset << std::endl;
      status.emit(StatusPure::kUnhealthy);
    } else {
      status.emit(StatusPure::kHealthy);
    }
  }

  // 1.1.65: run/timeout — timeout(1) in front of the command (TERM at the
  // deadline, KILL kRunTimeoutKillAfter seconds later); exit 124 is then
  // "timed out" rather than the program's own code.
  const auto timeoutPrefix = RunPure::runTimeoutPrefix(spec.runTimeoutSec);
  if (spec.runTimeoutSec)
    LOG("run/timeout: the command is limited to " << spec.runTimeoutSec << " s")

  // copy X11 authentication files into the user's home directory in jail
  RunGui::copyX11Auth(spec, jailPath, homeDir, myuid, mygid);

  // Clipboard proxy daemon (§12)
  RunAtEnd killClipboardProxy = RunGui::setupClipboard(spec, jailXname, jidStr, args.logProgress);

  // gui.mode: compositor — launch a Wayland compositor inside the jail
  // (post-jail: needs jid; runs before the jail command so XDG_RUNTIME_DIR
  // / WAYLAND_DISPLAY are set in jailEnv below and the compositor socket
  // exists when the command connects).
  RunAtEnd killCompositorAtEnd =
    RunGui::setupCompositor(spec, jailPath, jailXname, jidStr, mounts, setJailEnv, args.logProgress);

  // run the process
  runScript("run:before-execute");
  int returnCode = 0;
  std::string exitReason = "exited normally";
  bool timedOut = false;
  if (!spec.runCmdExecutable.empty()) {
    LOG("running the command in jail: env=" << jailEnv)
    std::string prefix;
    for (auto &p : timeoutPrefix) prefix += p + " ";
    auto innerCmd = STR(prefix << "/usr/bin/env " << jailEnv
                        << (spec.optionExists("dbg-ktrace") ? " /usr/bin/ktrace" : "")
                        << " " << Util::shellQuote(spec.runCmdExecutable) << spec.runCmdArgs << argsToString(argc, argv));
    status.emit(StatusPure::kExecStarted, {StatusPure::str("user", runUser.name),
                                           StatusPure::str("command", spec.runCmdExecutable)});
    int st = JailExec::execInJail(jid, {"/bin/sh", "-c", innerCmd}, runUser.name, "run command in jail");
    returnCode = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    timedOut = WIFEXITED(st) && RunPure::runTimedOut(spec.runTimeoutSec, returnCode);
    // 0.8.28: surface OOM / RCTL / signal context to the operator
    // log so they don't have to correlate exit codes with rctl(8)
    // by hand. diagnoseExitReason returns "exited normally" for
    // clean exits — only log when something interesting happened.
    if (timedOut) {
      exitReason = STR("timed out after " << spec.runTimeoutSec << " s (run/timeout)");
      std::cerr << rang::fg::yellow << "run/timeout: the command was killed after "
                << spec.runTimeoutSec << " s" << rang::style::reset << std::endl;
    } else if (returnCode != 0 || !WIFEXITED(st)) {
      exitReason = RunJail::diagnoseExitReason(jid, st);
      LOG("command has finished in jail: returnCode=" << returnCode << " (" << exitReason << ")")
    } else {
      LOG("command has finished in jail: returnCode=" << returnCode)
    }
  } else {
    LOG("this is a service-only crate, install and run the command that exits on Ctrl-C")
    auto cmdFile = "/run.sh";
    writeFileInJail(STR(
        "#!/bin/sh"                                                 << std::endl <<
        ""                                                          << std::endl <<
        "trap onSIGINT 2"                                           << std::endl <<
        ""                                                          << std::endl <<
        "onSIGINT()"                                                << std::endl <<
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
    // 1.1.64: readable by whoever run/user resolved to (root-owned 0555
    // when it is not the mirrored operator)
    if (runUser.mirrored) {
      Util::Fs::chown(J(cmdFile), myuid, mygid);
      Util::Fs::chmod(J(cmdFile), 0500);
    } else {
      Util::Fs::chmod(J(cmdFile), 0555);
    }

    // Start background healthcheck monitor for service-only crates (§20)
    std::atomic<bool> hcStopFlag{false};
    std::thread hcThread;
    // 1.1.51: a joinable std::thread being destroyed on an exception
    // (execInJail can throw) called std::terminate and skipped every
    // RunAtEnd; this guard stops and joins it on any exit path.
    struct HcGuard {
      std::atomic<bool> &flag; std::thread &t;
      ~HcGuard() { flag.store(true); if (t.joinable()) t.join(); }
    } hcGuard{hcStopFlag, hcThread};
    if (spec.healthcheck) {
      LOG("starting background healthcheck monitor")
      hcThread = std::thread(healthcheckMonitorLoop, jidStr, runUser.name, *spec.healthcheck, args.logProgress,
                             std::ref(hcStopFlag), &status);
    }
    {
      std::vector<std::string> cmd = timeoutPrefix;
      cmd.push_back(cmdFile);
      status.emit(StatusPure::kExecStarted, {StatusPure::str("user", runUser.name),
                                             StatusPure::str("command", cmdFile)});
      int st = JailExec::execInJail(jid, cmd, runUser.name, "run service command in jail");
      returnCode = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
      timedOut = WIFEXITED(st) && RunPure::runTimedOut(spec.runTimeoutSec, returnCode);
      // 0.8.28: same OOM / RCTL diagnosis hook as the
      // executable-mode path above. Service-only crates are MORE
      // likely to hit RCTL (memoryuse caps trip after weeks of
      // accumulating cache); the diagnosis line saves operators
      // a syslog dive.
      if (timedOut) {
        exitReason = STR("timed out after " << spec.runTimeoutSec << " s (run/timeout)");
        LOG("run/timeout: the service-only container reached its time limit")
      } else if (returnCode != 0 || !WIFEXITED(st)) {
        exitReason = RunJail::diagnoseExitReason(jid, st);
        LOG("service command has finished in jail: returnCode=" << returnCode
            << " (" << exitReason << ")")
      }
    }
    // Stop healthcheck monitor
    if (hcThread.joinable()) {
      hcStopFlag.store(true);
      hcThread.join();
    }
  }

  // Check if interrupted by signal
  if (g_signalReceived != 0) {
    LOG("interrupted by signal " << g_signalReceived << ", skipping post-exec, cleaning up")
    returnCode = 128 + g_signalReceived;
    exitReason = STR("interrupted by signal " << g_signalReceived);
  }
  status.emit(StatusPure::kExited, {StatusPure::num("code", returnCode),
                                    StatusPure::str("reason", exitReason),
                                    StatusPure::boolean("timed_out", timedOut)});
  if (g_signalReceived == 0) {
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
  // Stop the in-jail compositor (+ wayvnc) and drop its registry entry
  // BEFORE destroyJail/unmounts, so the processes are gone before their
  // jail and the bound seatd socket disappear (mirrors the other GUI
  // helpers, which are explicitly torn down here rather than at scope
  // exit).
  killCompositorAtEnd.doNow();
  if (!spec.limits.empty())
    removeRctlRules.doNow();
  if (!spec.zfsDatasets.empty())
    detachZfsDatasets.doNow();
  // Passthrough: reclaim physical NIC BEFORE jail destruction (or NIC is lost until reboot)
  if (optionNet && optionNet->mode == Spec::NetOptDetails::Mode::Passthrough)
    reclaimPassthroughAtEnd.doNow();
  // Reclaim extra passthrough interfaces before jail destruction (reverse order)
  for (auto it = destroyExtraInterfaces.rbegin(); it != destroyExtraInterfaces.rend(); ++it)
    it->doNow();
  destroyExtraInterfaces.clear();
  destroyJail.doNow();
  killXephyrAtEnd.doNow();
  destroySocatProxies.doNow();
  for (auto &m : mounts)
    m->unmount();
  if (optionNet && optionNet->mode == Spec::NetOptDetails::Mode::Bridge) {
    destroyPfAnchor.doNow();
    destroyBridgeEpairAtEnd.doNow();
    destroyAutoBridgeAtEnd.doNow();   // 1.1.51
  } else if (optionNet && optionNet->mode == Spec::NetOptDetails::Mode::Passthrough) {
    destroyPfAnchor.doNow();
    // reclaimPassthroughAtEnd already done above (before jail destroy)
  } else if (optionNet && optionNet->mode == Spec::NetOptDetails::Mode::Netgraph) {
    destroyPfAnchor.doNow();
    destroyNetgraphAtEnd.doNow();
  } else if (optionNet && (optionNet->allowOutbound() || optionNet->allowInbound())) {
    destroyPfAnchor.doNow();
    destroyFirewallRulesAtEnd.doNow();
    destroyEpipeAtEnd.doNow();
    releaseFwSlot.doNow();
    releaseFwLeaseAtEnd.doNow();   // 1.1.57
    restoreIp6ForwardingAtEnd.doNow();
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
