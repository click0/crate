// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "util.h"
#include "err.h"
#include "misc.h"
#include "audit.h"
#include "commands.h"
#include "profile.h"   // 1.1.59: `crate run <profile>`, --template merge persisted

#include <rang.hpp>
#include <yaml-cpp/yaml.h>

#include <paths.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>   // 1.1.46: SIGINT/SIGTERM in the restart loop
#include <sys/stat.h>

#include <iostream>
#include <string>

static int mainGuarded(int argc, char** argv) {

  //
  // 1.1.34: no uid/euid gate. Up to 0.9.x crate(1) was setuid root and
  // refused to run unless euid==0 && uid!=0. The 1.0.0 setuid removal
  // flipped the Makefile to -m 0755 but left that gate in place, so the
  // installed binary exited with "crate has to run as a regular user
  // setuid to root" for every invocation — as the operator (euid!=0),
  // as root / under sudo (uid==0), and when crated(8) exec'ed `crate run`
  // for a control-socket or HTTP start. Only the legacy setuid crate.x
  // ever passed it. Privileged work is delegated to crated(8) over the
  // privops socket (lib/privops_client.cpp) when crate runs unprivileged,
  // and done directly when it runs as root.
  //

  //
  // Sanitize the environment (CWE-426, CWE-250). Kept after the setuid
  // removal: every helper is exec'ed by absolute path, but a clean PATH /
  // no LD_* keeps the child environment of jexec'ed and chroot'ed
  // processes predictable. Clear everything, rebuild with safe defaults.
  //
  bool envNoColor = false;
  {
    const char* term    = ::getenv("TERM");
    const char* display = ::getenv("DISPLAY");
    const char* wayland = ::getenv("WAYLAND_DISPLAY");
    const char* lang    = ::getenv("LANG");
    const char* xauth   = ::getenv("XAUTHORITY");
    const char* nocolor = ::getenv("NO_COLOR");
    // 0.8.48: preserve XDG_RUNTIME_DIR (needed by 0.8.18 Wayland +
    // 0.8.44 PipeWire + 0.8.47 PulseAudio bind blocks) and
    // XDG_CURRENT_DESKTOP (compositor-ID hint surfaced by
    // `crate doctor wayland-readiness`). Without this, all four
    // Wayland releases were silent no-ops in the setuid-prod path
    // — sanitize wiped environ before those getenv() calls fired.
    const char* xdgRun  = ::getenv("XDG_RUNTIME_DIR");
    const char* xdgCur  = ::getenv("XDG_CURRENT_DESKTOP");
    envNoColor = (nocolor != nullptr);

    extern char **environ;
    static char *empty_env[] = { nullptr };
    environ = empty_env;

    ::setenv("PATH", _PATH_DEFPATH, 1);
    // 1.1.34: HOME is the invoking user's home from the password
    // database (was hard-coded "/root" from the setuid era), so
    // ~/.config/crate/{crate.yml,templates/} resolve for the operator.
    // getpwuid(getuid()) rather than the inherited $HOME, which is
    // caller-controlled.
    {
      auto home = Util::Fs::getUserHomeDir();
      ::setenv("HOME", home.empty() ? "/" : home.c_str(), 1);
    }
    ::setenv("SHELL", _PATH_BSHELL, 1);
    if (term)    ::setenv("TERM", term, 1);
    if (display) ::setenv("DISPLAY", display, 1);
    if (wayland) ::setenv("WAYLAND_DISPLAY", wayland, 1);
    if (lang)    ::setenv("LANG", lang, 1);
    if (xauth)   ::setenv("XAUTHORITY", xauth, 1);
    if (envNoColor) ::setenv("NO_COLOR", "", 1);
    if (xdgRun)  ::setenv("XDG_RUNTIME_DIR", xdgRun, 1);
    if (xdgCur)  ::setenv("XDG_CURRENT_DESKTOP", xdgCur, 1);
  }

  //
  // Can't run in jail because we need to create jails ourselves
  //
  if (Util::getSysctlInt("security.jail.jailed") != 0) {
    std::cerr << rang::fg::red << "crate can not run in jail" << rang::style::reset << std::endl;
    return 1;
  }

  //
  // parse the arguments
  //
  unsigned numArgsProcessed = 0;
  Args args = parseArguments(argc, argv, numArgsProcessed);
  args.validate();

  //
  // Make sure the runtime directory exists. 1.1.34: after argument
  // parsing, so --help/--version/-h have no filesystem side effects and
  // work for a user who cannot create /var/run/crate; as a non-root
  // operator this only checks that crated(8) has created it (see
  // lib/misc.cpp).
  //
  createJailsDirectoryIfNeeded();

  // Audit: record the invocation now that args are valid. Read-only
  // commands (list/info/stats/logs/validate) are skipped inside
  // Audit::logStart to keep the log lean. The matching logEnd is
  // emitted via the try/catch wrapping the dispatch switch below.
  Audit::logStart(argc, argv, args);
  bool auditFlushed = false;
  auto auditOnce = [&](const std::string &errMsg) {
    if (auditFlushed) return;
    auditFlushed = true;
    Audit::logEnd(argc, argv, args, errMsg);
  };

  //
  // Handle NO_COLOR (https://no-color.org/) and --no-color flag.
  // When either is set, disable all colored output.
  //
  if (args.noColor || envNoColor)
    rang::setControlMode(rang::control::Off);

  //
  // run the requested command
  //
  bool succ = false;
  int returnCode = 0;

  try {
  switch (args.cmd) {
  case CmdCreate: {
    // Support URL-based spec and template fetching (§23)
    std::string specPath = args.createSpec;
    std::string templatePath = args.createTemplate;
    std::string tmpDir;
    if (Util::isUrl(specPath) || Util::isUrl(templatePath)) {
      tmpDir = STR("/tmp/crate-fetch-" << Util::randomHex(4));
      Util::Fs::mkdir(tmpDir, S_IRWXU);
    }
    if (Util::isUrl(specPath))
      specPath = Util::fetchUrl(specPath, tmpDir);
    if (Util::isUrl(templatePath))
      templatePath = Util::fetchUrl(templatePath, tmpDir);

    // Template merging (§10). 1.1.59: merged at the YAML level into a
    // file, and THAT file is the spec from here on — createCrate copies
    // args.createSpec into +CRATE.SPEC verbatim, so the Spec-level merge
    // used before never reached `crate run` (a `--template privacy` crate
    // ran without tor, encryption, COW or the DNS filter). `--template X`
    // without -s makes validate() point createSpec at the template itself;
    // nothing to merge then.
    Args createArgs = args;
    if (!templatePath.empty() && templatePath != specPath) {
      if (tmpDir.empty()) {
        tmpDir = STR("/tmp/crate-fetch-" << Util::randomHex(4));
        Util::Fs::mkdir(tmpDir, S_IRWXU);
      }
      auto mergedPath = STR(tmpDir << "/merged-spec.yml");
      Profile::writeMerged(templatePath, specPath, mergedPath);
      specPath = mergedPath;
    }
    createArgs.createSpec = specPath;

    auto spec = parseSpecWithVars(specPath, args.vars);
    spec.validate();
    createCacheDirectoryIfNeeded();
    succ = createCrate(createArgs, spec.preprocess());

    // Clean up temp dir
    if (!tmpDir.empty())
      Util::Fs::rmdirHier(tmpDir);
    break;
  } case CmdRun: {
    // Extract restart policy from the crate spec (if any) before running.
    // The spec is inside the .crate archive at +CRATE.SPEC — extract it
    // via a lightweight tar pipe without unpacking the whole archive.
    // For --warm-base runs there is no .crate file; the restart policy
    // (if any) lives in the cloned dataset's +CRATE.SPEC and is honoured
    // by lib/run.cpp once the clone is mounted, but not by this outer
    // restart loop. Operators wanting outer-loop restart should run the
    // jail under a daemon (rc.d) wrapper instead.
    //
    // 1.1.59: `crate run <profile>` resolves to an ordinary -f run on the
    // .crate built from the profile (+ its .local) under
    // ~/.local/share/crate/profiles/ (lib/profile.cpp). Everything below,
    // including the registry entry crated uses for PostStart, sees a
    // plain crate file.
    //
    Args runArgs = args;
    if (!args.runProfile.empty())
      runArgs.runCrateFile = Profile::resolveForRun(args);

    std::unique_ptr<Spec::RestartPolicy> restartPolicy;
    if (!runArgs.runCrateFile.empty()) try {
      auto specYaml = Util::execCommandGetOutput(
        {"/usr/bin/tar", "xf", runArgs.runCrateFile, "-O", "+CRATE.SPEC"},
        "extract spec for restart policy");
      auto specNode = YAML::Load(specYaml);
      if (specNode["restart"] || specNode["restart_policy"]) {
        auto key = specNode["restart"] ? "restart" : "restart_policy";
        restartPolicy = std::make_unique<Spec::RestartPolicy>();
        if (specNode[key].IsScalar()) {
          restartPolicy->policy = specNode[key].as<std::string>();
        } else if (specNode[key].IsMap()) {
          if (specNode[key]["policy"])
            restartPolicy->policy = specNode[key]["policy"].as<std::string>();
          if (specNode[key]["max_retries"])
            restartPolicy->maxRetries = specNode[key]["max_retries"].as<unsigned>();
          if (specNode[key]["delay"])
            restartPolicy->delaySec = specNode[key]["delay"].as<unsigned>();
        }
        // 1.1.46: the embedded spec was validated at create time, but an
        // older .crate may carry a typo — say so instead of "run once".
        const auto &pol = restartPolicy->policy;
        if (pol != "no" && pol != "on-failure" && pol != "always" && pol != "unless-stopped") {
          std::cerr << rang::fg::yellow << "restart policy '" << pol
                    << "' is not one of no/on-failure/always/unless-stopped — treating as 'no'"
                    << rang::style::reset << std::endl;
          restartPolicy->policy = "no";
        }
        if (restartPolicy->delaySec == 0) restartPolicy->delaySec = 1;   // never a tight loop
      }
    } catch (...) {
      // If spec extraction fails, no restart policy — run once.
    }

    unsigned attempt = 0;
    for (;;) {
      attempt++;
      succ = runCrate(runArgs, argc - numArgsProcessed, argv + numArgsProcessed, returnCode);

      if (!restartPolicy || restartPolicy->policy == "no")
        break;

      // 1.1.46: a run that ended because WE were signalled (Ctrl-C,
      // `crate stop`, service stop) must not be restarted — runCrate
      // reports that as 128+signal (lib/run.cpp). The comment below
      // always promised this; the check was missing, so `restart:
      // always` looped forever after Ctrl-C.
      if (returnCode == 128 + SIGINT || returnCode == 128 + SIGTERM) {
        std::cerr << rang::fg::yellow << "restart policy (" << restartPolicy->policy
                  << "): stopped by signal, not restarting" << rang::style::reset << std::endl;
        break;
      }

      // "always" restarts on any exit (except explicit crate stop via SIGTERM)
      // "on-failure" restarts only on non-zero exit
      bool shouldRestart = false;
      if (restartPolicy->policy == "always") {
        shouldRestart = true;
      } else if (restartPolicy->policy == "on-failure") {
        shouldRestart = (returnCode != 0);
      } else if (restartPolicy->policy == "unless-stopped") {
        shouldRestart = true;
      }

      if (!shouldRestart)
        break;

      if (attempt > restartPolicy->maxRetries) {
        std::cerr << rang::fg::yellow << "restart policy: max retries ("
                  << restartPolicy->maxRetries << ") reached, giving up"
                  << rang::style::reset << std::endl;
        break;
      }

      std::cerr << rang::fg::yellow << "restart policy (" << restartPolicy->policy
                << "): restarting container (attempt " << attempt
                << "/" << restartPolicy->maxRetries << ") in "
                << restartPolicy->delaySec << "s..."
                << rang::style::reset << std::endl;

      ::sleep(restartPolicy->delaySec);
    }
    break;
  } case CmdValidate: {
    succ = validateCrateSpec(args);
    break;
  } case CmdSnapshot: {
    succ = snapshotCrate(args);
    break;
  } case CmdList: {
    succ = listCrates(args);
    break;
  } case CmdInfo: {
    succ = infoCrate(args);
    break;
  } case CmdClean: {
    succ = cleanCrates(args);
    break;
  } case CmdConsole: {
    succ = consoleCrate(args, argc - numArgsProcessed, argv + numArgsProcessed);
    break;
  } case CmdExport: {
    succ = exportCrate(args);
    break;
  } case CmdImport: {
    succ = importCrate(args);
    break;
  } case CmdGui: {
    succ = guiCommand(args);
    break;
  } case CmdStack: {
    succ = stackCommand(args);
    break;
  } case CmdStats: {
    succ = statsCrate(args);
    break;
  } case CmdLogs: {
    succ = logsCrate(args);
    break;
  } case CmdStop: {
    succ = stopCrate(args);
    break;
  } case CmdRestart: {
    succ = restartCrate(args);
    break;
  } case CmdTop: {
    succ = topCrate(args);
    break;
  } case CmdInterDns: {
    succ = interDnsCommand(args);
    break;
  } case CmdVpn: {
    succ = vpnCommand(args);
    break;
  } case CmdInspect: {
    succ = inspectCrate(args);
    break;
  } case CmdMigrate: {
    succ = migrateCommand(args);
    break;
  } case CmdBackup: {
    succ = backupCrate(args);
    break;
  } case CmdRestore: {
    succ = restoreCrate(args);
    break;
  } case CmdBackupPrune: {
    succ = backupPruneCrate(args);
    break;
  } case CmdReplicate: {
    succ = replicateCrate(args);
    break;
  } case CmdTemplate: {
    // currently the only subcommand is "warm"
    succ = templateWarmCommand(args);
    break;
  } case CmdRetune: {
    succ = retuneCommand(args);
    break;
  } case CmdThrottle: {
    succ = throttleCommand(args);
    break;
  } case CmdDoctor: {
    succ = doctorCommand(args);
    break;
  } case CmdVmWrap: {
    succ = vmWrapCommand(args);
    break;
  } case CmdProfileFromTrace: {
    succ = profileFromTraceCommand(args, argc - numArgsProcessed, argv + numArgsProcessed);
    break;
  } case CmdAudit: {
    succ = jailAuditCommand(args);
    break;
  } case CmdWrap: {
    succ = wrapCommand(args);
    break;
  } case CmdUpdate: {
    succ = updateCommand(args);
    break;
  } case CmdNone: {
    break; // impossible
  }}
  } catch (const Exception &e) {
    auditOnce(e.what());
    throw;
  } catch (const std::exception &e) {
    auditOnce(std::string("std::exception: ") + e.what());
    throw;
  } catch (...) {
    auditOnce("unknown exception");
    throw;
  }
  auditOnce(succ ? "" : "command returned failure");

  return succ ? returnCode : 1;
}

int main(int argc, char** argv) {
  try {
    return mainGuarded(argc, argv);
  } catch (const Exception &e) {
    std::cerr << rang::fg::red << e.what() << rang::style::reset << std::endl;
    return 1;
  } catch (const std::exception& e) {
    std::cerr << rang::fg::red << "internal error (std::exception): " << e.what() << rang::style::reset << std::endl;
    return 1;
  } catch (...) {
    std::cerr << rang::fg::red << "internal error: unexpected exception caught" << rang::style::reset << std::endl;
    return 1;
  }
}
