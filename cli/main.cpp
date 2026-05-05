// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "util.h"
#include "err.h"
#include "misc.h"
#include "audit.h"
#include "commands.h"

#include <rang.hpp>
#include <yaml-cpp/yaml.h>

#include <paths.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <iostream>
#include <string>

static int mainGuarded(int argc, char** argv) {

  //
  // can only run as a privileged user because we need to run chroot(8) and need to create jails
  //
  if (::geteuid() != 0) {
    std::cerr << rang::fg::red << "crate has to run as a regular user setuid to root"
                               << " (you ran it just as a regular user with UID=" << ::geteuid() << ")"
                               << rang::style::reset << std::endl;
    return 1;
  }
  if (::getuid() == 0) {
    std::cerr << rang::fg::red << "crate has to run as a regular user setuid to root"
                               << " (you ran it just as root, this isn't yet supported)"
                               << rang::style::reset << std::endl;
    return 1;
  }

  //
  // Sanitize environment for setuid safety (CWE-426, CWE-250).
  // Clear all inherited environment variables and rebuild with safe defaults.
  // This prevents PATH manipulation, LD_PRELOAD injection, and other env-based attacks.
  //
  bool envNoColor = false;
  {
    const char* term    = ::getenv("TERM");
    const char* display = ::getenv("DISPLAY");
    const char* wayland = ::getenv("WAYLAND_DISPLAY");
    const char* lang    = ::getenv("LANG");
    const char* xauth   = ::getenv("XAUTHORITY");
    const char* nocolor = ::getenv("NO_COLOR");
    envNoColor = (nocolor != nullptr);

    extern char **environ;
    static char *empty_env[] = { nullptr };
    environ = empty_env;

    ::setenv("PATH", _PATH_DEFPATH, 1);
    ::setenv("HOME", "/root", 1);
    ::setenv("SHELL", _PATH_BSHELL, 1);
    if (term)    ::setenv("TERM", term, 1);
    if (display) ::setenv("DISPLAY", display, 1);
    if (wayland) ::setenv("WAYLAND_DISPLAY", wayland, 1);
    if (lang)    ::setenv("LANG", lang, 1);
    if (xauth)   ::setenv("XAUTHORITY", xauth, 1);
    if (envNoColor) ::setenv("NO_COLOR", "", 1);
  }

  //
  // Can't run in jail because we need to create jails ourselves
  //
  if (Util::getSysctlInt("security.jail.jailed") != 0) {
    std::cerr << rang::fg::red << "crate can not run in jail" << rang::style::reset << std::endl;
    return 1;
  }

  //
  // adjust uid, make it equal to euid
  //
  Util::ckSyscallError(::setuid(::geteuid()), "setuid", "geteuid()");

  //
  // create the jails directory if it doesn't yet exist
  //
  createJailsDirectoryIfNeeded();

  //
  // parse the arguments
  //
  unsigned numArgsProcessed = 0;
  Args args = parseArguments(argc, argv, numArgsProcessed);
  args.validate();

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

    auto spec = parseSpecWithVars(specPath, args.vars);
    // Template merging (§10): merge template spec with user spec
    if (!templatePath.empty()) {
      auto templateSpec = parseSpecWithVars(templatePath, args.vars);
      spec = mergeSpecs(templateSpec, spec);
    }
    spec.validate();
    createCacheDirectoryIfNeeded();
    succ = createCrate(args, spec.preprocess());

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
    std::unique_ptr<Spec::RestartPolicy> restartPolicy;
    if (!args.runCrateFile.empty()) try {
      auto specYaml = Util::execCommandGetOutput(
        {"/usr/bin/tar", "xf", args.runCrateFile, "-O", "+CRATE.SPEC"},
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
      }
    } catch (...) {
      // If spec extraction fails, no restart policy — run once.
    }

    unsigned attempt = 0;
    for (;;) {
      attempt++;
      succ = runCrate(args, argc - numArgsProcessed, argv + numArgsProcessed, returnCode);

      if (!restartPolicy || restartPolicy->policy == "no")
        break;

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
