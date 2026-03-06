// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "util.h"
#include "err.h"
#include "misc.h"
#include "commands.h"

#include <rang.hpp>

#include <paths.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>

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

  switch (args.cmd) {
  case CmdCreate: {
    auto spec = parseSpecWithVars(args.createSpec, args.vars);
    // Template merging (§10): merge template spec with user spec
    if (!args.createTemplate.empty()) {
      auto templateSpec = parseSpecWithVars(args.createTemplate, args.vars);
      spec = mergeSpecs(templateSpec, spec);
    }
    spec.validate();
    createCacheDirectoryIfNeeded();
    succ = createCrate(args, spec.preprocess());
    break;
  } case CmdRun: {
    succ = runCrate(args, argc - numArgsProcessed, argv + numArgsProcessed, returnCode);
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
  } case CmdNone: {
    break; // impossible
  }}

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
