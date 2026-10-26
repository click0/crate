// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate wrap install|remove|list` (1.1.66, TODO §17.9 — firejail's
// firecfg). Writes, deletes and lists the per-user launchers that put a
// profile's container in front of a program: ~/.local/bin/<name> and,
// with --desktop, ~/.local/share/applications/crate-<profile>.desktop.
// The text and the paths are WrapPure; this file is the file I/O and the
// profile lookup. Everything happens in the invoking user's home; no
// privilege is needed or used.
//

#include "args.h"
#include "commands.h"
#include "wrap_pure.h"
#include "profile_pure.h"
#include "spec.h"
#include "pathnames.h"
#include "version.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define ERR(msg...) ERR2("wrap", msg)

namespace {

std::string readFile(const std::string &path, size_t maxBytes = 64 * 1024) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return "";
  std::string s;
  s.resize(maxBytes);
  in.read(&s[0], (std::streamsize)maxBytes);
  s.resize((size_t)in.gcount());
  return s;
}

// Write `content` to `path` through a temp file + rename so a reader
// never sees a half-written launcher.
void writeAtomic(const std::string &path, const std::string &content, mode_t mode) {
  const std::string tmp = path + ".tmp." + std::to_string(::getpid());
  Util::Fs::writeFile(content, tmp);
  Util::Fs::chmod(tmp, mode);
  if (::rename(tmp.c_str(), path.c_str()) != 0) {
    int e = errno;
    ::unlink(tmp.c_str());
    ERR("cannot write " << path << ": " << ::strerror(e))
  }
}

std::string env(const char *name) {
  const char *v = ::getenv(name);
  return v ? v : "";
}

std::string homeDir() {
  const auto home = Util::Fs::getUserHomeDir();
  if (home.empty() || home[0] != '/')
    ERR("cannot determine the invoking user's home directory (getpwuid)")
  return home;
}

// The profile's spec, or "" with the searched paths in `searched`.
std::string findProfile(const std::string &home, const std::string &name, std::string &searched) {
  const auto candidates = ProfilePure::specSearchPaths(home, name);
  std::ostringstream s;
  for (size_t i = 0; i < candidates.size(); i++) {
    if (Util::Fs::fileExists(candidates[i])) return candidates[i];
    s << (i ? ", " : "") << candidates[i];
  }
  searched = s.str();
  return "";
}

// A GUI program gets Terminal=false; anything else asks for a terminal.
// A spec that does not parse here (e.g. unresolved ${VAR}) is treated
// as a GUI one when it mentions x11/gui at all.
bool specIsGui(const std::string &specPath) {
  try {
    Spec spec = parseSpec(specPath);
    return spec.x11Options || spec.guiOptions || spec.optionExists("x11") || spec.optionExists("gl");
  } catch (...) {
    const std::string text = readFile(specPath);
    return text.find("x11") != std::string::npos || text.find("gui") != std::string::npos;
  }
}

// Is `path` a launcher / desktop file of ours? Sets `profile` when so.
bool ownsLauncher(const std::string &path, std::string &profile) {
  if (!Util::Fs::fileExists(path)) return false;
  return WrapPure::launcherProfile(readFile(path, 4096), profile);
}
bool ownsDesktop(const std::string &path, std::string &profile) {
  if (!Util::Fs::fileExists(path)) return false;
  return WrapPure::desktopProfile(readFile(path, 16 * 1024), profile);
}

void ensureDir(const std::string &dir) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) ERR("cannot create " << dir << ": " << ec.message())
}

bool wrapInstall(const Args &args) {
  const auto home = homeDir();
  const auto &profile = args.wrapProfile;
  const std::string name = args.wrapName.empty() ? profile : args.wrapName;

  std::string searched;
  const std::string specPath = findProfile(home, profile, searched);
  if (specPath.empty())
    ERR("profile '" << profile << "' not found; searched " << searched
        << " — a launcher needs a profile `crate run " << profile << "` can find")

  const std::string xdg = env("XDG_DATA_HOME");
  const std::string launcher = WrapPure::launcherPath(home, name);
  const std::string desktop  = WrapPure::desktopPath(home, xdg, profile);
  bool wrote = false;

  if (!args.wrapNoLauncher) {
    std::string owner;
    if (Util::Fs::fileExists(launcher) && !ownsLauncher(launcher, owner) && !args.wrapForce)
      ERR(launcher << " exists and was not written by `crate wrap`; use --force to replace it, or --name for another name")
    ensureDir(WrapPure::binDir(home));
    writeAtomic(launcher, WrapPure::renderLauncher(profile, CRATE_PATH_CRATE, CRATE_VERSION), 0755);
    std::cout << rang::fg::green << "installed " << rang::style::reset << launcher
              << "  ->  crate run " << profile << " -- \"$@\"" << std::endl;
    if (!owner.empty() && owner != profile)
      std::cout << rang::fg::yellow << "  (it pointed at profile '" << owner << "' before)"
                << rang::style::reset << std::endl;
    if (!WrapPure::pathHasDir(env("PATH"), WrapPure::binDir(home)))
      std::cout << rang::fg::yellow << "note: " << WrapPure::binDir(home)
                << " is not in $PATH; add it in front of /usr/local/bin for `" << name
                << "` to start the container" << rang::style::reset << std::endl;
    wrote = true;
  }

  if (args.wrapDesktop) {
    std::string owner;
    if (Util::Fs::fileExists(desktop) && !ownsDesktop(desktop, owner) && !args.wrapForce)
      ERR(desktop << " exists and was not written by `crate wrap`; use --force to replace it")
    ensureDir(WrapPure::applicationsDir(home, xdg));
    const bool gui = specIsGui(specPath);
    writeAtomic(desktop, WrapPure::renderDesktop(profile, CRATE_PATH_CRATE, CRATE_VERSION, !gui, args.wrapIcon), 0644);
    std::cout << rang::fg::green << "installed " << rang::style::reset << desktop
              << "  (" << WrapPure::displayName(profile) << (gui ? "" : ", Terminal=true") << ")" << std::endl;
    wrote = true;
  }

  if (!wrote)
    ERR("nothing to install: --no-launcher without --desktop")
  return true;
}

bool wrapRemove(const Args &args) {
  const auto home = homeDir();
  const auto &profile = args.wrapProfile;
  const std::string name = args.wrapName.empty() ? profile : args.wrapName;
  const std::string xdg = env("XDG_DATA_HOME");
  unsigned removed = 0;

  for (const auto &path : {WrapPure::launcherPath(home, name), WrapPure::desktopPath(home, xdg, profile)}) {
    if (!Util::Fs::fileExists(path)) continue;
    std::string owner;
    const bool ours = (path == WrapPure::launcherPath(home, name)) ? ownsLauncher(path, owner) : ownsDesktop(path, owner);
    if (!ours) {
      std::cerr << rang::fg::yellow << "kept " << path << ": not written by `crate wrap`"
                << rang::style::reset << std::endl;
      continue;
    }
    if (owner != profile && args.wrapName.empty()) {
      std::cerr << rang::fg::yellow << "kept " << path << ": it wraps profile '" << owner
                << "', not '" << profile << "'" << rang::style::reset << std::endl;
      continue;
    }
    Util::Fs::unlink(path);
    std::cout << rang::fg::green << "removed " << rang::style::reset << path << std::endl;
    removed++;
  }
  if (removed == 0)
    std::cout << "nothing installed for profile '" << profile << "'" << std::endl;
  return true;
}

bool wrapList(const Args &) {
  const auto home = homeDir();
  const std::string xdg = env("XDG_DATA_HOME");
  std::vector<WrapPure::Entry> entries;
  auto entryFor = [&](const std::string &profile) -> WrapPure::Entry& {
    for (auto &e : entries) if (e.profile == profile) return e;
    entries.push_back({profile, "", ""});
    return entries.back();
  };

  std::error_code ec;
  for (const auto &dirEntry : std::filesystem::directory_iterator(WrapPure::binDir(home), ec)) {
    if (!dirEntry.is_regular_file(ec)) continue;
    std::string p;
    if (ownsLauncher(dirEntry.path().string(), p)) {
      auto &e = entryFor(p);
      e.launcher += (e.launcher.empty() ? "" : ", ") + dirEntry.path().string();
    }
  }
  ec.clear();
  for (const auto &dirEntry : std::filesystem::directory_iterator(WrapPure::applicationsDir(home, xdg), ec)) {
    if (!dirEntry.is_regular_file(ec)) continue;
    if (dirEntry.path().extension() != ".desktop") continue;
    std::string p;
    if (ownsDesktop(dirEntry.path().string(), p)) entryFor(p).desktop = dirEntry.path().string();
  }

  if (entries.empty()) {
    std::cout << "no launchers installed by `crate wrap` in " << WrapPure::binDir(home)
              << " or " << WrapPure::applicationsDir(home, xdg) << std::endl;
    return true;
  }
  std::sort(entries.begin(), entries.end(),
            [](const WrapPure::Entry &a, const WrapPure::Entry &b) { return a.profile < b.profile; });
  std::cout << WrapPure::renderList(entries);
  return true;
}

} // namespace

bool wrapCommand(const Args &args) {
  if (args.wrapSubcmd == "install") return wrapInstall(args);
  if (args.wrapSubcmd == "remove")  return wrapRemove(args);
  if (args.wrapSubcmd == "list")    return wrapList(args);
  ERR("unknown wrap subcommand '" << args.wrapSubcmd << "' (install, remove, list)")
}
