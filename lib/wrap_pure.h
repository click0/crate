// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.66 (TODO §17.9, firejail's firecfg): `crate wrap install <profile>`
// puts a launcher in front of a profile so that a program started from
// the shell or from a desktop menu runs in its container:
//
//   ~/.local/bin/<name>                      a two-line sh script:
//                                            exec /usr/local/bin/crate run <profile> -- "$@"
//                                            (the shell finds it before /usr/local/bin/<name>
//                                            when ~/.local/bin leads $PATH)
//   ~/.local/share/applications/crate-<profile>.desktop
//                                            a Desktop Entry with
//                                            Exec=/usr/local/bin/crate run <profile> -- %U
//                                            (--desktop; $XDG_DATA_HOME honoured)
//
// Both files carry a marker naming the profile, and `wrap remove` /
// `wrap list` only touch files that carry it — an operator's own
// ~/.local/bin/firefox is never overwritten (without --force) or removed.
// This module is the text and the paths; the file I/O is lib/wrap.cpp.

#pragma once

#include <string>
#include <vector>

namespace WrapPure {

// ~/.local/bin
std::string binDir(const std::string &home);
// $XDG_DATA_HOME/applications, or ~/.local/share/applications when
// xdgDataHome is empty or not absolute.
std::string applicationsDir(const std::string &home, const std::string &xdgDataHome);
std::string launcherPath(const std::string &home, const std::string &name);
std::string desktopPath(const std::string &home, const std::string &xdgDataHome,
                        const std::string &profile);
// crate-<profile>.desktop
std::string desktopFileName(const std::string &profile);

// A launcher name is a profile-shaped word ([A-Za-z0-9._-], not starting
// with '-' or '.') that is not "crate" itself (the launcher would exec
// itself forever). "" when acceptable.
std::string validateLauncherName(const std::string &name);

// The launcher script. `cratePath` is the crate binary (CRATE_PATH_CRATE),
// `version` the crate that wrote it (for the marker).
std::string renderLauncher(const std::string &profile, const std::string &cratePath,
                           const std::string &version);

// The Desktop Entry. `terminal` = the program has no GUI (the spec names
// no x11/gui), so the entry asks for a terminal; `icon` empty = the
// profile name (the icon theme usually has one for the program).
std::string renderDesktop(const std::string &profile, const std::string &cratePath,
                          const std::string &version, bool terminal,
                          const std::string &icon = "");

// "firefox" -> "Firefox (crate)", "firefox-gpu" -> "Firefox Gpu (crate)".
std::string displayName(const std::string &profile);

// Read the profile back from a file's content. False when the file was
// not written by `crate wrap` (no marker, or a marker naming an invalid
// profile).
bool launcherProfile(const std::string &content, std::string &profileOut);
bool desktopProfile(const std::string &content, std::string &profileOut);

// true when `dir` is one of the ':'-separated entries of `pathEnv`
// (exact match, trailing '/' ignored).
bool pathHasDir(const std::string &pathEnv, const std::string &dir);

// One installed wrapper, for `wrap list`.
struct Entry {
  std::string profile;
  std::string launcher;   // path, "" when none
  std::string desktop;    // path, "" when none
};
// Render the list as aligned text (header + one line per entry); "" for
// an empty list is the caller's business.
std::string renderList(const std::vector<Entry> &entries);

}
