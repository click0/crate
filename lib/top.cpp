// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate top` — live, htop-style resource monitor for crate-managed
// jails. Polls JailQuery + RCTL once per second and re-renders the
// table. Pure formatting/arithmetic lives in lib/top_pure.cpp; this
// file is the I/O glue.
//

#include "args.h"
#include "top_pure.h"
#include "jail_query.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

namespace {

std::atomic<bool> g_stop{false};

void onSignal(int) { g_stop.store(true); }

// One previous CPU sample per JID for percentage calculation.
struct PrevSample {
  uint64_t cputime = 0;
  std::chrono::steady_clock::time_point ts;
};

uint64_t parseRctlNumber(const std::string &rctlOutput, const std::string &key) {
  // RCTL emits "key=value\n" lines. Linear scan is fine — output is small.
  size_t i = 0;
  while (i < rctlOutput.size()) {
    auto nl = rctlOutput.find('\n', i);
    if (nl == std::string::npos) nl = rctlOutput.size();
    auto line = rctlOutput.substr(i, nl - i);
    i = nl + 1;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    if (line.substr(0, eq) == key) {
      try { return std::stoull(line.substr(eq + 1)); } catch (...) { return 0; }
    }
  }
  return 0;
}

// Put stdin into non-blocking, non-canonical mode so we can check
// for 'q' presses without ncurses. Saves and restores the previous
// settings on exit.
class RawStdin {
  bool changed = false;
  termios prev{};
  int prevFlags = 0;
public:
  RawStdin() {
    if (!::isatty(STDIN_FILENO)) return;
    if (::tcgetattr(STDIN_FILENO, &prev) != 0) return;
    termios cur = prev;
    cur.c_lflag &= ~(ICANON | ECHO);
    cur.c_cc[VMIN] = 0;
    cur.c_cc[VTIME] = 0;
    if (::tcsetattr(STDIN_FILENO, TCSANOW, &cur) != 0) return;
    prevFlags = ::fcntl(STDIN_FILENO, F_GETFL, 0);
    ::fcntl(STDIN_FILENO, F_SETFL, prevFlags | O_NONBLOCK);
    changed = true;
  }
  ~RawStdin() {
    if (!changed) return;
    ::tcsetattr(STDIN_FILENO, TCSANOW, &prev);
    ::fcntl(STDIN_FILENO, F_SETFL, prevFlags);
  }
};

bool quitKeyPressed() {
  if (!::isatty(STDIN_FILENO)) return false;
  char c;
  while (::read(STDIN_FILENO, &c, 1) == 1) {
    if (c == 'q' || c == 'Q' || c == 0x03 /* Ctrl-C */)
      return true;
  }
  return false;
}

} // anon

bool topCrate(const Args &/*args*/) {
  // Install signal handlers so Ctrl-C / SIGTERM exit cleanly.
  ::signal(SIGINT,  onSignal);
  ::signal(SIGTERM, onSignal);
  ::signal(SIGHUP,  onSignal);

  RawStdin rawStdin;

  // Hide cursor and switch to alternate screen so we don't trash
  // scrollback. Use printf so the escapes go through normal stdio
  // buffering (flushed below).
  bool useEscapes = ::isatty(STDOUT_FILENO);
  if (useEscapes) {
    std::cout << "\x1b[?1049h"  // alternate screen
              << "\x1b[?25l"    // hide cursor
              << std::flush;
  }

  std::map<int, PrevSample> prev;
  TopPure::ColWidths cw;

  auto cleanup = [&]() {
    if (useEscapes) {
      std::cout << "\x1b[?25h"   // show cursor
                << "\x1b[?1049l" // leave alternate screen
                << std::flush;
    }
  };

  try {
    while (!g_stop.load()) {
      auto jails = JailQuery::getAllJails(true /*crateOnly*/);

      auto now = std::chrono::steady_clock::now();
      std::vector<TopPure::Row> rows;
      rows.reserve(jails.size());
      for (auto &j : jails) {
        TopPure::Row r;
        r.name = j.name;
        r.jid = j.jid;
        r.ip = j.ip4;

        std::string rctlOut;
        try {
          rctlOut = Util::execCommandGetOutput(
            {CRATE_PATH_RCTL, "-u", "jail:" + std::to_string(j.jid)},
            "query RCTL usage");
        } catch (...) {
          // RCTL not available or jail vanished mid-poll — show what we have.
        }
        TopPure::applyRctlOutput(rctlOut, r);

        uint64_t cputime = parseRctlNumber(rctlOut, "cputime");
        auto it = prev.find(j.jid);
        if (it != prev.end()) {
          double dt = std::chrono::duration<double>(now - it->second.ts).count();
          r.cpuPct = TopPure::cpuPercent(it->second.cputime, cputime, dt);
        }
        prev[j.jid] = {cputime, now};

        rows.push_back(r);
      }

      // Drop stale entries for jails that have exited.
      for (auto it = prev.begin(); it != prev.end();) {
        bool alive = false;
        for (auto &j : jails) if (j.jid == it->first) { alive = true; break; }
        if (alive) ++it; else it = prev.erase(it);
      }

      if (useEscapes) {
        std::cout << "\x1b[H"      // home
                  << "\x1b[2J"     // clear screen
                  << rang::style::bold << "crate top" << rang::style::reset
                  << "    "
                  << "(press 'q' to quit)\n\n"
                  << TopPure::formatFrame(rows, cw)
                  << std::flush;
      } else {
        // Non-tty: emit one frame and exit. Useful for scripted runs.
        std::cout << TopPure::formatFrame(rows, cw) << "\n";
        break;
      }

      // Sleep ~1s but wake early if the user presses q/Q/Ctrl-C.
      for (int i = 0; i < 10 && !g_stop.load(); i++) {
        ::usleep(100000); // 100ms
        if (quitKeyPressed()) { g_stop.store(true); break; }
      }
    }
  } catch (...) {
    cleanup();
    throw;
  }
  cleanup();
  return true;
}
