// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// REST API routes — F1 read-only + F2 management endpoints.

#include "routes.h"
#include "auth.h"
#include "metrics.h"
#include "rate_limit.h"
#include "routes_pure.h"
#include "transfer_pure.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include "args.h"
#include "commands.h"
#include "gui_registry.h"
#include "jail_query.h"
#include "locs.h"
#include "pathnames.h"
#include "util.h"
#include "zfs_ops.h"

#include <openssl/evp.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __FreeBSD__
#include <sys/event.h>   // 0.8.5: kqueue/kevent for log-stream tail
#include <sys/types.h>
#include <sys/time.h>
#endif

#include <atomic>
#include <ctime>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>

namespace Crated {

// --- Per-endpoint rate limiter ---
//
// 0.8.8: thin wrapper over the shared `RateLimit::check` module
// (introduced in 0.7.15 for control sockets). Behaviour is
// identical to the prior local impl — same {clientId, endpoint}
// key, same per-second counter, same cap constants — but both
// API planes now share state and any future tuning lands in one
// place.
//
// Constants moved to daemon/rate_limit.h:
//   RateLimit::kMutating  (10 req/s)  — formerly RATE_LIMIT_MUTATING
//   RateLimit::kRead      (100 req/s) — formerly RATE_LIMIT_READ

// 0.8.4: cap the number of concurrent log-streaming clients so a
// burst of polling agents (Prometheus exporters, log shippers,
// curl-in-a-tight-loop scripts) cannot exhaust the daemon's
// thread pool. The real fix — single bg thread + kqueue
// multiplex — is tracked as a follow-up; this counter is the
// operational guard until then.
static std::atomic<int> g_streamingClients{0};
static constexpr int     kMaxStreamingClients = 32;

static bool checkRateLimit(const std::string &clientId, const std::string &endpoint,
                           int maxPerSecond) {
  // Same key shape ("<clientId>|<endpoint>") as the prior local
  // impl so existing buckets carry over cleanly across hot-reload.
  return RateLimit::check(clientId + "|" + endpoint, maxPerSecond);
}

static std::string getClientId(const httplib::Request &req) {
  auto addr = req.get_header_value("REMOTE_ADDR");
  return addr.empty() ? "unix" : addr;
}

// Cap constants live in daemon/rate_limit.h since 0.7.15.
// (Pre-0.8.8 this file had local constexpr aliases; removed in
// the routes.cpp rate-limit refactor.)

// --- JSON helpers ---

static void jsonOk(httplib::Response &res, const std::string &data) {
  res.set_content("{\"status\":\"ok\",\"data\":" + data + "}", "application/json");
}

static void jsonError(httplib::Response &res, int code, const std::string &msg) {
  res.status = code;
  res.set_content("{\"status\":\"error\",\"error\":\"" + msg + "\"}", "application/json");
}

// --- GET /api/v1/containers ---
// Returns JSON array of running containers (delegates to jls).

static void handleListContainers(const httplib::Request &, httplib::Response &res) {
  try {
    auto jlsOutput = Util::execCommandGetOutput(
      {CRATE_PATH_JLS, "--libxo", "json"}, "list jails");
    jsonOk(res, jlsOutput);
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- GET /api/v1/containers/{name}/gui ---

static void handleContainerGui(const httplib::Request &req, httplib::Response &res) {
  auto name = req.path_params.at("name");
  try {
    auto reg = Ctx::GuiRegistry::lock();
    auto *entry = reg->findByTarget(name);
    if (!entry) {
      reg->unlock();
      jsonError(res, 404, "no GUI session for container '" + name + "'");
      return;
    }
    auto e = *entry;
    reg->unlock();

    std::ostringstream ss;
    ss << "{\"display\":" << e.displayNum
       << ",\"pid\":" << e.ownerPid
       << ",\"xpid\":" << e.xServerPid
       << ",\"vnc_port\":" << e.vncPort
       << ",\"ws_port\":" << e.wsPort
       << ",\"mode\":\"" << e.mode << "\""
       << ",\"jail\":\"" << e.jailName << "\""
       << "}";
    jsonOk(res, ss.str());
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- GET /api/v1/host ---

static void handleHostInfo(const httplib::Response &, httplib::Response &res) {
  try {
    auto osrelease = Util::getSysctlString("kern.osrelease");
    auto hostname = Util::getSysctlString("kern.hostname");
    auto machine = Util::getSysctlString("hw.machine");
    auto ncpu = Util::getSysctlInt("hw.ncpu");
    auto physmem = Util::getSysctlInt("hw.physmem");

    std::ostringstream ss;
    ss << "{\"hostname\":\"" << hostname << "\""
       << ",\"osrelease\":\"" << osrelease << "\""
       << ",\"machine\":\"" << machine << "\""
       << ",\"ncpu\":" << ncpu
       << ",\"physmem\":" << physmem
       << "}";
    jsonOk(res, ss.str());
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- GET /metrics ---

static void handleMetrics(const httplib::Request &, httplib::Response &res) {
  res.set_content(Crated::collectPrometheusMetrics(), "text/plain; version=0.0.4");
}

// --- F2: GET /api/v1/containers/:name/stats ---

static void handleContainerStats(const httplib::Request &req, httplib::Response &res,
                                  const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "viewer", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto jail = JailQuery::getJailByName(name);
  if (!jail) {
    try {
      int jid = std::stoi(name);
      jail = JailQuery::getJailByJid(jid);
    } catch (...) {}
  }
  if (!jail) {
    jsonError(res, 404, "container not found");
    return;
  }

  try {
    auto jidStr = std::to_string(jail->jid);
    auto rctlOutput = Util::execCommandGetOutput(
      {CRATE_PATH_RCTL, "-u", "jail:" + jidStr}, "query RCTL usage");

    std::map<std::string, std::string> usage;
    std::istringstream is(rctlOutput);
    std::string line;
    while (std::getline(is, line)) {
      auto eq = line.find('=');
      if (eq != std::string::npos)
        usage[line.substr(0, eq)] = line.substr(eq + 1);
    }

    std::ostringstream ss;
    ss << "{\"name\":\"" << jail->name << "\""
       << ",\"jid\":" << jail->jid
       << ",\"ip\":\"" << jail->ip4 << "\"";
    for (auto &kv : usage)
      ss << ",\"" << kv.first << "\":" << kv.second;
    ss << "}";
    jsonOk(res, ss.str());
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- F2: POST /api/v1/containers/:name/stop ---

static void handleContainerStop(const httplib::Request &req, httplib::Response &res,
                                 const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "admin", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto jail = JailQuery::getJailByName(name);
  if (!jail) {
    try {
      int jid = std::stoi(name);
      jail = JailQuery::getJailByJid(jid);
    } catch (...) {}
  }
  if (!jail) {
    jsonError(res, 404, "container not found");
    return;
  }

  try {
    Util::execCommand({CRATE_PATH_JEXEC, std::to_string(jail->jid),
                       "/bin/kill", "-TERM", "-1"},
      "send SIGTERM to jail processes");
  } catch (...) {}

  // Wait up to 10 seconds for jail to exit
  for (int i = 0; i < 10; i++) {
    auto check = JailQuery::getJailByJid(jail->jid);
    if (!check) {
      jsonOk(res, "{\"stopped\":true,\"name\":\"" + jail->name + "\"}");
      return;
    }
    ::sleep(1);
  }

  // Force kill
  try {
    Util::execCommand({CRATE_PATH_JEXEC, std::to_string(jail->jid),
                       "/bin/kill", "-KILL", "-1"},
      "send SIGKILL to jail processes");
    ::sleep(1);
    auto still = JailQuery::getJailByJid(jail->jid);
    if (still) {
      Util::execCommand({CRATE_PATH_JAIL, "-r", std::to_string(jail->jid)},
        "force remove jail");
    }
  } catch (...) {}

  jsonOk(res, "{\"stopped\":true,\"name\":\"" + jail->name + "\",\"forced\":true}");
}

// --- F2: POST /api/v1/containers/:name/start ---

static void handleContainerStart(const httplib::Request &req, httplib::Response &res,
                                  const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "admin", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }


  // Check if already running
  auto jail = JailQuery::getJailByName(name);
  if (jail) {
    jsonError(res, 409, "container already running");
    return;
  }

  // Look for saved .crate file
  auto crateFile = "/var/run/crate/" + name + ".crate";
  if (!Util::Fs::fileExists(crateFile)) {
    jsonError(res, 404, "no saved .crate file for '" + name + "'");
    return;
  }

  try {
    Args runArgs;
    runArgs.cmd = CmdRun;
    runArgs.runCrateFile = crateFile;
    int returnCode = 0;
    if (runCrate(runArgs, 0, nullptr, returnCode)) {
      jsonOk(res, "{\"started\":true,\"name\":\"" + name + "\"}");
    } else {
      jsonError(res, 500, "failed to start container");
    }
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- F2: DELETE /api/v1/containers/:name ---

static void handleContainerDestroy(const httplib::Request &req, httplib::Response &res,
                                    const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "admin", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }


  // Stop if running
  auto jail = JailQuery::getJailByName(name);
  if (jail) {
    try {
      Util::execCommand({CRATE_PATH_JEXEC, std::to_string(jail->jid),
                         "/bin/kill", "-KILL", "-1"},
        "kill jail processes");
      ::sleep(1);
      Util::execCommand({CRATE_PATH_JAIL, "-r", std::to_string(jail->jid)},
        "remove jail");
    } catch (...) {}
  }

  jsonOk(res, "{\"destroyed\":true,\"name\":\"" + name + "\"}");
}

// --- Route registration ---

// --- F2: GET /api/v1/containers/:name/logs ---
// Supports ?follow=true for chunked streaming (long-poll).

static void handleContainerLogs(const httplib::Request &req, httplib::Response &res,
                                 const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "viewer", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto jail = JailQuery::getJailByName(name);
  if (!jail) {
    try {
      int jid = std::stoi(name);
      jail = JailQuery::getJailByJid(jid);
    } catch (...) {}
  }
  if (!jail) {
    jsonError(res, 404, "container not found");
    return;
  }

  // Determine log file path (convention: /var/log/crate/<name>/console.log)
  auto logPath = "/var/log/crate/" + jail->name + "/console.log";

  auto followParam = req.get_param_value("follow");
  bool follow = (followParam == "true" || followParam == "1");

  auto tailParam = req.get_param_value("tail");
  int tailLines = 100; // default
  if (!tailParam.empty()) {
    try { tailLines = std::stoi(tailParam); } catch (...) {}
  }

  if (!follow) {
    // Non-streaming: read last N lines and return as JSON
    try {
      auto output = Util::execCommandGetOutput(
        {"/usr/bin/tail", "-n", std::to_string(tailLines), logPath},
        "read container log");
      // Return as JSON with log lines
      std::ostringstream ss;
      ss << "{\"name\":\"" << jail->name << "\",\"log\":\"";
      for (char c : output) {
        if (c == '"') ss << "\\\"";
        else if (c == '\\') ss << "\\\\";
        else if (c == '\n') ss << "\\n";
        else if (c == '\r') ss << "\\r";
        else if (c == '\t') ss << "\\t";
        else ss << c;
      }
      ss << "\"}";
      jsonOk(res, ss.str());
    } catch (const std::exception &e) {
      jsonError(res, 500, e.what());
    }
    return;
  }

  // Streaming mode: chunked transfer encoding with a polling tail-f
  // loop inside the chunked content provider. One server thread per
  // active streaming client.
  //
  // 0.8.4: bounded concurrency via g_streamingClients (cap
  // kMaxStreamingClients=32). Beyond the cap we return HTTP 503
  // with Retry-After so well-behaved clients back off instead of
  // queueing on the daemon's thread pool. Underlying kqueue/epoll
  // multiplex refactor remains tracked as future work.

  if (g_streamingClients.load() >= kMaxStreamingClients) {
    res.status = 503;
    res.set_header("Retry-After", "5");
    jsonError(res, 503,
      "log-stream concurrency limit reached ("
      + std::to_string(kMaxStreamingClients)
      + " clients); retry shortly");
    return;
  }
  g_streamingClients.fetch_add(1);

  res.set_header("X-Content-Type-Options", "nosniff");
  res.set_header("Cache-Control", "no-cache");

  res.set_chunked_content_provider(
    "text/plain",
    [logPath, name](size_t /*offset*/, httplib::DataSink &sink) -> bool {
      // Open log file and seek to end, then watch for new lines
      std::ifstream ifs(logPath, std::ios::ate);
      if (!ifs.is_open()) {
        sink.done();
        return false;
      }

      // First, send last 10 lines as initial context
      // Seek backwards to find 10 newlines
      auto endPos = ifs.tellg();
      int newlines = 0;
      std::streamoff pos = endPos;
      while (pos > 0 && newlines < 10) {
        pos--;
        ifs.seekg(pos);
        if (ifs.peek() == '\n')
          newlines++;
      }
      if (pos > 0)
        ifs.seekg(pos + std::streamoff(1));
      else
        ifs.seekg(0);

      std::string line;
      while (std::getline(ifs, line)) {
        line += "\n";
        if (!sink.write(line.c_str(), line.size()))
          return false;
      }

      // 0.8.5: tail loop — block on kqueue(2) for new bytes instead
      // of busy-waiting with usleep(500ms). Each streaming client
      // gets its own kqueue fd watching its own log file. Wakeup is
      // immediate when the log is appended; 1s timeout ensures we
      // periodically check whether the client disconnected (sink
      // write returns false) even on quiet logs.
      //
      // Linux fallback (dev environment only — crated runs on
      // FreeBSD): no kqueue, keep the 500ms poll.
#ifdef __FreeBSD__
      int kqFd = ::kqueue();
      int watchFd = -1;
      if (kqFd >= 0) {
        watchFd = ::open(logPath.c_str(), O_RDONLY | O_CLOEXEC);
        if (watchFd < 0) {
          ::close(kqFd);
          kqFd = -1;
        } else {
          struct kevent ev;
          EV_SET(&ev, watchFd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
                 NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME,
                 0, nullptr);
          if (::kevent(kqFd, &ev, 1, nullptr, 0, nullptr) < 0) {
            ::close(watchFd); watchFd = -1;
            ::close(kqFd);    kqFd    = -1;
          }
        }
      }
      // RAII-style closer so any return path frees both fds.
      struct FdCloser {
        int *kq; int *wf;
        ~FdCloser() {
          if (*wf >= 0) ::close(*wf);
          if (*kq >= 0) ::close(*kq);
        }
      } closer{&kqFd, &watchFd};
#endif
      ifs.clear(); // clear EOF flag
      for (;;) {
        while (std::getline(ifs, line)) {
          line += "\n";
          if (!sink.write(line.c_str(), line.size()))
            return false; // client disconnected
        }
        ifs.clear();
#ifdef __FreeBSD__
        if (kqFd >= 0) {
          struct timespec timeout{1, 0};  // 1s — also forces a
                                          // periodic disconnect check.
          struct kevent triggered;
          int n = ::kevent(kqFd, nullptr, 0, &triggered, 1, &timeout);
          // 0.8.12: handle log rotation (NOTE_DELETE | NOTE_RENAME).
          // Old fd now points at the renamed/deleted inode; the new
          // file (logrotate created /var/log/crate/<jail>/console.log
          // again) lives at the same path. Close + re-open + re-watch.
          //
          // Brief sleep before re-open: logrotate typically does
          // rename-old, then-create-new in two syscalls; if we re-
          // open in the gap we'd hit ENOENT. 50ms is a generous
          // safety margin without being operator-visible.
          if (n > 0
              && (triggered.fflags & (NOTE_DELETE | NOTE_RENAME))) {
            ::usleep(50000);
            ::close(watchFd); watchFd = -1;
            for (int i = 0; i < 20 && watchFd < 0; i++) {
              watchFd = ::open(logPath.c_str(), O_RDONLY | O_CLOEXEC);
              if (watchFd < 0) ::usleep(50000);  // up to 1s total
            }
            if (watchFd < 0) {
              // Rotator never created the new file. End the stream
              // cleanly so client can re-curl manually.
              return false;
            }
            // Re-register kqueue filter on the new fd.
            struct kevent ev;
            EV_SET(&ev, watchFd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
                   NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME,
                   0, nullptr);
            (void)::kevent(kqFd, &ev, 1, nullptr, 0, nullptr);
            // Reset the ifstream to the new file from start.
            ifs.close();
            ifs.open(logPath, std::ios::in);
            if (!ifs.is_open()) return false;
          }
        } else {
          ::usleep(500000);
        }
#else
        ::usleep(500000);
#endif
      }
      // Unreachable; streaming ends when client disconnects.
    },
    [](bool /*success*/) {
      // 0.8.4: release the streaming-clients counter slot whether
      // the stream finished cleanly (client disconnected) or
      // erroed out. Any path that aborts this provider eventually
      // gets here.
      g_streamingClients.fetch_sub(1);
    }
  );
}

// --- F2: POST /api/v1/containers/:name/restart ---

static void handleContainerRestart(const httplib::Request &req, httplib::Response &res,
                                    const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "admin", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto jail = JailQuery::getJailByName(name);

  // Stop phase: send SIGTERM, wait up to 10s, fall back to SIGKILL.
  if (jail) {
    try {
      Util::execCommand({CRATE_PATH_JEXEC, std::to_string(jail->jid),
                         "/bin/kill", "-TERM", "-1"},
        "send SIGTERM to jail processes");
    } catch (...) {}
    bool gone = false;
    for (int i = 0; i < 10; i++) {
      auto check = JailQuery::getJailByJid(jail->jid);
      if (!check) { gone = true; break; }
      ::sleep(1);
    }
    if (!gone) {
      try {
        Util::execCommand({CRATE_PATH_JEXEC, std::to_string(jail->jid),
                           "/bin/kill", "-KILL", "-1"},
          "force kill jail processes");
        ::sleep(1);
        auto still = JailQuery::getJailByJid(jail->jid);
        if (still) {
          Util::execCommand({CRATE_PATH_JAIL, "-r", std::to_string(jail->jid)},
            "force remove jail");
        }
      } catch (...) {}
    }
  }

  // Start phase: must have a saved .crate file.
  auto crateFile = "/var/run/crate/" + name + ".crate";
  if (!Util::Fs::fileExists(crateFile)) {
    jsonError(res, 404, "no saved .crate file for '" + name + "'; container stopped but cannot restart");
    return;
  }
  try {
    Args runArgs;
    runArgs.cmd = CmdRun;
    runArgs.runCrateFile = crateFile;
    int returnCode = 0;
    if (runCrate(runArgs, 0, nullptr, returnCode)) {
      jsonOk(res, "{\"restarted\":true,\"name\":\"" + name + "\"}");
    } else {
      jsonError(res, 500, "failed to start container after stop");
    }
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- Snapshot helpers ---

static std::string datasetForJail(const std::string &name) {
  // The snapshot endpoints accept either a running jail name or a dataset
  // name. If a running jail matches, derive its dataset from the path;
  // otherwise treat the URL parameter as a dataset name as-is, mirroring
  // how the CLI's snapshot subcommand operates on raw datasets.
  auto jail = JailQuery::getJailByName(name);
  if (jail)
    return Util::Fs::getZfsDataset(jail->path);
  return name;
}

// --- F2: GET /api/v1/containers/:name/snapshots ---

static void handleListSnapshots(const httplib::Request &req, httplib::Response &res,
                                 const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "viewer", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto ds = datasetForJail(name);
  if (ds.empty()) {
    jsonError(res, 404, "container or dataset not found");
    return;
  }
  try {
    auto snaps = ZfsOps::listSnapshots(ds);
    std::ostringstream ss;
    ss << "{\"dataset\":\"" << ds << "\",\"snapshots\":[";
    bool first = true;
    for (auto &s : snaps) {
      if (!first) ss << ",";
      first = false;
      // ZfsOps emits "<dataset>@<snap>"; expose just the snap name to clients
      // so they can pass it back to the DELETE endpoint without parsing.
      auto at = s.name.find('@');
      auto shortName = (at == std::string::npos) ? s.name : s.name.substr(at + 1);
      ss << "{\"name\":\"" << shortName << "\""
         << ",\"used\":\"" << s.used << "\""
         << ",\"refer\":\"" << s.refer << "\""
         << ",\"creation\":\"" << s.creation << "\"}";
    }
    ss << "]}";
    jsonOk(res, ss.str());
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- F2: POST /api/v1/containers/:name/snapshots ---
// Body: optional {"name":"<snap>"}; if absent, an auto-generated name is used.

static void handleCreateSnapshot(const httplib::Request &req, httplib::Response &res,
                                  const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "admin", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto ds = datasetForJail(name);
  if (ds.empty()) {
    jsonError(res, 404, "container or dataset not found");
    return;
  }

  std::string snapName = RoutesPure::extractStringField(req.body, "name");
  if (snapName.empty()) {
    // Generate a timestamp-based name.
    auto t = ::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "auto_%Y-%m-%d_%H%M%S", ::gmtime(&t));
    snapName = buf;
  }
  auto reason = RoutesPure::validateSnapshotName(snapName);
  if (!reason.empty()) {
    jsonError(res, 400, reason);
    return;
  }

  try {
    auto fullName = ds + "@" + snapName;
    ZfsOps::snapshot(fullName);
    jsonOk(res, "{\"created\":true,\"snapshot\":\"" + fullName + "\"}");
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- F2: DELETE /api/v1/containers/:name/snapshots/:snap ---

static void handleDeleteSnapshot(const httplib::Request &req, httplib::Response &res,
                                  const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "admin", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto snap = req.path_params.at("snap");

  auto reason = RoutesPure::validateSnapshotName(snap);
  if (!reason.empty()) {
    jsonError(res, 400, reason);
    return;
  }
  auto ds = datasetForJail(name);
  if (ds.empty()) {
    jsonError(res, 404, "container or dataset not found");
    return;
  }

  try {
    auto fullName = ds + "@" + snap;
    ZfsOps::destroy(fullName);
    jsonOk(res, "{\"deleted\":true,\"snapshot\":\"" + fullName + "\"}");
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- F2: GET /api/v1/containers/:name/stats/stream ---
// Server-Sent Events stream of RCTL usage. One event per second until
// the client disconnects.

static void handleStatsStream(const httplib::Request &req, httplib::Response &res,
                               const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "viewer", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto jail = JailQuery::getJailByName(name);
  if (!jail) {
    try { jail = JailQuery::getJailByJid(std::stoi(name)); } catch (...) {}
  }
  if (!jail) {
    jsonError(res, 404, "container not found");
    return;
  }

  res.set_header("Cache-Control", "no-cache");
  res.set_header("X-Accel-Buffering", "no");

  int jid = jail->jid;
  std::string jailName = jail->name;
  std::string jailIp = jail->ip4;

  res.set_chunked_content_provider(
    "text/event-stream",
    [jid, jailName, jailIp](size_t /*offset*/, httplib::DataSink &sink) -> bool {
      for (;;) {
        // Bail out if the jail has exited.
        auto current = JailQuery::getJailByJid(jid);
        if (!current) {
          std::string ev = "event: end\ndata: {\"reason\":\"jail-gone\"}\n\n";
          sink.write(ev.c_str(), ev.size());
          sink.done();
          return true;
        }

        std::vector<std::pair<std::string, std::string>> usage;
        try {
          auto rctlOutput = Util::execCommandGetOutput(
            {CRATE_PATH_RCTL, "-u", "jail:" + std::to_string(jid)},
            "query RCTL usage");
          std::istringstream is(rctlOutput);
          std::string line;
          while (std::getline(is, line)) {
            auto eq = line.find('=');
            if (eq != std::string::npos)
              usage.emplace_back(line.substr(0, eq), line.substr(eq + 1));
          }
        } catch (...) {
          // Skip this tick — keep the stream alive, the next tick may succeed.
        }

        RoutesPure::StatsInput in{jailName, jid, jailIp, usage};
        auto frame = RoutesPure::formatStatsSseEvent(in, ::time(nullptr));
        if (!sink.write(frame.c_str(), frame.size()))
          return false; // client disconnected
        ::sleep(1);
      }
    },
    [](bool /*success*/) {}
  );
}

// --- F2: export/import helpers ---

static std::string sha256OfFile(const std::string &path) {
  // OpenSSL 3.0 deprecated the SHA256_* one-shot API in favour of the
  // EVP interface. Use that here so the daemon compiles cleanly on
  // FreeBSD 14+ (libcrypto 3.x).
  int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) return "";
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { ::close(fd); return ""; }
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx); ::close(fd); return "";
  }
  unsigned char buf[64 * 1024];
  ssize_t n;
  while ((n = ::read(fd, buf, sizeof(buf))) > 0)
    EVP_DigestUpdate(ctx, buf, (size_t)n);
  ::close(fd);
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLen = 0;
  EVP_DigestFinal_ex(ctx, hash, &hashLen);
  EVP_MD_CTX_free(ctx);
  return TransferPure::hexEncode(
    std::string(reinterpret_cast<char*>(hash), hashLen));
}

// Where the daemon stores generated/uploaded artifacts.
static const std::string ARTIFACT_DIR = "/var/run/crate";

// --- F2: POST /api/v1/containers/:name/export ---
// Synchronously exports the live container to
// `/var/run/crate/<name>-<unixtime>.crate` (no encryption / no
// signing — those would require the daemon to read user-supplied
// key files, which is a separate authorisation problem). Returns
// the artifact filename, byte size, and SHA-256 hex digest.

static void handleContainerExport(const httplib::Request &req, httplib::Response &res,
                                   const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "admin", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto jail = JailQuery::getJailByName(name);
  if (!jail) {
    try { jail = JailQuery::getJailByJid(std::stoi(name)); } catch (...) {}
  }
  if (!jail) {
    jsonError(res, 404, "container not found");
    return;
  }

  // Build a deterministic-ish filename: <name>-<unixtime>.crate
  auto filename = jail->name + "-" + std::to_string(::time(nullptr)) + ".crate";
  auto reason = TransferPure::validateArtifactName(filename);
  if (!reason.empty()) {
    // Only triggers if jail name itself contains forbidden chars.
    jsonError(res, 400, reason);
    return;
  }
  auto outPath = ARTIFACT_DIR + "/" + filename;

  try {
    // Pipeline: tar cf - -C <path> . | xz --extreme > <outPath>
    std::vector<std::vector<std::string>> pipeline = {
      {"/usr/bin/tar", "cf", "-", "-C", jail->path, "."},
      {"/usr/bin/xz", "--extreme"},
    };
    Util::execPipeline(pipeline, "export container filesystem", "", outPath);

    struct stat st{};
    if (::stat(outPath.c_str(), &st) != 0) {
      jsonError(res, 500, "export pipeline produced no output file");
      return;
    }
    auto digest = sha256OfFile(outPath);
    jsonOk(res, TransferPure::formatExportResponse(filename, (uint64_t)st.st_size, digest));
  } catch (const std::exception &e) {
    jsonError(res, 500, e.what());
  }
}

// --- F2: GET /api/v1/exports/:filename ---
// Streams a previously-generated artifact back to the client. The
// filename is validated against `validateArtifactName` so the
// endpoint cannot be coaxed into reading arbitrary files.

static void handleExportDownload(const httplib::Request &req, httplib::Response &res,
                                  const Config &config) {
  if (!isAuthorized(req, config, "admin")) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto filename = req.path_params.at("filename");
  auto reason = TransferPure::validateArtifactName(filename);
  if (!reason.empty()) {
    jsonError(res, 400, reason);
    return;
  }
  auto path = ARTIFACT_DIR + "/" + filename;
  struct stat st{};
  if (::stat(path.c_str(), &st) != 0) {
    jsonError(res, 404, "artifact not found");
    return;
  }

  int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) { jsonError(res, 500, "open failed"); return; }

  res.set_header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
  res.set_content_provider(
    (size_t)st.st_size,
    "application/octet-stream",
    [fd](size_t offset, size_t length, httplib::DataSink &sink) -> bool {
      char buf[64 * 1024];
      ::lseek(fd, (off_t)offset, SEEK_SET);
      ssize_t n = ::read(fd, buf, std::min(sizeof(buf), length));
      if (n <= 0) { sink.done(); return true; }
      return sink.write(buf, (size_t)n);
    },
    [fd](bool /*success*/) { ::close(fd); }
  );
}

// --- F2: POST /api/v1/imports/:name ---
// Accepts a raw `.crate` body (Content-Type: application/octet-stream),
// writes it to `/var/run/crate/<name>.crate`, sniffs the magic bytes
// to confirm it looks like a crate archive, and returns size + sha256.
// The runtime caller is expected to subsequently invoke the local
// `crate import` for full validation if it cares about contents.

static void handleContainerImport(const httplib::Request &req, httplib::Response &res,
                                   const Config &config) {
  auto name = req.path_params.at("name");
  if (!isAuthorizedForContainer(req, config, "admin", name)) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto reason = TransferPure::validateArtifactName(name + ".crate");
  if (!reason.empty()) {
    jsonError(res, 400, reason);
    return;
  }
  if (req.body.empty()) {
    jsonError(res, 400, "empty body — expected raw .crate octet-stream");
    return;
  }
  auto kind = TransferPure::sniffArchiveType(req.body.substr(0, 16));
  if (std::string(kind) == "unknown") {
    jsonError(res, 400, "body is not a crate archive (xz or openssl-encrypted)");
    return;
  }

  auto filename = name + ".crate";
  auto outPath = ARTIFACT_DIR + "/" + filename;

  // Atomic write: write to a temp file then rename. Avoids leaving a
  // half-written .crate in place if the connection drops mid-upload.
  auto tmpPath = outPath + ".tmp." + std::to_string(::getpid());
  int fd = ::open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) { jsonError(res, 500, "open temp failed"); return; }
  ssize_t off = 0;
  while ((size_t)off < req.body.size()) {
    ssize_t n = ::write(fd, req.body.data() + off, req.body.size() - (size_t)off);
    if (n <= 0) { ::close(fd); ::unlink(tmpPath.c_str()); jsonError(res, 500, "write failed"); return; }
    off += n;
  }
  ::close(fd);
  if (::rename(tmpPath.c_str(), outPath.c_str()) != 0) {
    ::unlink(tmpPath.c_str());
    jsonError(res, 500, "rename failed");
    return;
  }

  auto digest = sha256OfFile(outPath);
  jsonOk(res, TransferPure::formatImportResponse(filename, (uint64_t)req.body.size(), digest));
}

// --- Route registration ---

void registerRoutes(httplib::Server &srv, const Config &config) {
  // Health check (no rate limit)
  srv.Get("/healthz", [](const httplib::Request &, httplib::Response &res) {
    res.set_content("{\"status\":\"ok\"}", "application/json");
  });

  // API v1 — read-only (F1) with rate limiting
  srv.Get("/api/v1/containers",
    [](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers", RateLimit::kRead)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleListContainers(req, res);
    });
  srv.Get("/api/v1/containers/:name/gui",
    [](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/gui", RateLimit::kRead)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerGui(req, res);
    });
  srv.Get("/api/v1/host",
    [](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/host", RateLimit::kRead)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleHostInfo(res, res);
    });

  // Prometheus metrics (no auth, with read rate limit)
  srv.Get("/metrics",
    [](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/metrics", RateLimit::kRead)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleMetrics(req, res);
    });

  // API v1 — management (F2) with auth + rate limiting
  srv.Get("/api/v1/containers/:name/stats",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/stats", RateLimit::kRead)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerStats(req, res, config);
    });
  srv.Get("/api/v1/containers/:name/logs",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/logs", RateLimit::kRead)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerLogs(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/stop",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/stop", RateLimit::kMutating)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerStop(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/start",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/start", RateLimit::kMutating)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerStart(req, res, config);
    });
  srv.Delete("/api/v1/containers/:name",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/destroy", RateLimit::kMutating)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerDestroy(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/restart",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/restart", RateLimit::kMutating)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerRestart(req, res, config);
    });
  srv.Get("/api/v1/containers/:name/snapshots",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/snapshots-list", RateLimit::kRead)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleListSnapshots(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/snapshots",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/snapshots-create", RateLimit::kMutating)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleCreateSnapshot(req, res, config);
    });
  srv.Delete(R"(/api/v1/containers/:name/snapshots/:snap)",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/snapshots-delete", RateLimit::kMutating)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleDeleteSnapshot(req, res, config);
    });
  srv.Get("/api/v1/containers/:name/stats/stream",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/stats-stream", RateLimit::kRead)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleStatsStream(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/export",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/export", RateLimit::kMutating)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerExport(req, res, config);
    });
  srv.Get(R"(/api/v1/exports/:filename)",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/exports/download", RateLimit::kRead)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleExportDownload(req, res, config);
    });
  srv.Post(R"(/api/v1/imports/:name)",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/imports", RateLimit::kMutating)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerImport(req, res, config);
    });
}

}
