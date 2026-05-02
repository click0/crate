// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// REST API routes — F1 read-only + F2 management endpoints.

#include "routes.h"
#include "auth.h"
#include "metrics.h"
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

#include <openssl/sha.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>

namespace Crated {

// --- Simple per-endpoint rate limiter ---
// Tracks request counts per second for each (clientId, endpoint) pair.
// Mutating endpoints: 10 req/s. Read endpoints: 100 req/s.

static std::mutex g_rateMutex;
static std::map<std::string, std::pair<int, time_t>> g_rateBuckets;

static bool checkRateLimit(const std::string &clientId, const std::string &endpoint,
                           int maxPerSecond) {
  std::lock_guard<std::mutex> lock(g_rateMutex);
  auto key = clientId + "|" + endpoint;
  auto now = ::time(nullptr);
  auto &bucket = g_rateBuckets[key];
  if (bucket.second != now) {
    bucket.first = 1;
    bucket.second = now;
    return true;
  }
  bucket.first++;
  return bucket.first <= maxPerSecond;
}

static std::string getClientId(const httplib::Request &req) {
  auto addr = req.get_header_value("REMOTE_ADDR");
  return addr.empty() ? "unix" : addr;
}

static constexpr int RATE_LIMIT_MUTATING = 10;
static constexpr int RATE_LIMIT_READ = 100;

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
  if (!isAuthorized(req, config, "viewer")) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto name = req.path_params.at("name");
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
  if (!isAuthorized(req, config, "admin")) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto name = req.path_params.at("name");
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
  if (!isAuthorized(req, config, "admin")) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto name = req.path_params.at("name");

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
  if (!isAuthorized(req, config, "admin")) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto name = req.path_params.at("name");

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
  if (!isAuthorized(req, config, "viewer")) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto name = req.path_params.at("name");
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

  // Streaming mode: use chunked transfer encoding with tail -f
  // cpp-httplib supports set_chunked_content_provider for streaming responses.
  //
  // TODO: Full implementation requires a background thread running tail -f
  // and feeding chunks to the provider callback. The current approach uses
  // set_chunked_content_provider with a blocking read from tail -f, which
  // works but ties up a server thread per streaming client.
  //
  // Future improvements:
  //   - Use epoll/kqueue to multiplex log file watching
  //   - Add a connection limit for streaming clients
  //   - Support WebSocket upgrade for bidirectional streaming (RFC 6455)
  //   - Implement server-sent events (SSE) as an alternative transport

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

      // Now tail: poll for new data every 500ms
      ifs.clear(); // clear EOF flag
      for (;;) {
        while (std::getline(ifs, line)) {
          line += "\n";
          if (!sink.write(line.c_str(), line.size()))
            return false; // client disconnected
        }
        ifs.clear();
        ::usleep(500000); // 500ms poll interval
      }
      // Unreachable; streaming ends when client disconnects
    },
    [](bool /*success*/) {
      // Cleanup callback — nothing to do
    }
  );
}

// --- F2: POST /api/v1/containers/:name/restart ---

static void handleContainerRestart(const httplib::Request &req, httplib::Response &res,
                                    const Config &config) {
  if (!isAuthorized(req, config, "admin")) {
    jsonError(res, 403, "unauthorized");
    return;
  }

  auto name = req.path_params.at("name");
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
  if (!isAuthorized(req, config, "viewer")) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto name = req.path_params.at("name");
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
  if (!isAuthorized(req, config, "admin")) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto name = req.path_params.at("name");
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
  if (!isAuthorized(req, config, "admin")) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto name = req.path_params.at("name");
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
  if (!isAuthorized(req, config, "viewer")) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto name = req.path_params.at("name");
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
  int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) return "";
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  unsigned char buf[64 * 1024];
  ssize_t n;
  while ((n = ::read(fd, buf, sizeof(buf))) > 0)
    SHA256_Update(&ctx, buf, (size_t)n);
  ::close(fd);
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, &ctx);
  return TransferPure::hexEncode(
    std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH));
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
  if (!isAuthorized(req, config, "admin")) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto name = req.path_params.at("name");
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
  if (!isAuthorized(req, config, "admin")) {
    jsonError(res, 403, "unauthorized");
    return;
  }
  auto name = req.path_params.at("name");
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
      if (!checkRateLimit(getClientId(req), "/api/v1/containers", RATE_LIMIT_READ)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleListContainers(req, res);
    });
  srv.Get("/api/v1/containers/:name/gui",
    [](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/gui", RATE_LIMIT_READ)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerGui(req, res);
    });
  srv.Get("/api/v1/host",
    [](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/host", RATE_LIMIT_READ)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleHostInfo(res, res);
    });

  // Prometheus metrics (no auth, with read rate limit)
  srv.Get("/metrics",
    [](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/metrics", RATE_LIMIT_READ)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleMetrics(req, res);
    });

  // API v1 — management (F2) with auth + rate limiting
  srv.Get("/api/v1/containers/:name/stats",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/stats", RATE_LIMIT_READ)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerStats(req, res, config);
    });
  srv.Get("/api/v1/containers/:name/logs",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/logs", RATE_LIMIT_READ)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerLogs(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/stop",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/stop", RATE_LIMIT_MUTATING)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerStop(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/start",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/start", RATE_LIMIT_MUTATING)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerStart(req, res, config);
    });
  srv.Delete("/api/v1/containers/:name",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/destroy", RATE_LIMIT_MUTATING)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerDestroy(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/restart",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/restart", RATE_LIMIT_MUTATING)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerRestart(req, res, config);
    });
  srv.Get("/api/v1/containers/:name/snapshots",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/snapshots-list", RATE_LIMIT_READ)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleListSnapshots(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/snapshots",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/snapshots-create", RATE_LIMIT_MUTATING)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleCreateSnapshot(req, res, config);
    });
  srv.Delete(R"(/api/v1/containers/:name/snapshots/:snap)",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/snapshots-delete", RATE_LIMIT_MUTATING)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleDeleteSnapshot(req, res, config);
    });
  srv.Get("/api/v1/containers/:name/stats/stream",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/stats-stream", RATE_LIMIT_READ)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleStatsStream(req, res, config);
    });
  srv.Post("/api/v1/containers/:name/export",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/containers/export", RATE_LIMIT_MUTATING)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerExport(req, res, config);
    });
  srv.Get(R"(/api/v1/exports/:filename)",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/exports/download", RATE_LIMIT_READ)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleExportDownload(req, res, config);
    });
  srv.Post(R"(/api/v1/imports/:name)",
    [&config](const httplib::Request &req, httplib::Response &res) {
      if (!checkRateLimit(getClientId(req), "/api/v1/imports", RATE_LIMIT_MUTATING)) {
        jsonError(res, 429, "rate limit exceeded");
        return;
      }
      handleContainerImport(req, res, config);
    });
}

}
