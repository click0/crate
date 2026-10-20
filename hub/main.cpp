// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// crate-hub — central aggregator for multi-host crate management.
// Polls crated instances on remote nodes, stores metrics in SQLite,
// serves aggregated REST API and Prometheus /metrics.
// Includes embedded web dashboard (hub/web/).
//
// 0.8.43: also dispatches a one-shot CLI subcommand `schedule
// <jail-name>` that wraps the /api/v1/scheduling/least-loaded
// endpoint + `crate migrate`. Runs in the same binary so
// operators don't need a separate package.

#include "poller.h"

#include <yaml-cpp/yaml.h>   // 1.1.49: listen_port / listen_host
#include <sys/stat.h>        // mkdir
#include "store.h"
#include "api.h"
#include "scheduling_pure.h"
#include "version.h"          // 1.1.52: generated from VERSION by the Makefile

#include <httplib.h>

#include <signal.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

static volatile sig_atomic_t g_running = 1;

static void signalHandler(int) { g_running = 0; }

// 0.8.43: `crate-hub schedule <jail>` one-shot CLI helper.
// Composes the curl-jq-migrate dance from 0.8.40 into one
// invocation. NOT the daemon path — exits as soon as the
// migrate (or dry-run) completes.
//
// Args:
//   schedule <jail>
//     --from <host:port>            current host (where the jail runs today)
//     --from-token-file <path>      admin token for source crated
//     --to-token-file <path>        admin token for destination crated
//     [--current <name>]            anti-flap hint passed to the endpoint
//     [--hub-url <url>]             default http://localhost:9810
//     [--dry-run]                   print the resolved target + migrate
//                                   command, don't exec
static int scheduleSubcommand(int argc, char **argv) {
  std::string jail;
  std::string fromHost;
  std::string fromTokenFile;
  std::string toTokenFile;
  std::string currentNodeHint;
  std::string hubUrl = "http://localhost:9810";
  bool dryRun = false;

  for (int i = 2; i < argc; i++) {
    std::string a = argv[i];
    if (a == "-h" || a == "--help") {
      std::cout
        << "Usage: crate-hub schedule <jail-name>\n"
        << "                       --from <host:port>\n"
        << "                       --from-token-file <path>\n"
        << "                       --to-token-file <path>\n"
        << "                       [--current <name>]\n"
        << "                       [--hub-url <url>]\n"
        << "                       [--dry-run]\n"
        << "\n"
        << "Resolves the least-loaded node via the hub's\n"
        << "/api/v1/scheduling/least-loaded endpoint and execs\n"
        << "`crate migrate` to move <jail> there.\n";
      return 0;
    }
    if (a == "--from"            && i + 1 < argc) { fromHost = argv[++i]; continue; }
    if (a == "--from-token-file" && i + 1 < argc) { fromTokenFile = argv[++i]; continue; }
    if (a == "--to-token-file"   && i + 1 < argc) { toTokenFile = argv[++i]; continue; }
    if (a == "--current"         && i + 1 < argc) { currentNodeHint = argv[++i]; continue; }
    if (a == "--hub-url"         && i + 1 < argc) { hubUrl = argv[++i]; continue; }
    if (a == "--dry-run") { dryRun = true; continue; }
    if (!a.empty() && a[0] == '-') {
      std::cerr << "crate-hub schedule: unknown option '" << a << "'\n";
      return 1;
    }
    if (jail.empty()) { jail = a; continue; }
    std::cerr << "crate-hub schedule: too many positional arguments\n";
    return 1;
  }

  if (jail.empty() || fromHost.empty()
      || fromTokenFile.empty() || toTokenFile.empty()) {
    std::cerr << "crate-hub schedule: missing required argument; "
                 "see --help\n";
    return 1;
  }

  // Query the hub. We use cpp-httplib's Client which handles the
  // "split URL into scheme+host+port" mechanics for us.
  httplib::Client cli(hubUrl);
  cli.set_connection_timeout(5);
  cli.set_read_timeout(5);
  // buildLeastLoadedUrl returns just the "/api/v1/..." path when
  // we pass an empty base — cpp-httplib's Client already holds
  // scheme+host+port from `hubUrl`, so passing the whole URL
  // back through Get() would double the host.
  auto path = SchedulingPure::buildLeastLoadedUrl("", currentNodeHint);
  auto res = cli.Get(path.c_str());
  if (!res) {
    std::cerr << "crate-hub schedule: hub query failed (is "
              << hubUrl << " reachable?)\n";
    return 1;
  }
  if (res->status != 200) {
    std::cerr << "crate-hub schedule: hub returned HTTP "
              << res->status << ": " << res->body << "\n";
    return 1;
  }

  auto target = SchedulingPure::extractTargetField(res->body);
  auto toHost = SchedulingPure::extractHostField(res->body);
  if (target.empty() || toHost.empty()) {
    std::cerr << "crate-hub schedule: no candidate node "
                 "(reply: " << res->body << ")\n";
    return 1;
  }

  // Anti-flap: when the operator passed --current and the hub
  // recommended that same node back, there's nothing to migrate.
  if (!currentNodeHint.empty() && target == currentNodeHint) {
    std::cout << "crate-hub schedule: '" << jail
              << "' stays on '" << target
              << "' (already on least-loaded; no migration needed)\n";
    return 0;
  }

  auto cratePath = "/usr/local/bin/crate";
  auto migrateArgv = SchedulingPure::buildMigrateArgv(
    cratePath, jail, fromHost, toHost, fromTokenFile, toTokenFile);

  if (dryRun) {
    std::cout << "crate-hub schedule (dry-run): would exec:\n ";
    for (auto &a : migrateArgv) std::cout << " " << a;
    std::cout << "\n";
    return 0;
  }

  std::cout << "crate-hub schedule: target='" << target
            << "' host='" << toHost << "', invoking `crate migrate`...\n";

  // Build C-style argv for execv.
  std::vector<char*> cargv;
  cargv.reserve(migrateArgv.size() + 1);
  for (auto &s : migrateArgv) cargv.push_back(const_cast<char*>(s.c_str()));
  cargv.push_back(nullptr);
  ::execv(cargv[0], cargv.data());
  std::cerr << "crate-hub schedule: execv " << cratePath
            << " failed: " << std::strerror(errno) << "\n";
  return 1;
}

int main(int argc, char **argv) {
  // 0.8.43: dispatch one-shot subcommands before the daemon
  // setup. `schedule` is the only one today; future helpers
  // (e.g. `nodes-list`, `ha-eval`) can register here.
  if (argc >= 2 && std::strcmp(argv[1], "schedule") == 0)
    return scheduleSubcommand(argc, argv);

  unsigned port = 0;                 // 0 = not given on the command line
  std::string bindHost;              // "" = not given on the command line
  std::string configPath = "/usr/local/etc/crate-hub.conf";
  std::string webDir = "/usr/local/share/crate-hub/web";
  bool foreground = false;

  // 1.1.49: long options as documented in crate-hub.8 too; -p parsed
  // defensively (std::stoi threw out of main on garbage).
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-f" || arg == "--foreground") foreground = true;
    else if ((arg == "-c" || arg == "--config") && i + 1 < argc) configPath = argv[++i];
    else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
      std::string v = argv[++i];
      if (v.empty() || v.size() > 5 || v.find_first_not_of("0123456789") != std::string::npos ||
          std::stoul(v) < 1 || std::stoul(v) > 65535) {
        std::cerr << "crate-hub: -p expects a port number 1..65535, got '" << v << "'" << std::endl;
        return 1;
      }
      port = (unsigned)std::stoul(v);
    }
    else if ((arg == "-b" || arg == "--bind") && i + 1 < argc) bindHost = argv[++i];
    else if ((arg == "-w" || arg == "--webdir") && i + 1 < argc) webDir = argv[++i];
    else if (arg == "-h" || arg == "--help") {
      std::cout << "Usage: crate-hub [-f] [-c config] [-p port] [-b bind-address] [-w webdir]\n";
      return 0;
    } else if (arg == "-V" || arg == "--version") {   // 1.1.52: shared version.h
      std::cout << "crate-hub " << CRATE_VERSION << std::endl;
      return 0;
    } else {
      std::cerr << "crate-hub: unknown argument '" << arg << "'" << std::endl;
      return 1;
    }
  }

  // Config-file listen settings (listen_port / listen_host, crate-hub.8);
  // command line wins. 1.1.49: the man page documented listen_port but
  // nothing read it. The hub API is unauthenticated, so the default
  // bind is loopback — put a TLS reverse proxy in front for remote use.
  {
    try {
      YAML::Node root = YAML::LoadFile(configPath);
      if (port == 0 && root["listen_port"]) port = root["listen_port"].as<unsigned>();
      if (bindHost.empty() && root["listen_host"]) bindHost = root["listen_host"].as<std::string>();
    } catch (...) {}
    if (port == 0) port = 9810;
    if (bindHost.empty()) bindHost = "127.0.0.1";
  }

  ::signal(SIGINT, signalHandler);
  ::signal(SIGTERM, signalHandler);

  // Load node configuration
  unsigned pollIntervalSec = 15;
  auto nodes = CrateHub::loadNodes(configPath, &pollIntervalSec);
  if (nodes.empty()) {
    std::cerr << "crate-hub: no nodes configured in " << configPath << std::endl;
    return 1;
  }

  // Optional HA specs (added in 0.7.3). Empty when no `ha:`
  // section present.
  long haThresholdSeconds = 60;
  auto haSpecs = CrateHub::loadHaSpecs(configPath, &haThresholdSeconds);
  if (auto reason = HaPure::validateSpecs(haSpecs); !reason.empty()) {
    std::cerr << "crate-hub: invalid HA spec: " << reason << std::endl;
    return 1;
  }

  // 1.1.49: daemonise BEFORE any thread exists. The poller thread used
  // to be started first and fork() then produced a child with only the
  // forking thread — no poll loop ever ran in the default mode, and the
  // final pollerThread.join() joined a thread that did not exist in
  // that process.
  // 1.1.52: open the SQLite store BEFORE daemonising so a failure is
  // reported on the operator's terminal instead of being an uncaught
  // exception (std::terminate, "unable to open database file" with no
  // path) in a detached child. `db_path:` in the config overrides the
  // default; the parent directory is created when missing.
  std::string dbPath = "/var/db/crate-hub/metrics.db";
  try {
    YAML::Node root = YAML::LoadFile(configPath);
    if (root["db_path"]) dbPath = root["db_path"].as<std::string>();
  } catch (...) {}
  std::unique_ptr<CrateHub::Store> storePtr;
  try {
    auto slash = dbPath.find_last_of('/');
    if (slash != std::string::npos && slash > 0)
      ::mkdir(dbPath.substr(0, slash).c_str(), 0750);
    storePtr = std::make_unique<CrateHub::Store>(dbPath);
  } catch (const std::exception &e) {
    std::cerr << "crate-hub: " << e.what() << " (" << dbPath << ")" << std::endl;
    return 1;
  }
  CrateHub::Store &store = *storePtr;

  if (!foreground) {
    pid_t pid = ::fork();
    if (pid < 0) { std::cerr << "fork failed\n"; return 1; }
    if (pid > 0) ::_exit(0);
    ::setsid();
  }

  // Start poller thread
  CrateHub::Poller poller(nodes, store, pollIntervalSec);
  std::thread pollerThread([&poller]() { poller.run(); });

  // Start HTTP server
  httplib::Server srv;
  CrateHub::registerApiRoutes(srv, store, poller, haSpecs, haThresholdSeconds);

  // Serve static web dashboard
  srv.set_mount_point("/", webDir);

  // 1.1.49: bind the configured address and fail loudly — a failed
  // listen() used to be silent while main slept forever.
  if (!srv.bind_to_port(bindHost, (int)port)) {
    std::cerr << "crate-hub: cannot listen on " << bindHost << ":" << port << std::endl;
    poller.stop();
    pollerThread.join();
    return 1;
  }
  std::cerr << "crate-hub: listening on " << bindHost << ":" << port
            << ", " << nodes.size() << " nodes configured" << std::endl;

  std::thread srvThread([&srv]() {
    srv.listen_after_bind();
  });

  while (g_running)
    ::sleep(1);

  srv.stop();
  poller.stop();
  srvThread.join();
  pollerThread.join();

  return 0;
}
