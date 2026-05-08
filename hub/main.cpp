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
#include "store.h"
#include "api.h"
#include "scheduling_pure.h"

#include <httplib.h>

#include <signal.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
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

  unsigned port = 9810;
  std::string configPath = "/usr/local/etc/crate-hub.conf";
  std::string webDir = "/usr/local/share/crate-hub/web";
  bool foreground = false;

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-f") foreground = true;
    else if (arg == "-c" && i + 1 < argc) configPath = argv[++i];
    else if (arg == "-p" && i + 1 < argc) port = std::stoi(argv[++i]);
    else if (arg == "-w" && i + 1 < argc) webDir = argv[++i];
    else if (arg == "-h") {
      std::cout << "Usage: crate-hub [-f] [-c config] [-p port] [-w webdir]\n";
      return 0;
    }
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

  // Initialize SQLite store
  CrateHub::Store store("/var/db/crate-hub/metrics.db");

  // Start poller thread
  CrateHub::Poller poller(nodes, store, pollIntervalSec);
  std::thread pollerThread([&poller]() { poller.run(); });

  // Start HTTP server
  httplib::Server srv;
  CrateHub::registerApiRoutes(srv, store, poller, haSpecs, haThresholdSeconds);

  // Serve static web dashboard
  srv.set_mount_point("/", webDir);

  if (!foreground) {
    pid_t pid = ::fork();
    if (pid < 0) { std::cerr << "fork failed\n"; return 1; }
    if (pid > 0) ::_exit(0);
    ::setsid();
  }

  std::cerr << "crate-hub: listening on :" << port
            << ", " << nodes.size() << " nodes configured" << std::endl;

  std::thread srvThread([&srv, port]() {
    srv.listen("0.0.0.0", port);
  });

  while (g_running)
    ::sleep(1);

  srv.stop();
  poller.stop();
  srvThread.join();
  pollerThread.join();

  return 0;
}
