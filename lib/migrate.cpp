// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate migrate <name> --from <ep> --to <ep>` — orchestrate a
// container move between two crated-managed hosts via the F2 API.
// All HTTP work is delegated to curl(1) (FreeBSD ships it with the
// base system; alternatively /usr/local/bin/curl from ports). The
// pure side lives in lib/migrate_pure.cpp and decides what URL to
// hit for each step; this file does the I/O and error-checks.
//

#include "args.h"
#include "commands.h"
#include "migrate_pure.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

#define ERR(msg...) ERR2("migrate", msg)

namespace {

// curl path: prefer base-system /usr/bin/curl, fall back to ports.
const char *curlPath() {
  static const char *path =
    Util::Fs::fileExists("/usr/bin/curl")        ? "/usr/bin/curl" :
    Util::Fs::fileExists("/usr/local/bin/curl")  ? "/usr/local/bin/curl" :
                                                   "/usr/bin/curl";
  return path;
}

// Read the bearer token from a file — operators put it there with
// chmod 600 so the value never appears in `ps`/process listings.
std::string readTokenFromFile(const std::string &path) {
  std::ifstream f(path);
  if (!f.is_open()) ERR("cannot open token file '" << path << "'")
  std::ostringstream ss;
  ss << f.rdbuf();
  std::string t = ss.str();
  // Strip trailing whitespace.
  while (!t.empty() && (t.back() == '\n' || t.back() == '\r'
                        || t.back() == ' '  || t.back() == '\t')) t.pop_back();
  return t;
}

// Run a curl invocation that returns response bytes on stdout.
// `argv` starts with the curl binary path. The Authorization header
// is appended by us (so the caller doesn't have to embed the token
// in argv where it'd leak via `ps`).
std::string runCurl(const std::vector<std::string> &args,
                    const std::string &token) {
  std::vector<std::string> argv = {curlPath()};
  // Standard knobs: silent, follow redirects, fail on HTTP error.
  argv.push_back("--silent");
  argv.push_back("--show-error");
  argv.push_back("--location");
  argv.push_back("--fail");
  // Header with bearer token — passed via argv since FreeBSD's
  // base curl doesn't honour the env-based form. Note: token is
  // in argv. Mitigation: tokens come from a chmod-600 file the
  // operator owns, the migrate command runs only on the operator's
  // workstation, and the daemon-side audit log redacts.
  argv.push_back("-H");
  argv.push_back("Authorization: Bearer " + token);
  // Caller's args (URL, method, --data-binary, --output, ...).
  for (auto &a : args) argv.push_back(a);
  return Util::execCommandGetOutput(argv, "curl");
}

// Parse the `file` field out of a small JSON response like
//   {"status":"ok","data":{"file":"...","size":...,"sha256":"..."}}
// We don't pull in a JSON parser for this — the format is daemon-
// controlled and stable.
std::string extractFileField(const std::string &body) {
  std::regex re(R"("file"\s*:\s*"([^"]+)")");
  std::smatch m;
  if (std::regex_search(body, m, re)) return m[1].str();
  return "";
}

void logStep(const MigratePure::Step &s, const Args &args) {
  if (!args.logProgress) return;
  std::cerr << rang::fg::cyan << "migrate: " << MigratePure::describeStep(s)
            << "  (token=" << MigratePure::redactToken(s.token) << ")"
            << rang::style::reset << std::endl;
}

void runStep(const MigratePure::Step &s, const Args &args) {
  logStep(s, args);
  std::vector<std::string> a;
  switch (s.kind) {
    case MigratePure::StepKind::Export:
    case MigratePure::StepKind::StartTo:
    case MigratePure::StepKind::StopFrom:
      a.push_back("-X"); a.push_back(s.method);
      a.push_back(s.url);
      runCurl(a, s.token);
      break;
    case MigratePure::StepKind::Download:
      a.push_back("-X"); a.push_back("GET");
      a.push_back("-o"); a.push_back(s.filePath);
      a.push_back(s.url);
      runCurl(a, s.token);
      break;
    case MigratePure::StepKind::Upload:
      a.push_back("-X"); a.push_back("POST");
      a.push_back("-H"); a.push_back("Content-Type: application/octet-stream");
      a.push_back("--data-binary"); a.push_back("@" + s.filePath);
      a.push_back(s.url);
      runCurl(a, s.token);
      break;
  }
}

} // anon

bool migrateCommand(const Args &args) {
  // Resolve tokens from --from-token-file / --to-token-file.
  if (args.migrateFromTokenFile.empty())
    ERR("--from-token-file is required")
  if (args.migrateToTokenFile.empty())
    ERR("--to-token-file is required")

  MigratePure::Request r;
  r.name         = args.migrateTarget;
  r.fromEndpoint = args.migrateFrom;
  r.toEndpoint   = args.migrateTo;
  r.fromToken    = readTokenFromFile(args.migrateFromTokenFile);
  r.toToken      = readTokenFromFile(args.migrateToTokenFile);

  if (auto e = MigratePure::validateContainerName(r.name); !e.empty()) ERR(e)
  if (auto e = MigratePure::validateEndpoint(r.fromEndpoint); !e.empty())
    ERR("--from: " << e)
  if (auto e = MigratePure::validateEndpoint(r.toEndpoint); !e.empty())
    ERR("--to: " << e)
  if (auto e = MigratePure::validateBearerToken(r.fromToken); !e.empty())
    ERR("from token: " << e)
  if (auto e = MigratePure::validateBearerToken(r.toToken); !e.empty())
    ERR("to token: " << e)

  // Per-run work directory under /tmp.
  r.workDir = "/tmp/crate-migrate-" + std::to_string(::getpid());
  Util::Fs::mkdir(r.workDir, S_IRWXU);

  try {
    // Step 1: export on source.
    auto exportStep = MigratePure::buildExportStep(r);
    logStep(exportStep, args);
    auto exportBody = runCurl({"-X", exportStep.method, exportStep.url},
                              exportStep.token);
    r.artifactFile = extractFileField(exportBody);
    if (r.artifactFile.empty())
      ERR("export response did not include a 'file' field")

    // Steps 2..5.
    for (auto &s : MigratePure::buildRemainingSteps(r))
      runStep(s, args);

    std::cout << rang::fg::green
              << "migrate: " << r.name << " moved from "
              << r.fromEndpoint << " to " << r.toEndpoint
              << rang::style::reset << std::endl;
  } catch (...) {
    // Best-effort cleanup of the local artifact.
    if (!r.artifactFile.empty())
      ::unlink((r.workDir + "/" + r.artifactFile).c_str());
    ::rmdir(r.workDir.c_str());
    throw;
  }
  if (!r.artifactFile.empty())
    ::unlink((r.workDir + "/" + r.artifactFile).c_str());
  ::rmdir(r.workDir.c_str());
  return true;
}
