// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for `crate migrate <name>` — orchestrate moving a
// container from one crated-managed host to another via the F2 API.
// The runtime (lib/migrate.cpp) shells out to curl(1) for the HTTP
// hops; everything in this module is validation + step planning,
// no I/O.
//
// Migration plan:
//   1. export    → POST   {from}/api/v1/containers/{name}/export
//   2. download  → GET    {from}/api/v1/exports/{file}
//   3. upload    → POST   {to}/api/v1/imports/{name}      (octet-stream)
//   4. start-to  → POST   {to}/api/v1/containers/{name}/start
//   5. stop-from → POST   {from}/api/v1/containers/{name}/stop
//
// Step 5 only fires after step 4 reports success — the destination
// has to be live before we kill the source. If anything fails before
// step 4 we never touch the source: the original container keeps
// running.
//

#include <string>
#include <vector>

namespace MigratePure {

// --- Validators ---

// Validate `host:port` with optional `https://` prefix. Accepts:
//   alpha.example.com:9800
//   https://alpha.example.com:9800
//   10.0.0.5:9800
//   [::1]:9800
//   https://[::1]:9800
// Returns "" on success.
std::string validateEndpoint(const std::string &endpoint);

// Validate a Bearer token format. We can't verify the token is
// authoritative (only the daemon can), but we can refuse anything
// that's obviously broken: empty, has whitespace, has control
// characters, longer than 512 chars (defense against a paste-bin
// going wrong).
std::string validateBearerToken(const std::string &token);

// Validate a container name as fed to the F2 API. Same rules as
// the daemon's TransferPure::validateArtifactName modulo length —
// matches what a client can put in a URL path segment.
std::string validateContainerName(const std::string &name);

// --- Plan ---

enum class StepKind {
  Export,        // POST {from}/api/v1/containers/{name}/export
  Download,      // GET  {from}/api/v1/exports/{artifactFile}
  Upload,        // POST {to}/api/v1/imports/{name}
  StartTo,       // POST {to}/api/v1/containers/{name}/start
  StopFrom,      // POST {from}/api/v1/containers/{name}/stop
};

struct Step {
  StepKind kind;
  std::string method;       // "POST" | "GET"
  std::string url;          // full https://host:port/path
  std::string token;        // Bearer token for this step's host
  // For Upload: local file path that becomes the request body.
  // For Download: local destination path.
  std::string filePath;
};

struct Request {
  std::string name;          // container name on both ends
  std::string fromEndpoint;  // host:port (or https://host:port)
  std::string fromToken;
  std::string toEndpoint;
  std::string toToken;
  // Local working directory for the temp .crate file. The runtime
  // creates this; the planner just embeds the path it'll use.
  std::string workDir;
  // Artifact filename returned by /export (the runtime parses it
  // from the export response and feeds it back in).
  std::string artifactFile;
};

// Build the export step (always first, runs before we know the
// artifactFile).
Step buildExportStep(const Request &r);

// Build the remaining steps once the export step has reported the
// artifact filename. Caller fills in r.artifactFile from the
// /export JSON response.
std::vector<Step> buildRemainingSteps(const Request &r);

// One-line human description of a step, suitable for `--progress`
// logging. Token is NEVER included.
std::string describeStep(const Step &s);

// Render the bearer token as `<redacted: N chars>` for log output.
std::string redactToken(const std::string &token);

// Normalize `endpoint` into a base URL with the `https://` scheme:
//   alpha:9800              -> https://alpha:9800
//   https://alpha:9800      -> https://alpha:9800
//   http://10.0.0.5:9800    -> http://10.0.0.5:9800   (kept as-is)
std::string normalizeBaseUrl(const std::string &endpoint);

} // namespace MigratePure
