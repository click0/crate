// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "control_socket_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using ControlSocketPure::Action;
using ControlSocketPure::AuthorizeInput;
using ControlSocketPure::ContainerSummary;
using ControlSocketPure::ControlSocketSpec;
using ControlSocketPure::Decision;
using ControlSocketPure::ParsedHttp;
using ControlSocketPure::ParsedRoute;
using ControlSocketPure::ResourcesPatch;
using ControlSocketPure::authorize;
using ControlSocketPure::buildHttpResponse;
using ControlSocketPure::httpStatusFor;
using ControlSocketPure::isModeSafe;
using ControlSocketPure::parseHttpHead;
using ControlSocketPure::parseResourcesPatch;
using ControlSocketPure::parseRoute;
using ControlSocketPure::poolVisibleOnSocket;
using ControlSocketPure::renderContainersJson;
using ControlSocketPure::renderErrorJson;
using ControlSocketPure::renderPatchOkJson;
using ControlSocketPure::validateSocketSpec;

// ----------------------------------------------------------------------
// validateSocketSpec
// ----------------------------------------------------------------------

static ControlSocketSpec mkSpec() {
  ControlSocketSpec s;
  s.path  = "/var/run/crate/control/dev.sock";
  s.group = "dev-team";
  s.mode  = 0660;
  s.pools = {"dev", "stage"};
  s.role  = "viewer";
  return s;
}

ATF_TEST_CASE_WITHOUT_HEAD(spec_typical_accepted);
ATF_TEST_CASE_BODY(spec_typical_accepted) {
  ATF_REQUIRE_EQ(validateSocketSpec(mkSpec()), std::string());

  auto s = mkSpec();
  s.role  = "admin";
  s.pools = {"*"};
  ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(spec_path_must_be_under_control_dir);
ATF_TEST_CASE_BODY(spec_path_must_be_under_control_dir) {
  // Must live under /var/run/crate/control/ — operators can't drop
  // the socket in /tmp or /etc.
  auto s = mkSpec();
  s.path = "/tmp/foo.sock";
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  s.path = "/var/run/crate/dev.sock";  // missing /control/ subdir
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  s.path = "/etc/crate/control.sock";
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  // Relative path
  s.path = "control/dev.sock";
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  // Empty
  s.path = "";
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  // .. segment
  s.path = "/var/run/crate/control/../etc/secret";
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  // Shell metacharacter
  s.path = "/var/run/crate/control/foo;rm.sock";
  ATF_REQUIRE(!validateSocketSpec(s).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(spec_group_validated);
ATF_TEST_CASE_BODY(spec_group_validated) {
  auto s = mkSpec();
  s.group = "";
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  s.group = std::string(33, 'a');
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  s.group = "bad group";   // space
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  s.group = "bad/group";   // slash
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  s.group = "ok-group_1.2";  // alnum + ._- accepted
  ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(spec_mode_range);
ATF_TEST_CASE_BODY(spec_mode_range) {
  auto s = mkSpec();
  s.mode = 0;       ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());
  s.mode = 0660;    ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());
  s.mode = 0700;    ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());
  s.mode = 01000;   ATF_REQUIRE(!validateSocketSpec(s).empty());  // out of 0..0777
}

ATF_TEST_CASE_WITHOUT_HEAD(spec_role_validated);
ATF_TEST_CASE_BODY(spec_role_validated) {
  auto s = mkSpec();
  s.role = "admin";    ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());
  s.role = "viewer";   ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());
  s.role = "owner";    ATF_REQUIRE(!validateSocketSpec(s).empty());
  s.role = "";         ATF_REQUIRE(!validateSocketSpec(s).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(spec_pools_validated);
ATF_TEST_CASE_BODY(spec_pools_validated) {
  auto s = mkSpec();
  s.pools = {};
  ATF_REQUIRE(!validateSocketSpec(s).empty());

  s.pools = {"*"};        ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());
  s.pools = {"dev"};      ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());
  s.pools = {"dev","prod"}; ATF_REQUIRE_EQ(validateSocketSpec(s), std::string());

  s.pools = {""};         ATF_REQUIRE(!validateSocketSpec(s).empty());
  s.pools = {"bad pool"}; ATF_REQUIRE(!validateSocketSpec(s).empty());
  s.pools = {"a/b"};      ATF_REQUIRE(!validateSocketSpec(s).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(mode_safety);
ATF_TEST_CASE_BODY(mode_safety) {
  // No world-bits = safe
  ATF_REQUIRE(isModeSafe(0660));
  ATF_REQUIRE(isModeSafe(0600));
  ATF_REQUIRE(isModeSafe(0640));
  ATF_REQUIRE(isModeSafe(0));
  // Any world-bit = unsafe
  ATF_REQUIRE(!isModeSafe(0666));
  ATF_REQUIRE(!isModeSafe(0664));
  ATF_REQUIRE(!isModeSafe(0661));
  ATF_REQUIRE(!isModeSafe(0777));
}

// ----------------------------------------------------------------------
// parseRoute
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(route_list_containers);
ATF_TEST_CASE_BODY(route_list_containers) {
  auto r = parseRoute("GET", "/v1/control/containers");
  ATF_REQUIRE(r.action == Action::ListContainers);
  ATF_REQUIRE_EQ(r.container, std::string());

  // Trailing slash also accepted (splitPath drops empty trailing)
  r = parseRoute("GET", "/v1/control/containers/");
  ATF_REQUIRE(r.action == Action::ListContainers);

  // POST on the list endpoint is unknown
  r = parseRoute("POST", "/v1/control/containers");
  ATF_REQUIRE(r.action == Action::Unknown);
}

ATF_TEST_CASE_WITHOUT_HEAD(route_get_container);
ATF_TEST_CASE_BODY(route_get_container) {
  auto r = parseRoute("GET", "/v1/control/containers/postgres");
  ATF_REQUIRE(r.action == Action::GetContainer);
  ATF_REQUIRE_EQ(r.container, std::string("postgres"));

  // Method other than GET -> unknown
  r = parseRoute("PATCH", "/v1/control/containers/postgres");
  ATF_REQUIRE(r.action == Action::Unknown);
}

ATF_TEST_CASE_WITHOUT_HEAD(route_stats);
ATF_TEST_CASE_BODY(route_stats) {
  auto r = parseRoute("GET", "/v1/control/containers/dev-redis/stats");
  ATF_REQUIRE(r.action == Action::GetContainerStats);
  ATF_REQUIRE_EQ(r.container, std::string("dev-redis"));
}

ATF_TEST_CASE_WITHOUT_HEAD(route_patch_resources);
ATF_TEST_CASE_BODY(route_patch_resources) {
  auto r = parseRoute("PATCH", "/v1/control/containers/torrent/resources");
  ATF_REQUIRE(r.action == Action::PatchResources);
  ATF_REQUIRE_EQ(r.container, std::string("torrent"));

  // GET on /resources is undefined
  r = parseRoute("GET", "/v1/control/containers/torrent/resources");
  ATF_REQUIRE(r.action == Action::Unknown);
}

ATF_TEST_CASE_WITHOUT_HEAD(route_unknown);
ATF_TEST_CASE_BODY(route_unknown) {
  // Wrong prefix
  ATF_REQUIRE(parseRoute("GET", "/api/v1/containers").action == Action::Unknown);
  ATF_REQUIRE(parseRoute("GET", "/v1/admin/containers").action == Action::Unknown);
  // Unknown trailing
  ATF_REQUIRE(parseRoute("GET",
    "/v1/control/containers/foo/start").action == Action::Unknown);
  // Bad container name
  ATF_REQUIRE(parseRoute("GET",
    "/v1/control/containers/bad;name").action == Action::Unknown);
  ATF_REQUIRE(parseRoute("GET",
    "/v1/control/containers/").action == Action::ListContainers);  // trailing slash on list is OK
}

// ----------------------------------------------------------------------
// authorize — full ACL matrix
// ----------------------------------------------------------------------

static AuthorizeInput mkInput() {
  AuthorizeInput in;
  in.peerUid = 1001;
  in.peerGid = 5000;
  in.socketExpectedGid = 5000;
  in.socketRole = "admin";
  in.socketPools = {"dev", "stage"};
  in.action = Action::ListContainers;
  in.poolSeparator = '-';
  return in;
}

ATF_TEST_CASE_WITHOUT_HEAD(authz_typical_allow);
ATF_TEST_CASE_BODY(authz_typical_allow) {
  ATF_REQUIRE(authorize(mkInput()) == Decision::Allow);

  auto in = mkInput();
  in.action = Action::GetContainer;
  in.container = "dev-postgres";
  ATF_REQUIRE(authorize(in) == Decision::Allow);

  in.action = Action::PatchResources;
  ATF_REQUIRE(authorize(in) == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authz_gid_mismatch_denies);
ATF_TEST_CASE_BODY(authz_gid_mismatch_denies) {
  // Layer-2 defence: even if filesystem perms get loosened, peer.gid
  // must equal the socket's expected gid.
  auto in = mkInput();
  in.peerGid = 9999;  // wrong group
  ATF_REQUIRE(authorize(in) == Decision::DenyGidMismatch);

  in.peerGid = -1;    // unknown / not extracted
  ATF_REQUIRE(authorize(in) == Decision::DenyGidMismatch);
}

ATF_TEST_CASE_WITHOUT_HEAD(authz_pool_filter_per_container);
ATF_TEST_CASE_BODY(authz_pool_filter_per_container) {
  auto in = mkInput();
  in.action = Action::GetContainer;
  // Container's pool inferred from name via PoolPure::inferPool.
  in.container = "prod-postgres";  // pool="prod", not in [dev,stage]
  ATF_REQUIRE(authorize(in) == Decision::DenyPoolMismatch);

  in.container = "dev-postgres";
  ATF_REQUIRE(authorize(in) == Decision::Allow);

  // Pool-less container (no separator in name) reachable only via "*"
  in.container = "monolithic";
  ATF_REQUIRE(authorize(in) == Decision::DenyPoolMismatch);

  in.socketPools = {"*"};
  ATF_REQUIRE(authorize(in) == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authz_viewer_cant_patch);
ATF_TEST_CASE_BODY(authz_viewer_cant_patch) {
  auto in = mkInput();
  in.socketRole = "viewer";
  in.action = Action::PatchResources;
  in.container = "dev-postgres";
  ATF_REQUIRE(authorize(in) == Decision::DenyRoleMismatch);

  // viewer GET is fine
  in.action = Action::GetContainer;
  ATF_REQUIRE(authorize(in) == Decision::Allow);

  in.action = Action::GetContainerStats;
  ATF_REQUIRE(authorize(in) == Decision::Allow);

  in.action = Action::ListContainers;
  ATF_REQUIRE(authorize(in) == Decision::Allow);
}

ATF_TEST_CASE_WITHOUT_HEAD(authz_unknown_action_denied);
ATF_TEST_CASE_BODY(authz_unknown_action_denied) {
  auto in = mkInput();
  in.action = Action::Unknown;
  ATF_REQUIRE(authorize(in) == Decision::DenyUnknownAction);
}

ATF_TEST_CASE_WITHOUT_HEAD(authz_alt_separator);
ATF_TEST_CASE_BODY(authz_alt_separator) {
  // Operators with hyphens already in container names switch
  // separator to '_' or '.'. Pool inference must follow.
  auto in = mkInput();
  in.poolSeparator = '_';
  in.action = Action::GetContainer;
  in.container = "dev_postgres-1";  // pool="dev" with '_' separator
  ATF_REQUIRE(authorize(in) == Decision::Allow);

  in.container = "prod_postgres";   // pool="prod", denied
  ATF_REQUIRE(authorize(in) == Decision::DenyPoolMismatch);
}

// ----------------------------------------------------------------------
// parseResourcesPatch — whitelist + JSON parser
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(patch_typical);
ATF_TEST_CASE_BODY(patch_typical) {
  ResourcesPatch p;
  ATF_REQUIRE_EQ(parseResourcesPatch(R"({"pcpu":"20","writebps":"5M"})", p),
                 std::string());
  ATF_REQUIRE_EQ(p.pcpu,     std::string("20"));
  ATF_REQUIRE_EQ(p.writebps, std::string("5M"));
  ATF_REQUIRE_EQ(p.memoryuse, std::string());
  ATF_REQUIRE_EQ(p.readbps,  std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(patch_all_keys);
ATF_TEST_CASE_BODY(patch_all_keys) {
  ResourcesPatch p;
  ATF_REQUIRE_EQ(parseResourcesPatch(
    R"({"pcpu":"30","memoryuse":"512M","readbps":"2M","writebps":"2M"})", p),
    std::string());
  ATF_REQUIRE_EQ(p.pcpu,      std::string("30"));
  ATF_REQUIRE_EQ(p.memoryuse, std::string("512M"));
  ATF_REQUIRE_EQ(p.readbps,   std::string("2M"));
  ATF_REQUIRE_EQ(p.writebps,  std::string("2M"));
}

ATF_TEST_CASE_WITHOUT_HEAD(patch_unknown_key_rejected);
ATF_TEST_CASE_BODY(patch_unknown_key_rejected) {
  // Unknown keys are rejected (not silently ignored) — typo by a
  // tray developer should fail loudly, not be a no-op.
  ResourcesPatch p;
  ATF_REQUIRE(!parseResourcesPatch(R"({"writebsp":"5M"})", p).empty());
  ATF_REQUIRE(!parseResourcesPatch(R"({"maxproc":"100"})", p).empty()); // not in whitelist
  ATF_REQUIRE(!parseResourcesPatch(R"({"pcpu":"20","unknown":"x"})", p).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(patch_empty_rejected);
ATF_TEST_CASE_BODY(patch_empty_rejected) {
  ResourcesPatch p;
  ATF_REQUIRE(!parseResourcesPatch("",      p).empty());
  ATF_REQUIRE(!parseResourcesPatch("{}",    p).empty());
  ATF_REQUIRE(!parseResourcesPatch("[]",    p).empty());  // not an object
  ATF_REQUIRE(!parseResourcesPatch("null",  p).empty());
  ATF_REQUIRE(!parseResourcesPatch("\"x\"", p).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(patch_malformed_json_rejected);
ATF_TEST_CASE_BODY(patch_malformed_json_rejected) {
  ResourcesPatch p;
  ATF_REQUIRE(!parseResourcesPatch(R"({pcpu:"20"})",      p).empty());  // unquoted key
  ATF_REQUIRE(!parseResourcesPatch(R"({"pcpu":20})",      p).empty());  // unquoted value
  ATF_REQUIRE(!parseResourcesPatch(R"({"pcpu":"20")",     p).empty());  // unterminated
  ATF_REQUIRE(!parseResourcesPatch(R"({"pcpu":"20",})",   p).empty());  // trailing comma
  ATF_REQUIRE(!parseResourcesPatch(R"({"pcpu":"20" "x":"y"})", p).empty()); // missing comma
}

// ----------------------------------------------------------------------
// JSON rendering
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(render_containers_sorted);
ATF_TEST_CASE_BODY(render_containers_sorted) {
  std::vector<ContainerSummary> items = {
    {"redis",    "dev",  "running", 42},
    {"postgres", "dev",  "running", 17},
  };
  auto j = renderContainersJson(items);
  // Stable sort: postgres should appear before redis in output.
  auto pp = j.find("postgres");
  auto pr = j.find("redis");
  ATF_REQUIRE(pp != std::string::npos);
  ATF_REQUIRE(pr != std::string::npos);
  ATF_REQUIRE(pp < pr);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_containers_empty);
ATF_TEST_CASE_BODY(render_containers_empty) {
  auto j = renderContainersJson({});
  ATF_REQUIRE_EQ(j, std::string("{\"containers\":[]}"));
}

ATF_TEST_CASE_WITHOUT_HEAD(render_error_escapes_quotes_and_newlines);
ATF_TEST_CASE_BODY(render_error_escapes_quotes_and_newlines) {
  auto j = renderErrorJson("oops \"quoted\" \n line2");
  // Must contain escaped quote and \n
  ATF_REQUIRE(j.find("\\\"quoted\\\"") != std::string::npos);
  ATF_REQUIRE(j.find("\\n") != std::string::npos);
  // Should not contain a raw newline.
  ATF_REQUIRE(j.find('\n') == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_patch_ok_omits_empty_keys);
ATF_TEST_CASE_BODY(render_patch_ok_omits_empty_keys) {
  ResourcesPatch p;
  p.pcpu     = "20";
  p.writebps = "5M";
  // memoryuse and readbps left empty
  auto j = renderPatchOkJson(p);
  ATF_REQUIRE(j.find("pcpu")     != std::string::npos);
  ATF_REQUIRE(j.find("writebps") != std::string::npos);
  ATF_REQUIRE(j.find("memoryuse") == std::string::npos);
  ATF_REQUIRE(j.find("readbps")   == std::string::npos);
}

// ----------------------------------------------------------------------
// HTTP status mapping
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(http_status_mapping);
ATF_TEST_CASE_BODY(http_status_mapping) {
  ATF_REQUIRE_EQ(httpStatusFor(Decision::Allow),               200);
  ATF_REQUIRE_EQ(httpStatusFor(Decision::DenyGidMismatch),     403);
  ATF_REQUIRE_EQ(httpStatusFor(Decision::DenyPoolMismatch),    403);
  ATF_REQUIRE_EQ(httpStatusFor(Decision::DenyRoleMismatch),    403);
  ATF_REQUIRE_EQ(httpStatusFor(Decision::DenyUnknownAction),   404);
}

// ----------------------------------------------------------------------
// poolVisibleOnSocket
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(pool_visibility);
ATF_TEST_CASE_BODY(pool_visibility) {
  ATF_REQUIRE( poolVisibleOnSocket("dev",  {"dev","stage"}));
  ATF_REQUIRE( poolVisibleOnSocket("stage",{"dev","stage"}));
  ATF_REQUIRE(!poolVisibleOnSocket("prod", {"dev","stage"}));

  // "*" matches anything, including pool-less ("")
  ATF_REQUIRE( poolVisibleOnSocket("dev", {"*"}));
  ATF_REQUIRE( poolVisibleOnSocket("",    {"*"}));

  // Pool-less + non-wildcard socket = denied
  ATF_REQUIRE(!poolVisibleOnSocket("",    {"dev"}));
}

// ----------------------------------------------------------------------
// HTTP parsing (0.7.11)
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(http_parse_typical_get);
ATF_TEST_CASE_BODY(http_parse_typical_get) {
  std::string head =
    "GET /v1/control/containers HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "User-Agent: test\r\n"
    "\r\n";
  auto p = parseHttpHead(head);
  ATF_REQUIRE(!p.bad);
  ATF_REQUIRE_EQ(p.method, std::string("GET"));
  ATF_REQUIRE_EQ(p.path,   std::string("/v1/control/containers"));
  ATF_REQUIRE_EQ(p.contentLength, (std::size_t)0);
}

ATF_TEST_CASE_WITHOUT_HEAD(http_parse_patch_with_content_length);
ATF_TEST_CASE_BODY(http_parse_patch_with_content_length) {
  std::string head =
    "PATCH /v1/control/containers/dev-pg/resources HTTP/1.1\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 23\r\n"
    "\r\n";
  auto p = parseHttpHead(head);
  ATF_REQUIRE(!p.bad);
  ATF_REQUIRE_EQ(p.method, std::string("PATCH"));
  ATF_REQUIRE_EQ(p.path,   std::string("/v1/control/containers/dev-pg/resources"));
  ATF_REQUIRE_EQ(p.contentLength, (std::size_t)23);
}

ATF_TEST_CASE_WITHOUT_HEAD(http_parse_content_length_case_insensitive);
ATF_TEST_CASE_BODY(http_parse_content_length_case_insensitive) {
  // RFC 9110: header field names are case-insensitive.
  std::string head =
    "PATCH /v1/control/containers/x/resources HTTP/1.1\r\n"
    "CONTENT-LENGTH: 5\r\n"
    "\r\n";
  auto p = parseHttpHead(head);
  ATF_REQUIRE(!p.bad);
  ATF_REQUIRE_EQ(p.contentLength, (std::size_t)5);

  head = "PATCH /v1/control/containers/x/resources HTTP/1.1\r\n"
         "content-length: 7\r\n"
         "\r\n";
  p = parseHttpHead(head);
  ATF_REQUIRE(!p.bad);
  ATF_REQUIRE_EQ(p.contentLength, (std::size_t)7);
}

ATF_TEST_CASE_WITHOUT_HEAD(http_parse_http_1_0_accepted);
ATF_TEST_CASE_BODY(http_parse_http_1_0_accepted) {
  // Some clients (curl --http1.0, simple wrappers) negotiate HTTP/1.0.
  std::string head =
    "GET /v1/control/containers HTTP/1.0\r\n"
    "\r\n";
  auto p = parseHttpHead(head);
  ATF_REQUIRE(!p.bad);
}

ATF_TEST_CASE_WITHOUT_HEAD(http_parse_rejects_malformed);
ATF_TEST_CASE_BODY(http_parse_rejects_malformed) {
  ATF_REQUIRE(parseHttpHead("").bad);                            // empty
  ATF_REQUIRE(parseHttpHead("not http").bad);                    // no CRLF
  ATF_REQUIRE(parseHttpHead("GET\r\n\r\n").bad);                 // missing path/version
  ATF_REQUIRE(parseHttpHead("GET / HTTP/2.0\r\n\r\n").bad);      // unsupported version
  ATF_REQUIRE(parseHttpHead("GET space path HTTP/1.1\r\n\r\n").bad); // path has space
  // Non-numeric Content-Length
  ATF_REQUIRE(parseHttpHead(
    "PATCH /v1/control/containers/x/resources HTTP/1.1\r\n"
    "Content-Length: abc\r\n\r\n").bad);
  // Over 64KB cap
  ATF_REQUIRE(parseHttpHead(
    "PATCH /v1/control/containers/x/resources HTTP/1.1\r\n"
    "Content-Length: 999999999\r\n\r\n").bad);
  // Header without colon
  ATF_REQUIRE(parseHttpHead(
    "GET /x HTTP/1.1\r\n"
    "BadHeader\r\n\r\n").bad);
  // Truncated (no final empty CRLF)
  ATF_REQUIRE(parseHttpHead(
    "GET /x HTTP/1.1\r\n"
    "Host: localhost\r\n").bad);
}

ATF_TEST_CASE_WITHOUT_HEAD(http_parse_rejects_bad_method_chars);
ATF_TEST_CASE_BODY(http_parse_rejects_bad_method_chars) {
  // Method with non-letter — reject.
  ATF_REQUIRE(parseHttpHead("GET! /x HTTP/1.1\r\n\r\n").bad);
  ATF_REQUIRE(parseHttpHead("G3T /x HTTP/1.1\r\n\r\n").bad);
  // Method too long (over 16-char cap) — reject.
  ATF_REQUIRE(parseHttpHead(std::string(20, 'A') + " /x HTTP/1.1\r\n\r\n").bad);
}

ATF_TEST_CASE_WITHOUT_HEAD(http_response_shape);
ATF_TEST_CASE_BODY(http_response_shape) {
  auto r = buildHttpResponse(200, R"({"ok":true})");
  ATF_REQUIRE(r.find("HTTP/1.1 200 OK\r\n")             != std::string::npos);
  ATF_REQUIRE(r.find("Content-Type: application/json")  != std::string::npos);
  ATF_REQUIRE(r.find("Content-Length: 11")              != std::string::npos);
  ATF_REQUIRE(r.find("Connection: close")               != std::string::npos);
  // Body is included verbatim after the empty CRLF.
  auto pos = r.find("\r\n\r\n");
  ATF_REQUIRE(pos != std::string::npos);
  ATF_REQUIRE_EQ(r.substr(pos + 4), std::string(R"({"ok":true})"));
}

ATF_TEST_CASE_WITHOUT_HEAD(http_response_status_codes);
ATF_TEST_CASE_BODY(http_response_status_codes) {
  ATF_REQUIRE(buildHttpResponse(400, "{}").find(" 400 Bad Request")  != std::string::npos);
  ATF_REQUIRE(buildHttpResponse(403, "{}").find(" 403 Forbidden")    != std::string::npos);
  ATF_REQUIRE(buildHttpResponse(404, "{}").find(" 404 Not Found")    != std::string::npos);
  ATF_REQUIRE(buildHttpResponse(500, "{}").find(" 500 Internal Server Error") != std::string::npos);
}

// ----------------------------------------------------------------------
// Test entrypoint
// ----------------------------------------------------------------------

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, spec_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, spec_path_must_be_under_control_dir);
  ATF_ADD_TEST_CASE(tcs, spec_group_validated);
  ATF_ADD_TEST_CASE(tcs, spec_mode_range);
  ATF_ADD_TEST_CASE(tcs, spec_role_validated);
  ATF_ADD_TEST_CASE(tcs, spec_pools_validated);
  ATF_ADD_TEST_CASE(tcs, mode_safety);
  ATF_ADD_TEST_CASE(tcs, route_list_containers);
  ATF_ADD_TEST_CASE(tcs, route_get_container);
  ATF_ADD_TEST_CASE(tcs, route_stats);
  ATF_ADD_TEST_CASE(tcs, route_patch_resources);
  ATF_ADD_TEST_CASE(tcs, route_unknown);
  ATF_ADD_TEST_CASE(tcs, authz_typical_allow);
  ATF_ADD_TEST_CASE(tcs, authz_gid_mismatch_denies);
  ATF_ADD_TEST_CASE(tcs, authz_pool_filter_per_container);
  ATF_ADD_TEST_CASE(tcs, authz_viewer_cant_patch);
  ATF_ADD_TEST_CASE(tcs, authz_unknown_action_denied);
  ATF_ADD_TEST_CASE(tcs, authz_alt_separator);
  ATF_ADD_TEST_CASE(tcs, patch_typical);
  ATF_ADD_TEST_CASE(tcs, patch_all_keys);
  ATF_ADD_TEST_CASE(tcs, patch_unknown_key_rejected);
  ATF_ADD_TEST_CASE(tcs, patch_empty_rejected);
  ATF_ADD_TEST_CASE(tcs, patch_malformed_json_rejected);
  ATF_ADD_TEST_CASE(tcs, render_containers_sorted);
  ATF_ADD_TEST_CASE(tcs, render_containers_empty);
  ATF_ADD_TEST_CASE(tcs, render_error_escapes_quotes_and_newlines);
  ATF_ADD_TEST_CASE(tcs, render_patch_ok_omits_empty_keys);
  ATF_ADD_TEST_CASE(tcs, http_status_mapping);
  ATF_ADD_TEST_CASE(tcs, pool_visibility);
  ATF_ADD_TEST_CASE(tcs, http_parse_typical_get);
  ATF_ADD_TEST_CASE(tcs, http_parse_patch_with_content_length);
  ATF_ADD_TEST_CASE(tcs, http_parse_content_length_case_insensitive);
  ATF_ADD_TEST_CASE(tcs, http_parse_http_1_0_accepted);
  ATF_ADD_TEST_CASE(tcs, http_parse_rejects_malformed);
  ATF_ADD_TEST_CASE(tcs, http_parse_rejects_bad_method_chars);
  ATF_ADD_TEST_CASE(tcs, http_response_shape);
  ATF_ADD_TEST_CASE(tcs, http_response_status_codes);
}
