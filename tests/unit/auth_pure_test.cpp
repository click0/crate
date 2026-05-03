// ATF unit tests for AuthPure (lib/auth_pure.cpp).
//
// The Bearer-token gate guards every TCP-bound /api/* call to crated.
// A regression here = a broken auth check on a network-facing daemon.

#include <atf-c++.hpp>
#include <string>
#include <vector>

#include "auth_pure.h"

// Identity-mapping "hash" for tests — passes the token straight through
// so we can write expectations in plain text.
static std::string fakeSha(const std::string &s) { return "sha256:" + s; }

static std::vector<Crated::AuthToken> mkTokens() {
	return {
		{"viewer-1", "sha256:secret-viewer", "viewer"},
		{"admin-1",  "sha256:secret-admin",  "admin"},
		{"writer-1", "sha256:secret-writer", "writer"},
	};
}

// ===================================================================
// parseBearerToken
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(parseBearer_basic);
ATF_TEST_CASE_BODY(parseBearer_basic)
{
	ATF_REQUIRE_EQ(AuthPure::parseBearerToken("Bearer abc123"), "abc123");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseBearer_empty);
ATF_TEST_CASE_BODY(parseBearer_empty)
{
	ATF_REQUIRE_EQ(AuthPure::parseBearerToken(""), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseBearer_just_prefix);
ATF_TEST_CASE_BODY(parseBearer_just_prefix)
{
	// "Bearer " alone (7 chars, == prefix size) — current code says
	// size <= prefix.size() → empty. Pin behaviour.
	ATF_REQUIRE_EQ(AuthPure::parseBearerToken("Bearer "), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseBearer_wrong_scheme);
ATF_TEST_CASE_BODY(parseBearer_wrong_scheme)
{
	ATF_REQUIRE_EQ(AuthPure::parseBearerToken("Basic abc123"), "");
	ATF_REQUIRE_EQ(AuthPure::parseBearerToken("bearer abc"), "");  // lowercase
	ATF_REQUIRE_EQ(AuthPure::parseBearerToken("token abc"), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseBearer_token_with_spaces);
ATF_TEST_CASE_BODY(parseBearer_token_with_spaces)
{
	// Token may itself contain spaces — they survive verbatim.
	ATF_REQUIRE_EQ(AuthPure::parseBearerToken("Bearer a b c"), "a b c");
}

// ===================================================================
// checkTokenRole
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(checkTokenRole_unknown_hash_rejected);
ATF_TEST_CASE_BODY(checkTokenRole_unknown_hash_rejected)
{
	ATF_REQUIRE(!AuthPure::checkTokenRole("sha256:nope", mkTokens(), "viewer"));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkTokenRole_viewer_role_any_token);
ATF_TEST_CASE_BODY(checkTokenRole_viewer_role_any_token)
{
	auto t = mkTokens();
	ATF_REQUIRE( AuthPure::checkTokenRole("sha256:secret-viewer", t, "viewer"));
	ATF_REQUIRE( AuthPure::checkTokenRole("sha256:secret-admin",  t, "viewer"));
	ATF_REQUIRE( AuthPure::checkTokenRole("sha256:secret-writer", t, "viewer"));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkTokenRole_admin_required);
ATF_TEST_CASE_BODY(checkTokenRole_admin_required)
{
	auto t = mkTokens();
	ATF_REQUIRE( AuthPure::checkTokenRole("sha256:secret-admin",  t, "admin"));
	ATF_REQUIRE(!AuthPure::checkTokenRole("sha256:secret-viewer", t, "admin"));
	ATF_REQUIRE(!AuthPure::checkTokenRole("sha256:secret-writer", t, "admin"));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkTokenRole_writer_required);
ATF_TEST_CASE_BODY(checkTokenRole_writer_required)
{
	// admin gets writer access (admin ⊇ all roles); viewer doesn't.
	auto t = mkTokens();
	ATF_REQUIRE( AuthPure::checkTokenRole("sha256:secret-writer", t, "writer"));
	ATF_REQUIRE( AuthPure::checkTokenRole("sha256:secret-admin",  t, "writer"));
	ATF_REQUIRE(!AuthPure::checkTokenRole("sha256:secret-viewer", t, "writer"));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkTokenRole_empty_tokens);
ATF_TEST_CASE_BODY(checkTokenRole_empty_tokens)
{
	std::vector<Crated::AuthToken> none;
	ATF_REQUIRE(!AuthPure::checkTokenRole("sha256:anything", none, "viewer"));
	ATF_REQUIRE(!AuthPure::checkTokenRole("sha256:anything", none, "admin"));
}

// ===================================================================
// checkBearerAuth (full flow with injected sha256)
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(checkBearer_happy);
ATF_TEST_CASE_BODY(checkBearer_happy)
{
	ATF_REQUIRE(AuthPure::checkBearerAuth(
		"Bearer secret-admin", mkTokens(), "admin", fakeSha));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkBearer_missing_header);
ATF_TEST_CASE_BODY(checkBearer_missing_header)
{
	ATF_REQUIRE(!AuthPure::checkBearerAuth(
		"", mkTokens(), "viewer", fakeSha));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkBearer_wrong_scheme);
ATF_TEST_CASE_BODY(checkBearer_wrong_scheme)
{
	ATF_REQUIRE(!AuthPure::checkBearerAuth(
		"Basic dXNlcjpwYXNz", mkTokens(), "viewer", fakeSha));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkBearer_role_escalation_blocked);
ATF_TEST_CASE_BODY(checkBearer_role_escalation_blocked)
{
	// viewer tries to invoke admin — must be rejected.
	ATF_REQUIRE(!AuthPure::checkBearerAuth(
		"Bearer secret-viewer", mkTokens(), "admin", fakeSha));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkBearer_admin_can_do_anything);
ATF_TEST_CASE_BODY(checkBearer_admin_can_do_anything)
{
	auto h = "Bearer secret-admin";
	for (auto role : {"viewer", "admin", "writer", "any"}) {
		ATF_REQUIRE(AuthPure::checkBearerAuth(h, mkTokens(), role, fakeSha));
	}
}

// ===================================================================
// TTL + scope (0.7.1)
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(parseIso8601_canonical);
ATF_TEST_CASE_BODY(parseIso8601_canonical)
{
	// Canonical epochs — the boundaries crate uses elsewhere.
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc("1970-01-01T00:00:00Z"), 0L);
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc("2000-01-01T00:00:00Z"), 946684800L);
	// Last second of 2026 — token expiry that operators paste.
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc("2026-12-31T23:59:59Z"), 1798761599L);
}

ATF_TEST_CASE_WITHOUT_HEAD(parseIso8601_invalid_rejected);
ATF_TEST_CASE_BODY(parseIso8601_invalid_rejected)
{
	// Bad shape, bad month, bad timezone all return -1.
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc(""),                    -1L);
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc("not a date"),          -1L);
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc("2026/12/31T23:59:59Z"), -1L);
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc("2026-13-31T00:00:00Z"), -1L);
	// Non-UTC timezone offsets are rejected on purpose — keep
	// crated.conf timestamps unambiguous.
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc("2026-12-31T23:59:59+03:00"), -1L);
}

ATF_TEST_CASE_WITHOUT_HEAD(parseIso8601_offset_zero);
ATF_TEST_CASE_BODY(parseIso8601_offset_zero)
{
	// Both Z and +00:00 are accepted spellings for UTC.
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc("2000-01-01T00:00:00+00:00"),
	               AuthPure::parseIso8601Utc("2000-01-01T00:00:00Z"));
	ATF_REQUIRE_EQ(AuthPure::parseIso8601Utc("2000-01-01T00:00:00-00:00"),
	               AuthPure::parseIso8601Utc("2000-01-01T00:00:00Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(isExpired_zero_means_never);
ATF_TEST_CASE_BODY(isExpired_zero_means_never)
{
	// Backward compatibility: tokens loaded from old crated.conf
	// files have expiresAt == 0 and must NEVER be considered expired.
	Crated::AuthToken t{"forever", "sha256:x", "viewer", 0, {}};
	ATF_REQUIRE(!AuthPure::isExpired(t, 0));
	ATF_REQUIRE(!AuthPure::isExpired(t, 1700000000L));
	ATF_REQUIRE(!AuthPure::isExpired(t, 9999999999L));
}

ATF_TEST_CASE_WITHOUT_HEAD(isExpired_strict_after);
ATF_TEST_CASE_BODY(isExpired_strict_after)
{
	Crated::AuthToken t{"short", "sha256:x", "viewer", 1000, {}};
	// Strict-after: at the exact expiry second the token still works.
	ATF_REQUIRE(!AuthPure::isExpired(t, 999));
	ATF_REQUIRE(!AuthPure::isExpired(t, 1000));
	ATF_REQUIRE( AuthPure::isExpired(t, 1001));
}

ATF_TEST_CASE_WITHOUT_HEAD(scope_empty_allows_any_path);
ATF_TEST_CASE_BODY(scope_empty_allows_any_path)
{
	// Empty scope = unrestricted, matches the existing role-only model.
	ATF_REQUIRE(AuthPure::pathInScope({}, "/api/v1/anything"));
	ATF_REQUIRE(AuthPure::pathInScope({}, ""));
}

ATF_TEST_CASE_WITHOUT_HEAD(scope_exact_match);
ATF_TEST_CASE_BODY(scope_exact_match)
{
	std::vector<std::string> sc = {"/api/v1/host", "/healthz"};
	ATF_REQUIRE( AuthPure::pathInScope(sc, "/healthz"));
	ATF_REQUIRE( AuthPure::pathInScope(sc, "/api/v1/host"));
	ATF_REQUIRE(!AuthPure::pathInScope(sc, "/api/v1/containers"));
	// No partial-prefix matching without an explicit /* glob.
	ATF_REQUIRE(!AuthPure::pathInScope(sc, "/api/v1/host/foo"));
}

ATF_TEST_CASE_WITHOUT_HEAD(scope_trailing_glob);
ATF_TEST_CASE_BODY(scope_trailing_glob)
{
	std::vector<std::string> sc = {"/api/v1/containers/*"};
	ATF_REQUIRE( AuthPure::pathInScope(sc, "/api/v1/containers/foo"));
	ATF_REQUIRE( AuthPure::pathInScope(sc, "/api/v1/containers/foo/stats"));
	ATF_REQUIRE(!AuthPure::pathInScope(sc, "/api/v1/host"));
}

ATF_TEST_CASE_WITHOUT_HEAD(scope_glob_requires_slash);
ATF_TEST_CASE_BODY(scope_glob_requires_slash)
{
	// "/api/v1/foo/*" must NOT match the bare prefix "/api/v1/foo"
	// (no trailing slash) — operators rely on this distinction so
	// they can grant per-resource access without leaking the
	// collection-list endpoint.
	std::vector<std::string> sc = {"/api/v1/containers/*"};
	ATF_REQUIRE(!AuthPure::pathInScope(sc, "/api/v1/containers"));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkBearerFull_expired_rejected);
ATF_TEST_CASE_BODY(checkBearerFull_expired_rejected)
{
	std::vector<Crated::AuthToken> toks = {
		{"shortlived", "sha256:secret-X", "admin", 1000, {}},
	};
	// Now=1500 — expired even though role + scope match.
	ATF_REQUIRE(!AuthPure::checkBearerAuthFull(
		"Bearer secret-X", toks, "admin", "/api/v1/host", 1500, fakeSha));
	// Expiry is strict-after: at the exact second still alive.
	ATF_REQUIRE( AuthPure::checkBearerAuthFull(
		"Bearer secret-X", toks, "admin", "/api/v1/host", 1000, fakeSha));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkBearerFull_out_of_scope_rejected);
ATF_TEST_CASE_BODY(checkBearerFull_out_of_scope_rejected)
{
	std::vector<Crated::AuthToken> toks = {
		{"limited", "sha256:secret-Y", "admin", 0,
		 {"/api/v1/containers/*"}},
	};
	// Scope misses /api/v1/host even though role would otherwise allow.
	ATF_REQUIRE(!AuthPure::checkBearerAuthFull(
		"Bearer secret-Y", toks, "admin", "/api/v1/host", 0, fakeSha));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkBearerFull_in_scope_admin_ok);
ATF_TEST_CASE_BODY(checkBearerFull_in_scope_admin_ok)
{
	std::vector<Crated::AuthToken> toks = {
		{"ci", "sha256:secret-Z", "admin", 0, {"/api/v1/containers/*"}},
	};
	ATF_REQUIRE( AuthPure::checkBearerAuthFull(
		"Bearer secret-Z", toks, "admin",
		"/api/v1/containers/myjail/stop", 0, fakeSha));
}

ATF_TEST_CASE_WITHOUT_HEAD(checkBearerFull_unexpired_no_scope_ok);
ATF_TEST_CASE_BODY(checkBearerFull_unexpired_no_scope_ok)
{
	// Backward-compat: tokens loaded from a pre-0.7.1 crated.conf
	// have expiresAt=0 + scope=[] and must keep behaving as
	// unrestricted.
	std::vector<Crated::AuthToken> toks = {
		{"old", "sha256:secret-A", "admin", 0, {}},
	};
	ATF_REQUIRE(AuthPure::checkBearerAuthFull(
		"Bearer secret-A", toks, "admin", "/api/v1/host", 1700000000L, fakeSha));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, parseBearer_basic);
	ATF_ADD_TEST_CASE(tcs, parseBearer_empty);
	ATF_ADD_TEST_CASE(tcs, parseBearer_just_prefix);
	ATF_ADD_TEST_CASE(tcs, parseBearer_wrong_scheme);
	ATF_ADD_TEST_CASE(tcs, parseBearer_token_with_spaces);
	ATF_ADD_TEST_CASE(tcs, checkTokenRole_unknown_hash_rejected);
	ATF_ADD_TEST_CASE(tcs, checkTokenRole_viewer_role_any_token);
	ATF_ADD_TEST_CASE(tcs, checkTokenRole_admin_required);
	ATF_ADD_TEST_CASE(tcs, checkTokenRole_writer_required);
	ATF_ADD_TEST_CASE(tcs, checkTokenRole_empty_tokens);
	ATF_ADD_TEST_CASE(tcs, checkBearer_happy);
	ATF_ADD_TEST_CASE(tcs, checkBearer_missing_header);
	ATF_ADD_TEST_CASE(tcs, checkBearer_wrong_scheme);
	ATF_ADD_TEST_CASE(tcs, checkBearer_role_escalation_blocked);
	ATF_ADD_TEST_CASE(tcs, checkBearer_admin_can_do_anything);

	// --- TTL + scope (0.7.1) ---
	ATF_ADD_TEST_CASE(tcs, parseIso8601_canonical);
	ATF_ADD_TEST_CASE(tcs, parseIso8601_invalid_rejected);
	ATF_ADD_TEST_CASE(tcs, parseIso8601_offset_zero);
	ATF_ADD_TEST_CASE(tcs, isExpired_zero_means_never);
	ATF_ADD_TEST_CASE(tcs, isExpired_strict_after);
	ATF_ADD_TEST_CASE(tcs, scope_empty_allows_any_path);
	ATF_ADD_TEST_CASE(tcs, scope_exact_match);
	ATF_ADD_TEST_CASE(tcs, scope_trailing_glob);
	ATF_ADD_TEST_CASE(tcs, scope_glob_requires_slash);
	ATF_ADD_TEST_CASE(tcs, checkBearerFull_expired_rejected);
	ATF_ADD_TEST_CASE(tcs, checkBearerFull_out_of_scope_rejected);
	ATF_ADD_TEST_CASE(tcs, checkBearerFull_in_scope_admin_ok);
	ATF_ADD_TEST_CASE(tcs, checkBearerFull_unexpired_no_scope_ok);
}
