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
}
