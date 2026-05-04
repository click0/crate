// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "pool_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using PoolPure::inferPool;
using PoolPure::tokenAllowsContainer;
using PoolPure::validatePoolName;

// --- inferPool ---

ATF_TEST_CASE_WITHOUT_HEAD(infer_typical_dash_separator);
ATF_TEST_CASE_BODY(infer_typical_dash_separator) {
  ATF_REQUIRE_EQ(inferPool("dev-postgres-1", '-'),  std::string("dev"));
  ATF_REQUIRE_EQ(inferPool("stage-redis",     '-'), std::string("stage"));
  ATF_REQUIRE_EQ(inferPool("prod-web",        '-'), std::string("prod"));
}

ATF_TEST_CASE_WITHOUT_HEAD(infer_alternative_separator);
ATF_TEST_CASE_BODY(infer_alternative_separator) {
  // Operators with hyphens already in container names use '_' or '.'.
  ATF_REQUIRE_EQ(inferPool("dev_postgres",  '_'), std::string("dev"));
  ATF_REQUIRE_EQ(inferPool("stage.redis",   '.'), std::string("stage"));
}

ATF_TEST_CASE_WITHOUT_HEAD(infer_no_separator_is_no_pool);
ATF_TEST_CASE_BODY(infer_no_separator_is_no_pool) {
  // Monolithic name = no pool (not "" pool — they're distinct).
  ATF_REQUIRE_EQ(inferPool("monolithic", '-'), std::string(""));
  ATF_REQUIRE_EQ(inferPool("postgres",   '-'), std::string(""));
}

ATF_TEST_CASE_WITHOUT_HEAD(infer_leading_separator_is_no_pool);
ATF_TEST_CASE_BODY(infer_leading_separator_is_no_pool) {
  // "-foo" is not pool "" — it's *no* pool, same as monolithic.
  // (The ACL rule for "" is restrictive; mistakenly treating
  // "-foo" as pool "" would let pool-restricted tokens through.)
  ATF_REQUIRE_EQ(inferPool("-foo", '-'), std::string(""));
}

ATF_TEST_CASE_WITHOUT_HEAD(infer_empty_name);
ATF_TEST_CASE_BODY(infer_empty_name) {
  ATF_REQUIRE_EQ(inferPool("", '-'), std::string(""));
}

// --- validatePoolName ---

ATF_TEST_CASE_WITHOUT_HEAD(pool_name_typical_accepted);
ATF_TEST_CASE_BODY(pool_name_typical_accepted) {
  ATF_REQUIRE_EQ(validatePoolName("dev"),         std::string());
  ATF_REQUIRE_EQ(validatePoolName("stage"),       std::string());
  ATF_REQUIRE_EQ(validatePoolName("team-alpha"),  std::string());
  ATF_REQUIRE_EQ(validatePoolName("env_prod"),    std::string());
  ATF_REQUIRE_EQ(validatePoolName("v1"),          std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(pool_name_wildcard_accepted);
ATF_TEST_CASE_BODY(pool_name_wildcard_accepted) {
  // "*" is the explicit "all pools" grant.
  ATF_REQUIRE_EQ(validatePoolName("*"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(pool_name_invalid_rejected);
ATF_TEST_CASE_BODY(pool_name_invalid_rejected) {
  ATF_REQUIRE(!validatePoolName("").empty());
  ATF_REQUIRE(!validatePoolName(std::string(33, 'a')).empty());
  // Must start with alnum.
  ATF_REQUIRE(!validatePoolName("-dev").empty());
  ATF_REQUIRE(!validatePoolName("_dev").empty());
  // No dots, no slashes, no shell metas.
  ATF_REQUIRE(!validatePoolName("dev.prod").empty());
  ATF_REQUIRE(!validatePoolName("dev/prod").empty());
  ATF_REQUIRE(!validatePoolName("dev;rm").empty());
  ATF_REQUIRE(!validatePoolName("dev prod").empty());
}

// --- tokenAllowsContainer ---

ATF_TEST_CASE_WITHOUT_HEAD(acl_empty_token_pools_unrestricted);
ATF_TEST_CASE_BODY(acl_empty_token_pools_unrestricted) {
  // Backward compat: pre-0.7.4 tokens (no `pools:` in YAML) load
  // as empty list and get unrestricted access.
  ATF_REQUIRE( tokenAllowsContainer({}, "dev"));
  ATF_REQUIRE( tokenAllowsContainer({}, "stage"));
  ATF_REQUIRE( tokenAllowsContainer({}, ""));    // even no-pool jails
}

ATF_TEST_CASE_WITHOUT_HEAD(acl_wildcard_unrestricted);
ATF_TEST_CASE_BODY(acl_wildcard_unrestricted) {
  // "*" is the explicit unrestricted grant.
  ATF_REQUIRE( tokenAllowsContainer({"*"}, "dev"));
  ATF_REQUIRE( tokenAllowsContainer({"*"}, ""));
  ATF_REQUIRE( tokenAllowsContainer({"dev", "*"}, "stage"));
}

ATF_TEST_CASE_WITHOUT_HEAD(acl_pool_match_allowed);
ATF_TEST_CASE_BODY(acl_pool_match_allowed) {
  ATF_REQUIRE( tokenAllowsContainer({"dev"},          "dev"));
  ATF_REQUIRE( tokenAllowsContainer({"dev", "stage"}, "stage"));
}

ATF_TEST_CASE_WITHOUT_HEAD(acl_pool_mismatch_denied);
ATF_TEST_CASE_BODY(acl_pool_mismatch_denied) {
  ATF_REQUIRE(!tokenAllowsContainer({"dev"},          "prod"));
  ATF_REQUIRE(!tokenAllowsContainer({"dev", "stage"}, "prod"));
}

ATF_TEST_CASE_WITHOUT_HEAD(acl_no_pool_jail_only_unrestricted_tokens);
ATF_TEST_CASE_BODY(acl_no_pool_jail_only_unrestricted_tokens) {
  // Once an operator opts into pool ACLs (any non-wildcard entry
  // in `pools:`), pool-less jails (monolithic name with no
  // separator) become invisible to that token. Operators must
  // grant "*" to reach them. This is intentional: silent leakage
  // of jails that don't follow the naming convention would
  // defeat the ACL.
  ATF_REQUIRE(!tokenAllowsContainer({"dev"},  ""));
  ATF_REQUIRE( tokenAllowsContainer({"*"},    ""));   // wildcard wins
  ATF_REQUIRE(!tokenAllowsContainer({"dev", "stage"}, ""));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, infer_typical_dash_separator);
  ATF_ADD_TEST_CASE(tcs, infer_alternative_separator);
  ATF_ADD_TEST_CASE(tcs, infer_no_separator_is_no_pool);
  ATF_ADD_TEST_CASE(tcs, infer_leading_separator_is_no_pool);
  ATF_ADD_TEST_CASE(tcs, infer_empty_name);
  ATF_ADD_TEST_CASE(tcs, pool_name_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, pool_name_wildcard_accepted);
  ATF_ADD_TEST_CASE(tcs, pool_name_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, acl_empty_token_pools_unrestricted);
  ATF_ADD_TEST_CASE(tcs, acl_wildcard_unrestricted);
  ATF_ADD_TEST_CASE(tcs, acl_pool_match_allowed);
  ATF_ADD_TEST_CASE(tcs, acl_pool_mismatch_denied);
  ATF_ADD_TEST_CASE(tcs, acl_no_pool_jail_only_unrestricted_tokens);
}
