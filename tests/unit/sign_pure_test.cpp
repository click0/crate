// ATF unit tests for SignPure (lib/sign_pure.cpp).

#include <atf-c++.hpp>
#include <cstdio>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "sign_pure.h"
#include "err.h"

using SignPure::validateSecretKeyFile;
using SignPure::validatePublicKeyFile;
using SignPure::buildSignArgv;
using SignPure::buildVerifyArgv;
using SignPure::sidecarPath;

static std::string mkKeyFile(const std::string &content, mode_t mode) {
	char tmpl[] = "/tmp/crate-sign-key-XXXXXX";
	int fd = ::mkstemp(tmpl);
	if (fd < 0) return "";
	::write(fd, content.data(), content.size());
	::close(fd);
	::chmod(tmpl, mode);
	return std::string(tmpl);
}

// ===================================================================
// validateSecretKeyFile
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(secret_valid_0600);
ATF_TEST_CASE_BODY(secret_valid_0600)
{
	auto p = mkKeyFile("-----BEGIN PRIVATE KEY-----\nABC\n", 0600);
	ATF_REQUIRE(!p.empty());
	validateSecretKeyFile(p);
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(secret_world_readable_rejected);
ATF_TEST_CASE_BODY(secret_world_readable_rejected)
{
	auto p = mkKeyFile("PRIV", 0644);
	ATF_REQUIRE(!p.empty());
	ATF_REQUIRE_THROW(Exception, validateSecretKeyFile(p));
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(secret_group_readable_rejected);
ATF_TEST_CASE_BODY(secret_group_readable_rejected)
{
	auto p = mkKeyFile("PRIV", 0640);
	ATF_REQUIRE(!p.empty());
	ATF_REQUIRE_THROW(Exception, validateSecretKeyFile(p));
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(secret_empty_rejected);
ATF_TEST_CASE_BODY(secret_empty_rejected)
{
	auto p = mkKeyFile("", 0600);
	ATF_REQUIRE(!p.empty());
	ATF_REQUIRE_THROW(Exception, validateSecretKeyFile(p));
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(secret_missing_rejected);
ATF_TEST_CASE_BODY(secret_missing_rejected)
{
	ATF_REQUIRE_THROW(Exception, validateSecretKeyFile("/no/such/key"));
}

ATF_TEST_CASE_WITHOUT_HEAD(secret_directory_rejected);
ATF_TEST_CASE_BODY(secret_directory_rejected)
{
	ATF_REQUIRE_THROW(Exception, validateSecretKeyFile("/tmp"));
}

// ===================================================================
// validatePublicKeyFile — accepts looser permissions
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(public_644_ok);
ATF_TEST_CASE_BODY(public_644_ok)
{
	auto p = mkKeyFile("-----BEGIN PUBLIC KEY-----\nXYZ\n", 0644);
	ATF_REQUIRE(!p.empty());
	validatePublicKeyFile(p);
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(public_600_also_ok);
ATF_TEST_CASE_BODY(public_600_also_ok)
{
	auto p = mkKeyFile("PUB", 0600);
	ATF_REQUIRE(!p.empty());
	validatePublicKeyFile(p);  // tighter than required is fine
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(public_empty_rejected);
ATF_TEST_CASE_BODY(public_empty_rejected)
{
	auto p = mkKeyFile("", 0644);
	ATF_REQUIRE(!p.empty());
	ATF_REQUIRE_THROW(Exception, validatePublicKeyFile(p));
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(public_missing_rejected);
ATF_TEST_CASE_BODY(public_missing_rejected)
{
	ATF_REQUIRE_THROW(Exception, validatePublicKeyFile("/no/such/pub"));
}

// ===================================================================
// buildSignArgv / buildVerifyArgv — pin the openssl flags
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(sign_argv_shape);
ATF_TEST_CASE_BODY(sign_argv_shape)
{
	auto a = buildSignArgv("/k/sec.pem", "/o/file.crate", "/o/file.crate.sig");
	ATF_REQUIRE_EQ(a.size(), 10u);
	ATF_REQUIRE_EQ(a[0], "/usr/bin/openssl");
	ATF_REQUIRE_EQ(a[1], "pkeyutl");
	ATF_REQUIRE_EQ(a[2], "-sign");
	ATF_REQUIRE_EQ(a[3], "-inkey");
	ATF_REQUIRE_EQ(a[4], "/k/sec.pem");
	ATF_REQUIRE_EQ(a[5], "-rawin");           // ed25519 must be -rawin
	ATF_REQUIRE_EQ(a[6], "-in");
	ATF_REQUIRE_EQ(a[7], "/o/file.crate");
	ATF_REQUIRE_EQ(a[8], "-out");
	ATF_REQUIRE_EQ(a[9], "/o/file.crate.sig");
}

ATF_TEST_CASE_WITHOUT_HEAD(verify_argv_shape);
ATF_TEST_CASE_BODY(verify_argv_shape)
{
	auto a = buildVerifyArgv("/k/pub.pem", "/o/file.crate", "/o/file.crate.sig");
	ATF_REQUIRE_EQ(a.size(), 11u);
	ATF_REQUIRE_EQ(a[0], "/usr/bin/openssl");
	ATF_REQUIRE_EQ(a[1], "pkeyutl");
	ATF_REQUIRE_EQ(a[2], "-verify");
	ATF_REQUIRE_EQ(a[3], "-pubin");
	ATF_REQUIRE_EQ(a[4], "-inkey");
	ATF_REQUIRE_EQ(a[5], "/k/pub.pem");
	ATF_REQUIRE_EQ(a[6], "-rawin");
	ATF_REQUIRE_EQ(a[7], "-in");
	ATF_REQUIRE_EQ(a[8], "/o/file.crate");
	ATF_REQUIRE_EQ(a[9], "-sigfile");
	ATF_REQUIRE_EQ(a[10], "/o/file.crate.sig");
}

ATF_TEST_CASE_WITHOUT_HEAD(sidecar_path_basic);
ATF_TEST_CASE_BODY(sidecar_path_basic)
{
	ATF_REQUIRE_EQ(sidecarPath("/o/myapp.crate"),  "/o/myapp.crate.sig");
	ATF_REQUIRE_EQ(sidecarPath("a.tar.xz"),        "a.tar.xz.sig");
	ATF_REQUIRE_EQ(sidecarPath(""),                ".sig");
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, secret_valid_0600);
	ATF_ADD_TEST_CASE(tcs, secret_world_readable_rejected);
	ATF_ADD_TEST_CASE(tcs, secret_group_readable_rejected);
	ATF_ADD_TEST_CASE(tcs, secret_empty_rejected);
	ATF_ADD_TEST_CASE(tcs, secret_missing_rejected);
	ATF_ADD_TEST_CASE(tcs, secret_directory_rejected);
	ATF_ADD_TEST_CASE(tcs, public_644_ok);
	ATF_ADD_TEST_CASE(tcs, public_600_also_ok);
	ATF_ADD_TEST_CASE(tcs, public_empty_rejected);
	ATF_ADD_TEST_CASE(tcs, public_missing_rejected);
	ATF_ADD_TEST_CASE(tcs, sign_argv_shape);
	ATF_ADD_TEST_CASE(tcs, verify_argv_shape);
	ATF_ADD_TEST_CASE(tcs, sidecar_path_basic);
}
