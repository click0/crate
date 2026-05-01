// ATF unit tests for CryptoPure (lib/crypto_pure.cpp).
//
// Encryption envelope detection + passphrase-file validation. The
// argv builders are pinned to OpenSSL's `enc -aes-256-cbc -pbkdf2`
// invocation; if those flags ever change in production, the test
// fails before users hit a confusing CLI error.

#include <atf-c++.hpp>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto_pure.h"
#include "err.h"

using CryptoPure::Format;
using CryptoPure::detectFormat;
using CryptoPure::detectFile;
using CryptoPure::validatePassphraseFile;
using CryptoPure::buildEncryptArgv;
using CryptoPure::buildDecryptArgv;

// ===================================================================
// detectFormat — magic-byte sniffer
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(detect_xz_magic);
ATF_TEST_CASE_BODY(detect_xz_magic)
{
	std::string buf{"\xFD\x37\x7A\x58\x5A\x00", 6};
	ATF_REQUIRE(detectFormat(buf) == Format::Plain);
}

ATF_TEST_CASE_WITHOUT_HEAD(detect_openssl_salted);
ATF_TEST_CASE_BODY(detect_openssl_salted)
{
	std::string buf = "Salted__\x00\x00\x00\x00\x00\x00\x00\x00";
	ATF_REQUIRE(detectFormat(buf) == Format::Encrypted);
}

ATF_TEST_CASE_WITHOUT_HEAD(detect_too_short);
ATF_TEST_CASE_BODY(detect_too_short)
{
	ATF_REQUIRE(detectFormat("") == Format::Unknown);
	ATF_REQUIRE(detectFormat("xz") == Format::Unknown);
	ATF_REQUIRE(detectFormat("Salt") == Format::Unknown);
}

ATF_TEST_CASE_WITHOUT_HEAD(detect_garbage);
ATF_TEST_CASE_BODY(detect_garbage)
{
	std::string buf{"\x00\x00\x00\x00\x00\x00\x00\x00", 8};
	ATF_REQUIRE(detectFormat(buf) == Format::Unknown);
	ATF_REQUIRE(detectFormat("PK\x03\x04zip!") == Format::Unknown);  // ZIP
}

ATF_TEST_CASE_WITHOUT_HEAD(detect_does_not_misclassify_almost_match);
ATF_TEST_CASE_BODY(detect_does_not_misclassify_almost_match)
{
	// One bit off in xz magic
	std::string buf{"\xFD\x37\x7A\x58\x5A\x01", 6};
	ATF_REQUIRE(detectFormat(buf) == Format::Unknown);
	// "Salted_X" instead of "Salted__"
	ATF_REQUIRE(detectFormat("Salted_X") == Format::Unknown);
}

ATF_TEST_CASE_WITHOUT_HEAD(detect_file_xz);
ATF_TEST_CASE_BODY(detect_file_xz)
{
	char tmpl[] = "/tmp/crate-detect-XXXXXX";
	int fd = ::mkstemp(tmpl);
	ATF_REQUIRE(fd >= 0);
	::write(fd, "\xFD\x37\x7A\x58\x5A\x00plain", 11);
	::close(fd);
	ATF_REQUIRE(detectFile(tmpl) == Format::Plain);
	::unlink(tmpl);
}

ATF_TEST_CASE_WITHOUT_HEAD(detect_file_encrypted);
ATF_TEST_CASE_BODY(detect_file_encrypted)
{
	char tmpl[] = "/tmp/crate-detect-XXXXXX";
	int fd = ::mkstemp(tmpl);
	ATF_REQUIRE(fd >= 0);
	::write(fd, "Salted__\x01\x02\x03\x04\x05\x06\x07\x08garbage", 22);
	::close(fd);
	ATF_REQUIRE(detectFile(tmpl) == Format::Encrypted);
	::unlink(tmpl);
}

ATF_TEST_CASE_WITHOUT_HEAD(detect_file_missing);
ATF_TEST_CASE_BODY(detect_file_missing)
{
	ATF_REQUIRE(detectFile("/no/such/file/i-hope-this-doesnt-exist") == Format::Unknown);
}

// ===================================================================
// validatePassphraseFile — security checks
// ===================================================================

static std::string mkPwFile(const std::string &content, mode_t mode) {
	char tmpl[] = "/tmp/crate-pw-XXXXXX";
	int fd = ::mkstemp(tmpl);
	if (fd < 0) return "";
	::write(fd, content.data(), content.size());
	::close(fd);
	::chmod(tmpl, mode);
	return std::string(tmpl);
}

ATF_TEST_CASE_WITHOUT_HEAD(passphrase_valid_0600);
ATF_TEST_CASE_BODY(passphrase_valid_0600)
{
	auto p = mkPwFile("hunter2\n", 0600);
	ATF_REQUIRE(!p.empty());
	validatePassphraseFile(p);  // no throw
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(passphrase_world_readable_rejected);
ATF_TEST_CASE_BODY(passphrase_world_readable_rejected)
{
	auto p = mkPwFile("hunter2\n", 0644);
	ATF_REQUIRE(!p.empty());
	ATF_REQUIRE_THROW(Exception, validatePassphraseFile(p));
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(passphrase_group_readable_rejected);
ATF_TEST_CASE_BODY(passphrase_group_readable_rejected)
{
	auto p = mkPwFile("hunter2\n", 0640);
	ATF_REQUIRE(!p.empty());
	ATF_REQUIRE_THROW(Exception, validatePassphraseFile(p));
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(passphrase_empty_rejected);
ATF_TEST_CASE_BODY(passphrase_empty_rejected)
{
	auto p = mkPwFile("", 0600);
	ATF_REQUIRE(!p.empty());
	ATF_REQUIRE_THROW(Exception, validatePassphraseFile(p));
	::unlink(p.c_str());
}

ATF_TEST_CASE_WITHOUT_HEAD(passphrase_missing_rejected);
ATF_TEST_CASE_BODY(passphrase_missing_rejected)
{
	ATF_REQUIRE_THROW(Exception, validatePassphraseFile("/no/such/file"));
}

ATF_TEST_CASE_WITHOUT_HEAD(passphrase_directory_rejected);
ATF_TEST_CASE_BODY(passphrase_directory_rejected)
{
	ATF_REQUIRE_THROW(Exception, validatePassphraseFile("/tmp"));
}

// ===================================================================
// buildEncryptArgv / buildDecryptArgv — pin the openssl flags
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(encrypt_argv_shape);
ATF_TEST_CASE_BODY(encrypt_argv_shape)
{
	auto a = buildEncryptArgv("/secret/passphrase");
	ATF_REQUIRE_EQ(a.size(), 8u);
	ATF_REQUIRE_EQ(a[0], "/usr/bin/openssl");
	ATF_REQUIRE_EQ(a[1], "enc");
	ATF_REQUIRE_EQ(a[2], "-e");
	ATF_REQUIRE_EQ(a[3], "-aes-256-cbc");
	ATF_REQUIRE_EQ(a[4], "-pbkdf2");
	ATF_REQUIRE_EQ(a[5], "-salt");
	ATF_REQUIRE_EQ(a[6], "-kfile");
	ATF_REQUIRE_EQ(a[7], "/secret/passphrase");
}

ATF_TEST_CASE_WITHOUT_HEAD(decrypt_argv_shape);
ATF_TEST_CASE_BODY(decrypt_argv_shape)
{
	auto a = buildDecryptArgv("/secret/passphrase");
	ATF_REQUIRE_EQ(a.size(), 7u);
	ATF_REQUIRE_EQ(a[0], "/usr/bin/openssl");
	ATF_REQUIRE_EQ(a[1], "enc");
	ATF_REQUIRE_EQ(a[2], "-d");
	ATF_REQUIRE_EQ(a[3], "-aes-256-cbc");
	ATF_REQUIRE_EQ(a[4], "-pbkdf2");
	ATF_REQUIRE_EQ(a[5], "-kfile");
	ATF_REQUIRE_EQ(a[6], "/secret/passphrase");
}

ATF_TEST_CASE_WITHOUT_HEAD(argv_passphrase_path_passed_via_kfile);
ATF_TEST_CASE_BODY(argv_passphrase_path_passed_via_kfile)
{
	// Critical: passphrase must NEVER appear on the command line itself
	// (would leak via `ps`). Always via -kfile.
	auto a = buildEncryptArgv("hunter2");
	for (size_t i = 0; i + 1 < a.size(); i++)
		if (a[i] == "-kfile")
			ATF_REQUIRE_EQ(a[i + 1], "hunter2");  // path, not the secret itself
	// And no -k option that would take the passphrase inline.
	for (auto &arg : a) {
		ATF_REQUIRE(arg != "-k");
		ATF_REQUIRE(arg != "-pass");
	}
}

ATF_INIT_TEST_CASES(tcs)
{
	// detectFormat
	ATF_ADD_TEST_CASE(tcs, detect_xz_magic);
	ATF_ADD_TEST_CASE(tcs, detect_openssl_salted);
	ATF_ADD_TEST_CASE(tcs, detect_too_short);
	ATF_ADD_TEST_CASE(tcs, detect_garbage);
	ATF_ADD_TEST_CASE(tcs, detect_does_not_misclassify_almost_match);
	// detectFile
	ATF_ADD_TEST_CASE(tcs, detect_file_xz);
	ATF_ADD_TEST_CASE(tcs, detect_file_encrypted);
	ATF_ADD_TEST_CASE(tcs, detect_file_missing);
	// validatePassphraseFile
	ATF_ADD_TEST_CASE(tcs, passphrase_valid_0600);
	ATF_ADD_TEST_CASE(tcs, passphrase_world_readable_rejected);
	ATF_ADD_TEST_CASE(tcs, passphrase_group_readable_rejected);
	ATF_ADD_TEST_CASE(tcs, passphrase_empty_rejected);
	ATF_ADD_TEST_CASE(tcs, passphrase_missing_rejected);
	ATF_ADD_TEST_CASE(tcs, passphrase_directory_rejected);
	// argv builders
	ATF_ADD_TEST_CASE(tcs, encrypt_argv_shape);
	ATF_ADD_TEST_CASE(tcs, decrypt_argv_shape);
	ATF_ADD_TEST_CASE(tcs, argv_passphrase_path_passed_via_kfile);
}
