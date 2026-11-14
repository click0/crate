// ATF unit tests for RunGuiPure (lib/run_gui_pure.cpp).
//
// VESA CVT modeline math + resolution helpers. The CVT formula is
// well-defined (VESA CVT 1.1 RB), so we can pin down the output for
// canonical resolutions. A regression here breaks `crate` GUI mode
// (xrandr/Xephyr) for non-default sizes.

#include <atf-c++.hpp>
#include <cmath>
#include <string>

#include "run_gui_pure.h"
#include "spec.h"

using RunGuiPure::computeCvtModeline;
using RunGuiPure::resolveResolution;
using RunGuiPure::parseResolution;
using RunGuiPure::CvtModeline;

// ===================================================================
// computeCvtModeline — pin known-good results
// ===================================================================

static bool approx(double a, double b, double eps = 0.5) {
	return std::fabs(a - b) <= eps;
}

ATF_TEST_CASE_WITHOUT_HEAD(cvt_1080p_60);
ATF_TEST_CASE_BODY(cvt_1080p_60)
{
	auto m = computeCvtModeline(1920, 1080, 60.0);
	ATF_REQUIRE_EQ(m.hdisp, 1920u);
	ATF_REQUIRE_EQ(m.vdisp, 1080u);
	// htotal = w + 160 (RB H blank)
	ATF_REQUIRE_EQ(m.htotal, 2080u);
	// hsync_start = w + 48, hsync_end = +32
	ATF_REQUIRE_EQ(m.hsyncStart, 1968u);
	ATF_REQUIRE_EQ(m.hsyncEnd, 2000u);
	// vsync timing
	ATF_REQUIRE_EQ(m.vsyncStart, 1083u);
	ATF_REQUIRE_EQ(m.vsyncEnd, 1087u);
	// CVT-RB pixel clock for 1920x1080@60Hz is ~138.5 MHz
	ATF_REQUIRE(approx(m.pixelClock, 138.5, 1.0));
}

ATF_TEST_CASE_WITHOUT_HEAD(cvt_720p_60);
ATF_TEST_CASE_BODY(cvt_720p_60)
{
	auto m = computeCvtModeline(1280, 720, 60.0);
	ATF_REQUIRE_EQ(m.hdisp, 1280u);
	ATF_REQUIRE_EQ(m.vdisp, 720u);
	ATF_REQUIRE_EQ(m.htotal, 1440u);
	// CVT-RB pixel clock for 1280x720@60Hz is ~64.0 MHz
	ATF_REQUIRE(approx(m.pixelClock, 64.0, 1.0));
}

ATF_TEST_CASE_WITHOUT_HEAD(cvt_4k_60);
ATF_TEST_CASE_BODY(cvt_4k_60)
{
	auto m = computeCvtModeline(3840, 2160, 60.0);
	ATF_REQUIRE_EQ(m.hdisp, 3840u);
	ATF_REQUIRE_EQ(m.vdisp, 2160u);
	ATF_REQUIRE_EQ(m.htotal, 4000u);
	// 4K@60Hz CVT-RB ~533 MHz pixel clock
	ATF_REQUIRE(m.pixelClock > 500.0 && m.pixelClock < 600.0);
}

ATF_TEST_CASE_WITHOUT_HEAD(cvt_invariants);
ATF_TEST_CASE_BODY(cvt_invariants)
{
	// Iterate a handful of common sizes; each must satisfy structural
	// invariants of any CVT modeline.
	struct { unsigned w, h; } sizes[] = {
		{640, 480}, {800, 600}, {1024, 768},
		{1280, 1024}, {1600, 900}, {2560, 1440},
	};
	for (auto &s : sizes) {
		auto m = computeCvtModeline(s.w, s.h);
		ATF_REQUIRE_EQ(m.hdisp, s.w);
		ATF_REQUIRE_EQ(m.vdisp, s.h);
		ATF_REQUIRE(m.htotal > m.hdisp);
		ATF_REQUIRE(m.vtotal > m.vdisp);
		ATF_REQUIRE(m.hsyncStart >= m.hdisp);
		ATF_REQUIRE(m.hsyncEnd > m.hsyncStart);
		ATF_REQUIRE(m.hsyncEnd <= m.htotal);
		ATF_REQUIRE(m.vsyncStart >= m.vdisp);
		ATF_REQUIRE(m.vsyncEnd > m.vsyncStart);
		ATF_REQUIRE(m.vsyncEnd <= m.vtotal);
		ATF_REQUIRE(m.pixelClock > 0.0);
	}
}

ATF_TEST_CASE_WITHOUT_HEAD(cvt_higher_refresh_higher_clock);
ATF_TEST_CASE_BODY(cvt_higher_refresh_higher_clock)
{
	// 1080p @ 60 vs @ 120 — 120Hz must produce higher pixel clock.
	auto m60  = computeCvtModeline(1920, 1080, 60.0);
	auto m120 = computeCvtModeline(1920, 1080, 120.0);
	ATF_REQUIRE(m120.pixelClock > m60.pixelClock);
}

// ===================================================================
// resolveResolution — Spec → string
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(resolveRes_default);
ATF_TEST_CASE_BODY(resolveRes_default)
{
	Spec s;
	ATF_REQUIRE_EQ(resolveResolution(s), "1280x720");
}

ATF_TEST_CASE_WITHOUT_HEAD(resolveRes_gui_overrides);
ATF_TEST_CASE_BODY(resolveRes_gui_overrides)
{
	Spec s;
	s.guiOptions = std::make_unique<Spec::GuiOptions>();
	s.guiOptions->resolution = "1920x1080";
	ATF_REQUIRE_EQ(resolveResolution(s), "1920x1080");
}

ATF_TEST_CASE_WITHOUT_HEAD(resolveRes_x11_fallback);
ATF_TEST_CASE_BODY(resolveRes_x11_fallback)
{
	Spec s;
	s.x11Options = std::make_unique<Spec::X11Options>();
	s.x11Options->resolution = "1024x768";
	ATF_REQUIRE_EQ(resolveResolution(s), "1024x768");
}

ATF_TEST_CASE_WITHOUT_HEAD(resolveRes_gui_wins_over_x11);
ATF_TEST_CASE_BODY(resolveRes_gui_wins_over_x11)
{
	Spec s;
	s.guiOptions = std::make_unique<Spec::GuiOptions>();
	s.guiOptions->resolution = "1920x1080";
	s.x11Options = std::make_unique<Spec::X11Options>();
	s.x11Options->resolution = "1024x768";
	ATF_REQUIRE_EQ(resolveResolution(s), "1920x1080");
}

// ===================================================================
// parseResolution — "WxH"
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(parseRes_basic);
ATF_TEST_CASE_BODY(parseRes_basic)
{
	unsigned w = 0, h = 0;
	ATF_REQUIRE(parseResolution("1920x1080", w, h));
	ATF_REQUIRE_EQ(w, 1920u);
	ATF_REQUIRE_EQ(h, 1080u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRes_zero_rejected);
ATF_TEST_CASE_BODY(parseRes_zero_rejected)
{
	unsigned w, h;
	ATF_REQUIRE(!parseResolution("0x1080", w, h));
	ATF_REQUIRE(!parseResolution("1920x0", w, h));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRes_garbage);
ATF_TEST_CASE_BODY(parseRes_garbage)
{
	unsigned w, h;
	ATF_REQUIRE(!parseResolution("", w, h));
	ATF_REQUIRE(!parseResolution("1920", w, h));
	ATF_REQUIRE(!parseResolution("x1080", w, h));
	ATF_REQUIRE(!parseResolution("1920x", w, h));
	ATF_REQUIRE(!parseResolution("abc", w, h));
	ATF_REQUIRE(!parseResolution("1920x1080xfoo", w, h));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRes_extra_chars);
ATF_TEST_CASE_BODY(parseRes_extra_chars)
{
	unsigned w, h;
	ATF_REQUIRE(!parseResolution("1920px", w, h));
	ATF_REQUIRE(!parseResolution(" 1920x1080", w, h));
	ATF_REQUIRE(!parseResolution("1920x1080 ", w, h));
}

// ===================================================================
// generateGpuXorgConf — string-builder for headless GPU xorg.conf
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(xorg_conf_default_driver);
ATF_TEST_CASE_BODY(xorg_conf_default_driver)
{
	auto out = RunGuiPure::generateGpuXorgConf(0, "1920x1080", "", "");
	ATF_REQUIRE(out.find("Driver     \"dummy\"") != std::string::npos);
	ATF_REQUIRE(out.find("\"1920x1080\"") != std::string::npos);
	ATF_REQUIRE(out.find("Virtual    1920 1080") != std::string::npos);
	// No BusID line when device is empty
	ATF_REQUIRE(out.find("BusID") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(xorg_conf_explicit_driver);
ATF_TEST_CASE_BODY(xorg_conf_explicit_driver)
{
	auto out = RunGuiPure::generateGpuXorgConf(0, "1280x720", "intel", "PCI:0:2:0");
	ATF_REQUIRE(out.find("Driver     \"intel\"") != std::string::npos);
	ATF_REQUIRE(out.find("BusID      \"PCI:0:2:0\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(xorg_conf_nvidia_extras);
ATF_TEST_CASE_BODY(xorg_conf_nvidia_extras)
{
	auto out = RunGuiPure::generateGpuXorgConf(0, "1920x1080", "nvidia", "PCI:1:0:0");
	ATF_REQUIRE(out.find("Driver     \"nvidia\"") != std::string::npos);
	ATF_REQUIRE(out.find("AllowEmptyInitialConfiguration") != std::string::npos);
	ATF_REQUIRE(out.find("ConnectedMonitor") != std::string::npos);
	ATF_REQUIRE(out.find("CustomEDID") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(xorg_conf_no_nvidia_extras_for_dummy);
ATF_TEST_CASE_BODY(xorg_conf_no_nvidia_extras_for_dummy)
{
	auto out = RunGuiPure::generateGpuXorgConf(0, "1920x1080", "dummy", "");
	ATF_REQUIRE(out.find("AllowEmptyInitialConfiguration") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(xorg_conf_required_sections_present);
ATF_TEST_CASE_BODY(xorg_conf_required_sections_present)
{
	auto out = RunGuiPure::generateGpuXorgConf(0, "1024x768", "", "");
	for (auto sec : {"Section \"Device\"", "Section \"Monitor\"",
	                 "Section \"Screen\"", "Section \"ServerLayout\"",
	                 "Section \"ServerFlags\""}) {
		ATF_REQUIRE(out.find(sec) != std::string::npos);
	}
}

ATF_TEST_CASE_WITHOUT_HEAD(xorg_conf_garbage_resolution_falls_back);
ATF_TEST_CASE_BODY(xorg_conf_garbage_resolution_falls_back)
{
	// Invalid resolution → falls back to 1280x720 internally.
	auto out = RunGuiPure::generateGpuXorgConf(0, "garbage", "", "");
	ATF_REQUIRE(out.find("Virtual    1280 720") != std::string::npos);
}

// ===================================================================
// 0.8.18: gui: auto resolution + Wayland socket parser
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(autoMode_display_set_picks_shared);
ATF_TEST_CASE_BODY(autoMode_display_set_picks_shared)
{
	ATF_REQUIRE_EQ(RunGuiPure::resolveAutoMode(true,  false, false), std::string("shared"));
	ATF_REQUIRE_EQ(RunGuiPure::resolveAutoMode(true,  true,  true),  std::string("shared"));
	// GPU presence shouldn't override the shared path when DISPLAY is set.
	ATF_REQUIRE_EQ(RunGuiPure::resolveAutoMode(true,  false, true),  std::string("shared"));
}

ATF_TEST_CASE_WITHOUT_HEAD(autoMode_wayland_only_picks_shared);
ATF_TEST_CASE_BODY(autoMode_wayland_only_picks_shared)
{
	// Wayland-only host (no X server) -> shared path. The shared
	// branch in setupX11 conditionally skips X11 when DISPLAY is
	// unset and just sets up Wayland.
	ATF_REQUIRE_EQ(RunGuiPure::resolveAutoMode(false, true, false), std::string("shared"));
	ATF_REQUIRE_EQ(RunGuiPure::resolveAutoMode(false, true, true),  std::string("shared"));
}

ATF_TEST_CASE_WITHOUT_HEAD(autoMode_no_display_with_gpu_picks_gpu);
ATF_TEST_CASE_BODY(autoMode_no_display_with_gpu_picks_gpu)
{
	// SSH session into a GPU host: no DISPLAY, no Wayland, has GPU.
	ATF_REQUIRE_EQ(RunGuiPure::resolveAutoMode(false, false, true), std::string("gpu"));
}

ATF_TEST_CASE_WITHOUT_HEAD(autoMode_nothing_picks_headless);
ATF_TEST_CASE_BODY(autoMode_nothing_picks_headless)
{
	ATF_REQUIRE_EQ(RunGuiPure::resolveAutoMode(false, false, false), std::string("headless"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseWayland_basenames);
ATF_TEST_CASE_BODY(parseWayland_basenames)
{
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay("wayland-0"), std::string("wayland-0"));
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay("wayland-1"), std::string("wayland-1"));
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay("custom_socket-name.42"), std::string("custom_socket-name.42"));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseWayland_rejects_paths_and_garbage);
ATF_TEST_CASE_BODY(parseWayland_rejects_paths_and_garbage)
{
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay(""), std::string());
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay("/abs/path"), std::string());
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay("rel/path"), std::string());
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay(".."), std::string());
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay("."), std::string());
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay("$(rm -rf /)"), std::string());
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay("with space"), std::string());
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay("with;semicolon"), std::string());
	// Length cap at 64.
	std::string toolong(65, 'a');
	ATF_REQUIRE_EQ(RunGuiPure::parseWaylandDisplay(toolong), std::string());
}

// --- 0.8.44: PipeWire socket list ---

ATF_TEST_CASE_WITHOUT_HEAD(pipewireSocketNames_lists_two_canonical);
ATF_TEST_CASE_BODY(pipewireSocketNames_lists_two_canonical)
{
	auto names = RunGuiPure::pipewireSocketNames();
	ATF_REQUIRE_EQ(names.size(), (size_t)2);
	// Order matters: client API socket before manager.
	ATF_REQUIRE_EQ(names[0], std::string("pipewire-0"));
	ATF_REQUIRE_EQ(names[1], std::string("pipewire-0-manager"));
}

ATF_TEST_CASE_WITHOUT_HEAD(pipewireSocketNames_excludes_pulse_compat);
ATF_TEST_CASE_BODY(pipewireSocketNames_excludes_pulse_compat)
{
	// pulse/native lives under a subdir of XDG_RUNTIME_DIR which
	// the flat-bind strategy doesn't support yet. Belt-and-braces
	// against an accidental future addition that breaks the binder.
	auto names = RunGuiPure::pipewireSocketNames();
	for (const auto &n : names) {
		ATF_REQUIRE(n.find('/') == std::string::npos);
		ATF_REQUIRE(n != "pulse");
	}
}

// --- 0.8.47: PulseAudio compat socket ---

ATF_TEST_CASE_WITHOUT_HEAD(pulseSocketRelpath_canonical);
ATF_TEST_CASE_BODY(pulseSocketRelpath_canonical)
{
	// Pinning the relpath stops a future "let's switch to
	// pulseaudio.sock" rename from sneaking past CI without
	// updating ops docs.
	ATF_REQUIRE_EQ(RunGuiPure::pulseSocketRelpath(),
	               std::string("pulse/native"));
}

ATF_TEST_CASE_WITHOUT_HEAD(pulseSocketRelpath_has_subdir);
ATF_TEST_CASE_BODY(pulseSocketRelpath_has_subdir)
{
	// Defensive: the runtime detects sub-dir form via the
	// presence of '/' and creates the parent. If pulse/native
	// ever loses its subdir (operator-supplied override?),
	// the runtime fast-path would silently regress.
	auto p = RunGuiPure::pulseSocketRelpath();
	ATF_REQUIRE(p.find('/') != std::string::npos);
	auto slash = p.find('/');
	ATF_REQUIRE(slash > 0);                    // non-empty parent
	ATF_REQUIRE(slash < p.size() - 1);         // non-empty basename
}

// 1.1.74: the jail's X socket directory and the host-cookie decision.
ATF_TEST_CASE_WITHOUT_HEAD(own_x_socket_dir);
ATF_TEST_CASE_BODY(own_x_socket_dir)
{
	const std::string t = RunGuiPure::ownXSocketDirTemplate();
	// inside /tmp/.X11-unix (same filesystem as the socket), mkdtemp form
	ATF_REQUIRE_EQ(t.compare(0, 15, "/tmp/.X11-unix/"), 0);
	ATF_REQUIRE(t.size() >= 6 && t.compare(t.size() - 6, 6, "XXXXXX") == 0);
	ATF_REQUIRE(RunGuiPure::isOwnXSocketDir(t));
	ATF_REQUIRE(RunGuiPure::isOwnXSocketDir("/tmp/.X11-unix/.crate-Ab12Cd34"));
	ATF_REQUIRE(!RunGuiPure::isOwnXSocketDir("/tmp/.X11-unix"));
	ATF_REQUIRE(!RunGuiPure::isOwnXSocketDir("/tmp/.X11-unix/X0"));
	ATF_REQUIRE(!RunGuiPure::isOwnXSocketDir("/tmp/.X11-unix/.crate-"));
	ATF_REQUIRE(!RunGuiPure::isOwnXSocketDir("/var/tmp/.X11-unix/.crate-x"));
	ATF_REQUIRE_EQ(RunGuiPure::xSocketName(0), std::string("X0"));
	ATF_REQUIRE_EQ(RunGuiPure::xSocketName(12), std::string("X12"));
	// 1.1.78: the shared mode's directory with the HOST display's socket
	// has a name of its own, and is not taken for an own-server one
	const std::string h = RunGuiPure::hostXSocketDirTemplate();
	ATF_REQUIRE_EQ(h.compare(0, 15, "/tmp/.X11-unix/"), 0);
	ATF_REQUIRE(h.size() >= 6 && h.compare(h.size() - 6, 6, "XXXXXX") == 0);
	ATF_REQUIRE(RunGuiPure::isHostXSocketDir(h));
	ATF_REQUIRE(RunGuiPure::isHostXSocketDir("/tmp/.X11-unix/.crate-host-Ab12Cd34/X0"));
	ATF_REQUIRE(!RunGuiPure::isOwnXSocketDir(h));
	ATF_REQUIRE(!RunGuiPure::isHostXSocketDir(t));
	ATF_REQUIRE(!RunGuiPure::isHostXSocketDir("/tmp/.X11-unix/.crate-hostAb12"));
	ATF_REQUIRE(!RunGuiPure::isHostXSocketDir("/tmp/.X11-unix"));
}

ATF_TEST_CASE_WITHOUT_HEAD(host_x11_cookie);
ATF_TEST_CASE_BODY(host_x11_cookie)
{
	using RunGuiPure::hostX11CookieWanted;
	// the shared mode talks to the host's X server
	ATF_REQUIRE(hostX11CookieWanted("shared", false, "", ""));
	ATF_REQUIRE(hostX11CookieWanted("shared", false, "shared", "isolated"));
	// own servers: nested (the bug), headless, gpu
	ATF_REQUIRE(!hostX11CookieWanted("nested", false, "nested", ""));
	ATF_REQUIRE(!hostX11CookieWanted("nested", false, "nested", "none"));
	ATF_REQUIRE(!hostX11CookieWanted("nested", false, "", ""));        // gui.mode: nested
	ATF_REQUIRE(!hostX11CookieWanted("headless", false, "", ""));
	ATF_REQUIRE(!hostX11CookieWanted("gpu", false, "", ""));
	// no host X socket at all
	ATF_REQUIRE(!hostX11CookieWanted("none", false, "", ""));
	ATF_REQUIRE(!hostX11CookieWanted("compositor", false, "", ""));
	ATF_REQUIRE(!hostX11CookieWanted("shared", true, "", ""));         // gui.mode: wayland
	// the pre-1.1.74 rules of the shared mode
	ATF_REQUIRE(!hostX11CookieWanted("shared", false, "none", ""));
	ATF_REQUIRE(!hostX11CookieWanted("shared", false, "shared", "none"));
	ATF_REQUIRE(hostX11CookieWanted("shared", false, "", "none"));     // no x11 options
	ATF_REQUIRE(hostX11CookieWanted("shared", false, "nested", "none"));
}

ATF_TEST_CASE_WITHOUT_HEAD(xauthority_entry);
ATF_TEST_CASE_BODY(xauthority_entry)
{
	using RunGuiPure::xauthorityEntry;
	const std::string cookie("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\xff", 16);
	const auto e = xauthorityEntry(10, cookie);
	// family FamilyWild, empty address, number "10", the protocol name,
	// the 16 bytes — every length 2 bytes big-endian
	const std::string want =
	    std::string("\xff\xff", 2) +
	    std::string("\x00\x00", 2) +
	    std::string("\x00\x02", 2) + "10" +
	    std::string("\x00\x12", 2) + "MIT-MAGIC-COOKIE-1" +
	    std::string("\x00\x10", 2) + cookie;
	ATF_REQUIRE(e == want);
	ATF_REQUIRE_EQ(e.size(), (size_t)(2 + 2 + 2 + 2 + 2 + 18 + 2 + 16));
	// the number is the display's
	ATF_REQUIRE(xauthorityEntry(0, cookie).find(std::string("\x00\x01", 2) + "0") != std::string::npos);
	ATF_REQUIRE(xauthorityEntry(123, cookie).find(std::string("\x00\x03", 2) + "123") != std::string::npos);
	// a cookie of the wrong size gives no record (an empty -auth file
	// makes the server open to every local client)
	ATF_REQUIRE(xauthorityEntry(10, "").empty());
	ATF_REQUIRE(xauthorityEntry(10, "short").empty());
	ATF_REQUIRE(xauthorityEntry(10, cookie + "x").empty());
	ATF_REQUIRE_EQ(RunGuiPure::kXCookieSize, 16u);
}

ATF_TEST_CASE_WITHOUT_HEAD(local_display_number);
ATF_TEST_CASE_BODY(local_display_number)
{
	using RunGuiPure::localDisplayNumber;
	ATF_REQUIRE_EQ(localDisplayNumber(":0"), 0);
	ATF_REQUIRE_EQ(localDisplayNumber(":0.0"), 0);
	ATF_REQUIRE_EQ(localDisplayNumber(":1"), 1);
	ATF_REQUIRE_EQ(localDisplayNumber(":12.3"), 12);
	ATF_REQUIRE_EQ(localDisplayNumber("unix:2"), 2);
	ATF_REQUIRE_EQ(localDisplayNumber("unix:2.0"), 2);
	ATF_REQUIRE_EQ(localDisplayNumber(":99999"), 99999);
	// not a local socket: TCP displays (ssh -X), a launchd path, garbage
	ATF_REQUIRE_EQ(localDisplayNumber("localhost:10.0"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber("192.168.1.5:0"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber("host/unix:0"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber("/private/tmp/com.apple.launchd.x/org.xquartz:0"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber(""), -1);
	ATF_REQUIRE_EQ(localDisplayNumber(":"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber(":x"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber(":0."), -1);
	ATF_REQUIRE_EQ(localDisplayNumber(":0.x"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber(":0/../../etc"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber(":-1"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber(":123456"), -1);
	ATF_REQUIRE_EQ(localDisplayNumber(":0 "), -1);
}

ATF_TEST_CASE_WITHOUT_HEAD(websockify_args);
ATF_TEST_CASE_BODY(websockify_args)
{
	using RunGuiPure::websockifyListenArg;
	using RunGuiPure::websockifyTargetArg;
	// the default bind: both ends on loopback (the listen side had no
	// address at all — every interface)
	ATF_REQUIRE_EQ(websockifyListenArg("127.0.0.1", 6010), "127.0.0.1:6010");
	ATF_REQUIRE_EQ(websockifyTargetArg("127.0.0.1", 5910), "127.0.0.1:5910");
	// a specific address: x11vnc listens there only, so the target is it
	ATF_REQUIRE_EQ(websockifyListenArg("192.168.1.5", 6010), "192.168.1.5:6010");
	ATF_REQUIRE_EQ(websockifyTargetArg("192.168.1.5", 5910), "192.168.1.5:5910");
	// a wildcard: listen on it, reach x11vnc over loopback
	ATF_REQUIRE_EQ(websockifyListenArg("0.0.0.0", 6010), "0.0.0.0:6010");
	ATF_REQUIRE_EQ(websockifyTargetArg("0.0.0.0", 5910), "127.0.0.1:5910");
	ATF_REQUIRE_EQ(websockifyListenArg("::", 6010), "[::]:6010");
	ATF_REQUIRE_EQ(websockifyTargetArg("::", 5910), "[::1]:5910");
	// IPv6 literals are bracketed
	ATF_REQUIRE_EQ(websockifyListenArg("::1", 6010), "[::1]:6010");
	ATF_REQUIRE_EQ(websockifyTargetArg("fd00::5", 5910), "[fd00::5]:5910");
	// names pass through
	ATF_REQUIRE_EQ(websockifyListenArg("localhost", 6010), "localhost:6010");
}

ATF_TEST_CASE_WITHOUT_HEAD(wayland_context_policy);
ATF_TEST_CASE_BODY(wayland_context_policy)
{
	using namespace RunGuiPure;
	WaylandContextMode m = WaylandContextMode::Off;
	ATF_REQUIRE(parseWaylandContextMode("", m) && m == WaylandContextMode::Auto);
	ATF_REQUIRE(parseWaylandContextMode("auto", m) && m == WaylandContextMode::Auto);
	ATF_REQUIRE(parseWaylandContextMode("require", m) && m == WaylandContextMode::Require);
	ATF_REQUIRE(parseWaylandContextMode("off", m) && m == WaylandContextMode::Off);
	ATF_REQUIRE(!parseWaylandContextMode("on", m));
	ATF_REQUIRE(!parseWaylandContextMode("Require", m));
	ATF_REQUIRE(!parseWaylandContextMode("true", m));

	// the restricted socket whenever the compositor made one ...
	ATF_REQUIRE(waylandBindDecision(WaylandContextMode::Auto, true) == WaylandBind::Restricted);
	ATF_REQUIRE(waylandBindDecision(WaylandContextMode::Require, true) == WaylandBind::Restricted);
	// ... the raw one as a fallback only by default; `require` refuses
	ATF_REQUIRE(waylandBindDecision(WaylandContextMode::Auto, false) == WaylandBind::Raw);
	ATF_REQUIRE(waylandBindDecision(WaylandContextMode::Require, false) == WaylandBind::Refuse);
	// `off` is the raw socket whatever the compositor can do
	ATF_REQUIRE(waylandBindDecision(WaylandContextMode::Off, false) == WaylandBind::Raw);
	ATF_REQUIRE(waylandBindDecision(WaylandContextMode::Off, true) == WaylandBind::Raw);

	// the private directory: under the operator's runtime dir, mkdtemp form
	const auto t = waylandContextDirTemplate("/var/run/user/1001");
	ATF_REQUIRE_EQ(t, std::string("/var/run/user/1001/crate-wl-XXXXXXXX"));
	ATF_REQUIRE(isWaylandContextDir("/var/run/user/1001/crate-wl-Ab12Cd34"));
	ATF_REQUIRE(isWaylandContextDir("/var/run/user/1001/crate-wl-Ab12Cd34/wayland-1"));
	ATF_REQUIRE(!isWaylandContextDir("/var/run/user/1001/wayland-1"));
	ATF_REQUIRE(!isWaylandContextDir("/var/run/user/1001/crate-wl-"));
	ATF_REQUIRE(!isWaylandContextDir("/var/run/user/1001"));

	// the spec key: three values, and only where a host socket is bound
	ATF_REQUIRE(waylandContextKeyError("auto", "require").empty());
	ATF_REQUIRE(waylandContextKeyError("wayland", "off").empty());
	ATF_REQUIRE(waylandContextKeyError("wayland", "auto").empty());
	ATF_REQUIRE(!waylandContextKeyError("wayland", "yes").empty());
	ATF_REQUIRE(!waylandContextKeyError("nested", "require").empty());
	ATF_REQUIRE(!waylandContextKeyError("headless", "off").empty());
	ATF_REQUIRE(!waylandContextKeyError("compositor", "require").empty());

	// gui/vnc_bind: every mode that can have a VNC server (it was
	// refused outside compositor)
	for (const char *mode : {"compositor", "nested", "headless", "gpu", "auto"})
		ATF_REQUIRE(vncBindKeyError(mode).empty());
	ATF_REQUIRE(!vncBindKeyError("wayland").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(shared_display_warnings);
ATF_TEST_CASE_BODY(shared_display_warnings)
{
	using RunGuiPure::sharedDisplayWarnings;
	// plain x11 / gui: auto with DISPLAY → X11 socket bound, X11 warns
	auto w = sharedDisplayWarnings(false, false, true, false, false);
	ATF_REQUIRE(w.x11);
	ATF_REQUIRE(!w.wayland);
	// gui: auto with DISPLAY unset but a Wayland session → Wayland warns,
	// X11 does not (no X11 socket bound)
	w = sharedDisplayWarnings(true, false, false, true, true);
	ATF_REQUIRE(!w.x11);
	ATF_REQUIRE(w.wayland);
	// gui.mode: wayland must NOT raise the X11 warning even if DISPLAY is
	// set (it routes through the shared block but binds no X11 socket) —
	// the asymmetry 1.1.77 fixed
	w = sharedDisplayWarnings(false, true, true, true, true);
	ATF_REQUIRE(!w.x11);
	ATF_REQUIRE(w.wayland);
	// gui: auto with both DISPLAY and a Wayland session → both bound
	w = sharedDisplayWarnings(true, false, true, true, true);
	ATF_REQUIRE(w.x11);
	ATF_REQUIRE(w.wayland);
	// WAYLAND_DISPLAY set but no XDG_RUNTIME_DIR → socket cannot be
	// located, no Wayland bind, no Wayland warning
	w = sharedDisplayWarnings(true, false, false, true, false);
	ATF_REQUIRE(!w.x11);
	ATF_REQUIRE(!w.wayland);
	// a non-auto, non-wayland flow (explicit x11 shared) without DISPLAY
	// binds nothing here → neither warns
	w = sharedDisplayWarnings(false, false, false, false, false);
	ATF_REQUIRE(!w.x11);
	ATF_REQUIRE(!w.wayland);
	// wayland flow without a Wayland session (the strict-mode error path
	// handles the refusal) → no Wayland warning
	w = sharedDisplayWarnings(false, true, false, false, true);
	ATF_REQUIRE(!w.x11);
	ATF_REQUIRE(!w.wayland);
}

ATF_INIT_TEST_CASES(tcs)
{
	// 0.8.18: gui: auto
	ATF_ADD_TEST_CASE(tcs, autoMode_display_set_picks_shared);
	ATF_ADD_TEST_CASE(tcs, autoMode_wayland_only_picks_shared);
	ATF_ADD_TEST_CASE(tcs, autoMode_no_display_with_gpu_picks_gpu);
	ATF_ADD_TEST_CASE(tcs, autoMode_nothing_picks_headless);
	ATF_ADD_TEST_CASE(tcs, parseWayland_basenames);
	ATF_ADD_TEST_CASE(tcs, parseWayland_rejects_paths_and_garbage);

	ATF_ADD_TEST_CASE(tcs, xorg_conf_default_driver);
	ATF_ADD_TEST_CASE(tcs, xorg_conf_explicit_driver);
	ATF_ADD_TEST_CASE(tcs, xorg_conf_nvidia_extras);
	ATF_ADD_TEST_CASE(tcs, xorg_conf_no_nvidia_extras_for_dummy);
	ATF_ADD_TEST_CASE(tcs, xorg_conf_required_sections_present);
	ATF_ADD_TEST_CASE(tcs, xorg_conf_garbage_resolution_falls_back);
	ATF_ADD_TEST_CASE(tcs, cvt_1080p_60);
	ATF_ADD_TEST_CASE(tcs, cvt_720p_60);
	ATF_ADD_TEST_CASE(tcs, cvt_4k_60);
	ATF_ADD_TEST_CASE(tcs, cvt_invariants);
	ATF_ADD_TEST_CASE(tcs, cvt_higher_refresh_higher_clock);
	ATF_ADD_TEST_CASE(tcs, resolveRes_default);
	ATF_ADD_TEST_CASE(tcs, resolveRes_gui_overrides);
	ATF_ADD_TEST_CASE(tcs, resolveRes_x11_fallback);
	ATF_ADD_TEST_CASE(tcs, resolveRes_gui_wins_over_x11);
	ATF_ADD_TEST_CASE(tcs, parseRes_basic);
	ATF_ADD_TEST_CASE(tcs, parseRes_zero_rejected);
	ATF_ADD_TEST_CASE(tcs, parseRes_garbage);
	ATF_ADD_TEST_CASE(tcs, parseRes_extra_chars);
	ATF_ADD_TEST_CASE(tcs, pipewireSocketNames_lists_two_canonical);
	ATF_ADD_TEST_CASE(tcs, pipewireSocketNames_excludes_pulse_compat);
	ATF_ADD_TEST_CASE(tcs, pulseSocketRelpath_canonical);
	ATF_ADD_TEST_CASE(tcs, pulseSocketRelpath_has_subdir);
	ATF_ADD_TEST_CASE(tcs, own_x_socket_dir);
	ATF_ADD_TEST_CASE(tcs, host_x11_cookie);
	ATF_ADD_TEST_CASE(tcs, xauthority_entry);
	ATF_ADD_TEST_CASE(tcs, local_display_number);
	ATF_ADD_TEST_CASE(tcs, websockify_args);
	ATF_ADD_TEST_CASE(tcs, wayland_context_policy);
	ATF_ADD_TEST_CASE(tcs, shared_display_warnings);
}
