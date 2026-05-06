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
}
