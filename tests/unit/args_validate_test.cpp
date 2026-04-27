// ATF unit tests for Args::validate (cli/args_pure.cpp).
//
// Validates that the per-command argument-validation rules in the
// setuid-root crate binary throw Exception with a clear message when
// required input is missing. Catches input-validation regressions
// before they reach production.

#include <atf-c++.hpp>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <unistd.h>

#include "args.h"
#include "err.h"

// Helper: build an Args struct with the given command.
static Args mkArgs(Command c) {
	Args a;
	a.cmd = c;
	return a;
}

// ===================================================================
// CmdCreate
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(create_requires_spec_or_template);
ATF_TEST_CASE_BODY(create_requires_spec_or_template)
{
	auto a = mkArgs(CmdCreate);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(create_with_spec_only_ok);
ATF_TEST_CASE_BODY(create_with_spec_only_ok)
{
	auto a = mkArgs(CmdCreate);
	a.createSpec = "/tmp/some.yml";
	a.validate();  // no throw
}

ATF_TEST_CASE_WITHOUT_HEAD(create_template_not_found_throws);
ATF_TEST_CASE_BODY(create_template_not_found_throws)
{
	// Template name resolution: tries ~/.config/crate/templates/X.yml,
	// /usr/local/share/crate/templates/X.yml, then X as path. None of
	// these exist for a random name in the test env, so it must throw.
	auto a = mkArgs(CmdCreate);
	a.createTemplate = "definitely-nonexistent-template-xyz123";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

// ===================================================================
// CmdRun
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(run_requires_file);
ATF_TEST_CASE_BODY(run_requires_file)
{
	auto a = mkArgs(CmdRun);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(run_missing_file_throws);
ATF_TEST_CASE_BODY(run_missing_file_throws)
{
	auto a = mkArgs(CmdRun);
	a.runCrateFile = "/nonexistent/path/to.crate";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(run_existing_file_ok);
ATF_TEST_CASE_BODY(run_existing_file_ok)
{
	// Use mkstemp() over tmpnam() to avoid the deprecated-call warning.
	char tmpl[] = "/tmp/crate-args-validate-XXXXXX";
	int fd = ::mkstemp(tmpl);
	ATF_REQUIRE(fd >= 0);
	::close(fd);
	std::ofstream(tmpl) << "dummy";
	auto a = mkArgs(CmdRun);
	a.runCrateFile = tmpl;
	a.validate();
	std::remove(tmpl);
}

// ===================================================================
// CmdValidate
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(validate_requires_spec);
ATF_TEST_CASE_BODY(validate_requires_spec)
{
	auto a = mkArgs(CmdValidate);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(validate_with_spec_ok);
ATF_TEST_CASE_BODY(validate_with_spec_ok)
{
	auto a = mkArgs(CmdValidate);
	a.validateSpec = "/some/spec.yml";
	a.validate();
}

// ===================================================================
// CmdSnapshot
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_requires_subcmd);
ATF_TEST_CASE_BODY(snapshot_requires_subcmd)
{
	auto a = mkArgs(CmdSnapshot);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_requires_dataset);
ATF_TEST_CASE_BODY(snapshot_requires_dataset)
{
	auto a = mkArgs(CmdSnapshot);
	a.snapshotSubcmd = "create";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_restore_requires_name);
ATF_TEST_CASE_BODY(snapshot_restore_requires_name)
{
	auto a = mkArgs(CmdSnapshot);
	a.snapshotSubcmd = "restore";
	a.snapshotDataset = "tank/jail";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_delete_requires_name);
ATF_TEST_CASE_BODY(snapshot_delete_requires_name)
{
	auto a = mkArgs(CmdSnapshot);
	a.snapshotSubcmd = "delete";
	a.snapshotDataset = "tank/jail";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_diff_requires_name);
ATF_TEST_CASE_BODY(snapshot_diff_requires_name)
{
	auto a = mkArgs(CmdSnapshot);
	a.snapshotSubcmd = "diff";
	a.snapshotDataset = "tank/jail";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_create_minimal_ok);
ATF_TEST_CASE_BODY(snapshot_create_minimal_ok)
{
	auto a = mkArgs(CmdSnapshot);
	a.snapshotSubcmd = "create";
	a.snapshotDataset = "tank/jail";
	a.validate();
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_list_no_name_ok);
ATF_TEST_CASE_BODY(snapshot_list_no_name_ok)
{
	// 'list' does not require snapshotName
	auto a = mkArgs(CmdSnapshot);
	a.snapshotSubcmd = "list";
	a.snapshotDataset = "tank/jail";
	a.validate();
}

// ===================================================================
// CmdList / CmdClean — no required arguments
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(list_no_args_ok);
ATF_TEST_CASE_BODY(list_no_args_ok)
{
	auto a = mkArgs(CmdList);
	a.validate();
}

ATF_TEST_CASE_WITHOUT_HEAD(clean_no_args_ok);
ATF_TEST_CASE_BODY(clean_no_args_ok)
{
	auto a = mkArgs(CmdClean);
	a.validate();
}

// ===================================================================
// Target-only commands: info, console, stats, logs, stop, restart
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(info_requires_target);
ATF_TEST_CASE_BODY(info_requires_target)
{
	auto a = mkArgs(CmdInfo);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(console_requires_target);
ATF_TEST_CASE_BODY(console_requires_target)
{
	auto a = mkArgs(CmdConsole);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(stats_requires_target);
ATF_TEST_CASE_BODY(stats_requires_target)
{
	auto a = mkArgs(CmdStats);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(logs_requires_target);
ATF_TEST_CASE_BODY(logs_requires_target)
{
	auto a = mkArgs(CmdLogs);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(stop_requires_target);
ATF_TEST_CASE_BODY(stop_requires_target)
{
	auto a = mkArgs(CmdStop);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(restart_requires_target);
ATF_TEST_CASE_BODY(restart_requires_target)
{
	auto a = mkArgs(CmdRestart);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(target_set_ok);
ATF_TEST_CASE_BODY(target_set_ok)
{
	{ auto a = mkArgs(CmdInfo);    a.infoTarget    = "web"; a.validate(); }
	{ auto a = mkArgs(CmdConsole); a.consoleTarget = "web"; a.validate(); }
	{ auto a = mkArgs(CmdStats);   a.statsTarget   = "web"; a.validate(); }
	{ auto a = mkArgs(CmdLogs);    a.logsTarget    = "web"; a.validate(); }
	{ auto a = mkArgs(CmdStop);    a.stopTarget    = "web"; a.validate(); }
	{ auto a = mkArgs(CmdRestart); a.restartTarget = "web"; a.validate(); }
}

// ===================================================================
// CmdGui
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(gui_requires_subcmd);
ATF_TEST_CASE_BODY(gui_requires_subcmd)
{
	auto a = mkArgs(CmdGui);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(gui_focus_requires_target);
ATF_TEST_CASE_BODY(gui_focus_requires_target)
{
	auto a = mkArgs(CmdGui);
	a.guiSubcmd = "focus";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(gui_attach_requires_target);
ATF_TEST_CASE_BODY(gui_attach_requires_target)
{
	auto a = mkArgs(CmdGui);
	a.guiSubcmd = "attach";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(gui_resize_requires_resolution);
ATF_TEST_CASE_BODY(gui_resize_requires_resolution)
{
	auto a = mkArgs(CmdGui);
	a.guiSubcmd = "resize";
	a.guiTarget = "web";
	// missing resolution -> throw
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(gui_list_no_target_ok);
ATF_TEST_CASE_BODY(gui_list_no_target_ok)
{
	// 'list' and 'tile' do not require a target
	auto a = mkArgs(CmdGui);
	a.guiSubcmd = "list";
	a.validate();
}

ATF_TEST_CASE_WITHOUT_HEAD(gui_resize_with_resolution_ok);
ATF_TEST_CASE_BODY(gui_resize_with_resolution_ok)
{
	auto a = mkArgs(CmdGui);
	a.guiSubcmd = "resize";
	a.guiTarget = "web";
	a.guiResolution = "1920x1080";
	a.validate();
}

// ===================================================================
// CmdStack
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(stack_requires_subcmd);
ATF_TEST_CASE_BODY(stack_requires_subcmd)
{
	auto a = mkArgs(CmdStack);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(stack_requires_file);
ATF_TEST_CASE_BODY(stack_requires_file)
{
	auto a = mkArgs(CmdStack);
	a.stackSubcmd = "up";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(stack_exec_requires_container);
ATF_TEST_CASE_BODY(stack_exec_requires_container)
{
	auto a = mkArgs(CmdStack);
	a.stackSubcmd = "exec";
	a.stackFile = "stack.yml";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(stack_exec_requires_args);
ATF_TEST_CASE_BODY(stack_exec_requires_args)
{
	auto a = mkArgs(CmdStack);
	a.stackSubcmd = "exec";
	a.stackFile = "stack.yml";
	a.stackExecContainer = "web";
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_TEST_CASE_WITHOUT_HEAD(stack_up_minimal_ok);
ATF_TEST_CASE_BODY(stack_up_minimal_ok)
{
	auto a = mkArgs(CmdStack);
	a.stackSubcmd = "up";
	a.stackFile = "stack.yml";
	a.validate();
}

// ===================================================================
// Default — no command given
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(default_no_command_throws);
ATF_TEST_CASE_BODY(default_no_command_throws)
{
	auto a = mkArgs(CmdNone);
	ATF_REQUIRE_THROW(Exception, a.validate());
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, create_requires_spec_or_template);
	ATF_ADD_TEST_CASE(tcs, create_with_spec_only_ok);
	ATF_ADD_TEST_CASE(tcs, create_template_not_found_throws);
	ATF_ADD_TEST_CASE(tcs, run_requires_file);
	ATF_ADD_TEST_CASE(tcs, run_missing_file_throws);
	ATF_ADD_TEST_CASE(tcs, run_existing_file_ok);
	ATF_ADD_TEST_CASE(tcs, validate_requires_spec);
	ATF_ADD_TEST_CASE(tcs, validate_with_spec_ok);
	ATF_ADD_TEST_CASE(tcs, snapshot_requires_subcmd);
	ATF_ADD_TEST_CASE(tcs, snapshot_requires_dataset);
	ATF_ADD_TEST_CASE(tcs, snapshot_restore_requires_name);
	ATF_ADD_TEST_CASE(tcs, snapshot_delete_requires_name);
	ATF_ADD_TEST_CASE(tcs, snapshot_diff_requires_name);
	ATF_ADD_TEST_CASE(tcs, snapshot_create_minimal_ok);
	ATF_ADD_TEST_CASE(tcs, snapshot_list_no_name_ok);
	ATF_ADD_TEST_CASE(tcs, list_no_args_ok);
	ATF_ADD_TEST_CASE(tcs, clean_no_args_ok);
	ATF_ADD_TEST_CASE(tcs, info_requires_target);
	ATF_ADD_TEST_CASE(tcs, console_requires_target);
	ATF_ADD_TEST_CASE(tcs, stats_requires_target);
	ATF_ADD_TEST_CASE(tcs, logs_requires_target);
	ATF_ADD_TEST_CASE(tcs, stop_requires_target);
	ATF_ADD_TEST_CASE(tcs, restart_requires_target);
	ATF_ADD_TEST_CASE(tcs, target_set_ok);
	ATF_ADD_TEST_CASE(tcs, gui_requires_subcmd);
	ATF_ADD_TEST_CASE(tcs, gui_focus_requires_target);
	ATF_ADD_TEST_CASE(tcs, gui_attach_requires_target);
	ATF_ADD_TEST_CASE(tcs, gui_resize_requires_resolution);
	ATF_ADD_TEST_CASE(tcs, gui_list_no_target_ok);
	ATF_ADD_TEST_CASE(tcs, gui_resize_with_resolution_ok);
	ATF_ADD_TEST_CASE(tcs, stack_requires_subcmd);
	ATF_ADD_TEST_CASE(tcs, stack_requires_file);
	ATF_ADD_TEST_CASE(tcs, stack_exec_requires_container);
	ATF_ADD_TEST_CASE(tcs, stack_exec_requires_args);
	ATF_ADD_TEST_CASE(tcs, stack_up_minimal_ok);
	ATF_ADD_TEST_CASE(tcs, default_no_command_throws);
}
