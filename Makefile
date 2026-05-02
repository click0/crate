
# --- Source files ---

LIB_SRCS = lib/spec.cpp lib/spec_pure.cpp lib/create.cpp lib/run.cpp \
           lib/list.cpp lib/info.cpp lib/clean.cpp lib/console.cpp \
           lib/export.cpp lib/import.cpp lib/import_pure.cpp \
           lib/gui.cpp lib/run_net.cpp lib/run_jail.cpp lib/run_gui.cpp \
           lib/run_services.cpp lib/locs.cpp lib/cmd.cpp lib/mount.cpp \
           lib/net.cpp lib/ctx.cpp lib/gui_registry.cpp lib/scripts.cpp \
           lib/misc.cpp lib/util.cpp lib/util_pure.cpp lib/err.cpp \
           lib/validate.cpp lib/validate_pure.cpp \
           lib/snapshot.cpp lib/config.cpp \
           lib/scripts_pure.cpp lib/run_pure.cpp lib/autoname_pure.cpp \
           lib/auth_pure.cpp lib/list_pure.cpp lib/run_gui_pure.cpp \
           lib/snapshot_pure.cpp lib/crypto_pure.cpp lib/log_pure.cpp \
           lib/sign_pure.cpp lib/audit.cpp lib/audit_pure.cpp \
           lib/share_pure.cpp \
           lib/top_pure.cpp lib/top.cpp \
           lib/bridge_pure.cpp \
           lib/stack.cpp lib/stack_pure.cpp \
           lib/jail_query.cpp lib/zfs_ops.cpp lib/ifconfig_ops.cpp \
           lib/pfctl_ops.cpp lib/mac_ops.cpp lib/ipfw_ops.cpp \
           lib/capsicum_ops.cpp lib/netgraph_ops.cpp lib/nv_protocol.cpp \
           lib/lifecycle.cpp lib/lifecycle_pure.cpp

CLI_SRCS = cli/main.cpp cli/args.cpp cli/args_pure.cpp

DAEMON_SRCS = daemon/main.cpp daemon/config.cpp daemon/server.cpp \
              daemon/routes.cpp daemon/routes_pure.cpp daemon/auth.cpp \
              daemon/metrics.cpp daemon/metrics_pure.cpp

SNMPD_SRCS = snmpd/main.cpp snmpd/collector.cpp \
             snmpd/mib.cpp snmpd/mib_pure.cpp

LIB_OBJS = $(LIB_SRCS:.cpp=.o)
CLI_OBJS = $(CLI_SRCS:.cpp=.o)
DAEMON_OBJS = $(DAEMON_SRCS:.cpp=.o)
SNMPD_OBJS = $(SNMPD_SRCS:.cpp=.o)

# --- Flags ---

PREFIX   ?= /usr/local
CXXFLAGS += `pkg-config --cflags yaml-cpp`
LDFLAGS  += `pkg-config --libs yaml-cpp`
LIBS     += -ljail -lnetgraph -lmd -lpthread

# Optional native API support (fallback to shell commands if not defined)
ifdef HAVE_LIBZFS
CXXFLAGS += -DHAVE_LIBZFS
LIBS     += -lzfs -lzfs_core -lnvpair
endif
ifdef HAVE_LIBIFCONFIG
CXXFLAGS += -DHAVE_LIBIFCONFIG
LIBS     += -lifconfig
endif
ifdef HAVE_LIBPFCTL
CXXFLAGS += -DHAVE_LIBPFCTL
LIBS     += -lpfctl
endif
ifdef HAVE_CAPSICUM
CXXFLAGS += -DHAVE_CAPSICUM
LIBS     += -lcasper -lcap_dns -lcap_syslog
endif
ifdef WITH_LIBVIRT
CXXFLAGS += -DHAVE_LIBVIRT
LIB_SRCS += lib/vm_spec.cpp lib/vm_run.cpp lib/vm_stack.cpp
LIBS     += -lvirt
endif
ifdef WITH_LIBVNCSERVER
CXXFLAGS += -DHAVE_LIBVNCSERVER
LIB_SRCS += lib/vnc_server.cpp
LIBS     += -lvncserver
endif
ifdef WITH_X11
CXXFLAGS += -DHAVE_X11
LIB_SRCS += lib/x11_ops.cpp
LIBS     += -lX11 -lXrandr -lXext
endif
ifdef WITH_LIBSEAT
CXXFLAGS += -DHAVE_LIBSEAT
LIB_SRCS += lib/drm_session.cpp
LIBS     += -lseat
endif

CXXFLAGS += -Wall -std=c++17
CXXFLAGS += -Ilib             # lib/ headers visible to all
CXXFLAGS += -Idaemon          # daemon/ headers for daemon build
CXXFLAGS += -Isnmpd           # snmpd/ headers for snmpd build

LIBS_DAEMON = $(LIBS) -lssl -lcrypto -lpthread

# --- Targets ---

all: crate

all-daemon: crate crated

all-snmpd: crate crate-snmpd

libcrate.a: $(LIB_OBJS)
	$(AR) rcs $@ $^

crate: libcrate.a $(CLI_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(CLI_OBJS) libcrate.a $(LIBS)

crated: libcrate.a $(DAEMON_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(DAEMON_OBJS) libcrate.a $(LIBS_DAEMON)

crate-snmpd: libcrate.a $(SNMPD_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(SNMPD_OBJS) libcrate.a $(LIBS) -lpthread

install: crate
	@mkdir -p $(DESTDIR)$(PREFIX)/bin
	@mkdir -p $(DESTDIR)$(PREFIX)/man/man5
	install -s -m 04755 crate $(DESTDIR)$(PREFIX)/bin
	gzip -9 < crate.5 > $(DESTDIR)$(PREFIX)/man/man5/crate.5.gz

install-daemon: crated
	@mkdir -p $(DESTDIR)$(PREFIX)/sbin
	@mkdir -p $(DESTDIR)$(PREFIX)/etc/rc.d
	install -s -m 0755 crated $(DESTDIR)$(PREFIX)/sbin/crated
	install -m 0555 daemon/crated.rc $(DESTDIR)$(PREFIX)/etc/rc.d/crated
	install -m 0640 daemon/crated.conf.sample $(DESTDIR)$(PREFIX)/etc/crated.conf.sample
	@if [ ! -f $(DESTDIR)$(PREFIX)/etc/crated.conf ]; then \
		install -m 0640 daemon/crated.conf.sample $(DESTDIR)$(PREFIX)/etc/crated.conf; \
	fi

install-local: crate.x

install-examples:
	@mkdir -p $(DESTDIR)$(PREFIX)/share/examples/crate/broken
	@mkdir -p $(DESTDIR)$(PREFIX)/share/examples/crate/matrix
	@find examples -type f | while read f; do \
		install -m 644 "$$f" $(DESTDIR)$(PREFIX)/share/examples/crate/$${f#examples/}; \
	done

install-completions:
	@mkdir -p $(DESTDIR)$(PREFIX)/share/crate/completions
	install -m 644 completions/crate.sh $(DESTDIR)$(PREFIX)/share/crate/completions/crate.sh

crate.x: crate
	sudo install -s -m 04755 -o 0 -g 0 crate crate.x

install-snmpd: crate-snmpd
	install -s -m 0755 crate-snmpd $(DESTDIR)$(PREFIX)/sbin/crate-snmpd
	@mkdir -p $(DESTDIR)$(PREFIX)/share/snmp/mibs
	install -m 0644 snmpd/CRATE-MIB.txt $(DESTDIR)$(PREFIX)/share/snmp/mibs/CRATE-MIB.txt

UNIT_TESTS = util_test spec_test spec_netopt_test lifecycle_test \
             network_test network_ipv6_test err_test \
             snmpd_mib_test daemon_metrics_test stack_test \
             util_security_test import_test cli_args_test \
             args_validate_test util_subst_test spec_subst_test \
             scripts_test adversarial_test spec_validate_test \
             validate_pure_test run_pure_test autoname_test \
             auth_pure_test list_pure_test run_gui_pure_test \
             snapshot_pure_test crypto_pure_test log_pure_test \
             sign_pure_test audit_pure_test share_pure_test \
             routes_pure_test top_pure_test bridge_pure_test
UNIT_TEST_BINS = $(addprefix tests/unit/,$(UNIT_TESTS))

test: $(UNIT_TEST_BINS)
	cd tests && kyua test

# test-unit: run only the unit test suite (no functional tests).
# Handy for local development on Linux where functional/crate_info_test
# requires a FreeBSD jail and will otherwise be reported as broken.
test-unit: $(UNIT_TEST_BINS)
	cd tests && kyua test unit

# build-unit-tests: build every unit test binary without running anything.
# Useful in CI where the build runs as a regular user but kyua must run
# with elevated privileges (FreeBSD jail tests).
build-unit-tests: $(UNIT_TEST_BINS)

# Pure platform-independent sources tests can safely link against.
# Compiled inline (no separate .o) to avoid colliding with the
# main lib/*.o build that uses different CXXFLAGS.
TEST_LINK_SRCS = lib/util_pure.cpp lib/err.cpp \
                 lib/spec_pure.cpp lib/stack_pure.cpp \
                 lib/lifecycle_pure.cpp lib/import_pure.cpp \
                 lib/scripts_pure.cpp lib/validate_pure.cpp \
                 lib/run_pure.cpp lib/autoname_pure.cpp \
                 lib/auth_pure.cpp lib/list_pure.cpp lib/run_gui_pure.cpp \
                 lib/snapshot_pure.cpp lib/crypto_pure.cpp lib/log_pure.cpp \
                 lib/sign_pure.cpp lib/audit_pure.cpp \
                 lib/share_pure.cpp lib/top_pure.cpp lib/bridge_pure.cpp \
                 cli/args_pure.cpp daemon/metrics_pure.cpp \
                 daemon/routes_pure.cpp \
                 snmpd/mib_pure.cpp

# -Icli/-Idaemon/-Isnmpd let tests #include the *_pure.h files directly.
TEST_INCLUDES = -Ilib -Icli -Idaemon -Isnmpd

tests/unit/%: tests/unit/%.cpp $(TEST_LINK_SRCS) lib/lst-all-script-sections.h tests/unit/_test_config_stub.cpp
	$(CXX) -std=c++17 $(TEST_INCLUDES) $(COVERAGE_CXXFLAGS) -o $@ $< $(TEST_LINK_SRCS) tests/unit/_test_config_stub.cpp $(COVERAGE_LDFLAGS) -L/usr/local/lib -latf-c++ -latf-c

# coverage: build unit tests with gcov instrumentation, run them, and
# render an HTML report under coverage-html/. Requires lcov + genhtml.
#
# Usage:
#   gmake coverage           # build, run, report
#   gmake coverage-clean     # remove .gcda/.gcno + report
#
# Note: tests currently embed local copies of the functions under test
# (see tests/unit/*.cpp). gcov measures coverage of those *test-local*
# copies — useful for spotting un-exercised branches in test logic, less
# useful as production-code coverage. A future change to link tests
# against libcrate.a would make this report fully accurate.
COVERAGE_CXXFLAGS ?=
COVERAGE_LDFLAGS  ?=

coverage: clean-tests
	@$(MAKE) COVERAGE_CXXFLAGS="-O0 -g --coverage -fprofile-arcs -ftest-coverage" \
	         COVERAGE_LDFLAGS="--coverage" \
	         build-unit-tests
	cd tests && kyua test unit || true
	@command -v lcov >/dev/null 2>&1 || { echo "lcov not installed: apt install lcov / pkg install lcov"; exit 1; }
	@command -v genhtml >/dev/null 2>&1 || { echo "genhtml not installed (ships with lcov)"; exit 1; }
	lcov --capture --directory tests/unit --output-file coverage.info \
	     --rc geninfo_unexecuted_blocks=1 \
	     --ignore-errors source,inconsistent,mismatch,negative
	lcov --remove coverage.info '/usr/*' '*/atf-c++.hpp' \
	     --output-file coverage.info \
	     --ignore-errors unused
	genhtml coverage.info --output-directory coverage-html \
	        --ignore-errors source,inconsistent,corrupt
	@echo
	@echo "  Coverage report: coverage-html/index.html"

coverage-clean:
	rm -f coverage.info
	rm -rf coverage-html
	find tests/unit -name '*.gcda' -delete
	find tests/unit -name '*.gcno' -delete

clean-tests:
	rm -f $(UNIT_TEST_BINS)

clean: clean-tests coverage-clean
	rm -f $(LIB_OBJS) $(CLI_OBJS) $(DAEMON_OBJS) $(SNMPD_OBJS) libcrate.a crate crated crate-snmpd lib/lst-all-script-sections.h

# --- Generated sources ---

lib/lst-all-script-sections.h: lib/create.cpp lib/run.cpp lib/run_net.cpp lib/run_jail.cpp lib/run_gui.cpp lib/run_services.cpp
	@(echo "static std::set<std::string> allScriptSections = {\"\"" && \
	  grep -h "runScript(" lib/create.cpp lib/run.cpp lib/run_net.cpp lib/run_jail.cpp lib/run_gui.cpp lib/run_services.cpp | sed -e 's|.*runScript(|, |; s|);||' && \
	  echo "};" \
	 ) > $@
	@touch lib/spec.cpp
	@echo "generate $@"
lib/spec.cpp: lib/lst-all-script-sections.h

# --- Shortcuts ---
a: all
c: clean
d: all-daemon
l: install-local
e: install-examples
s: all-snmpd
