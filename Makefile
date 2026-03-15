
# --- Source files ---

LIB_SRCS = lib/spec.cpp lib/create.cpp lib/run.cpp lib/list.cpp lib/info.cpp \
           lib/clean.cpp lib/console.cpp lib/export.cpp lib/import.cpp \
           lib/gui.cpp lib/run_net.cpp lib/run_jail.cpp lib/run_gui.cpp \
           lib/run_services.cpp lib/locs.cpp lib/cmd.cpp lib/mount.cpp \
           lib/net.cpp lib/ctx.cpp lib/gui_registry.cpp lib/scripts.cpp \
           lib/misc.cpp lib/util.cpp lib/err.cpp lib/validate.cpp \
           lib/snapshot.cpp lib/config.cpp lib/stack.cpp \
           lib/jail_query.cpp lib/zfs_ops.cpp lib/ifconfig_ops.cpp \
           lib/pfctl_ops.cpp lib/mac_ops.cpp lib/ipfw_ops.cpp \
           lib/capsicum_ops.cpp lib/netgraph_ops.cpp lib/nv_protocol.cpp \
           lib/lifecycle.cpp

CLI_SRCS = cli/main.cpp cli/args.cpp

DAEMON_SRCS = daemon/main.cpp daemon/config.cpp daemon/server.cpp \
              daemon/routes.cpp daemon/auth.cpp daemon/metrics.cpp

SNMPD_SRCS = snmpd/main.cpp snmpd/collector.cpp snmpd/mib.cpp

LIB_OBJS = $(LIB_SRCS:.cpp=.o)
CLI_OBJS = $(CLI_SRCS:.cpp=.o)
DAEMON_OBJS = $(DAEMON_SRCS:.cpp=.o)
SNMPD_OBJS = $(SNMPD_SRCS:.cpp=.o)

# --- Flags ---

PREFIX   ?= /usr/local
CXXFLAGS += `pkg-config --cflags yaml-cpp`
LDFLAGS  += `pkg-config --libs yaml-cpp`
LIBS     += -ljail

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
LIB_SRCS += lib/vm_spec.cpp lib/vm_run.cpp
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
             network_test network_ipv6_test err_test
UNIT_TEST_BINS = $(addprefix tests/unit/,$(UNIT_TESTS))

test: $(UNIT_TEST_BINS)
	cd tests && kyua test

tests/unit/%: tests/unit/%.cpp
	$(CXX) -std=c++17 -Ilib -o $@ $< -L/usr/local/lib -latf-c++ -latf-c

clean-tests:
	rm -f $(UNIT_TEST_BINS)

clean: clean-tests
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
