
# --- Source files ---

LIB_SRCS = lib/spec.cpp lib/create.cpp lib/run.cpp lib/list.cpp lib/info.cpp \
           lib/clean.cpp lib/console.cpp lib/export.cpp lib/import.cpp \
           lib/gui.cpp lib/run_net.cpp lib/run_jail.cpp lib/run_gui.cpp \
           lib/run_services.cpp lib/locs.cpp lib/cmd.cpp lib/mount.cpp \
           lib/net.cpp lib/ctx.cpp lib/gui_registry.cpp lib/scripts.cpp \
           lib/misc.cpp lib/util.cpp lib/err.cpp lib/validate.cpp \
           lib/snapshot.cpp lib/config.cpp

CLI_SRCS = cli/main.cpp cli/args.cpp

SNMPD_SRCS = snmpd/main.cpp snmpd/collector.cpp snmpd/mib.cpp

LIB_OBJS = $(LIB_SRCS:.cpp=.o)
CLI_OBJS = $(CLI_SRCS:.cpp=.o)
SNMPD_OBJS = $(SNMPD_SRCS:.cpp=.o)

# --- Flags ---

PREFIX   ?= /usr/local
CXXFLAGS += `pkg-config --cflags yaml-cpp`
LDFLAGS  += `pkg-config --libs yaml-cpp`
LIBS     += -ljail

CXXFLAGS += -Wall -std=c++17
CXXFLAGS += -Ilib             # lib/ headers visible to all
CXXFLAGS += -Isnmpd           # snmpd/ headers for snmpd build

# --- Targets ---

all: crate

all-snmpd: crate crate-snmpd

libcrate.a: $(LIB_OBJS)
	$(AR) rcs $@ $^

crate: libcrate.a $(CLI_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(CLI_OBJS) libcrate.a $(LIBS)

crate-snmpd: libcrate.a $(SNMPD_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(SNMPD_OBJS) libcrate.a $(LIBS) -lpthread

install: crate
	install -s -m 04755 crate $(DESTDIR)$(PREFIX)/bin
	gzip -9 < crate.5 > $(DESTDIR)$(PREFIX)/man/man5/crate.5.gz

install-local: crate.x

install-examples:
	@mkdir -p $(DESTDIR)$(PREFIX)/share/examples/crate
	@for e in `ls examples/`; do \
		install examples/$$e $(DESTDIR)$(PREFIX)/share/examples/crate/$$e; \
	done;

install-completions:
	@mkdir -p $(DESTDIR)$(PREFIX)/share/crate/completions
	install -m 644 completions/crate.sh $(DESTDIR)$(PREFIX)/share/crate/completions/crate.sh

crate.x: crate
	sudo install -s -m 04755 -o 0 -g 0 crate crate.x

install-snmpd: crate-snmpd
	install -s -m 0755 crate-snmpd $(DESTDIR)$(PREFIX)/sbin/crate-snmpd
	@mkdir -p $(DESTDIR)$(PREFIX)/share/snmp/mibs
	install -m 0644 snmpd/CRATE-MIB.txt $(DESTDIR)$(PREFIX)/share/snmp/mibs/CRATE-MIB.txt

clean:
	rm -f $(LIB_OBJS) $(CLI_OBJS) $(SNMPD_OBJS) libcrate.a crate crate-snmpd lib/lst-all-script-sections.h

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
l: install-local
e: install-examples
