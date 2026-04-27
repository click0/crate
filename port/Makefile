PORTNAME=	crate
PORTVERSION=	0.4.4
CATEGORIES=	sysutils
MASTER_SITES=	GH
GH_ACCOUNT=	click0
GH_PROJECT=	crate

MAINTAINER=	admin@support.od.ua
COMMENT=	FreeBSD container manager using jails, ZFS, and VNET
WWW=		https://github.com/click0/crate

LICENSE=	BSD3CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

LIB_DEPENDS=	libyaml-cpp.so:devel/yaml-cpp

USES=		compiler:c++17-lang pkgconfig

MAKE_ARGS=	PREFIX=${PREFIX} DESTDIR=${STAGEDIR} \
		CXX="${CXX}" CXXFLAGS="${CXXFLAGS}" LDFLAGS="${LDFLAGS}"

OPTIONS_SUB=	yes

# --- OPTIONS ---

OPTIONS_DEFINE=		DAEMON SNMPD EXAMPLES COMPLETIONS \
			ZFS IFCONFIG PFCTL CAPSICUM \
			LIBVIRT X11 VNCSERVER LIBSEAT

OPTIONS_DEFAULT=	DAEMON SNMPD EXAMPLES \
			ZFS IFCONFIG PFCTL CAPSICUM \
			LIBVIRT X11 LIBSEAT

DAEMON_DESC=		Container lifecycle daemon (crated)
SNMPD_DESC=		SNMP monitoring agent (crate-snmpd)
EXAMPLES_DESC=		Example container specifications
COMPLETIONS_DESC=	Bash/ZSH shell completions
ZFS_DESC=		Native ZFS API (libzfs)
IFCONFIG_DESC=		Native interface configuration (libifconfig)
PFCTL_DESC=		Native PF firewall control (libpfctl)
CAPSICUM_DESC=		Capsicum sandbox support (libcasper)
LIBVIRT_DESC=		Virtual machine support (libvirt)
X11_DESC=		X11 display forwarding
VNCSERVER_DESC=		Embedded VNC server
LIBSEAT_DESC=		DRM/GPU session management

# --- Option implementations ---

# ZFS, IFCONFIG, PFCTL, CAPSICUM — base system libraries
ZFS_MAKE_ARGS=		HAVE_LIBZFS=1
IFCONFIG_MAKE_ARGS=	HAVE_LIBIFCONFIG=1
PFCTL_MAKE_ARGS=	HAVE_LIBPFCTL=1
CAPSICUM_MAKE_ARGS=	HAVE_CAPSICUM=1

LIBVIRT_LIB_DEPENDS=	libvirt.so:devel/libvirt
LIBVIRT_MAKE_ARGS=	WITH_LIBVIRT=1

X11_USES=		xorg
X11_USE=		XORG=x11,xrandr,xext
X11_MAKE_ARGS=		WITH_X11=1

VNCSERVER_LIB_DEPENDS=	libvncserver.so:net/libvncserver
VNCSERVER_MAKE_ARGS=	WITH_LIBVNCSERVER=1

LIBSEAT_LIB_DEPENDS=	libseat.so:sysutils/seatd
LIBSEAT_MAKE_ARGS=	WITH_LIBSEAT=1

DAEMON_USES=		ssl

# --- Build / Install ---

do-build:
	cd ${WRKSRC} && ${MAKE_CMD} ${MAKE_ARGS} all
.if ${PORT_OPTIONS:MDAEMON}
	cd ${WRKSRC} && ${MAKE_CMD} ${MAKE_ARGS} crated
.endif
.if ${PORT_OPTIONS:MSNMPD}
	cd ${WRKSRC} && ${MAKE_CMD} ${MAKE_ARGS} crate-snmpd
.endif

do-install:
	cd ${WRKSRC} && ${MAKE_CMD} ${MAKE_ARGS} install
.if ${PORT_OPTIONS:MDAEMON}
	cd ${WRKSRC} && ${MAKE_CMD} ${MAKE_ARGS} install-daemon
.endif
.if ${PORT_OPTIONS:MSNMPD}
	cd ${WRKSRC} && ${MAKE_CMD} ${MAKE_ARGS} install-snmpd
.endif
.if ${PORT_OPTIONS:MEXAMPLES}
	cd ${WRKSRC} && ${MAKE_CMD} ${MAKE_ARGS} install-examples
.endif
.if ${PORT_OPTIONS:MCOMPLETIONS}
	cd ${WRKSRC} && ${MAKE_CMD} ${MAKE_ARGS} install-completions
.endif

do-test:
	cd ${WRKSRC} && ${MAKE_CMD} ${MAKE_ARGS} test

.include <bsd.port.mk>
