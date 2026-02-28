// pathnames.h — Absolute paths to external commands used by crate
// Standard FreeBSD locations. For non-standard installations, edit and recompile.
//
// Build-time override example:
//   make CXXFLAGS+='-DCRATE_PATH_ZFS=\"/usr/local/sbin/zfs\"'
//
// Follows the same pattern as FreeBSD <paths.h> which defines _PATH_IFCONFIG,
// _PATH_MOUNT, etc. for base system utilities.
//
// Security: crate is a setuid root binary. Using absolute paths prevents
// CWE-426 (Untrusted Search Path) attacks where an attacker manipulates PATH
// to execute arbitrary code as root. See docs/security-command-paths.md.

#pragma once

// --- FreeBSD base system: /sbin ---

#ifndef CRATE_PATH_ZFS
#define CRATE_PATH_ZFS        "/sbin/zfs"
#endif
#ifndef CRATE_PATH_ZPOOL
#define CRATE_PATH_ZPOOL      "/sbin/zpool"
#endif
#ifndef CRATE_PATH_IPFW
#define CRATE_PATH_IPFW       "/sbin/ipfw"
#endif
#ifndef CRATE_PATH_PFCTL
#define CRATE_PATH_PFCTL      "/sbin/pfctl"
#endif
#ifndef CRATE_PATH_IFCONFIG
#define CRATE_PATH_IFCONFIG   "/sbin/ifconfig"
#endif
#ifndef CRATE_PATH_ROUTE
#define CRATE_PATH_ROUTE      "/sbin/route"
#endif
#ifndef CRATE_PATH_DEVFS
#define CRATE_PATH_DEVFS      "/sbin/devfs"
#endif
#ifndef CRATE_PATH_SYSCTL
#define CRATE_PATH_SYSCTL     "/sbin/sysctl"
#endif

// --- FreeBSD base system: /bin ---

#ifndef CRATE_PATH_SH
#define CRATE_PATH_SH         "/bin/sh"
#endif

// --- FreeBSD base system: /usr/bin ---

#ifndef CRATE_PATH_XZ
#define CRATE_PATH_XZ         "/usr/bin/xz"
#endif
#ifndef CRATE_PATH_TAR
#define CRATE_PATH_TAR        "/usr/bin/tar"
#endif
#ifndef CRATE_PATH_NETSTAT
#define CRATE_PATH_NETSTAT    "/usr/bin/netstat"
#endif
#ifndef CRATE_PATH_GREP
#define CRATE_PATH_GREP       "/usr/bin/grep"
#endif
#ifndef CRATE_PATH_SED
#define CRATE_PATH_SED        "/usr/bin/sed"
#endif
#ifndef CRATE_PATH_RCTL
#define CRATE_PATH_RCTL       "/usr/bin/rctl"
#endif
#ifndef CRATE_PATH_FETCH
#define CRATE_PATH_FETCH      "/usr/bin/fetch"
#endif
#ifndef CRATE_PATH_ID
#define CRATE_PATH_ID         "/usr/bin/id"
#endif
#ifndef CRATE_PATH_CPUSET
#define CRATE_PATH_CPUSET     "/usr/bin/cpuset"
#endif

// --- FreeBSD base system: /usr/sbin ---

#ifndef CRATE_PATH_UGIDFW
#define CRATE_PATH_UGIDFW     "/usr/sbin/ugidfw"
#endif
#ifndef CRATE_PATH_JEXEC
#define CRATE_PATH_JEXEC      "/usr/sbin/jexec"
#endif
#ifndef CRATE_PATH_JLS
#define CRATE_PATH_JLS        "/usr/sbin/jls"
#endif
#ifndef CRATE_PATH_JAIL
#define CRATE_PATH_JAIL       "/usr/sbin/jail"
#endif
#ifndef CRATE_PATH_CHROOT
#define CRATE_PATH_CHROOT     "/usr/sbin/chroot"
#endif
#ifndef CRATE_PATH_PW
#define CRATE_PATH_PW         "/usr/sbin/pw"
#endif
#ifndef CRATE_PATH_SERVICE
#define CRATE_PATH_SERVICE    "/usr/sbin/service"
#endif
#ifndef CRATE_PATH_PKG
#define CRATE_PATH_PKG        "/usr/sbin/pkg"
#endif

// --- Ports/packages: /usr/local ---

#ifndef CRATE_PATH_XEPHYR
#define CRATE_PATH_XEPHYR     "/usr/local/bin/Xephyr"
#endif
#ifndef CRATE_PATH_SOCAT
#define CRATE_PATH_SOCAT      "/usr/local/bin/socat"
#endif
#ifndef CRATE_PATH_UNBOUND
#define CRATE_PATH_UNBOUND    "/usr/local/sbin/unbound"
#endif
