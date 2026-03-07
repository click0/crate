// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Netgraph via PF_NETGRAPH socket with ngctl(8) fallback.

#include "netgraph_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

// Netgraph headers (FreeBSD base)
#ifdef __FreeBSD__
#include <netgraph.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_socket.h>
#endif

#include <string.h>
#include <unistd.h>

#define ERR(msg...) ERR2("netgraph", msg)

namespace NetgraphOps {

#ifdef __FreeBSD__
static int g_csock = -1;  // control socket
static int g_dsock = -1;  // data socket

static bool ensureSocket() {
  if (g_csock >= 0) return true;
  if (NgMkSockNode(nullptr, &g_csock, &g_dsock) < 0)
    return false;
  return true;
}
#endif

bool available() {
#ifdef __FreeBSD__
  return ensureSocket();
#else
  return false;
#endif
}

bool mkpeer(const std::string &path, const std::string &type,
            const std::string &hook, const std::string &peerhook) {
#ifdef __FreeBSD__
  if (ensureSocket()) {
    struct ngm_mkpeer mp;
    ::strlcpy(mp.type, type.c_str(), sizeof(mp.type));
    ::strlcpy(mp.ourhook, hook.c_str(), sizeof(mp.ourhook));
    ::strlcpy(mp.peerhook, peerhook.c_str(), sizeof(mp.peerhook));

    if (NgSendMsg(g_csock, path.c_str(), NGM_GENERIC_COOKIE,
                  NGM_MKPEER, &mp, sizeof(mp)) >= 0)
      return true;
  }
#endif
  // Fallback
  try {
    Util::execCommand({CRATE_PATH_NGCTL, "mkpeer", path, type, hook, peerhook},
      "ngctl mkpeer");
    return true;
  } catch (...) { return false; }
}

bool name(const std::string &path, const std::string &newName) {
#ifdef __FreeBSD__
  if (ensureSocket()) {
    struct ngm_name nm;
    ::strlcpy(nm.name, newName.c_str(), sizeof(nm.name));
    if (NgSendMsg(g_csock, path.c_str(), NGM_GENERIC_COOKIE,
                  NGM_NAME, &nm, sizeof(nm)) >= 0)
      return true;
  }
#endif
  try {
    Util::execCommand({CRATE_PATH_NGCTL, "name", path, newName}, "ngctl name");
    return true;
  } catch (...) { return false; }
}

bool connect(const std::string &path1, const std::string &path2,
             const std::string &hook1, const std::string &hook2) {
#ifdef __FreeBSD__
  if (ensureSocket()) {
    struct ngm_connect con;
    ::strlcpy(con.path, path2.c_str(), sizeof(con.path));
    ::strlcpy(con.ourhook, hook1.c_str(), sizeof(con.ourhook));
    ::strlcpy(con.peerhook, hook2.c_str(), sizeof(con.peerhook));
    if (NgSendMsg(g_csock, path1.c_str(), NGM_GENERIC_COOKIE,
                  NGM_CONNECT, &con, sizeof(con)) >= 0)
      return true;
  }
#endif
  try {
    Util::execCommand({CRATE_PATH_NGCTL, "connect",
                       STR(path1 << ":"), STR(path2 << ":"), hook1, hook2},
      "ngctl connect");
    return true;
  } catch (...) { return false; }
}

bool msg(const std::string &path, const std::string &message) {
  // For arbitrary ASCII messages, use ngctl msg
  try {
    Util::execCommand({CRATE_PATH_NGCTL, "msg", STR(path << ":"), message},
      "ngctl msg");
    return true;
  } catch (...) { return false; }
}

bool shutdown(const std::string &path) {
#ifdef __FreeBSD__
  if (ensureSocket()) {
    if (NgSendMsg(g_csock, path.c_str(), NGM_GENERIC_COOKIE,
                  NGM_SHUTDOWN, nullptr, 0) >= 0)
      return true;
  }
#endif
  try {
    Util::execCommand({CRATE_PATH_NGCTL, "shutdown", STR(path << ":")},
      "ngctl shutdown");
    return true;
  } catch (...) { return false; }
}

std::string show(const std::string &path) {
#ifdef __FreeBSD__
  if (ensureSocket()) {
    char name[NG_NODESIZ];
    char type[NG_TYPESIZ];
    ng_ID_t id;
    if (NgNameNode(g_csock, path.c_str(), "%s", name) >= 0)
      return std::string(name);
  }
#endif
  try {
    return Util::execCommandGetOutput({CRATE_PATH_NGCTL, "show", STR(path << ":")},
      "ngctl show");
  } catch (...) { return ""; }
}

}
