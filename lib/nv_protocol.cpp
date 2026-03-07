// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// nvlist protocol over Unix socket.

#include "nv_protocol.h"

#ifdef __FreeBSD__
#include <sys/nv.h>
#endif

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

namespace NvProtocol {

bool sendMessage(int fd, const Message &msg) {
#ifdef __FreeBSD__
  nvlist_t *nvl = nvlist_create(0);
  if (!nvl) return false;

  nvlist_add_string(nvl, "action", msg.action.c_str());
  nvlist_add_number(nvl, "status", msg.status);
  if (!msg.error.empty())
    nvlist_add_string(nvl, "error", msg.error.c_str());

  // Pack params as a nested nvlist
  nvlist_t *params = nvlist_create(0);
  for (auto &kv : msg.params)
    nvlist_add_string(params, kv.first.c_str(), kv.second.c_str());
  nvlist_add_nvlist(nvl, "params", params);
  nvlist_destroy(params);

  int err = nvlist_send(fd, nvl);
  nvlist_destroy(nvl);
  return err == 0;
#else
  (void)fd; (void)msg;
  return false;
#endif
}

bool recvMessage(int fd, Message &msg) {
#ifdef __FreeBSD__
  nvlist_t *nvl = nvlist_recv(fd, 0);
  if (!nvl) return false;

  if (nvlist_exists_string(nvl, "action"))
    msg.action = nvlist_get_string(nvl, "action");
  if (nvlist_exists_number(nvl, "status"))
    msg.status = static_cast<int>(nvlist_get_number(nvl, "status"));
  if (nvlist_exists_string(nvl, "error"))
    msg.error = nvlist_get_string(nvl, "error");

  if (nvlist_exists_nvlist(nvl, "params")) {
    const nvlist_t *params = nvlist_get_nvlist(nvl, "params");
    void *cookie = nullptr;
    while (true) {
      const char *name = nvlist_next(params, nullptr, &cookie);
      if (!name) break;
      if (nvlist_exists_string(params, name))
        msg.params[name] = nvlist_get_string(params, name);
    }
  }

  nvlist_destroy(nvl);
  return true;
#else
  (void)fd; (void)msg;
  return false;
#endif
}

int connectToDaemon(const std::string &socketPath) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  ::strlcpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path));

  if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
    ::close(fd);
    return -1;
  }

  return fd;
}

Message sendCommand(const std::string &socketPath, const Message &cmd) {
  Message response;
  response.status = -1;
  response.error = "connection failed";

  int fd = connectToDaemon(socketPath);
  if (fd < 0) return response;

  if (!sendMessage(fd, cmd)) {
    ::close(fd);
    response.error = "send failed";
    return response;
  }

  if (!recvMessage(fd, response)) {
    ::close(fd);
    response.status = -1;
    response.error = "recv failed";
    return response;
  }

  ::close(fd);
  return response;
}

}
