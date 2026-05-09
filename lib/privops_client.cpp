// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_client.h"

#include <cerrno>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <sys/nv.h>
#endif

//
// Wire-transport half of privops_client (0.9.16 split — see
// lib/privops_client_pure.cpp for the pure half + history).
//
// This file owns the FreeBSD libnv send/recv path AND the Linux
// stub. It is in LIB_SRCS only — never in TEST_LINK_SRCS — so
// libnv symbols don't leak into the test-binary link line on
// FreeBSD CI.
//

namespace PrivOpsClient {

#ifdef __FreeBSD__

namespace {

int connectSocket(const std::string &socketPath) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (socketPath.size() >= sizeof(addr.sun_path)) {
    ::close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int e = errno;
    ::close(fd);
    errno = e;
    return -1;
  }
  return fd;
}

nvlist_t *fieldMapToNvlist(const PrivOpsNvPure::FieldMap &fields) {
  nvlist_t *nvl = nvlist_create(0);
  if (!nvl) return nullptr;
  for (const auto &kv : fields)
    nvlist_add_string(nvl, kv.first.c_str(), kv.second.c_str());
  return nvl;
}

} // anon

Response sendRequest(const std::string &socketPath,
                     const PrivOpsNvPure::FieldMap &fields) {
  Response r;
  if (socketPath.empty()) {
    r.transportError = "no privops socket configured";
    return r;
  }

  int fd = connectSocket(socketPath);
  if (fd < 0) {
    r.transportError = std::string("connect ") + socketPath +
                       ": " + ::strerror(errno);
    return r;
  }

  nvlist_t *req = fieldMapToNvlist(fields);
  if (!req) {
    ::close(fd);
    r.transportError = "nvlist_create failed (out of memory?)";
    return r;
  }
  if (nvlist_send(fd, req) != 0) {
    int e = errno;
    nvlist_destroy(req);
    ::close(fd);
    r.transportError = std::string("nvlist_send: ") + ::strerror(e);
    return r;
  }
  nvlist_destroy(req);

  nvlist_t *resp = nvlist_recv(fd, 0);
  ::close(fd);
  if (!resp) {
    r.transportError = std::string("nvlist_recv: ") + ::strerror(errno);
    return r;
  }
  if (nvlist_exists_number(resp, "status"))
    r.status = (int)nvlist_get_number(resp, "status");
  if (nvlist_exists_string(resp, "body"))
    r.body = nvlist_get_string(resp, "body");
  nvlist_destroy(resp);
  return r;
}

#else // !__FreeBSD__

Response sendRequest(const std::string &/*socketPath*/,
                     const PrivOpsNvPure::FieldMap &/*fields*/) {
  Response r;
  r.transportError = "libnv unavailable on this platform "
                     "(FreeBSD required)";
  return r;
}

#endif

} // namespace PrivOpsClient
