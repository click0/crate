// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "replicate_pure.h"
#include "backup_pure.h"

#include <sstream>

namespace ReplicatePure {

namespace {

bool isAlnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
      || (c >= '0' && c <= '9');
}

bool isV4Octet(const std::string &s) {
  if (s.empty() || s.size() > 3) return false;
  for (char c : s) if (c < '0' || c > '9') return false;
  int n = 0;
  for (char c : s) n = n * 10 + (c - '0');
  return n <= 255;
}

bool isV4(const std::string &s) {
  size_t pos = 0;
  for (int i = 0; i < 4; i++) {
    auto dot = s.find('.', pos);
    auto end = (i == 3) ? s.size() : dot;
    if (i < 3 && dot == std::string::npos) return false;
    if (!isV4Octet(s.substr(pos, end - pos))) return false;
    pos = (i == 3) ? s.size() : (dot + 1);
  }
  return pos == s.size();
}

bool isHostname(const std::string &s) {
  if (s.empty() || s.size() > 253) return false;
  size_t i = 0;
  while (i < s.size()) {
    size_t labelStart = i;
    while (i < s.size() && s[i] != '.') i++;
    auto label = s.substr(labelStart, i - labelStart);
    if (label.empty() || label.size() > 63) return false;
    if (!isAlnum(label.front()) || !isAlnum(label.back())) return false;
    for (char c : label)
      if (!isAlnum(c) && c != '-') return false;
    if (i < s.size()) i++;
  }
  return true;
}

bool looksLikeV4Shape(const std::string &s) {
  if (s.empty()) return false;
  bool sawDot = false;
  for (char c : s) {
    if (c == '.') { sawDot = true; continue; }
    if (c < '0' || c > '9') return false;
  }
  return sawDot;
}

bool isValidUser(const std::string &u) {
  if (u.empty() || u.size() > 32) return false;
  for (char c : u)
    if (!isAlnum(c) && c != '.' && c != '_' && c != '-')
      return false;
  return true;
}

bool hasShellMetachar(const std::string &s) {
  for (char c : s) {
    if (c == '\'' || c == '"' || c == ';' || c == '`' || c == '$'
        || c == '|' || c == '&' || c == '<' || c == '>' || c == '\\'
        || c == '\n' || c == '\r' || c == '\t')
      return true;
  }
  return false;
}

bool hasDotDotSegment(const std::string &p) {
  size_t i = 0;
  while (i < p.size()) {
    auto slash = p.find('/', i);
    auto end = (slash == std::string::npos) ? p.size() : slash;
    if (p.substr(i, end - i) == "..") return true;
    if (slash == std::string::npos) break;
    i = slash + 1;
  }
  return false;
}

} // anon

std::string parseSshRemote(const std::string &remote, SshSpec &out) {
  if (remote.empty()) return "ssh remote is empty";
  if (remote.size() > 256) return "ssh remote longer than 256 chars";
  if (hasShellMetachar(remote))
    return "ssh remote contains shell metacharacters";

  auto at = remote.find('@');
  std::string host;
  if (at != std::string::npos) {
    out.user = remote.substr(0, at);
    host = remote.substr(at + 1);
    if (!isValidUser(out.user))
      return "ssh remote user contains invalid characters";
  } else {
    out.user.clear();
    host = remote;
  }
  if (host.empty()) return "ssh remote host is empty";
  // Dotted-numeric must validate as IPv4 (not silently fall through
  // to hostname check) — same fix as in MigratePure.
  if (looksLikeV4Shape(host)) {
    if (!isV4(host))
      return "ssh remote host looks like IPv4 but has invalid octets";
  } else if (!isHostname(host)) {
    return "ssh remote host is neither IPv4 nor a valid hostname";
  }
  out.host = host;
  return "";
}

std::string validateSshRemote(const std::string &remote) {
  SshSpec tmp;
  return parseSshRemote(remote, tmp);
}

std::string validateSshOpt(const std::string &kv) {
  if (kv.empty()) return "ssh-opt is empty";
  if (kv.size() > 256) return "ssh-opt longer than 256 chars";
  auto eq = kv.find('=');
  if (eq == std::string::npos)
    return "ssh-opt must be KEY=VALUE";
  if (eq == 0)
    return "ssh-opt KEY is empty";
  auto key = kv.substr(0, eq);
  auto val = kv.substr(eq + 1);
  if (key.size() > 64) return "ssh-opt KEY longer than 64 chars";
  for (char c : key)
    if (!isAlnum(c))
      return "ssh-opt KEY must be alphanumeric";
  // Disallow control / whitespace / shell metas in VALUE; ssh -o
  // values are passed unquoted on the local side and remote, so
  // any of these would be a footgun.
  for (char c : val) {
    if (c < 0x20 || c == 0x7f)
      return "ssh-opt VALUE contains a control character";
    if (c == ' ' || c == '\t')
      return "ssh-opt VALUE contains whitespace";
  }
  if (hasShellMetachar(val))
    return "ssh-opt VALUE contains shell metacharacters";
  return "";
}

std::string validateSshKey(const std::string &path) {
  if (path.empty()) return "ssh-key path is empty";
  if (path.size() > 1024) return "ssh-key path longer than 1024 chars";
  if (path.front() != '/') return "ssh-key path must be absolute";
  if (hasDotDotSegment(path))
    return "ssh-key path must not contain '..' segments";
  if (hasShellMetachar(path))
    return "ssh-key path contains shell metacharacters";
  return "";
}

std::string validateDestDataset(const std::string &ds) {
  if (ds.empty()) return "destination dataset is empty";
  if (ds.size() > 256) return "destination dataset longer than 256 chars";
  if (ds.front() == '/' || ds.back() == '/')
    return "destination dataset must not start or end with '/'";
  if (ds.find("//") != std::string::npos)
    return "destination dataset must not contain empty path segments";
  for (char c : ds) {
    bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-' || c == '/';
    if (!ok) {
      std::ostringstream os;
      os << "invalid character '" << c << "' in destination dataset";
      return os.str();
    }
  }
  // Reject any segment that's `.` or `..`
  size_t i = 0;
  while (i < ds.size()) {
    auto slash = ds.find('/', i);
    auto end = (slash == std::string::npos) ? ds.size() : slash;
    auto seg = ds.substr(i, end - i);
    if (seg == "." || seg == "..")
      return "destination dataset must not contain '.' or '..' segments";
    if (slash == std::string::npos) break;
    i = slash + 1;
  }
  return "";
}

std::vector<std::string> buildSshArgv(const SshSpec &ssh,
                                      const std::string &remoteCommand) {
  std::vector<std::string> a = {"/usr/bin/ssh"};
  // Sensible defaults: BatchMode prevents password prompts in
  // automated runs; ServerAliveInterval keeps the long send
  // pipeline alive across firewalls. Operators can override
  // either via --ssh-opt.
  a.push_back("-o"); a.push_back("BatchMode=yes");
  a.push_back("-o"); a.push_back("ServerAliveInterval=30");
  if (ssh.port != 0) {
    a.push_back("-p"); a.push_back(std::to_string(ssh.port));
  }
  if (!ssh.identityFile.empty()) {
    a.push_back("-i"); a.push_back(ssh.identityFile);
  }
  if (!ssh.configFile.empty()) {
    a.push_back("-F"); a.push_back(ssh.configFile);
  }
  for (auto &o : ssh.extraOpts) {
    a.push_back("-o"); a.push_back(o);
  }
  // user@host or host
  if (!ssh.user.empty())
    a.push_back(ssh.user + "@" + ssh.host);
  else
    a.push_back(ssh.host);
  a.push_back(remoteCommand);
  return a;
}

std::string buildRemoteRecvCommand(const std::string &destDataset) {
  // Plain command; validateDestDataset has already locked the
  // alphabet down so no quoting is needed.
  return std::string("zfs recv ") + destDataset;
}

std::vector<std::vector<std::string>>
buildReplicationPipeline(const ReplicateRequest &r) {
  std::vector<std::vector<std::string>> stages;
  stages.push_back(BackupPure::buildSendArgv(
    r.sourceDataset, r.currSnapshotSuffix, r.prevSnapshotSuffix));
  stages.push_back(buildSshArgv(r.ssh, buildRemoteRecvCommand(r.destDataset)));
  return stages;
}

} // namespace ReplicatePure
