// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "replicate_pure.h"

#include <atf-c++.hpp>

#include <string>

using ReplicatePure::ReplicateRequest;
using ReplicatePure::SshSpec;
using ReplicatePure::buildRemoteRecvCommand;
using ReplicatePure::buildReplicationPipeline;
using ReplicatePure::buildSshArgv;
using ReplicatePure::parseSshRemote;
using ReplicatePure::validateDestDataset;
using ReplicatePure::validateSshKey;
using ReplicatePure::validateSshOpt;
using ReplicatePure::validateSshRemote;

// --- validateSshRemote / parseSshRemote ---

ATF_TEST_CASE_WITHOUT_HEAD(remote_typical_accepted);
ATF_TEST_CASE_BODY(remote_typical_accepted) {
  ATF_REQUIRE_EQ(validateSshRemote("backup@host.example.com"),  std::string());
  ATF_REQUIRE_EQ(validateSshRemote("host.example.com"),         std::string());
  ATF_REQUIRE_EQ(validateSshRemote("backup@10.0.0.5"),          std::string());
  ATF_REQUIRE_EQ(validateSshRemote("10.0.0.5"),                 std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(remote_invalid_rejected);
ATF_TEST_CASE_BODY(remote_invalid_rejected) {
  ATF_REQUIRE(!validateSshRemote("").empty());
  ATF_REQUIRE(!validateSshRemote("@host").empty());           // empty user
  ATF_REQUIRE(!validateSshRemote("user@").empty());           // empty host
  ATF_REQUIRE(!validateSshRemote("user@256.0.0.1").empty()); // bad v4 octet
  ATF_REQUIRE(!validateSshRemote("u s e r@host").empty());    // ws in user
  ATF_REQUIRE(!validateSshRemote("user@under_score").empty()); // illegal hostname
  ATF_REQUIRE(!validateSshRemote("user@host;rm").empty());    // metachars
  ATF_REQUIRE(!validateSshRemote("user@host`x`").empty());
  ATF_REQUIRE(!validateSshRemote("user@host$").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_remote_splits_user_host);
ATF_TEST_CASE_BODY(parse_remote_splits_user_host) {
  SshSpec s;
  ATF_REQUIRE_EQ(parseSshRemote("backup@dr.example.com", s), std::string());
  ATF_REQUIRE_EQ(s.user, std::string("backup"));
  ATF_REQUIRE_EQ(s.host, std::string("dr.example.com"));
  // No user means user stays empty.
  s = SshSpec{};
  ATF_REQUIRE_EQ(parseSshRemote("dr.example.com", s), std::string());
  ATF_REQUIRE(s.user.empty());
  ATF_REQUIRE_EQ(s.host, std::string("dr.example.com"));
}

// --- validateSshOpt ---

ATF_TEST_CASE_WITHOUT_HEAD(ssh_opt_typical_accepted);
ATF_TEST_CASE_BODY(ssh_opt_typical_accepted) {
  ATF_REQUIRE_EQ(validateSshOpt("StrictHostKeyChecking=no"),         std::string());
  ATF_REQUIRE_EQ(validateSshOpt("UserKnownHostsFile=/dev/null"),      std::string());
  ATF_REQUIRE_EQ(validateSshOpt("ConnectTimeout=30"),                 std::string());
  ATF_REQUIRE_EQ(validateSshOpt("ProxyJump=bastion"),                 std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(ssh_opt_invalid_rejected);
ATF_TEST_CASE_BODY(ssh_opt_invalid_rejected) {
  ATF_REQUIRE(!validateSshOpt("").empty());
  ATF_REQUIRE(!validateSshOpt("=value").empty());            // empty key
  ATF_REQUIRE(!validateSshOpt("NoEqualsSign").empty());
  ATF_REQUIRE(!validateSshOpt("Bad-Key=value").empty());     // dash in key
  ATF_REQUIRE(!validateSshOpt("Key=val ue").empty());        // ws in value
  ATF_REQUIRE(!validateSshOpt("Key=val;rm").empty());        // shell metas
  ATF_REQUIRE(!validateSshOpt("Key=val`x`").empty());
  ATF_REQUIRE(!validateSshOpt("Key=val\nrest").empty());     // ctrl char
}

// --- validateSshKey ---

ATF_TEST_CASE_WITHOUT_HEAD(ssh_key_typical_accepted);
ATF_TEST_CASE_BODY(ssh_key_typical_accepted) {
  ATF_REQUIRE_EQ(validateSshKey("/root/.ssh/id_ed25519"),  std::string());
  ATF_REQUIRE_EQ(validateSshKey("/etc/ssh/replication_key"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(ssh_key_invalid_rejected);
ATF_TEST_CASE_BODY(ssh_key_invalid_rejected) {
  ATF_REQUIRE(!validateSshKey("").empty());
  ATF_REQUIRE(!validateSshKey("relative/path").empty());
  ATF_REQUIRE(!validateSshKey("/root/../../etc/passwd").empty());
  ATF_REQUIRE(!validateSshKey("/path/with;rm").empty());
}

// --- validateDestDataset ---

ATF_TEST_CASE_WITHOUT_HEAD(dest_dataset_typical);
ATF_TEST_CASE_BODY(dest_dataset_typical) {
  ATF_REQUIRE_EQ(validateDestDataset("tank/jails/foo"),   std::string());
  ATF_REQUIRE_EQ(validateDestDataset("backup-pool/dr"),    std::string());
  ATF_REQUIRE_EQ(validateDestDataset("a"),                 std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(dest_dataset_invalid);
ATF_TEST_CASE_BODY(dest_dataset_invalid) {
  ATF_REQUIRE(!validateDestDataset("").empty());
  ATF_REQUIRE(!validateDestDataset("/tank/jails").empty());
  ATF_REQUIRE(!validateDestDataset("tank/jails/").empty());
  ATF_REQUIRE(!validateDestDataset("tank//jails").empty());
  ATF_REQUIRE(!validateDestDataset("tank/../etc").empty());
  ATF_REQUIRE(!validateDestDataset("tank/./jails").empty());
  ATF_REQUIRE(!validateDestDataset("tank;rm/jails").empty());
  ATF_REQUIRE(!validateDestDataset("tank/jails:snap").empty());
}

// --- buildSshArgv ---

ATF_TEST_CASE_WITHOUT_HEAD(ssh_argv_minimal);
ATF_TEST_CASE_BODY(ssh_argv_minimal) {
  SshSpec s;
  s.user = "backup";
  s.host = "dr.example.com";
  auto a = buildSshArgv(s, "zfs recv tank/jails/foo");
  // First element must be the absolute path to ssh.
  ATF_REQUIRE_EQ(a.front(), std::string("/usr/bin/ssh"));
  // Defaults are present:
  bool sawBatch = false, sawAlive = false;
  for (size_t i = 0; i + 1 < a.size(); i++) {
    if (a[i] == "-o" && a[i + 1] == "BatchMode=yes")          sawBatch = true;
    if (a[i] == "-o" && a[i + 1] == "ServerAliveInterval=30") sawAlive = true;
  }
  ATF_REQUIRE(sawBatch);
  ATF_REQUIRE(sawAlive);
  // Last two args are user@host then the remote command.
  ATF_REQUIRE_EQ(a[a.size() - 2], std::string("backup@dr.example.com"));
  ATF_REQUIRE_EQ(a.back(),         std::string("zfs recv tank/jails/foo"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ssh_argv_full_options);
ATF_TEST_CASE_BODY(ssh_argv_full_options) {
  SshSpec s;
  s.user = "backup";
  s.host = "dr.example.com";
  s.port = 2222;
  s.identityFile = "/root/.ssh/id_ed25519";
  s.configFile   = "/etc/ssh/ssh_config.replication";
  s.extraOpts    = {"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null"};
  auto a = buildSshArgv(s, "zfs recv tank/jails/foo");

  // -p N
  bool sawP = false;
  for (size_t i = 0; i + 1 < a.size(); i++)
    if (a[i] == "-p" && a[i + 1] == "2222") sawP = true;
  ATF_REQUIRE(sawP);
  // -i KEY
  bool sawI = false;
  for (size_t i = 0; i + 1 < a.size(); i++)
    if (a[i] == "-i" && a[i + 1] == "/root/.ssh/id_ed25519") sawI = true;
  ATF_REQUIRE(sawI);
  // -F CONFIG
  bool sawF = false;
  for (size_t i = 0; i + 1 < a.size(); i++)
    if (a[i] == "-F" && a[i + 1] == "/etc/ssh/ssh_config.replication") sawF = true;
  ATF_REQUIRE(sawF);
  // Both --ssh-opt entries present.
  bool sawStrict = false, sawHosts = false;
  for (size_t i = 0; i + 1 < a.size(); i++) {
    if (a[i] == "-o" && a[i + 1] == "StrictHostKeyChecking=no")  sawStrict = true;
    if (a[i] == "-o" && a[i + 1] == "UserKnownHostsFile=/dev/null") sawHosts = true;
  }
  ATF_REQUIRE(sawStrict);
  ATF_REQUIRE(sawHosts);
}

ATF_TEST_CASE_WITHOUT_HEAD(ssh_argv_no_user);
ATF_TEST_CASE_BODY(ssh_argv_no_user) {
  SshSpec s;
  s.host = "dr.example.com";
  auto a = buildSshArgv(s, "zfs recv x");
  // No '@' when user is empty.
  ATF_REQUIRE_EQ(a[a.size() - 2], std::string("dr.example.com"));
}

// --- buildRemoteRecvCommand ---

ATF_TEST_CASE_WITHOUT_HEAD(remote_recv_command_shape);
ATF_TEST_CASE_BODY(remote_recv_command_shape) {
  ATF_REQUIRE_EQ(buildRemoteRecvCommand("tank/jails/foo"),
                 std::string("zfs recv tank/jails/foo"));
}

// --- buildReplicationPipeline ---

ATF_TEST_CASE_WITHOUT_HEAD(pipeline_full_two_stages);
ATF_TEST_CASE_BODY(pipeline_full_two_stages) {
  ReplicateRequest r;
  r.sourceDataset      = "pool/jails/foo";
  r.currSnapshotSuffix = "backup-NOW";
  r.prevSnapshotSuffix = "";   // full
  r.destDataset        = "tank/jails/foo";
  r.ssh.user = "backup";
  r.ssh.host = "dr";

  auto p = buildReplicationPipeline(r);
  ATF_REQUIRE_EQ(p.size(), (size_t)2);
  // Stage 0: zfs send pool/jails/foo@backup-NOW
  ATF_REQUIRE_EQ(p[0][0], std::string("/sbin/zfs"));
  ATF_REQUIRE_EQ(p[0][1], std::string("send"));
  ATF_REQUIRE_EQ(p[0].back(), std::string("pool/jails/foo@backup-NOW"));
  // Stage 1: ssh ... user@host  zfs recv tank/jails/foo
  ATF_REQUIRE_EQ(p[1][0], std::string("/usr/bin/ssh"));
  ATF_REQUIRE_EQ(p[1].back(), std::string("zfs recv tank/jails/foo"));
}

ATF_TEST_CASE_WITHOUT_HEAD(pipeline_incremental_uses_dash_i);
ATF_TEST_CASE_BODY(pipeline_incremental_uses_dash_i) {
  ReplicateRequest r;
  r.sourceDataset      = "pool/jails/foo";
  r.currSnapshotSuffix = "backup-NOW";
  r.prevSnapshotSuffix = "backup-PREV";
  r.destDataset        = "tank/jails/foo";
  r.ssh.host = "dr";

  auto p = buildReplicationPipeline(r);
  // Stage 0: zfs send -i prev curr
  ATF_REQUIRE_EQ(p[0][1], std::string("send"));
  ATF_REQUIRE_EQ(p[0][2], std::string("-i"));
  ATF_REQUIRE_EQ(p[0][3], std::string("pool/jails/foo@backup-PREV"));
  ATF_REQUIRE_EQ(p[0][4], std::string("pool/jails/foo@backup-NOW"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, remote_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, remote_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, parse_remote_splits_user_host);
  ATF_ADD_TEST_CASE(tcs, ssh_opt_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, ssh_opt_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, ssh_key_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, ssh_key_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, dest_dataset_typical);
  ATF_ADD_TEST_CASE(tcs, dest_dataset_invalid);
  ATF_ADD_TEST_CASE(tcs, ssh_argv_minimal);
  ATF_ADD_TEST_CASE(tcs, ssh_argv_full_options);
  ATF_ADD_TEST_CASE(tcs, ssh_argv_no_user);
  ATF_ADD_TEST_CASE(tcs, remote_recv_command_shape);
  ATF_ADD_TEST_CASE(tcs, pipeline_full_two_stages);
  ATF_ADD_TEST_CASE(tcs, pipeline_incremental_uses_dash_i);
}
