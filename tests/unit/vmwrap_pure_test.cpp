// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "vmwrap_pure.h"

#include <atf-c++.hpp>

#include <string>

using VmWrapPure::WrapSpec;
using VmWrapPure::buildBhyveInvocationHint;
using VmWrapPure::buildDevfsRuleset;
using VmWrapPure::buildDevfsReloadArgv;
using VmWrapPure::buildJailConfFragment;
using VmWrapPure::buildJailCreateArgv;
using VmWrapPure::buildZfsJailArgv;
using VmWrapPure::defaultJailPath;
using VmWrapPure::deriveRulesetNum;
using VmWrapPure::validateDataset;
using VmWrapPure::validateJailName;
using VmWrapPure::validateNmdm;
using VmWrapPure::validateRulesetNum;
using VmWrapPure::validateSpec;
using VmWrapPure::validateTap;
using VmWrapPure::validateVmName;

// --- Validators ---

ATF_TEST_CASE_WITHOUT_HEAD(vm_name_typical_accepted);
ATF_TEST_CASE_BODY(vm_name_typical_accepted) {
  ATF_REQUIRE_EQ(validateVmName("alpine"), std::string());
  ATF_REQUIRE_EQ(validateVmName("alpine-edge"), std::string());
  ATF_REQUIRE_EQ(validateVmName("vm_01"), std::string());
  ATF_REQUIRE_EQ(validateVmName("WebApp42"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(vm_name_rejects_garbage);
ATF_TEST_CASE_BODY(vm_name_rejects_garbage) {
  ATF_REQUIRE(!validateVmName("").empty());
  ATF_REQUIRE(!validateVmName("-leadingdash").empty());
  ATF_REQUIRE(!validateVmName(".leadingdot").empty());
  ATF_REQUIRE(!validateVmName("has space").empty());
  ATF_REQUIRE(!validateVmName("has/slash").empty());
  ATF_REQUIRE(!validateVmName("$(rm -rf /)").empty());
  ATF_REQUIRE(!validateVmName("vm;reboot").empty());
  // length cap
  std::string toolong(64, 'a');
  ATF_REQUIRE(!validateVmName(toolong).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(jail_name_alphabet_matches_vm);
ATF_TEST_CASE_BODY(jail_name_alphabet_matches_vm) {
  ATF_REQUIRE_EQ(validateJailName("myvm-cage"), std::string());
  ATF_REQUIRE(!validateJailName("").empty());
  ATF_REQUIRE(!validateJailName("a/b").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(dataset_typical_accepted);
ATF_TEST_CASE_BODY(dataset_typical_accepted) {
  ATF_REQUIRE_EQ(validateDataset(""), std::string());                   // empty allowed
  ATF_REQUIRE_EQ(validateDataset("zroot"), std::string());
  ATF_REQUIRE_EQ(validateDataset("zroot/vms/myvm"), std::string());
  ATF_REQUIRE_EQ(validateDataset("tank/jails/web-01"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(dataset_rejects_traversal_and_garbage);
ATF_TEST_CASE_BODY(dataset_rejects_traversal_and_garbage) {
  ATF_REQUIRE(!validateDataset("/leading/slash").empty());
  ATF_REQUIRE(!validateDataset("trailing/slash/").empty());
  ATF_REQUIRE(!validateDataset("zroot/../etc").empty());
  ATF_REQUIRE(!validateDataset("zroot/vms/$(id)").empty());
  ATF_REQUIRE(!validateDataset("0starts/with/digit").empty());  // first char must be alpha
  ATF_REQUIRE(!validateDataset("has space").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(tap_and_nmdm_ranges);
ATF_TEST_CASE_BODY(tap_and_nmdm_ranges) {
  ATF_REQUIRE_EQ(validateTap(-1), std::string());
  ATF_REQUIRE_EQ(validateTap(0), std::string());
  ATF_REQUIRE_EQ(validateTap(42), std::string());
  ATF_REQUIRE_EQ(validateTap(9999), std::string());
  ATF_REQUIRE(!validateTap(-2).empty());
  ATF_REQUIRE(!validateTap(10000).empty());

  ATF_REQUIRE_EQ(validateNmdm(-1), std::string());
  ATF_REQUIRE_EQ(validateNmdm(0), std::string());
  ATF_REQUIRE(!validateNmdm(-2).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(ruleset_num_range);
ATF_TEST_CASE_BODY(ruleset_num_range) {
  ATF_REQUIRE(!validateRulesetNum(0).empty());     // 0 is the "derive" sentinel
  ATF_REQUIRE_EQ(validateRulesetNum(1), std::string());
  ATF_REQUIRE_EQ(validateRulesetNum(150), std::string());
  ATF_REQUIRE_EQ(validateRulesetNum(65535), std::string());
  ATF_REQUIRE(!validateRulesetNum(65536).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(spec_validation_short_circuits);
ATF_TEST_CASE_BODY(spec_validation_short_circuits) {
  WrapSpec good;
  good.vmName = "alpine"; good.jailName = "alpine-cage";
  ATF_REQUIRE_EQ(validateSpec(good), std::string());

  WrapSpec bad = good;
  bad.vmName = "";
  ATF_REQUIRE(!validateSpec(bad).empty());

  bad = good;
  bad.dataset = "/leading/slash";
  ATF_REQUIRE(!validateSpec(bad).empty());

  bad = good;
  bad.tap = 99999;
  ATF_REQUIRE(!validateSpec(bad).empty());
}

// --- Derivations ---

ATF_TEST_CASE_WITHOUT_HEAD(ruleset_derivation_in_range);
ATF_TEST_CASE_BODY(ruleset_derivation_in_range) {
  for (auto name : {"alpine", "myvm-cage", "WebApp42", "x", "a-very-long-name-with-dashes"}) {
    auto n = deriveRulesetNum(name);
    ATF_REQUIRE(n >= 100u);
    ATF_REQUIRE(n <= 199u);
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(ruleset_derivation_deterministic);
ATF_TEST_CASE_BODY(ruleset_derivation_deterministic) {
  // Same input -> same output, every time.
  ATF_REQUIRE_EQ(deriveRulesetNum("myvm-cage"), deriveRulesetNum("myvm-cage"));
  // Different input -> usually different (not always — collisions
  // within 100..199 are rare but possible). At least one of these
  // pairs must differ.
  bool anyDiffer =
      (deriveRulesetNum("a") != deriveRulesetNum("b")) ||
      (deriveRulesetNum("c") != deriveRulesetNum("d")) ||
      (deriveRulesetNum("e") != deriveRulesetNum("f"));
  ATF_REQUIRE(anyDiffer);
}

ATF_TEST_CASE_WITHOUT_HEAD(default_jail_path_is_root);
ATF_TEST_CASE_BODY(default_jail_path_is_root) {
  ATF_REQUIRE_EQ(defaultJailPath("anything"), std::string("/"));
}

// --- Builders ---

ATF_TEST_CASE_WITHOUT_HEAD(devfs_block_contains_required_lines);
ATF_TEST_CASE_BODY(devfs_block_contains_required_lines) {
  WrapSpec s;
  s.vmName = "alpine"; s.jailName = "alpine-cage";
  s.tap = 42; s.nmdm = 0; s.rulesetNum = 150;
  auto out = buildDevfsRuleset(s);
  ATF_REQUIRE(out.find("[crate_vmwrap_alpine-cage=150]") != std::string::npos);
  ATF_REQUIRE(out.find("$devfsrules_hide_all") != std::string::npos);
  ATF_REQUIRE(out.find("'vmm/alpine'") != std::string::npos);
  ATF_REQUIRE(out.find("vmmctl") != std::string::npos);
  ATF_REQUIRE(out.find("'nmdm0*'") != std::string::npos);
  ATF_REQUIRE(out.find("tap42") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(devfs_block_skips_optional_devices);
ATF_TEST_CASE_BODY(devfs_block_skips_optional_devices) {
  WrapSpec s;
  s.vmName = "alpine"; s.jailName = "alpine-cage";
  // tap = -1 and nmdm = -1 (defaults) should not produce those lines.
  auto out = buildDevfsRuleset(s);
  ATF_REQUIRE(out.find("nmdm") == std::string::npos);
  ATF_REQUIRE(out.find("tap") == std::string::npos);
  // VM and vmmctl always present.
  ATF_REQUIRE(out.find("'vmm/alpine'") != std::string::npos);
  ATF_REQUIRE(out.find("vmmctl") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(devfs_block_resolves_derived_ruleset);
ATF_TEST_CASE_BODY(devfs_block_resolves_derived_ruleset) {
  WrapSpec s;
  s.vmName = "alpine"; s.jailName = "alpine-cage";
  // rulesetNum = 0 -> derive
  auto out = buildDevfsRuleset(s);
  auto derived = deriveRulesetNum("alpine-cage");
  ATF_REQUIRE(out.find("=" + std::to_string(derived) + "]") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(jail_conf_has_vnet_and_allow_vmm);
ATF_TEST_CASE_BODY(jail_conf_has_vnet_and_allow_vmm) {
  WrapSpec s;
  s.vmName = "alpine"; s.jailName = "alpine-cage";
  s.tap = 42; s.rulesetNum = 150;
  auto out = buildJailConfFragment(s);
  ATF_REQUIRE(out.find("alpine-cage {") != std::string::npos);
  ATF_REQUIRE(out.find("vnet;") != std::string::npos);
  ATF_REQUIRE(out.find("vnet.interface = \"tap42\";") != std::string::npos);
  ATF_REQUIRE(out.find("allow.vmm;") != std::string::npos);
  ATF_REQUIRE(out.find("allow.raw_sockets = 0;") != std::string::npos);
  ATF_REQUIRE(out.find("allow.sysvipc = 0;") != std::string::npos);
  ATF_REQUIRE(out.find("devfs_ruleset = 150;") != std::string::npos);
  ATF_REQUIRE(out.find("path = \"/\";") != std::string::npos);
  ATF_REQUIRE(out.find("host.hostname = \"alpine-cage\";") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(jail_conf_skips_vnet_iface_without_tap);
ATF_TEST_CASE_BODY(jail_conf_skips_vnet_iface_without_tap) {
  WrapSpec s;
  s.vmName = "alpine"; s.jailName = "alpine-cage";
  // No tap means the operator wires it up themselves later.
  auto out = buildJailConfFragment(s);
  ATF_REQUIRE(out.find("vnet;") != std::string::npos);
  ATF_REQUIRE(out.find("vnet.interface") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(jail_conf_overrides_path);
ATF_TEST_CASE_BODY(jail_conf_overrides_path) {
  WrapSpec s;
  s.vmName = "alpine"; s.jailName = "alpine-cage";
  s.jailPath = "/usr/jails/alpine-cage";
  auto out = buildJailConfFragment(s);
  ATF_REQUIRE(out.find("path = \"/usr/jails/alpine-cage\";") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(bhyve_hint_uses_vm_name);
ATF_TEST_CASE_BODY(bhyve_hint_uses_vm_name) {
  WrapSpec s;
  s.vmName = "alpine"; s.jailName = "alpine-cage";
  s.tap = 42; s.nmdm = 0; s.dataset = "zroot/vms/alpine";
  auto out = buildBhyveInvocationHint(s);
  ATF_REQUIRE(out.find("jexec alpine-cage") != std::string::npos);
  ATF_REQUIRE(out.find("bhyve") != std::string::npos);
  ATF_REQUIRE(out.find("virtio-net,tap42") != std::string::npos);
  ATF_REQUIRE(out.find("/dev/zvol/zroot/vms/alpine/disk0") != std::string::npos);
  ATF_REQUIRE(out.find("/dev/nmdm0A") != std::string::npos);
  // VM name must be the last positional arg to bhyve(8).
  ATF_REQUIRE(out.find("alpine\n") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(bhyve_hint_falls_back_without_dataset);
ATF_TEST_CASE_BODY(bhyve_hint_falls_back_without_dataset) {
  WrapSpec s;
  s.vmName = "alpine"; s.jailName = "alpine-cage";
  // No dataset, no tap, no nmdm -> hint emits a placeholder disk path
  // and skips network/console specs.
  auto out = buildBhyveInvocationHint(s);
  ATF_REQUIRE(out.find("/path/to/disk.img") != std::string::npos);
  ATF_REQUIRE(out.find("virtio-net") == std::string::npos);
  ATF_REQUIRE(out.find("nmdm") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(devfs_reload_argv);
ATF_TEST_CASE_BODY(devfs_reload_argv) {
  auto a = buildDevfsReloadArgv();
  ATF_REQUIRE_EQ(a.size(), (size_t)3);
  ATF_REQUIRE_EQ(a[0], std::string("/usr/sbin/service"));
  ATF_REQUIRE_EQ(a[1], std::string("devfs"));
  ATF_REQUIRE_EQ(a[2], std::string("restart"));
}

ATF_TEST_CASE_WITHOUT_HEAD(jail_create_argv);
ATF_TEST_CASE_BODY(jail_create_argv) {
  auto a = buildJailCreateArgv("/var/run/crate/x.jail.conf");
  ATF_REQUIRE_EQ(a.size(), (size_t)4);
  ATF_REQUIRE_EQ(a[0], std::string("/usr/sbin/jail"));
  ATF_REQUIRE_EQ(a[1], std::string("-c"));
  ATF_REQUIRE_EQ(a[2], std::string("-f"));
  ATF_REQUIRE_EQ(a[3], std::string("/var/run/crate/x.jail.conf"));
}

ATF_TEST_CASE_WITHOUT_HEAD(zfs_jail_argv);
ATF_TEST_CASE_BODY(zfs_jail_argv) {
  auto a = buildZfsJailArgv("alpine-cage", "zroot/vms/alpine");
  ATF_REQUIRE_EQ(a.size(), (size_t)4);
  ATF_REQUIRE_EQ(a[0], std::string("/sbin/zfs"));
  ATF_REQUIRE_EQ(a[1], std::string("jail"));
  ATF_REQUIRE_EQ(a[2], std::string("alpine-cage"));
  ATF_REQUIRE_EQ(a[3], std::string("zroot/vms/alpine"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, vm_name_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, vm_name_rejects_garbage);
  ATF_ADD_TEST_CASE(tcs, jail_name_alphabet_matches_vm);
  ATF_ADD_TEST_CASE(tcs, dataset_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, dataset_rejects_traversal_and_garbage);
  ATF_ADD_TEST_CASE(tcs, tap_and_nmdm_ranges);
  ATF_ADD_TEST_CASE(tcs, ruleset_num_range);
  ATF_ADD_TEST_CASE(tcs, spec_validation_short_circuits);
  ATF_ADD_TEST_CASE(tcs, ruleset_derivation_in_range);
  ATF_ADD_TEST_CASE(tcs, ruleset_derivation_deterministic);
  ATF_ADD_TEST_CASE(tcs, default_jail_path_is_root);
  ATF_ADD_TEST_CASE(tcs, devfs_block_contains_required_lines);
  ATF_ADD_TEST_CASE(tcs, devfs_block_skips_optional_devices);
  ATF_ADD_TEST_CASE(tcs, devfs_block_resolves_derived_ruleset);
  ATF_ADD_TEST_CASE(tcs, jail_conf_has_vnet_and_allow_vmm);
  ATF_ADD_TEST_CASE(tcs, jail_conf_skips_vnet_iface_without_tap);
  ATF_ADD_TEST_CASE(tcs, jail_conf_overrides_path);
  ATF_ADD_TEST_CASE(tcs, bhyve_hint_uses_vm_name);
  ATF_ADD_TEST_CASE(tcs, bhyve_hint_falls_back_without_dataset);
  ATF_ADD_TEST_CASE(tcs, devfs_reload_argv);
  ATF_ADD_TEST_CASE(tcs, jail_create_argv);
  ATF_ADD_TEST_CASE(tcs, zfs_jail_argv);
}
