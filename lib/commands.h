// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

class Args;
class Spec;

bool createCrate(const Args &args, const Spec &spec);
bool runCrate(const Args &args, int argc, char** argv, int &outReturnCode);
bool validateCrateSpec(const Args &args);
bool snapshotCrate(const Args &args);
bool listCrates(const Args &args);
bool infoCrate(const Args &args);
bool cleanCrates(const Args &args);
bool consoleCrate(const Args &args, int argc, char** argv);
bool exportCrate(const Args &args);
bool importCrate(const Args &args);
bool guiCommand(const Args &args);
bool stackCommand(const Args &args);
bool statsCrate(const Args &args);
bool logsCrate(const Args &args);
bool stopCrate(const Args &args);
bool restartCrate(const Args &args);
bool topCrate(const Args &args);
bool interDnsCommand(const Args &args);
bool vpnCommand(const Args &args);
bool inspectCrate(const Args &args);
bool migrateCommand(const Args &args);
bool backupCrate(const Args &args);
bool restoreCrate(const Args &args);
bool replicateCrate(const Args &args);
bool templateWarmCommand(const Args &args);
bool retuneCommand(const Args &args);
bool throttleCommand(const Args &args);
