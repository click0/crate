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
