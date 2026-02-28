// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

class Args;
class Spec;

bool createCrate(const Args &args, const Spec &spec);
bool runCrate(const Args &args, int argc, char** argv, int &outReturnCode);
bool validateCrateSpec(const Args &args);
bool snapshotCrate(const Args &args);
bool exportCrate(const Args &args);
bool importCrate(const Args &args);
