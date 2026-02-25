// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#pragma once

#include <string>

namespace Cmd {

extern const std::string xz;
extern const std::string xzThreadsArg; // "--threads=N" for exec-based pipelines
std::string chroot(const std::string &path); // returns cmroot command prefix with the trailing space

}

