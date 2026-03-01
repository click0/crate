// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "cmd.h"
#include "util.h"


namespace Cmd {

const std::string xzThreadsArg = STRg("--threads=" << Util::getSysctlInt("hw.ncpu"));

}
