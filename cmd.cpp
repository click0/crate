// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "cmd.h"
#include "util.h"


namespace Cmd {

const std::string xzThreadsArg = STRg("--threads=" << Util::getSysctlInt("hw.ncpu"));

}
