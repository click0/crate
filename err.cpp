// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "err.h"
#include "util.h"


Exception::Exception(const std::string &loc, const std::string &msg)
: xmsg(STR(loc << ": " << msg))
{ }

const char* Exception::what() const throw() {
  return xmsg.c_str();
}
