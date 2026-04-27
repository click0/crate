// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

#include <exception>
#include <iostream>
#include <string>

#include "util.h"   // for STR macro

class Exception : public std::exception {
  std::string xmsg;
public:
  Exception(const std::string &loc, const std::string &msg);

  const char* what() const throw();
};


#define ERR2(loc, msg...) \
  throw Exception(loc, STR(msg));

// WARN uses rang colours. Files that include this header AND rely on
// WARN must also #include <rang.hpp>. Kept out of err.h itself so unit
// tests on Linux (no librang) can include err.h via util.h chain.
#define WARN(msg...) \
  std::cerr << rang::fg::yellow << msg << rang::style::reset << std::endl;
