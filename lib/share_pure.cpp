// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "share_pure.h"

namespace SharePure {

FileStrategy chooseFileStrategy(const FileShareInputs &in) {
  if (!in.hostExists && !in.jailExists)
    return FileStrategy::Error;

  if (in.hostExists && in.jailExists) {
    return in.sameDevice
             ? FileStrategy::HardLinkHostToJail
             : FileStrategy::NullfsBindHostToJail;
  }

  if (in.hostExists) {
    return in.sameDevice
             ? FileStrategy::HardLinkHostToJailNew
             : FileStrategy::NullfsBindHostToJail;
  }

  // jail-only
  return in.sameDevice
           ? FileStrategy::HardLinkJailToHost
           : FileStrategy::CopyJailToHostThenBind;
}

const char *strategyName(FileStrategy s) {
  switch (s) {
    case FileStrategy::HardLinkHostToJail:    return "hardlink-host-to-jail";
    case FileStrategy::HardLinkHostToJailNew: return "hardlink-host-to-jail-new";
    case FileStrategy::HardLinkJailToHost:    return "hardlink-jail-to-host";
    case FileStrategy::NullfsBindHostToJail:  return "nullfs-bind-host-to-jail";
    case FileStrategy::CopyJailToHostThenBind:return "copy-jail-to-host-then-bind";
    case FileStrategy::Error:                 return "error";
  }
  return "unknown";
}

} // namespace SharePure
