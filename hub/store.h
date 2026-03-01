// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// SQLite store for crate-hub metrics retention.

#pragma once

#include <string>
#include <sqlite3.h>

namespace CrateHub {

class Store {
public:
  explicit Store(const std::string &dbPath);
  ~Store();

  // Record a poll result
  void recordPoll(const std::string &nodeName,
                  const std::string &hostInfo,
                  const std::string &containers);

  // Prune old data beyond retention period
  void prune(unsigned retentionHours = 48);

private:
  sqlite3 *db_ = nullptr;
  void initSchema();
};

}
