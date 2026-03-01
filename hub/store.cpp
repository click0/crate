// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "store.h"

#include <stdexcept>
#include <iostream>

namespace CrateHub {

Store::Store(const std::string &dbPath) {
  if (sqlite3_open(dbPath.c_str(), &db_) != SQLITE_OK)
    throw std::runtime_error(std::string("failed to open SQLite: ") + sqlite3_errmsg(db_));
  initSchema();
}

Store::~Store() {
  if (db_)
    sqlite3_close(db_);
}

void Store::initSchema() {
  const char *sql = R"(
    CREATE TABLE IF NOT EXISTS polls (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      node_name TEXT NOT NULL,
      timestamp INTEGER DEFAULT (strftime('%s','now')),
      host_info TEXT,
      containers TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_polls_node_ts ON polls(node_name, timestamp);
  )";
  char *err = nullptr;
  if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
    std::string msg = std::string("SQLite schema error: ") + err;
    sqlite3_free(err);
    throw std::runtime_error(msg);
  }
}

void Store::recordPoll(const std::string &nodeName,
                       const std::string &hostInfo,
                       const std::string &containers) {
  const char *sql = "INSERT INTO polls (node_name, host_info, containers) VALUES (?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return;
  sqlite3_bind_text(stmt, 1, nodeName.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, hostInfo.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, containers.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

void Store::prune(unsigned retentionHours) {
  const char *sql = "DELETE FROM polls WHERE timestamp < strftime('%s','now') - ?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return;
  sqlite3_bind_int(stmt, 1, retentionHours * 3600);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

}
