// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "top_pure.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace TopPure {

namespace {

void rightAligned(std::ostringstream &os, const std::string &s, int width) {
  if ((int)s.size() >= width) {
    os << s;
  } else {
    for (int i = 0; i < width - (int)s.size(); i++) os << ' ';
    os << s;
  }
}

void leftAligned(std::ostringstream &os, const std::string &s, int width) {
  os << s;
  for (int i = (int)s.size(); i < width; i++) os << ' ';
}

std::string fmtDouble(double v, int prec) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%.*f", prec, v);
  return std::string(buf);
}

std::string rstrip(const std::string &s) {
  auto end = s.size();
  while (end > 0 && s[end - 1] == ' ') end--;
  return s.substr(0, end);
}

} // anon

std::string humanCount(uint64_t n) {
  if (n < 1000) return std::to_string(n);
  static const char *suff[] = {"K", "M", "G", "T", "P"};
  double v = (double)n / 1000.0;
  int s = 0;
  while (v >= 1000.0 && s < 4) { v /= 1000.0; s++; }
  // Pick precision so output stays compact.
  if (v >= 100.0) return std::to_string((unsigned)(v + 0.5)) + suff[s];
  if (v >= 10.0)  return fmtDouble(v, 1) + suff[s];
  return fmtDouble(v, 1) + suff[s];
}

std::string humanBytes(uint64_t bytes) {
  if (bytes < 1024) return std::to_string(bytes) + " B";
  static const char *suff[] = {"KB", "MB", "GB", "TB", "PB"};
  double v = (double)bytes / 1024.0;
  int s = 0;
  while (v >= 1024.0 && s < 4) { v /= 1024.0; s++; }
  return fmtDouble(v, 1) + " " + suff[s];
}

double cpuPercent(uint64_t prevCpuTime, uint64_t currCpuTime, double dtSeconds) {
  if (dtSeconds <= 0.0) return 0.0;
  if (currCpuTime < prevCpuTime) return 0.0; // jail restarted, etc.
  uint64_t delta = currCpuTime - prevCpuTime;
  return ((double)delta / dtSeconds) * 100.0;
}

std::string truncateForColumn(const std::string &s, int width) {
  if (width <= 0) return std::string();
  if ((int)s.size() <= width) return s;
  // ASCII-safe truncation: keep width-1 bytes and append a single
  // '~' marker. UTF-8 multibyte truncation would need byte boundary
  // tracking, which is overkill here — jail names are ASCII by
  // convention.
  if (width == 1) return std::string("~");
  return s.substr(0, (size_t)(width - 1)) + "~";
}

std::string formatHeader(const ColWidths &cw) {
  std::ostringstream os;
  leftAligned(os, "NAME", cw.name);             os << " ";
  rightAligned(os, "JID", cw.jid);              os << " ";
  leftAligned(os, "IP", cw.ip);                 os << " ";
  rightAligned(os, "CPU%", cw.cpu);             os << " ";
  rightAligned(os, "MEM", cw.mem);              os << " ";
  rightAligned(os, "DISK", cw.disk);            os << " ";
  rightAligned(os, "PROC", cw.proc);
  return rstrip(os.str());
}

std::string formatRow(const Row &row, const ColWidths &cw) {
  std::ostringstream os;
  leftAligned(os, truncateForColumn(row.name, cw.name), cw.name); os << " ";
  rightAligned(os, std::to_string(row.jid), cw.jid);              os << " ";
  leftAligned(os, truncateForColumn(row.ip, cw.ip), cw.ip);       os << " ";
  rightAligned(os, fmtDouble(row.cpuPct, 1), cw.cpu);             os << " ";
  rightAligned(os, humanBytes(row.memBytes), cw.mem);             os << " ";
  rightAligned(os, humanBytes(row.diskBytes), cw.disk);           os << " ";
  rightAligned(os, humanCount(row.pcount), cw.proc);
  return rstrip(os.str());
}

std::string formatFooter(const std::vector<Row> &rows) {
  uint64_t totMem = 0, totDisk = 0, totProc = 0;
  double totCpu = 0;
  for (auto &r : rows) {
    totMem += r.memBytes;
    totDisk += r.diskBytes;
    totProc += r.pcount;
    totCpu += r.cpuPct;
  }
  std::ostringstream os;
  os << rows.size() << " jails  "
     << "CPU " << fmtDouble(totCpu, 1) << "%  "
     << "MEM " << humanBytes(totMem) << "  "
     << "DISK " << humanBytes(totDisk) << "  "
     << "PROC " << humanCount(totProc);
  return os.str();
}

std::string formatFrame(const std::vector<Row> &rows, const ColWidths &cw) {
  std::ostringstream os;
  os << formatHeader(cw) << "\n";
  for (auto &r : rows) os << formatRow(r, cw) << "\n";
  os << formatFooter(rows);
  return os.str();
}

void applyRctlOutput(const std::string &rctlOutput, Row &row) {
  // RCTL emits lines like "memoryuse=12345" / "pcpu=42" / "writebps=1024".
  // We pick a curated subset; everything else is ignored.
  size_t i = 0;
  while (i < rctlOutput.size()) {
    auto nl = rctlOutput.find('\n', i);
    if (nl == std::string::npos) nl = rctlOutput.size();
    auto line = rctlOutput.substr(i, nl - i);
    i = nl + 1;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    auto key = line.substr(0, eq);
    auto val = line.substr(eq + 1);
    uint64_t n = 0;
    try { n = std::stoull(val); } catch (...) { continue; }
    if (key == "memoryuse")     row.memBytes = n;
    else if (key == "writebps") row.diskBytes = n;
    else if (key == "maxproc")  row.pcount = n;
  }
}

} // namespace TopPure
