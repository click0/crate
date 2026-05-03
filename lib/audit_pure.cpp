// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "audit_pure.h"
#include "args.h"
#include "util.h"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

namespace AuditPure {

// JSON-escape a string. Handles ", \, control chars (\b \f \n \r \t)
// and falls back to \u00XX for the rest of [0..0x1f]. UTF-8 above
// 0x7f is passed through unchanged.
static std::string escape(const std::string &s) {
  std::ostringstream o;
  for (unsigned char c : s) {
    switch (c) {
    case '"':  o << "\\\""; break;
    case '\\': o << "\\\\"; break;
    case '\b': o << "\\b"; break;
    case '\f': o << "\\f"; break;
    case '\n': o << "\\n"; break;
    case '\r': o << "\\r"; break;
    case '\t': o << "\\t"; break;
    default:
      if (c < 0x20)
        o << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << (int)c
          << std::dec << std::setw(0);
      else
        o << static_cast<char>(c);
    }
  }
  return o.str();
}

std::string renderJson(const Event &ev) {
  std::ostringstream o;
  o << "{"
    << "\"ts\":\""      << escape(ev.ts)      << "\","
    << "\"pid\":"       << ev.pid             << ","
    << "\"uid\":"       << ev.uid             << ","
    << "\"euid\":"      << ev.euid            << ","
    << "\"gid\":"       << ev.gid             << ","
    << "\"egid\":"      << ev.egid            << ","
    << "\"user\":\""    << escape(ev.user)    << "\","
    << "\"host\":\""    << escape(ev.host)    << "\","
    << "\"cmd\":\""     << escape(ev.cmd)     << "\","
    << "\"target\":\""  << escape(ev.target)  << "\","
    << "\"argv\":\""    << escape(ev.argv)    << "\","
    << "\"outcome\":\"" << escape(ev.outcome) << "\""
    << "}";
  return o.str();
}

std::string pickTarget(const Args &args) {
  switch (args.cmd) {
  case CmdCreate:   return !args.createSpec.empty() ? args.createSpec : args.createTemplate;
  case CmdRun:      return args.runCrateFile;
  case CmdValidate: return args.validateSpec;
  case CmdSnapshot: return args.snapshotDataset + (args.snapshotName.empty() ? "" : "@" + args.snapshotName);
  case CmdInfo:     return args.infoTarget;
  case CmdConsole:  return args.consoleTarget;
  case CmdExport:   return args.exportTarget;
  case CmdImport:   return args.importFile;
  case CmdGui:      return args.guiSubcmd + (args.guiTarget.empty() ? "" : ":" + args.guiTarget);
  case CmdStack:    return args.stackSubcmd + (args.stackFile.empty() ? "" : ":" + args.stackFile);
  case CmdStats:    return args.statsTarget;
  case CmdLogs:     return args.logsTarget;
  case CmdStop:     return args.stopTarget;
  case CmdRestart:  return args.restartTarget;
  case CmdInspect:  return args.inspectTarget;
  case CmdList:
  case CmdClean:
  case CmdTop:
  case CmdInterDns:
  case CmdVpn:
  case CmdNone:
  default:          return "";
  }
}

std::string formatTimestampUtc(long timeT) {
  time_t t = static_cast<time_t>(timeT);
  std::tm tm{};
  ::gmtime_r(&t, &tm);
  char buf[24];
  ::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

std::string joinArgv(int argc, char **argv) {
  std::ostringstream o;
  for (int i = 0; i < argc; i++) {
    if (i > 0) o << " ";
    o << Util::shellQuote(argv[i] ? argv[i] : "");
  }
  return o.str();
}

}
