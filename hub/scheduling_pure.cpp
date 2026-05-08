// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "scheduling_pure.h"

#include <algorithm>
#include <cstdio>
#include <regex>
#include <sstream>

namespace SchedulingPure {

namespace {

// Build a JSON-quoted string. Escapes ", \, and control chars
// minimally; no need for full-spec JSON since names/hosts come
// from operator config and are validated upstream (jail name
// alphabet, hostname:port shape).
std::string jsonQuote(const std::string &s) {
  std::ostringstream os;
  os << '"';
  for (char c : s) {
    if (c == '"' || c == '\\') os << '\\' << c;
    else if (c < 0x20)         os << "\\u" << std::hex << (int)(unsigned char)c;
    else                       os << c;
  }
  os << '"';
  return os.str();
}

} // anon

Recommendation pickLeastLoaded(
  const std::vector<NodeView> &nodes,
  const std::string &currentNodeHint) {
  Recommendation rec;

  // Collect reachable nodes (sorted by count ascending, then name
  // for stable output across calls).
  std::vector<NodeView> reachable;
  reachable.reserve(nodes.size());
  for (const auto &n : nodes)
    if (n.reachable) reachable.push_back(n);

  if (reachable.empty()) {
    rec.rationale = "no reachable nodes";
    return rec;
  }

  std::sort(reachable.begin(), reachable.end(),
            [](const NodeView &a, const NodeView &b) {
              if (a.containerCount != b.containerCount)
                return a.containerCount < b.containerCount;
              return a.name < b.name;
            });

  const auto &best = reachable.front();
  // runnerUp falls back to best when there's only one reachable
  // node — confidence then becomes 100 (sole candidate).
  unsigned runnerUpCount =
    (reachable.size() >= 2) ? reachable[1].containerCount
                            : best.containerCount;

  // Anti-flap: if the operator passed `currentNodeHint` AND that
  // node is reachable AND its count is within tolerance of the
  // best, keep them on the current node. Avoids ping-pong
  // migrations under transient load swings.
  if (!currentNodeHint.empty()) {
    auto cur = std::find_if(reachable.begin(), reachable.end(),
                            [&](const NodeView &n) { return n.name == currentNodeHint; });
    if (cur != reachable.end()) {
      // tolerance = best * (1 + 10%); use integer arithmetic so
      // small counts round predictably (best=3 → tolerance=3,
      // best=10 → tolerance=11).
      unsigned tolerance =
        best.containerCount + (best.containerCount * kAntiFlapPercent / 100);
      if (cur->containerCount <= tolerance) {
        rec.targetName     = cur->name;
        rec.targetHost     = cur->host;
        rec.targetCount    = cur->containerCount;
        rec.runnerUpCount  = best.containerCount;
        rec.confidence     = 100;   // hard pick — anti-flap dominates
        std::ostringstream os;
        os << "keep on '" << cur->name << "' (count " << cur->containerCount
           << " within " << kAntiFlapPercent << "% of least-loaded '"
           << best.name << "' count " << best.containerCount << ")";
        rec.rationale = os.str();
        return rec;
      }
    }
  }

  rec.targetName    = best.name;
  rec.targetHost    = best.host;
  rec.targetCount   = best.containerCount;
  rec.runnerUpCount = runnerUpCount;

  // Confidence: 100% when there's exactly one reachable node
  // (no alternative to compare against). Otherwise scale by the
  // spread between best and runner-up.
  if (reachable.size() == 1) {
    rec.confidence = 100;
  } else if (runnerUpCount == 0) {
    // All reachable at zero load — pure tie.
    rec.confidence = 50;
  } else if (runnerUpCount <= best.containerCount) {
    rec.confidence = 0;   // tied at non-zero
  } else {
    // spread=runnerUp-best; normalised against runnerUp so
    // 1-vs-100 scores high (~99%) and 10-vs-11 scores low (~9%).
    long spread = (long)runnerUpCount - (long)best.containerCount;
    long pct = spread * 100 / (long)runnerUpCount;
    if (pct > 100) pct = 100;
    rec.confidence = (int)pct;
  }

  std::ostringstream os;
  os << "place on '" << best.name << "' (count " << best.containerCount;
  if (reachable.size() >= 2)
    os << " vs runner-up '" << reachable[1].name << "' count " << runnerUpCount;
  else
    os << ", sole reachable node";
  os << ")";
  rec.rationale = os.str();
  return rec;
}

std::string renderRecommendationJson(const Recommendation &rec) {
  std::ostringstream os;
  os << "{";
  if (rec.targetName.empty()) {
    os << "\"target\":null,"
       << "\"rationale\":" << jsonQuote(rec.rationale);
  } else {
    os << "\"target\":" << jsonQuote(rec.targetName) << ","
       << "\"host\":" << jsonQuote(rec.targetHost) << ","
       << "\"container_count\":" << rec.targetCount << ","
       << "\"runner_up_count\":" << rec.runnerUpCount << ","
       << "\"confidence\":" << rec.confidence << ","
       << "\"rationale\":" << jsonQuote(rec.rationale);
  }
  os << "}";
  return os.str();
}

namespace {

// Percent-encode anything outside [A-Za-z0-9._~-]. We use this on
// the currentNodeHint going into a query string. Conservative
// ruleset — operator-supplied jail names go through stricter
// validators upstream, but defence-in-depth never hurt.
std::string urlEncode(const std::string &s) {
  std::ostringstream os;
  for (unsigned char c : s) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9')
        || c == '.' || c == '_' || c == '~' || c == '-') {
      os << static_cast<char>(c);
    } else {
      char buf[4];
      std::snprintf(buf, sizeof(buf), "%%%02X", c);
      os << buf;
    }
  }
  return os.str();
}

} // anon

std::string buildLeastLoadedUrl(const std::string &hubUrl,
                                const std::string &currentNodeHint) {
  std::string base = hubUrl;
  // Strip a single trailing '/' so we don't double up.
  if (!base.empty() && base.back() == '/') base.pop_back();
  std::string out = base + "/api/v1/scheduling/least-loaded";
  if (!currentNodeHint.empty())
    out += "?current=" + urlEncode(currentNodeHint);
  return out;
}

std::string extractTargetField(const std::string &jsonBody) {
  // Match either "target":"<value>" or "target":null. Allow
  // optional whitespace after the colon (jq-printed bodies have
  // it; renderRecommendationJson doesn't).
  std::regex reStr(R"#("target"\s*:\s*"([^"]*)")#");
  std::smatch m;
  if (std::regex_search(jsonBody, m, reStr)) return m[1].str();
  return "";  // missing or null
}

std::string extractHostField(const std::string &jsonBody) {
  std::regex reStr(R"#("host"\s*:\s*"([^"]*)")#");
  std::smatch m;
  if (std::regex_search(jsonBody, m, reStr)) return m[1].str();
  return "";
}

std::vector<std::string> buildMigrateArgv(const std::string &cratePath,
                                          const std::string &jail,
                                          const std::string &fromHost,
                                          const std::string &toHost,
                                          const std::string &fromTokenFile,
                                          const std::string &toTokenFile) {
  return {cratePath, "migrate", jail,
          "--from", fromHost,
          "--to", toHost,
          "--from-token-file", fromTokenFile,
          "--to-token-file", toTokenFile};
}

} // namespace SchedulingPure
