// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "scheduling_pure.h"

#include <algorithm>
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

} // namespace SchedulingPure
