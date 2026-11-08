// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "profile.h"
#include "profile_pure.h"
#include "mounts_pure.h"   // 1.1.63: ":ro" suffix on .local shares
#include "args.h"
#include "spec.h"
#include "misc.h"
#include "util.h"
#include "err.h"
#include "commands.h"
#include "version.h"   // 1.1.71: CRATE_VERSION in the cache key

#include <rang.hpp>

#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#define ERR(msg...) ERR2("profile", msg)

namespace Profile {

// 1.1.71: nanoseconds (st_mtim) — the cache compares the .crate with the
// merged spec it was built from, often written the same second.
static long long mtimeNsOf(const std::string &path) {
  struct stat st;
  if (::stat(path.c_str(), &st) != 0) return -1;
  return (long long)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
}

static std::string readSmallFile(const std::string &path) {
  std::ifstream f(path);
  std::string s;
  if (f) std::getline(f, s);
  return s;
}

static void writeAtomically(const std::string &outPath, const std::string &text) {
  const auto tmp = outPath + ".tmp";
  {
    std::ofstream f(tmp, std::ios::trunc);
    if (!f) ERR("cannot write " << tmp << ": " << strerror(errno))
    f << text;
    if (!f) ERR("cannot write " << tmp)
  }
  if (::rename(tmp.c_str(), outPath.c_str()) != 0) {
    int e = errno;
    ::unlink(tmp.c_str());
    ERR("cannot rename " << tmp << " to " << outPath << ": " << strerror(e))
  }
}

static std::string emit(const YAML::Node &n) {
  YAML::Emitter em;
  em << n;
  return em.c_str() ? em.c_str() : "";
}

static YAML::Node loadFile(const std::string &path) {
  try {
    return YAML::LoadFile(path);
  } catch (const YAML::Exception &e) {
    ERR("cannot parse " << path << ": " << e.what())
  }
}

static YAML::Node mergeNode(const YAML::Node &base, const YAML::Node &overlay, bool topLevel);

// The spec's top-level `options` comes in two shapes the parser treats
// alike: a list of names (`- net`) or a map name -> details-or-nothing
// (`tor: {control-port: false}`, `net:`). A shape-blind merge would let
// a list replace a map and drop the template's `tor`. So options are
// merged BY NAME: details on both sides are merged like maps, a bare
// name on top of details keeps the details, unknown names are appended.
// The result is emitted as a list when no option carries details (the
// simple form survives) and as a map otherwise.
typedef std::vector<std::pair<std::string, YAML::Node>> OptionList;

static void collectOptions(const YAML::Node &n, OptionList &out, const char *what) {
  if (!n.IsDefined() || n.IsNull()) return;
  if (n.IsScalar()) {                       // `options: net`
    out.emplace_back(n.as<std::string>(), YAML::Node(YAML::NodeType::Null));
  } else if (n.IsSequence()) {
    for (const auto &item : n) {
      if (item.IsScalar())
        out.emplace_back(item.as<std::string>(), YAML::Node(YAML::NodeType::Null));
      else if (item.IsMap() && item.size() == 1)
        out.emplace_back(item.begin()->first.as<std::string>(), YAML::Clone(item.begin()->second));
      else
        ERR(what << ": options list entries must be option names")
    }
  } else if (n.IsMap()) {
    for (YAML::const_iterator it = n.begin(); it != n.end(); ++it) {
      if (!it->first.IsScalar()) ERR(what << ": option names must be scalars")
      out.emplace_back(it->first.as<std::string>(), YAML::Clone(it->second));
    }
  } else {
    ERR(what << ": options must be a list, a map or a name")
  }
}

static YAML::Node mergeOptions(const YAML::Node &base, const YAML::Node &overlay) {
  OptionList items, over;
  collectOptions(base, items, "base spec");
  collectOptions(overlay, over, "override");
  for (auto &o : over) {
    bool found = false;
    for (auto &b : items) {
      if (b.first != o.first) continue;
      if (b.second.IsMap() && o.second.IsMap())
        b.second = mergeNode(b.second, o.second, false);
      else if (!o.second.IsNull())
        b.second = o.second;
      found = true;
      break;
    }
    if (!found) items.push_back(o);
  }
  bool anyDetails = false;
  for (auto &i : items)
    if (!i.second.IsNull()) anyDetails = true;
  YAML::Node result(anyDetails ? YAML::NodeType::Map : YAML::NodeType::Sequence);
  for (auto &i : items) {
    if (anyDetails) result[i.first] = i.second;
    else            result.push_back(i.first);
  }
  return result;
}

static YAML::Node mergeNode(const YAML::Node &base, const YAML::Node &overlay, bool topLevel) {
  if (!overlay.IsDefined() || overlay.IsNull()) return YAML::Clone(base);
  if (!base.IsDefined() || base.IsNull()) return YAML::Clone(overlay);

  if (base.IsMap() && overlay.IsMap()) {
    YAML::Node result = YAML::Clone(base);
    for (YAML::const_iterator it = overlay.begin(); it != overlay.end(); ++it) {
      if (!it->first.IsScalar())
        ERR("overlay map keys must be scalars")
      auto key = it->first.as<std::string>();
      if (!result[key].IsDefined()) {
        result[key] = YAML::Clone(it->second);
      } else if (topLevel && key == "options") {
        YAML::Node merged = mergeOptions(result[key], it->second);
        result[key] = merged;
      } else {
        YAML::Node merged = mergeNode(result[key], it->second, false);
        result[key] = merged;
      }
    }
    return result;
  }

  if (base.IsSequence() && overlay.IsSequence()) {
    YAML::Node result = YAML::Clone(base);
    for (const auto &item : overlay) {
      const auto text = emit(item);
      bool present = false;
      for (const auto &existing : result)
        if (emit(existing) == text) { present = true; break; }
      if (!present) result.push_back(YAML::Clone(item));
    }
    return result;
  }

  return YAML::Clone(overlay);
}

YAML::Node mergeYaml(const YAML::Node &base, const YAML::Node &overlay) {
  return mergeNode(base, overlay, true);
}
// ---- end of merge ---- (the scratch harness in the 1.1.59 dev notes extracts up to here)

void checkLocalOverlay(const YAML::Node &overlay, const std::string &home, const std::string &path) {
  if (!overlay.IsDefined() || overlay.IsNull()) return;
  if (!overlay.IsMap())
    ERR(path << ": a .local override must be a YAML map of spec keys")

  // 1.1.71: every key of the top level and of the maps one level down,
  // in either spelling, and none of them twice (see ProfilePure).
  auto keysOf = [&](const YAML::Node &m, const std::string &where) {
    std::vector<std::string> keys;
    for (YAML::const_iterator it = m.begin(); it != m.end(); ++it) {
      if (!it->first.IsScalar())
        ERR(path << ": " << (where.empty() ? "top-level" : where) << " keys must be scalars")
      keys.push_back(it->first.as<std::string>());
    }
    if (auto e = ProfilePure::checkLocalDuplicateKeys(keys, where); !e.empty())
      ERR(path << ": " << e)
    return keys;
  };
  keysOf(overlay, "");

  for (YAML::const_iterator it = overlay.begin(); it != overlay.end(); ++it) {
    const auto key = ProfilePure::normaliseKey(it->first.as<std::string>());
    if (auto e = ProfilePure::checkLocalKeyPath({key}); !e.empty())
      ERR(path << ": " << e)
    if (it->second.IsMap() && key != "options")   // option names are not spec keys
      for (auto &sub : keysOf(it->second, key))
        if (auto e = ProfilePure::checkLocalKeyPath({key, sub}); !e.empty())
          ERR(path << ": " << e)

    if ((key == "dirs" || key == "files") && it->second.IsMap()) {
      auto share = it->second["share"];
      if (!share.IsDefined() || !share.IsSequence()) continue;   // the spec parser reports shape errors
      for (const auto &entry : share) {
        std::string host;
        if (entry.IsScalar())
          host = entry.as<std::string>();
        else if (entry.IsSequence() && (entry.size() == 2 || entry.size() == 3) && entry[1].IsScalar())
          host = entry[1].as<std::string>();   // [jail path, host path(, ro|rw)] — see lib/run.cpp
        else
          continue;
        MountsPure::splitRoSuffix(host);   // 1.1.63: "path:ro" is still the path
        if (auto e = ProfilePure::checkLocalShareHostPath(host, home); !e.empty())
          ERR(path << ": " << key << "/share: " << e)
      }
    }
  }
}

static std::string mergedText(const std::string &basePath, const std::string &overlayPath) {
  YAML::Node merged = loadFile(basePath);
  if (!overlayPath.empty())
    merged = mergeYaml(merged, loadFile(overlayPath));

  std::ostringstream out;
  out << "# generated by crate from " << basePath;
  if (!overlayPath.empty()) out << " + " << overlayPath;
  out << "\n# do not edit: change the source file(s) and run again\n";
  out << emit(merged) << "\n";
  return out.str();
}

void writeMerged(const std::string &basePath, const std::string &overlayPath,
                 const std::string &outPath) {
  writeAtomically(outPath, mergedText(basePath, overlayPath));
}

std::string resolveForRun(const Args &args) {
  const auto &name = args.runProfile;
  if (auto e = ProfilePure::validateProfileName(name); !e.empty())
    ERR(e)

  const auto home = Util::Fs::getUserHomeDir();
  if (home.empty() || home[0] != '/')
    ERR("cannot determine the invoking user's home directory (getpwuid)")

  // the profile: first hit wins
  std::string specPath;
  const auto candidates = ProfilePure::specSearchPaths(home, name);
  for (auto &c : candidates)
    if (Util::Fs::fileExists(c)) { specPath = c; break; }
  if (specPath.empty()) {
    std::ostringstream searched;
    for (size_t i = 0; i < candidates.size(); i++)
      searched << (i ? ", " : "") << candidates[i];
    ERR("profile '" << name << "' not found; searched " << searched.str()
        << " — copy a spec to the first path, or run a .crate file with -f")
  }

  const auto localPath = ProfilePure::localOverridePath(home, name);
  const bool haveLocal = Util::Fs::fileExists(localPath);

  // the build directory: ours, private
  const auto dir = ProfilePure::buildDir(home);
  try {
    std::filesystem::create_directories(dir);
  } catch (const std::exception &e) {
    ERR("cannot create " << dir << ": " << e.what())
  }
  ::chmod(dir.c_str(), 0700);

  const auto crate  = ProfilePure::cratePath(home, name);
  const auto merged = ProfilePure::mergedSpecPath(home, name);
  const auto keyPath = ProfilePure::cacheKeyPath(home, name);

  // the .local is the operator's; the profile directories are either the
  // operator's own or root-owned — only the overlay is policed.
  // 1.1.71: on every run, since the merge is redone every run.
  if (haveLocal)
    checkLocalOverlay(loadFile(localPath), home, localPath);

  // 1.1.71: the cache is keyed by content (see ProfilePure::cacheAction)
  const auto text = mergedText(specPath, haveLocal ? localPath : "");
  const auto key = Util::sha256hex(ProfilePure::cacheKeyInput(text, args.vars, CRATE_VERSION));
  switch (ProfilePure::cacheAction(mtimeNsOf(crate), mtimeNsOf(merged), readSmallFile(keyPath), key)) {
  case ProfilePure::CacheAction::UpToDate:
    if (args.logProgress)
      std::cerr << rang::fg::gray << Util::tmSecMs() << ": profile '" << name << "': " << crate
                << " is up to date" << rang::style::reset << std::endl;
    return crate;
  case ProfilePure::CacheAction::RewriteAndBuild:
    writeAtomically(merged, text);
    writeAtomically(keyPath, key + "\n");
    break;
  case ProfilePure::CacheAction::Build:
    break;
  }

  // `crate create` is not rootless yet (TODO): the create chroot lives in
  // /var/run/crate and needs root. Say so instead of failing on a mkdir,
  // and leave the merged spec behind so root can build exactly that.
  if (::geteuid() != 0) {
    std::ostringstream vars;   // 1.1.71: the build uses them (package names)
    for (auto &kv : args.vars)
      vars << " --var " << Util::shellQuote(kv.first + "=" + kv.second);
    ERR("profile '" << name << "': " << crate << " is not built for the current spec yet and building "
        "needs root (`crate create` is not rootless); the merged spec is at " << merged << " — as root: "
        "crate create -s " << merged << vars.str() << " -o " << crate << " && chown " << ::getuid()
        << " " << crate << ", then run again")
  }

  std::cerr << rang::fg::blue << "profile '" << name << "': building " << crate << " from " << specPath
            << (haveLocal ? " + " + localPath : std::string()) << rang::style::reset << std::endl;

  // build into <name>.crate.new and rename on success, so a build that
  // dies half-way never leaves a fresh-looking archive behind
  const auto partial = crate + ".new";
  Args createArgs;
  createArgs.cmd = CmdCreate;
  createArgs.createSpec = merged;      // the merged spec is what lands in +CRATE.SPEC
  createArgs.createOutput = partial;
  createArgs.logProgress = args.logProgress;
  createArgs.vars = args.vars;

  auto spec = parseSpecWithVars(merged, args.vars);
  spec.validate();
  createCacheDirectoryIfNeeded();
  bool ok = false;
  try {
    ok = createCrate(createArgs, spec.preprocess());
  } catch (...) {
    ::unlink(partial.c_str());
    throw;
  }
  if (!ok) {
    ::unlink(partial.c_str());
    ERR("profile '" << name << "': building the crate failed")
  }
  if (::rename(partial.c_str(), crate.c_str()) != 0) {
    int e = errno;
    ::unlink(partial.c_str());
    ERR("cannot rename " << partial << " to " << crate << ": " << strerror(e))
  }
  std::cerr << rang::fg::blue << "profile '" << name << "': " << crate << " is ready"
            << rang::style::reset << std::endl;
  return crate;
}

} // namespace Profile
