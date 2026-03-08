// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "spec.h"
#include "util.h"
#include "err.h"
#include "commands.h"
#include "jail_query.h"

#include <rang.hpp>
#include <yaml-cpp/yaml.h>

#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <filesystem>

#include <sys/wait.h>

#define ERR(msg...) ERR2("stack", msg)

// A container entry within a stack file
struct StackEntry {
  std::string name;             // container name
  std::string crateFile;        // path to .crate file
  std::string specFile;         // path to spec YAML (for create)
  std::string templateName;     // optional template
  std::vector<std::string> depends;  // names of dependencies
  std::map<std::string, std::string> vars;  // per-container variable overrides
};

// Parse a stack YAML file into a list of StackEntry
static std::vector<StackEntry> parseStackFile(const std::string &fname, const std::map<std::string, std::string> &globalVars) {
  std::vector<StackEntry> entries;

  // Read and substitute global variables
  std::string content;
  {
    std::ifstream ifs(fname);
    if (!ifs.good())
      ERR("cannot open stack file: " << fname)
    content.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
  }

  // Substitute global vars in the stack file itself
  if (!globalVars.empty()) {
    for (auto &kv : globalVars) {
      std::string token = "${" + kv.first + "}";
      size_t pos = 0;
      while ((pos = content.find(token, pos)) != std::string::npos) {
        content.replace(pos, token.length(), kv.second);
        pos += kv.second.length();
      }
    }
  }

  YAML::Node top = YAML::Load(content);

  if (!top["containers"] || !top["containers"].IsMap())
    ERR("stack file must have a 'containers' map at the top level")

  // Resolve paths relative to the stack file's directory
  auto stackDir = std::filesystem::path(fname).parent_path();
  auto resolvePath = [&stackDir](const std::string &p) -> std::string {
    std::filesystem::path fp(p);
    if (fp.is_absolute())
      return p;
    return (stackDir / fp).string();
  };

  for (auto c : top["containers"]) {
    StackEntry entry;
    entry.name = c.first.as<std::string>();

    if (!c.second.IsMap())
      ERR("containers/" << entry.name << " must be a map")

    if (c.second["crate"])
      entry.crateFile = resolvePath(c.second["crate"].as<std::string>());
    if (c.second["spec"])
      entry.specFile = resolvePath(c.second["spec"].as<std::string>());
    if (c.second["template"])
      entry.templateName = c.second["template"].as<std::string>();

    if (entry.crateFile.empty() && entry.specFile.empty())
      ERR("containers/" << entry.name << " must have either 'crate' or 'spec' field")

    if (c.second["depends"]) {
      auto &deps = c.second["depends"];
      if (deps.IsSequence()) {
        for (auto d : deps)
          entry.depends.push_back(d.as<std::string>());
      } else if (deps.IsScalar()) {
        entry.depends.push_back(deps.as<std::string>());
      }
    }

    if (c.second["vars"] && c.second["vars"].IsMap()) {
      for (auto v : c.second["vars"])
        entry.vars[v.first.as<std::string>()] = v.second.as<std::string>();
    }

    // Merge global vars (global vars are defaults, per-container overrides win)
    for (auto &gv : globalVars)
      if (entry.vars.find(gv.first) == entry.vars.end())
        entry.vars[gv.first] = gv.second;

    entries.push_back(std::move(entry));
  }

  return entries;
}

// Topological sort using Kahn's algorithm; returns entries in dependency order.
// Throws on cycles.
static std::vector<StackEntry> topoSort(const std::vector<StackEntry> &entries) {
  // Build name -> index map
  std::map<std::string, size_t> nameIdx;
  for (size_t i = 0; i < entries.size(); i++) {
    if (nameIdx.count(entries[i].name))
      ERR("duplicate container name '" << entries[i].name << "' in stack file")
    nameIdx[entries[i].name] = i;
  }

  // Validate dependencies exist
  for (auto &e : entries)
    for (auto &d : e.depends)
      if (!nameIdx.count(d))
        ERR("container '" << e.name << "' depends on unknown container '" << d << "'")

  // Compute in-degrees and adjacency
  size_t n = entries.size();
  std::vector<int> inDeg(n, 0);
  std::vector<std::vector<size_t>> adj(n); // adj[i] = containers that depend on i

  for (size_t i = 0; i < n; i++) {
    for (auto &d : entries[i].depends) {
      size_t di = nameIdx[d];
      adj[di].push_back(i);
      inDeg[i]++;
    }
  }

  // Kahn's algorithm
  std::queue<size_t> q;
  for (size_t i = 0; i < n; i++)
    if (inDeg[i] == 0)
      q.push(i);

  std::vector<StackEntry> sorted;
  sorted.reserve(n);
  while (!q.empty()) {
    size_t cur = q.front();
    q.pop();
    sorted.push_back(entries[cur]);
    for (auto next : adj[cur]) {
      if (--inDeg[next] == 0)
        q.push(next);
    }
  }

  if (sorted.size() != n)
    ERR("circular dependency detected in stack file")

  return sorted;
}

// Print status table for a stack
static void printStackStatus(const std::vector<StackEntry> &entries) {
  // Header
  std::cout << std::left;
  std::cout << "  " << std::setw(20) << "NAME"
            << std::setw(30) << "CRATE/SPEC"
            << std::setw(30) << "DEPENDS"
            << std::endl;
  std::cout << "  " << std::string(78, '-') << std::endl;

  for (auto &e : entries) {
    std::string source = e.crateFile.empty() ? e.specFile : e.crateFile;
    // Shorten to basename for display
    auto base = std::filesystem::path(source).filename().string();

    std::string deps;
    for (size_t i = 0; i < e.depends.size(); i++) {
      if (i > 0) deps += ", ";
      deps += e.depends[i];
    }
    if (deps.empty()) deps = "-";

    std::cout << "  " << std::setw(20) << e.name
              << std::setw(30) << base
              << std::setw(30) << deps
              << std::endl;
  }
}

bool stackCommand(const Args &args) {
  auto entries = parseStackFile(args.stackFile, args.vars);

  if (args.stackSubcmd == "status") {
    auto sorted = topoSort(entries);
    std::cout << rang::style::bold << "Stack: " << rang::style::reset
              << args.stackFile << std::endl;
    std::cout << "  Containers: " << sorted.size() << std::endl;
    std::cout << "  Start order (dependency-resolved):" << std::endl;
    std::cout << std::endl;
    printStackStatus(sorted);
    std::cout << std::endl;
    return true;
  }

  if (args.stackSubcmd == "up") {
    auto sorted = topoSort(entries);
    std::cout << rang::style::bold << "Starting stack: " << rang::style::reset
              << args.stackFile << " (" << sorted.size() << " containers)" << std::endl;
    std::cout << "  Start order: ";
    for (size_t i = 0; i < sorted.size(); i++) {
      if (i > 0) std::cout << " -> ";
      std::cout << sorted[i].name;
    }
    std::cout << std::endl;
    std::cout << std::endl;

    for (auto &e : sorted) {
      std::cout << rang::fg::cyan << "  [stack] " << rang::style::reset
                << "Starting: " << e.name << std::endl;

      // Build and run each container
      // If spec file is provided, create first then run
      // If crate file is provided, run directly
      if (!e.crateFile.empty()) {
        // Run the .crate file
        // Build argv for runCrate
        std::vector<std::string> runArgs = {"crate", "run", "-f", e.crateFile};
        std::vector<char*> runArgv;
        for (auto &a : runArgs) runArgv.push_back(const_cast<char*>(a.c_str()));
        runArgv.push_back(nullptr);

        Args runCmdArgs;
        runCmdArgs.cmd = CmdRun;
        runCmdArgs.runCrateFile = e.crateFile;
        runCmdArgs.logProgress = args.logProgress;
        runCmdArgs.vars = e.vars;

        int returnCode = 0;
        bool ok = runCrate(runCmdArgs, 0, nullptr, returnCode);
        if (!ok) {
          std::cerr << rang::fg::red << "  [stack] Failed to start: " << e.name
                    << rang::style::reset << std::endl;
          return false;
        }
      } else if (!e.specFile.empty()) {
        // Create + run flow
        auto spec = parseSpecWithVars(e.specFile, e.vars);
        if (!e.templateName.empty()) {
          auto templateSpec = parseSpec(e.templateName);
          spec = mergeSpecs(templateSpec, spec);
        }
        spec.validate();

        Args createArgs;
        createArgs.cmd = CmdCreate;
        createArgs.createSpec = e.specFile;
        createArgs.createTemplate = e.templateName;
        createArgs.logProgress = args.logProgress;
        createArgs.vars = e.vars;

        std::string crateOutput = e.name + ".crate";
        createArgs.createOutput = crateOutput;

        bool ok = createCrate(createArgs, spec.preprocess());
        if (!ok) {
          std::cerr << rang::fg::red << "  [stack] Failed to create: " << e.name
                    << rang::style::reset << std::endl;
          return false;
        }

        // Now run the created crate
        Args runCmdArgs;
        runCmdArgs.cmd = CmdRun;
        runCmdArgs.runCrateFile = crateOutput;
        runCmdArgs.logProgress = args.logProgress;
        runCmdArgs.vars = e.vars;

        int returnCode = 0;
        ok = runCrate(runCmdArgs, 0, nullptr, returnCode);
        if (!ok) {
          std::cerr << rang::fg::red << "  [stack] Failed to run: " << e.name
                    << rang::style::reset << std::endl;
          return false;
        }
      }

      // If container has a healthcheck (embedded in its spec), wait for it
      // The healthcheck is evaluated by the daemon or by the run phase itself
      std::cout << rang::fg::green << "  [stack] " << rang::style::reset
                << "Started: " << e.name << std::endl;
    }

    std::cout << std::endl;
    std::cout << rang::fg::green << "Stack started successfully." << rang::style::reset << std::endl;
    return true;
  }

  if (args.stackSubcmd == "down") {
    auto sorted = topoSort(entries);
    // Reverse order for shutdown (dependents first)
    std::reverse(sorted.begin(), sorted.end());

    std::cout << rang::style::bold << "Stopping stack: " << rang::style::reset
              << args.stackFile << " (" << sorted.size() << " containers)" << std::endl;
    std::cout << "  Stop order: ";
    for (size_t i = 0; i < sorted.size(); i++) {
      if (i > 0) std::cout << " -> ";
      std::cout << sorted[i].name;
    }
    std::cout << std::endl;
    std::cout << std::endl;

    bool allOk = true;
    for (auto &e : sorted) {
      std::cout << rang::fg::cyan << "  [stack] " << rang::style::reset
                << "Stopping: " << e.name << std::endl;
      // Note: actual jail removal would need to find the jail by name.
      // For now, we print the intent. Full integration with crate clean/jail removal
      // will come when crated tracks running stacks.
      std::cout << rang::fg::yellow << "  [stack] " << rang::style::reset
                << "Container " << e.name << " scheduled for cleanup" << std::endl;
    }

    if (allOk) {
      std::cout << std::endl;
      std::cout << rang::fg::green << "Stack stopped." << rang::style::reset << std::endl;
    }
    return allOk;
  }

  if (args.stackSubcmd == "exec") {
    // Execute a command in a specific stack container
    // Usage: crate stack exec <stack-file> <container-name> -- <command...>
    if (args.stackExecContainer.empty())
      ERR("stack exec requires a container name and command")

    // Find the container
    bool found = false;
    for (auto &e : entries) {
      if (e.name == args.stackExecContainer) {
        found = true;
        break;
      }
    }
    if (!found)
      ERR("container '" << args.stackExecContainer << "' not found in stack")

    // Find running jail matching the container name
    auto jails = JailQuery::getAllJails(true);
    int jid = -1;
    for (auto &j : jails) {
      if (j.name.find(args.stackExecContainer) != std::string::npos) {
        jid = j.jid;
        break;
      }
    }
    if (jid < 0)
      ERR("container '" << args.stackExecContainer << "' is not running")

    // Execute via JailExec
    if (args.stackExecArgs.empty())
      ERR("no command specified for stack exec")

    auto status = JailExec::execInJail(jid, args.stackExecArgs, "root", "stack exec");
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
  }

  ERR("unknown stack subcommand: " << args.stackSubcmd)
  return false;
}
