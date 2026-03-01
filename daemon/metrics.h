// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Prometheus metrics exporter for crated.
// Collects container stats and exposes in Prometheus exposition format.

#pragma once

#include <string>

namespace Crated {

// Collect all metrics and return as Prometheus text format.
std::string collectPrometheusMetrics();

}
