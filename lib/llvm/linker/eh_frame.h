// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#pragma once

#include "common/errcode.h"
#include "linker/link_graph.h"

#include <cstdint>
#include <vector>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

Expect<void> normalizeMachOEHFrame(LinkGraph &Graph);
Expect<void> validateMachOEHFrameCoverage(const LinkGraph &Graph);
Expect<std::vector<uint64_t>> machOEHFrameStarts(const LinkGraph &Graph,
                                                 uint64_t LoadBase);

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
