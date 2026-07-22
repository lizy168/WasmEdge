// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#pragma once

#include "common/errcode.h"
#include "common/span.h"
#include "common/types.h"
#include "linker/link_graph.h"

namespace WasmEdge {
namespace LLVM {
namespace Linker {

class ObjectReader {
public:
  static Expect<LinkGraph> read(Span<const Byte> Buffer,
                                Target ExpectedTarget) noexcept;
};

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
