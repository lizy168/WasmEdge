// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#pragma once

#include "linker/link_graph.h"
#include "linker/writer.h"

#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

class PEWriter {
public:
  static Expect<void> layout(LinkGraph &Graph) noexcept;
  static Expect<void> write(const LinkGraph &Graph, std::string_view DLLName,
                            Writer &Output) noexcept;
};

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
