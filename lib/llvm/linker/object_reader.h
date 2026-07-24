// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#pragma once

#include "common/errcode.h"
#include "common/span.h"
#include "common/types.h"
#include "linker/link_graph.h"

#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace Internal {

uint64_t normalizeSectionAlignment(uint64_t Alignment) noexcept;
std::optional<std::map<std::string, std::string>>
parseCOFFExports(std::string_view Directives);

} // namespace Internal

class ObjectReader {
public:
  static Expect<LinkGraph> read(Span<const Byte> Buffer, Target ExpectedTarget);
};

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
