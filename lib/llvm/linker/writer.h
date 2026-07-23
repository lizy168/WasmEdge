// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#pragma once

#include "common/errcode.h"
#include "common/span.h"
#include "common/types.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <vector>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

class Writer {
public:
  explicit Writer(const std::filesystem::path &Path) noexcept;
  explicit Writer(std::vector<Byte> &Buffer) noexcept : Buffer(&Buffer) {}

  Expect<void> writeByte(uint8_t Data) noexcept;
  Expect<void> writeU32(uint32_t Data) noexcept;
  Expect<void> writeU64(uint64_t Data) noexcept;
  Expect<void> writeName(std::string_view Data) noexcept;
  Expect<void> write(Span<const Byte> Data) noexcept;
  Expect<void> close() noexcept;

private:
  std::ofstream Stream;
  std::vector<Byte> *Buffer = nullptr;
};

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
