// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#pragma once

#include "common/errcode.h"
#include "common/span.h"
#include "common/types.h"

#include <cstdint>
#include <filesystem>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace Internal {
Expect<void> signMachO(const std::filesystem::path &Path,
                       const std::filesystem::path &Executable) noexcept;
}

enum class OutputKind : uint8_t { UniversalWasm, ELF, MachO, PE };

class NativeLinker {
public:
  static Expect<void> link(Span<const Byte> Object, Span<const Byte> Wasm,
                           const std::filesystem::path &Output,
                           OutputKind Kind) noexcept;
};

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
