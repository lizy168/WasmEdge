// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#pragma once

#include "linker/link_graph.h"

#include <cstdint>
#include <vector>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

Expect<void> applyRelocations(LinkGraph &Graph);

namespace Internal {

Expect<uint64_t> readUnsigned(Span<const Byte> Bytes, uint64_t Offset,
                              uint8_t Width, Endianness Endian) noexcept;
Expect<int64_t> readSigned(Span<const Byte> Bytes, uint64_t Offset,
                           uint8_t Width, Endianness Endian) noexcept;
Expect<void> writeUnsigned(Span<Byte> Bytes, uint64_t Offset, uint8_t Width,
                           Endianness Endian, uint64_t Value) noexcept;
Expect<void> writeSigned(Span<Byte> Bytes, uint64_t Offset, uint8_t Width,
                         Endianness Endian, int64_t Value) noexcept;
bool hasRebaseOverlap(Span<const Rebase> Rebases, SectionId Section,
                      uint64_t Offset, uint8_t Width) noexcept;

struct RelocationResult {
  std::vector<std::vector<Byte>> Content;
  std::vector<Rebase> Rebases;
};

Expect<RelocationResult> applyX86_64(const LinkGraph &Graph);
Expect<RelocationResult> applyARM(const LinkGraph &Graph);
Expect<RelocationResult> applyAArch64(const LinkGraph &Graph);
Expect<RelocationResult> applyRISCV(const LinkGraph &Graph);
Expect<RelocationResult> applyS390X(const LinkGraph &Graph);

} // namespace Internal
} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
