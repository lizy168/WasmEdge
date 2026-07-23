// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

using namespace std::literals;

bool validField(Span<const Byte> Bytes, uint64_t Offset,
                uint8_t Width) noexcept {
  return (Width == 1 || Width == 2 || Width == 4 || Width == 8) &&
         Offset <= Bytes.size() && Width <= Bytes.size() - Offset;
}

template <typename T> Expect<T> fieldError() noexcept {
  return Unexpect(ErrCode::Value::IllegalPath);
}

} // namespace

namespace Internal {

bool hasRebaseOverlap(Span<const Rebase> Rebases, SectionId Section,
                      uint64_t Offset, uint8_t Width) noexcept {
  return std::any_of(Rebases.begin(), Rebases.end(), [&](const auto &Old) {
    if (Old.Section != Section) {
      return false;
    }
    const uint64_t OldWidth = std::max<uint8_t>(Old.Width, 1);
    if (Offset <= Old.Offset) {
      return Width > Old.Offset - Offset;
    }
    return OldWidth > Offset - Old.Offset;
  });
}

Expect<uint64_t> readUnsigned(Span<const Byte> Bytes, uint64_t Offset,
                              uint8_t Width, Endianness Endian) noexcept {
  if (!validField(Bytes, Offset, Width)) {
    return fieldError<uint64_t>();
  }
  uint64_t Value = 0;
  for (uint8_t I = 0; I < Width; ++I) {
    const uint8_t Shift = Endian == Endianness::Little
                              ? static_cast<uint8_t>(I * 8)
                              : static_cast<uint8_t>((Width - I - 1) * 8);
    Value |= static_cast<uint64_t>(Bytes[Offset + I]) << Shift;
  }
  return Value;
}

Expect<int64_t> readSigned(Span<const Byte> Bytes, uint64_t Offset,
                           uint8_t Width, Endianness Endian) noexcept {
  auto Value = readUnsigned(Bytes, Offset, Width, Endian);
  if (!Value) {
    return fieldError<int64_t>();
  }
  if (Width == 8) {
    int64_t Result = 0;
    std::memcpy(&Result, &*Value, sizeof(Result));
    return Result;
  }
  const uint8_t Bits = static_cast<uint8_t>(Width * 8);
  if ((*Value & (UINT64_C(1) << (Bits - 1))) == 0) {
    return static_cast<int64_t>(*Value);
  }
  return static_cast<int64_t>(*Value | (~UINT64_C(0) << Bits));
}

Expect<void> writeUnsigned(Span<Byte> Bytes, uint64_t Offset, uint8_t Width,
                           Endianness Endian, uint64_t Value) noexcept {
  if (!validField(Span<const Byte>(Bytes.data(), Bytes.size()), Offset,
                  Width) ||
      (Width < 8 && Value >= (UINT64_C(1) << (Width * 8)))) {
    return fieldError<void>();
  }
  for (uint8_t I = 0; I < Width; ++I) {
    const uint8_t Shift = Endian == Endianness::Little
                              ? static_cast<uint8_t>(I * 8)
                              : static_cast<uint8_t>((Width - I - 1) * 8);
    Bytes[Offset + I] = static_cast<Byte>(Value >> Shift);
  }
  return {};
}

Expect<void> writeSigned(Span<Byte> Bytes, uint64_t Offset, uint8_t Width,
                         Endianness Endian, int64_t Value) noexcept {
  if (Width != 1 && Width != 2 && Width != 4 && Width != 8) {
    return fieldError<void>();
  }
  if (Width < 8) {
    const uint8_t Bits = static_cast<uint8_t>(Width * 8);
    const int64_t Minimum = -(INT64_C(1) << (Bits - 1));
    const int64_t Maximum = (INT64_C(1) << (Bits - 1)) - 1;
    if (Value < Minimum || Value > Maximum) {
      return fieldError<void>();
    }
  }
  uint64_t Bits = 0;
  std::memcpy(&Bits, &Value, sizeof(Bits));
  if (Width < 8) {
    Bits &= (UINT64_C(1) << (Width * 8)) - 1;
  }
  return writeUnsigned(Bytes, Offset, Width, Endian, Bits);
}

} // namespace Internal

Expect<void> applyRelocations(LinkGraph &Graph) noexcept {
  if (Graph.RelocationsApplied) {
    spdlog::error("native linker: relocations already applied"sv);
    return Unexpect(ErrCode::Value::IllegalPath);
  }
  if (auto Valid = Graph.validate(); !Valid) {
    spdlog::error("native linker: invalid graph: {}"sv, Valid.error().Message);
    return Unexpect(ErrCode::Value::IllegalPath);
  }
  const bool CorrectEndian = Graph.target() == Target::S390X
                                 ? Graph.endianness() == Endianness::Big
                                 : Graph.endianness() == Endianness::Little;
  if (!CorrectEndian) {
    spdlog::error("native linker: target input has wrong endianness"sv);
    return Unexpect(ErrCode::Value::IllegalPath);
  }
  Expect<Internal::RelocationResult> Result =
      Unexpect(ErrCode::Value::AOTNotImpl);
  switch (Graph.target()) {
  case Target::X86_64:
    Result = Internal::applyX86_64(Graph);
    break;
  case Target::ARM:
    Result = Internal::applyARM(Graph);
    break;
  case Target::AArch64:
    Result = Internal::applyAArch64(Graph);
    break;
  case Target::RISCV64:
    Result = Internal::applyRISCV(Graph);
    break;
  case Target::S390X:
    Result = Internal::applyS390X(Graph);
    break;
  default:
    spdlog::error("native linker: unsupported target {}"sv,
                  static_cast<uint32_t>(Graph.target()));
    break;
  }
  if (!Result) {
    return Unexpect(Result.error());
  }
  for (size_t I = 0; I < Result->Content.size(); ++I) {
    Graph.Sections[I].Content = std::move(Result->Content[I]);
  }
  Graph.Rebases = std::move(Result->Rebases);
  Graph.RelocationsApplied = true;
  return {};
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
