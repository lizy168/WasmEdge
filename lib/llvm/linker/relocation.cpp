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

constexpr uint8_t BitsPerByte = 8;
constexpr uint8_t ByteField = 1;
constexpr uint8_t HalfField = 2;
constexpr uint8_t WordField = 4;
constexpr uint8_t DoubleWordField = 8;

bool validField(Span<const Byte> Bytes, uint64_t Offset,
                uint8_t Width) noexcept {
  return (Width == ByteField || Width == HalfField || Width == WordField ||
          Width == DoubleWordField) &&
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
    const uint64_t OldWidth = std::max<uint8_t>(Old.Width, MinimumRebaseWidth);
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
    const uint8_t Shift =
        Endian == Endianness::Little
            ? static_cast<uint8_t>(I * BitsPerByte)
            : static_cast<uint8_t>((Width - I - 1) * BitsPerByte);
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
  if (Width == DoubleWordField) {
    int64_t Result = 0;
    std::memcpy(&Result, &*Value, sizeof(Result));
    return Result;
  }
  const uint8_t Bits = static_cast<uint8_t>(Width * BitsPerByte);
  if ((*Value & (UINT64_C(1) << (Bits - 1))) == 0) {
    return static_cast<int64_t>(*Value);
  }
  return static_cast<int64_t>(*Value | (~UINT64_C(0) << Bits));
}

Expect<void> writeUnsigned(Span<Byte> Bytes, uint64_t Offset, uint8_t Width,
                           Endianness Endian, uint64_t Value) noexcept {
  if (!validField(Span<const Byte>(Bytes.data(), Bytes.size()), Offset,
                  Width) ||
      (Width < DoubleWordField &&
       Value >= (UINT64_C(1) << (Width * BitsPerByte)))) {
    return fieldError<void>();
  }
  for (uint8_t I = 0; I < Width; ++I) {
    const uint8_t Shift =
        Endian == Endianness::Little
            ? static_cast<uint8_t>(I * BitsPerByte)
            : static_cast<uint8_t>((Width - I - 1) * BitsPerByte);
    Bytes[Offset + I] = static_cast<Byte>(Value >> Shift);
  }
  return {};
}

Expect<void> writeSigned(Span<Byte> Bytes, uint64_t Offset, uint8_t Width,
                         Endianness Endian, int64_t Value) noexcept {
  if (Width != ByteField && Width != HalfField && Width != WordField &&
      Width != DoubleWordField) {
    return fieldError<void>();
  }
  if (Width < DoubleWordField) {
    const uint8_t Bits = static_cast<uint8_t>(Width * BitsPerByte);
    const int64_t Minimum = -(INT64_C(1) << (Bits - 1));
    const int64_t Maximum = (INT64_C(1) << (Bits - 1)) - 1;
    if (Value < Minimum || Value > Maximum) {
      return fieldError<void>();
    }
  }
  uint64_t Bits = 0;
  std::memcpy(&Bits, &Value, sizeof(Bits));
  if (Width < DoubleWordField) {
    Bits &= (UINT64_C(1) << (Width * BitsPerByte)) - 1;
  }
  return writeUnsigned(Bytes, Offset, Width, Endian, Bits);
}

} // namespace Internal

Expect<void> applyRelocations(LinkGraph &Graph) {
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
#if WASMEDGE_LINKER_HAS_LINUX_RELOCATIONS
    Result = Internal::applyARM(Graph);
#endif
    break;
  case Target::AArch64:
#if WASMEDGE_LINKER_HAS_AARCH64
    Result = Internal::applyAArch64(Graph);
#endif
    break;
  case Target::RISCV64:
#if WASMEDGE_LINKER_HAS_LINUX_RELOCATIONS
    Result = Internal::applyRISCV(Graph);
#endif
    break;
  case Target::S390X:
#if WASMEDGE_LINKER_HAS_LINUX_RELOCATIONS
    Result = Internal::applyS390X(Graph);
#endif
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
