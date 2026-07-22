// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

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
  if (Graph.target() != Target::X86_64) {
    spdlog::error("native linker: unsupported target {}"sv,
                  static_cast<uint32_t>(Graph.target()));
    return Unexpect(ErrCode::Value::AOTNotImpl);
  }
  if (Graph.endianness() != Endianness::Little) {
    spdlog::error("native linker: x86_64 requires little-endian input"sv);
    return Unexpect(ErrCode::Value::IllegalPath);
  }
  auto Result = Internal::applyX86_64(Graph);
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
