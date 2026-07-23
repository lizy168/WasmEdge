// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <algorithm>
#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {
namespace Internal {

namespace {

using namespace std::literals;

Expect<RelocationResult> fail(const Relocation &Value,
                              std::string_view Message) {
  spdlog::error("native linker: {} (ARM type {}, offset {})"sv, Message,
                Value.Type, Value.Offset);
  return Unexpect(ErrCode::Value::IllegalPath);
}

bool signedBits(int128_t Value, unsigned Bits) {
  const int128_t Limit = int128_t(1) << (Bits - 1);
  return Value >= -Limit && Value < Limit;
}

} // namespace

Expect<RelocationResult> applyARM(const LinkGraph &Graph) {
  RelocationResult Result;
  for (const auto &Section : Graph.sections()) {
    Result.Content.push_back(Section.Content);
  }
  Result.Rebases = Graph.rebases();
  for (const auto &Rel : Graph.relocations()) {
    if (Rel.Format != ObjectFormat::ELF) {
      return fail(Rel, "unsupported object format");
    }
    if (Rel.Type == 0) {
      continue;
    }
    auto &Bytes = Result.Content[Rel.Section];
    auto Word = readUnsigned(Bytes, Rel.Offset, 4, Endianness::Little);
    if (!Word || (Rel.Offset & 3) != 0) {
      return fail(Rel, "invalid relocation field");
    }
    const auto &Symbol = Graph.symbols()[Rel.Symbol];
    const int128_t S =
        int128_t(Graph.sections()[Symbol.Section].Address) + Symbol.Offset;
    const int128_t P =
        int128_t(Graph.sections()[Rel.Section].Address) + Rel.Offset;
    int64_t Addend = Rel.Addend;
    if (Rel.AddendIsImplicit && Rel.Type != 42 && Rel.Type != 28 &&
        Rel.Type != 29) {
      auto Value = readSigned(Bytes, Rel.Offset, 4, Endianness::Little);
      if (!Value) {
        return fail(Rel, "cannot decode implicit addend");
      }
      Addend = *Value;
    }
    if (Rel.Type == 2) {
      const int128_t Value = S + Addend;
      if (Value < 0 || Value > UINT32_MAX ||
          !writeUnsigned(Bytes, Rel.Offset, 4, Endianness::Little,
                         static_cast<uint64_t>(Value))) {
        return fail(Rel, "absolute relocation overflows");
      }
      if (hasRebaseOverlap(Result.Rebases, Rel.Section, Rel.Offset, 4)) {
        return fail(Rel, "overlapping generated rebase");
      }
      Result.Rebases.push_back(
          Rebase{Rel.Section, Rel.Offset, Rel.Type, Addend, 4});
    } else if (Rel.Type == 3) {
      const int128_t Value = S + Addend - P;
      if (!signedBits(Value, 32) ||
          !writeSigned(Bytes, Rel.Offset, 4, Endianness::Little,
                       static_cast<int64_t>(Value))) {
        return fail(Rel, "relative relocation overflows");
      }
    } else if (Rel.Type == 28 || Rel.Type == 29) {
      if ((*Word & UINT32_C(0x0E000000)) != UINT32_C(0x0A000000)) {
        return fail(Rel, "invalid ARM branch instruction");
      }
      if (Rel.AddendIsImplicit) {
        uint32_t Immediate = static_cast<uint32_t>(*Word) & 0x00FFFFFF;
        const int32_t SignedImmediate =
            (Immediate & 0x00800000) != 0
                ? static_cast<int32_t>(Immediate | 0xFF000000)
                : static_cast<int32_t>(Immediate);
        Addend = static_cast<int64_t>(SignedImmediate) * 4;
      }
      const int128_t Value = S + Addend - P;
      if ((Value & 3) != 0 || !signedBits(Value, 26)) {
        return fail(Rel, "ARM branch displacement overflows");
      }
      const uint32_t Encoded = static_cast<uint32_t>(Value >> 2) & 0x00FFFFFF;
      if (!writeUnsigned(Bytes, Rel.Offset, 4, Endianness::Little,
                         (*Word & 0xFF000000) | Encoded)) {
        return fail(Rel, "cannot encode ARM branch");
      }
    } else if (Rel.Type == 42) {
      int64_t Implicit = Rel.Addend;
      if (Rel.AddendIsImplicit) {
        uint32_t Bits = static_cast<uint32_t>(*Word) & 0x7FFFFFFF;
        Implicit = (Bits & 0x40000000) != 0
                       ? static_cast<int64_t>(Bits | 0xFFFFFFFF80000000ULL)
                       : Bits;
      }
      const int128_t Value = S + Implicit - P;
      if (!signedBits(Value, 31) ||
          !writeUnsigned(Bytes, Rel.Offset, 4, Endianness::Little,
                         (*Word & 0x80000000) |
                             (static_cast<uint32_t>(Value) & 0x7FFFFFFF))) {
        return fail(Rel, "PREL31 relocation overflows");
      }
    } else {
      return fail(Rel, "unsupported ARM relocation type");
    }
  }
  return Result;
}

} // namespace Internal
} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
