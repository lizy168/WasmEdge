// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {
namespace Internal {
namespace {

using namespace std::literals;

Expect<RelocationResult> fail(const Relocation &Value,
                              std::string_view Message) {
  spdlog::error("native linker: {} (AArch64 type {}, offset {})"sv, Message,
                Value.Type, Value.Offset);
  return Unexpect(ErrCode::Value::IllegalPath);
}

bool signedBits(int128_t Value, unsigned Bits) {
  const int128_t Limit = int128_t(1) << (Bits - 1);
  return Value >= -Limit && Value < Limit;
}

} // namespace

Expect<RelocationResult> applyAArch64(const LinkGraph &Graph) {
  RelocationResult Result;
  for (const auto &Section : Graph.sections()) {
    Result.Content.push_back(Section.Content);
  }
  Result.Rebases = Graph.rebases();
  for (const auto &Rel : Graph.relocations()) {
    if (Rel.Format != ObjectFormat::ELF || (Rel.Offset & 3) != 0) {
      return fail(Rel, "invalid relocation field");
    }
    auto &Bytes = Result.Content[Rel.Section];
    const auto &Symbol = Graph.symbols()[Rel.Symbol];
    const int128_t S = int128_t(Graph.sections()[Symbol.Section].Address) +
                       Symbol.Offset + Rel.Addend;
    const int128_t P =
        int128_t(Graph.sections()[Rel.Section].Address) + Rel.Offset;
    if (Rel.Type == 0x101) {
      if (S < 0 || S > UINT64_MAX ||
          !writeUnsigned(Bytes, Rel.Offset, 8, Endianness::Little,
                         static_cast<uint64_t>(S))) {
        return fail(Rel, "absolute relocation overflows");
      }
      if (hasRebaseOverlap(Result.Rebases, Rel.Section, Rel.Offset, 8)) {
        return fail(Rel, "overlapping generated rebase");
      }
      Result.Rebases.push_back(
          Rebase{Rel.Section, Rel.Offset, Rel.Type, Rel.Addend, 8});
      continue;
    }
    if (Rel.Type == 0x105) {
      const int128_t Value = S - P;
      if (!signedBits(Value, 32) ||
          !writeSigned(Bytes, Rel.Offset, 4, Endianness::Little,
                       static_cast<int64_t>(Value))) {
        return fail(Rel, "PREL32 relocation overflows");
      }
      continue;
    }
    auto Word = readUnsigned(Bytes, Rel.Offset, 4, Endianness::Little);
    if (!Word) {
      return fail(Rel, "relocation field exceeds section content");
    }
    uint32_t Instruction = static_cast<uint32_t>(*Word);
    if (Rel.Type == 0x11A || Rel.Type == 0x11B) {
      const uint32_t Opcode = Rel.Type == 0x11B ? 0x94000000 : 0x14000000;
      if ((Instruction & 0xFC000000) != Opcode) {
        return fail(Rel, "invalid branch instruction");
      }
      const int128_t Value = S - P;
      if ((Value & 3) != 0 || !signedBits(Value, 28)) {
        return fail(Rel, "branch displacement overflows");
      }
      Instruction =
          Opcode | (static_cast<uint32_t>(Value >> 2) & UINT32_C(0x03FFFFFF));
    } else if (Rel.Type == 0x113) {
      if ((Instruction & UINT32_C(0x9F000000)) != UINT32_C(0x90000000)) {
        return fail(Rel, "invalid ADRP instruction");
      }
      const int128_t Pages = (S >> 12) - (P >> 12);
      if (!signedBits(Pages, 21)) {
        return fail(Rel, "ADRP page displacement overflows");
      }
      const uint32_t Value = static_cast<uint32_t>(Pages) & 0x1FFFFF;
      Instruction = (Instruction & UINT32_C(0x9F00001F)) | ((Value & 3) << 29) |
                    ((Value & 0x1FFFFC) << 3);
    } else {
      unsigned Scale = 0;
      uint32_t Mask = 0;
      uint32_t Opcode = 0;
      switch (Rel.Type) {
      case 0x115:
        Mask = UINT32_C(0x7F000000);
        Opcode = UINT32_C(0x11000000);
        break;
      case 0x116:
        Mask = UINT32_C(0x3B000000);
        Opcode = UINT32_C(0x39000000);
        break;
      case 0x11C:
        Scale = 1;
        Mask = UINT32_C(0x3F000000);
        Opcode = UINT32_C(0x39000000);
        break;
      case 0x11D:
        Scale = 2;
        Mask = UINT32_C(0x3F000000);
        Opcode = UINT32_C(0x39000000);
        break;
      case 0x11E:
        Scale = 3;
        Mask = UINT32_C(0x3F000000);
        Opcode = UINT32_C(0x39000000);
        break;
      case 0x12B:
        Scale = 4;
        Mask = UINT32_C(0x3F800000);
        Opcode = UINT32_C(0x3D800000);
        break;
      default:
        return fail(Rel, "unsupported AArch64 relocation type");
      }
      if ((Instruction & Mask) != Opcode) {
        return fail(Rel, "invalid low12 instruction");
      }
      const uint64_t Low = static_cast<uint64_t>(S) & 0xFFF;
      if ((Low & ((UINT64_C(1) << Scale) - 1)) != 0) {
        return fail(Rel, "unaligned low12 relocation");
      }
      Instruction = (Instruction & ~UINT32_C(0x003FFC00)) |
                    (static_cast<uint32_t>(Low >> Scale) << 10);
    }
    if (!writeUnsigned(Bytes, Rel.Offset, 4, Endianness::Little, Instruction)) {
      return fail(Rel, "cannot encode instruction");
    }
  }
  return Result;
}

} // namespace Internal
} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
