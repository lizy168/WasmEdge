// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <llvm/BinaryFormat/ELF.h>

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
  constexpr uint8_t InstructionWidth = 4;
  constexpr uint64_t InstructionAlignmentMask = InstructionWidth - 1;
  RelocationResult Result;
  for (const auto &Section : Graph.sections()) {
    Result.Content.push_back(Section.Content);
  }
  Result.Rebases = Graph.rebases();
  for (const auto &Rel : Graph.relocations()) {
    if (Rel.Format != ObjectFormat::ELF) {
      return fail(Rel, "unsupported object format");
    }
    if (Rel.Type == llvm::ELF::R_ARM_NONE) {
      continue;
    }
    auto &Bytes = Result.Content[Rel.Section];
    auto Word =
        readUnsigned(Bytes, Rel.Offset, InstructionWidth, Endianness::Little);
    if (!Word || (Rel.Offset & InstructionAlignmentMask) != 0) {
      return fail(Rel, "invalid relocation field");
    }
    const auto &Symbol = Graph.symbols()[Rel.Symbol];
    const int128_t S =
        int128_t(Graph.sections()[Symbol.Section].Address) + Symbol.Offset;
    const int128_t P =
        int128_t(Graph.sections()[Rel.Section].Address) + Rel.Offset;
    int64_t Addend = Rel.Addend;
    if (Rel.AddendIsImplicit && Rel.Type != llvm::ELF::R_ARM_PREL31 &&
        Rel.Type != llvm::ELF::R_ARM_CALL &&
        Rel.Type != llvm::ELF::R_ARM_JUMP24) {
      auto Value =
          readSigned(Bytes, Rel.Offset, InstructionWidth, Endianness::Little);
      if (!Value) {
        return fail(Rel, "cannot decode implicit addend");
      }
      Addend = *Value;
    }
    if (Rel.Type == llvm::ELF::R_ARM_ABS32) {
      const int128_t Value = S + Addend;
      if (Value < 0 || Value > UINT32_MAX ||
          !writeUnsigned(Bytes, Rel.Offset, InstructionWidth,
                         Endianness::Little, static_cast<uint64_t>(Value))) {
        return fail(Rel, "absolute relocation overflows");
      }
      if (hasRebaseOverlap(Result.Rebases, Rel.Section, Rel.Offset,
                           InstructionWidth)) {
        return fail(Rel, "overlapping generated rebase");
      }
      Result.Rebases.push_back(
          Rebase{Rel.Section, Rel.Offset, Rel.Type, Addend, InstructionWidth});
    } else if (Rel.Type == llvm::ELF::R_ARM_REL32) {
      constexpr unsigned WordBits = 32;
      const int128_t Value = S + Addend - P;
      if (!signedBits(Value, WordBits) ||
          !writeSigned(Bytes, Rel.Offset, InstructionWidth, Endianness::Little,
                       static_cast<int64_t>(Value))) {
        return fail(Rel, "relative relocation overflows");
      }
    } else if (Rel.Type == llvm::ELF::R_ARM_CALL ||
               Rel.Type == llvm::ELF::R_ARM_JUMP24) {
      constexpr unsigned BranchDisplacementBits = 26;
      constexpr unsigned BranchImmediateShift = 2;
      constexpr uint32_t BranchOpcodeMask = UINT32_C(0x0E000000);
      constexpr uint32_t BranchOpcode = UINT32_C(0x0A000000);
      constexpr uint32_t BranchImmediateMask = UINT32_C(0x00FFFFFF);
      constexpr uint32_t BranchImmediateSign = UINT32_C(0x00800000);
      constexpr uint32_t BranchImmediateSignExtension = UINT32_C(0xFF000000);
      constexpr uint32_t BranchInstructionMask = UINT32_C(0xFF000000);
      if ((*Word & BranchOpcodeMask) != BranchOpcode) {
        return fail(Rel, "invalid ARM branch instruction");
      }
      if (Rel.AddendIsImplicit) {
        uint32_t Immediate = static_cast<uint32_t>(*Word) & BranchImmediateMask;
        const int32_t SignedImmediate =
            (Immediate & BranchImmediateSign) != 0
                ? static_cast<int32_t>(Immediate | BranchImmediateSignExtension)
                : static_cast<int32_t>(Immediate);
        Addend = static_cast<int64_t>(SignedImmediate) * InstructionWidth;
      }
      const int128_t Value = S + Addend - P;
      if ((Value & InstructionAlignmentMask) != 0 ||
          !signedBits(Value, BranchDisplacementBits)) {
        return fail(Rel, "ARM branch displacement overflows");
      }
      const uint32_t Encoded =
          static_cast<uint32_t>(Value >> BranchImmediateShift) &
          BranchImmediateMask;
      if (!writeUnsigned(Bytes, Rel.Offset, InstructionWidth,
                         Endianness::Little,
                         (*Word & BranchInstructionMask) | Encoded)) {
        return fail(Rel, "cannot encode ARM branch");
      }
    } else if (Rel.Type == llvm::ELF::R_ARM_PREL31) {
      constexpr unsigned Prel31Bits = 31;
      constexpr uint32_t Prel31ValueMask = UINT32_C(0x7FFFFFFF);
      constexpr uint32_t Prel31Sign = UINT32_C(0x40000000);
      constexpr uint64_t Prel31SignExtension = UINT64_C(0xFFFFFFFF80000000);
      constexpr uint32_t Prel31InstructionBit = UINT32_C(0x80000000);
      int64_t Implicit = Rel.Addend;
      if (Rel.AddendIsImplicit) {
        uint32_t Bits = static_cast<uint32_t>(*Word) & Prel31ValueMask;
        Implicit = (Bits & Prel31Sign) != 0
                       ? static_cast<int64_t>(Bits | Prel31SignExtension)
                       : Bits;
      }
      const int128_t Value = S + Implicit - P;
      if (!signedBits(Value, Prel31Bits) ||
          !writeUnsigned(
              Bytes, Rel.Offset, InstructionWidth, Endianness::Little,
              (*Word & Prel31InstructionBit) |
                  (static_cast<uint32_t>(Value) & Prel31ValueMask))) {
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
