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
    const bool ThumbBranch = Rel.Type == llvm::ELF::R_ARM_THM_CALL;
    const uint64_t AlignmentMask =
        ThumbBranch ? UINT64_C(1) : InstructionAlignmentMask;
    if (!Word || (Rel.Offset & AlignmentMask) != 0) {
      return fail(Rel, "invalid relocation field");
    }
    const auto &Symbol = Graph.symbols()[Rel.Symbol];
    const int128_t S =
        int128_t(Graph.sections()[Symbol.Section].Address) + Symbol.Offset;
    const int128_t P =
        int128_t(Graph.sections()[Rel.Section].Address) + Rel.Offset;
    int64_t Addend = Rel.Addend;
    if (Rel.AddendIsImplicit && Rel.Type != llvm::ELF::R_ARM_PREL31 &&
        Rel.Type != llvm::ELF::R_ARM_CALL && !ThumbBranch &&
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
    } else if (ThumbBranch) {
      constexpr unsigned BranchDisplacementBits = 25;
      constexpr unsigned BranchImmediateShift = 1;
      constexpr uint16_t FirstOpcodeMask = UINT16_C(0xF800);
      constexpr uint16_t FirstOpcode = UINT16_C(0xF000);
      constexpr uint16_t SecondOpcodeMask = UINT16_C(0xD000);
      constexpr uint16_t SecondCallOpcode = UINT16_C(0xD000);
      constexpr uint16_t SignMask = UINT16_C(0x0400);
      constexpr uint16_t Imm10Mask = UINT16_C(0x03FF);
      constexpr uint16_t J1Mask = UINT16_C(0x2000);
      constexpr uint16_t J2Mask = UINT16_C(0x0800);
      constexpr uint16_t Imm11Mask = UINT16_C(0x07FF);
      constexpr unsigned SignShift = 24;
      constexpr unsigned I1Shift = 23;
      constexpr unsigned I2Shift = 22;
      constexpr unsigned Imm10Shift = 12;
      constexpr unsigned J1Shift = 13;
      constexpr unsigned J2Shift = 11;
      const uint16_t First = static_cast<uint16_t>(*Word);
      const uint16_t Second = static_cast<uint16_t>(*Word >> 16);
      if ((First & FirstOpcodeMask) != FirstOpcode ||
          (Second & SecondOpcodeMask) != SecondCallOpcode) {
        return fail(Rel, "invalid Thumb branch instruction");
      }
      if (Rel.AddendIsImplicit) {
        const uint32_t SBit = (First & SignMask) != 0;
        const uint32_t J1 = (Second & J1Mask) != 0;
        const uint32_t J2 = (Second & J2Mask) != 0;
        const uint32_t I1 = !(J1 ^ SBit);
        const uint32_t I2 = !(J2 ^ SBit);
        const uint32_t Encoded = (SBit << SignShift) | (I1 << I1Shift) |
                                 (I2 << I2Shift) |
                                 ((First & Imm10Mask) << Imm10Shift) |
                                 ((Second & Imm11Mask) << BranchImmediateShift);
        Addend = (Encoded & (UINT32_C(1) << SignShift)) != 0
                     ? static_cast<int64_t>(
                           static_cast<int32_t>(Encoded | UINT32_C(0xFE000000)))
                     : static_cast<int64_t>(Encoded);
      }
      const int128_t Value = S + Addend - P;
      if ((Value & 1) != 0 || !signedBits(Value, BranchDisplacementBits)) {
        return fail(Rel, "Thumb branch displacement overflows");
      }
      const uint32_t Encoded = static_cast<uint32_t>(Value);
      const uint32_t SBit = (Encoded >> SignShift) & 1;
      const uint32_t I1 = (Encoded >> I1Shift) & 1;
      const uint32_t I2 = (Encoded >> I2Shift) & 1;
      const uint32_t J1 = !(I1 ^ SBit);
      const uint32_t J2 = !(I2 ^ SBit);
      const uint16_t EncodedFirst = static_cast<uint16_t>(
          (First & FirstOpcodeMask) | (SBit ? SignMask : 0) |
          ((Encoded >> Imm10Shift) & Imm10Mask));
      const uint16_t EncodedSecond = static_cast<uint16_t>(
          (Second & SecondOpcodeMask) | (J1 << J1Shift) | (J2 << J2Shift) |
          ((Encoded >> BranchImmediateShift) & Imm11Mask));
      if (!writeUnsigned(Bytes, Rel.Offset, InstructionWidth,
                         Endianness::Little,
                         static_cast<uint32_t>(EncodedFirst) |
                             (static_cast<uint32_t>(EncodedSecond) << 16))) {
        return fail(Rel, "cannot encode Thumb branch");
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
