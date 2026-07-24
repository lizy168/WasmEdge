// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <llvm/BinaryFormat/COFF.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/BinaryFormat/MachO.h>

#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {
namespace Internal {
namespace {

using namespace std::literals;

enum class Low12Scale : unsigned {
  Byte,
  Half,
  Word,
  DoubleWord,
  QuadWord,
};

struct Low12Encoding {
  Low12Scale Scale;
  uint32_t OpcodeMask;
  uint32_t Opcode;
};

constexpr unsigned value(Low12Scale Value) noexcept {
  return static_cast<unsigned>(Value);
}

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
  constexpr uint8_t InstructionWidth = 4;
  constexpr uint64_t InstructionAlignmentMask = InstructionWidth - 1;
  RelocationResult Result;
  for (const auto &Section : Graph.sections()) {
    Result.Content.push_back(Section.Content);
  }
  Result.Rebases = Graph.rebases();
  for (const auto &Rel : Graph.relocations()) {
    auto &Bytes = Result.Content[Rel.Section];
    const auto &Symbol = Graph.symbols()[Rel.Symbol];
    const int128_t S = int128_t(Graph.sections()[Symbol.Section].Address) +
                       Symbol.Offset + Rel.Addend;
    const int128_t P =
        int128_t(Graph.sections()[Rel.Section].Address) + Rel.Offset;
    if (Rel.Format == ObjectFormat::COFF &&
        Rel.Type == llvm::COFF::IMAGE_REL_ARM64_ADDR32NB) {
      if (S < 0 || S > UINT32_MAX ||
          !writeUnsigned(Bytes, Rel.Offset, InstructionWidth,
                         Endianness::Little, static_cast<uint64_t>(S))) {
        return fail(Rel, "ADDR32NB relocation overflows");
      }
      continue;
    }
    if (Rel.Format == ObjectFormat::ELF &&
        Rel.Type == llvm::ELF::R_AARCH64_ABS64) {
      constexpr uint8_t DoubleWordWidth = 8;
      if (S < 0 || S > UINT64_MAX ||
          !writeUnsigned(Bytes, Rel.Offset, DoubleWordWidth, Endianness::Little,
                         static_cast<uint64_t>(S))) {
        return fail(Rel, "absolute relocation overflows");
      }
      if (hasRebaseOverlap(Result.Rebases, Rel.Section, Rel.Offset,
                           DoubleWordWidth)) {
        return fail(Rel, "overlapping generated rebase");
      }
      Result.Rebases.push_back(Rebase{Rel.Section, Rel.Offset, Rel.Type,
                                      Rel.Addend, DoubleWordWidth});
      continue;
    }
    if (Rel.Format == ObjectFormat::ELF &&
        Rel.Type == llvm::ELF::R_AARCH64_PREL64) {
      constexpr uint8_t DoubleWordWidth = 8;
      constexpr unsigned DoubleWordBits = 64;
      const int128_t Value = S - P;
      if (!signedBits(Value, DoubleWordBits) ||
          !writeSigned(Bytes, Rel.Offset, DoubleWordWidth, Endianness::Little,
                       static_cast<int64_t>(Value))) {
        return fail(Rel, "PREL64 relocation overflows");
      }
      continue;
    }
    if (Rel.Format == ObjectFormat::ELF &&
        Rel.Type == llvm::ELF::R_AARCH64_PREL32) {
      constexpr unsigned WordBits = 32;
      const int128_t Value = S - P;
      if (!signedBits(Value, WordBits) ||
          !writeSigned(Bytes, Rel.Offset, InstructionWidth, Endianness::Little,
                       static_cast<int64_t>(Value))) {
        return fail(Rel, "PREL32 relocation overflows");
      }
      continue;
    }
    if ((Rel.Offset & InstructionAlignmentMask) != 0) {
      return fail(Rel, "invalid relocation field");
    }
    auto Word =
        readUnsigned(Bytes, Rel.Offset, InstructionWidth, Endianness::Little);
    if (!Word) {
      return fail(Rel, "relocation field exceeds section content");
    }
    uint32_t Instruction = static_cast<uint32_t>(*Word);
    const bool Branch26 = (Rel.Format == ObjectFormat::ELF &&
                           (Rel.Type == llvm::ELF::R_AARCH64_JUMP26 ||
                            Rel.Type == llvm::ELF::R_AARCH64_CALL26)) ||
                          (Rel.Format == ObjectFormat::MachO &&
                           Rel.Type == llvm::MachO::ARM64_RELOC_BRANCH26) ||
                          (Rel.Format == ObjectFormat::COFF &&
                           Rel.Type == llvm::COFF::IMAGE_REL_ARM64_BRANCH26);
    if (Branch26) {
      constexpr unsigned BranchDisplacementBits = 28;
      constexpr unsigned BranchImmediateShift = 2;
      constexpr uint32_t BranchOpcodeMask = UINT32_C(0xFC000000);
      constexpr uint32_t BranchImmediateMask = UINT32_C(0x03FFFFFF);
      constexpr uint32_t JumpOpcode = UINT32_C(0x14000000);
      constexpr uint32_t CallOpcode = UINT32_C(0x94000000);
      const uint32_t Opcode = (Instruction & BranchOpcodeMask) == CallOpcode
                                  ? CallOpcode
                                  : JumpOpcode;
      if ((Instruction & BranchOpcodeMask) != Opcode) {
        return fail(Rel, "invalid branch instruction");
      }
      const int128_t Value = S - P;
      if ((Value & InstructionAlignmentMask) != 0 ||
          !signedBits(Value, BranchDisplacementBits)) {
        return fail(Rel, "branch displacement overflows");
      }
      Instruction =
          Opcode | (static_cast<uint32_t>(Value >> BranchImmediateShift) &
                    BranchImmediateMask);
    } else if ((Rel.Format == ObjectFormat::ELF &&
                Rel.Type == llvm::ELF::R_AARCH64_ADR_PREL_PG_HI21) ||
               (Rel.Format == ObjectFormat::MachO &&
                Rel.Type == llvm::MachO::ARM64_RELOC_PAGE21) ||
               (Rel.Format == ObjectFormat::COFF &&
                Rel.Type == llvm::COFF::IMAGE_REL_ARM64_PAGEBASE_REL21)) {
      constexpr unsigned PageShift = 12;
      constexpr unsigned PageDisplacementBits = 21;
      constexpr uint32_t AdrpOpcodeMask = UINT32_C(0x9F000000);
      constexpr uint32_t AdrpOpcode = UINT32_C(0x90000000);
      constexpr uint32_t AdrpPreservedMask = UINT32_C(0x9F00001F);
      constexpr uint32_t AdrpImmediateMask = UINT32_C(0x001FFFFF);
      constexpr uint32_t AdrpImmediateLowMask = UINT32_C(0x00000003);
      constexpr uint32_t AdrpImmediateHighMask = UINT32_C(0x001FFFFC);
      constexpr unsigned AdrpImmediateLowShift = 29;
      constexpr unsigned AdrpImmediateHighShift = 3;
      if ((Instruction & AdrpOpcodeMask) != AdrpOpcode) {
        return fail(Rel, "invalid ADRP instruction");
      }
      const int128_t Pages = (S >> PageShift) - (P >> PageShift);
      if (!signedBits(Pages, PageDisplacementBits)) {
        return fail(Rel, "ADRP page displacement overflows");
      }
      const uint32_t Value = static_cast<uint32_t>(Pages) & AdrpImmediateMask;
      Instruction = (Instruction & AdrpPreservedMask) |
                    ((Value & AdrpImmediateLowMask) << AdrpImmediateLowShift) |
                    ((Value & AdrpImmediateHighMask) << AdrpImmediateHighShift);
    } else {
      constexpr uint64_t PageOffsetMask = UINT64_C(0xFFF);
      constexpr uint32_t Low12ImmediateMask = UINT32_C(0x003FFC00);
      constexpr unsigned Low12ImmediateShift = 10;
      Low12Encoding Encoding{};
      if (Rel.Format == ObjectFormat::MachO &&
          Rel.Type == llvm::MachO::ARM64_RELOC_PAGEOFF12) {
        Encoding = {(Instruction & UINT32_C(0x3B000000)) == UINT32_C(0x39000000)
                        ? static_cast<Low12Scale>((Instruction >> 30) & 3)
                        : Low12Scale::Byte,
                    0, 0};
      } else if (Rel.Format == ObjectFormat::COFF &&
                 (Rel.Type == llvm::COFF::IMAGE_REL_ARM64_PAGEOFFSET_12A ||
                  Rel.Type == llvm::COFF::IMAGE_REL_ARM64_PAGEOFFSET_12L)) {
        Encoding = {Rel.Type == llvm::COFF::IMAGE_REL_ARM64_PAGEOFFSET_12L
                        ? static_cast<Low12Scale>((Instruction >> 30) & 3)
                        : Low12Scale::Byte,
                    0, 0};
      } else
        switch (Rel.Type) {
        case llvm::ELF::R_AARCH64_ADD_ABS_LO12_NC:
          Encoding = {Low12Scale::Byte, UINT32_C(0x7FC00000),
                      UINT32_C(0x11000000)};
          break;
        case llvm::ELF::R_AARCH64_LDST8_ABS_LO12_NC:
          Encoding = {Low12Scale::Byte, UINT32_C(0x3B000000),
                      UINT32_C(0x39000000)};
          break;
        case llvm::ELF::R_AARCH64_LDST16_ABS_LO12_NC:
          Encoding = {Low12Scale::Half, UINT32_C(0x3F000000),
                      UINT32_C(0x39000000)};
          break;
        case llvm::ELF::R_AARCH64_LDST32_ABS_LO12_NC:
          Encoding = {Low12Scale::Word, UINT32_C(0x3F000000),
                      UINT32_C(0x39000000)};
          break;
        case llvm::ELF::R_AARCH64_LDST64_ABS_LO12_NC:
          Encoding = {Low12Scale::DoubleWord, UINT32_C(0x3F000000),
                      UINT32_C(0x39000000)};
          break;
        case llvm::ELF::R_AARCH64_LDST128_ABS_LO12_NC:
          Encoding = {Low12Scale::QuadWord, UINT32_C(0x3F800000),
                      UINT32_C(0x3D800000)};
          break;
        default:
          return fail(Rel, "unsupported AArch64 relocation type");
        }
      if (Encoding.OpcodeMask != 0 &&
          (Instruction & Encoding.OpcodeMask) != Encoding.Opcode) {
        return fail(Rel, "invalid low12 instruction");
      }
      const uint64_t Low = static_cast<uint64_t>(S) & PageOffsetMask;
      if ((Low & ((UINT64_C(1) << value(Encoding.Scale)) - 1)) != 0) {
        return fail(Rel, "unaligned low12 relocation");
      }
      Instruction = (Instruction & ~Low12ImmediateMask) |
                    (static_cast<uint32_t>(Low >> value(Encoding.Scale))
                     << Low12ImmediateShift);
    }
    if (!writeUnsigned(Bytes, Rel.Offset, InstructionWidth, Endianness::Little,
                       Instruction)) {
      return fail(Rel, "cannot encode instruction");
    }
  }
  return Result;
}

} // namespace Internal
} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
