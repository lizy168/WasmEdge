// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <llvm/BinaryFormat/COFF.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/BinaryFormat/MachO.h>

#include <algorithm>
#include <limits>
#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {
namespace Internal {

namespace {

using namespace std::literals;

constexpr uint64_t PEImageBase = UINT64_C(0x180000000);

enum class Opcode : uint8_t {
  Group5 = 0xFF,
  Load = 0x8B,
  LoadEffectiveAddress = 0x8D,
  CallRelative = 0xE8,
  JumpRelative = 0xE9,
  Nop = 0x90,
};

enum class ModRM : uint8_t {
  CallPCRelative = 0x15,
  JumpPCRelative = 0x25,
  LoadPCRelative = 0x05,
};

enum class Prefix : uint8_t {
  AddressSizeOverride = 0x67,
  Rex = 0x40,
};

constexpr uint8_t value(Opcode Value) noexcept {
  return static_cast<uint8_t>(Value);
}

constexpr uint8_t value(ModRM Value) noexcept {
  return static_cast<uint8_t>(Value);
}

constexpr uint8_t value(Prefix Value) noexcept {
  return static_cast<uint8_t>(Value);
}

uint64_t magnitude(int64_t Value) noexcept {
  return Value < 0 ? static_cast<uint64_t>(-(Value + 1)) + 1
                   : static_cast<uint64_t>(Value);
}

bool addUnsigned(uint64_t Value, int64_t Addend, uint64_t &Result) noexcept {
  if (Addend < 0) {
    const uint64_t Amount = magnitude(Addend);
    if (Value < Amount) {
      return false;
    }
    Result = Value - Amount;
    return true;
  }
  const uint64_t Amount = static_cast<uint64_t>(Addend);
  if (Value > std::numeric_limits<uint64_t>::max() - Amount) {
    return false;
  }
  Result = Value + Amount;
  return true;
}

bool delta32(uint64_t Symbol, int64_t Addend, uint64_t Place,
             int64_t &Result) noexcept {
  constexpr uint64_t NegativeInt32Magnitude = UINT64_C(2147483648);
  bool Negative = Symbol < Place;
  uint64_t Amount = Negative ? Place - Symbol : Symbol - Place;
  const bool AddendNegative = Addend < 0;
  const uint64_t AddendAmount = magnitude(Addend);
  if (Negative == AddendNegative) {
    if (Amount > UINT64_MAX - AddendAmount) {
      return false;
    }
    Amount += AddendAmount;
  } else if (Amount >= AddendAmount) {
    Amount -= AddendAmount;
  } else {
    Amount = AddendAmount - Amount;
    Negative = AddendNegative;
  }
  if ((!Negative && Amount > static_cast<uint64_t>(INT32_MAX)) ||
      (Negative && Amount > NegativeInt32Magnitude)) {
    return false;
  }
  Result =
      Negative ? -static_cast<int64_t>(Amount) : static_cast<int64_t>(Amount);
  return true;
}

Expect<RelocationResult> fail(const Relocation &RelocationValue,
                              std::string_view Message) {
  spdlog::error(
      "native linker: {} (section {}, symbol {}, type {}, offset {})"sv,
      Message, RelocationValue.Section, RelocationValue.Symbol,
      RelocationValue.Type, RelocationValue.Offset);
  return Unexpect(ErrCode::Value::IllegalPath);
}

} // namespace

Expect<RelocationResult> applyX86_64(const LinkGraph &Graph) {
  constexpr uint8_t WordWidth = 4;
  constexpr uint8_t DoubleWordWidth = 8;
  constexpr int64_t PCRelativeAddendBias = -4;
  RelocationResult Result;
  Result.Content.reserve(Graph.sections().size());
  for (const auto &Section : Graph.sections()) {
    Result.Content.push_back(Section.Content);
  }
  Result.Rebases = Graph.rebases();

  for (const auto &RelocationValue : Graph.relocations()) {
    uint8_t Width = 0;
    bool Absolute = false;
    bool ImageRelative = false;
    bool Relax = false;
    int64_t FormatAdjustment = 0;
    if (RelocationValue.Format == ObjectFormat::ELF) {
      switch (RelocationValue.Type) {
      case llvm::ELF::R_X86_64_64:
        Width = DoubleWordWidth;
        Absolute = true;
        break;
      case llvm::ELF::R_X86_64_PC32:
      case llvm::ELF::R_X86_64_PLT32:
        Width = WordWidth;
        break;
      case llvm::ELF::R_X86_64_GOTPCRELX:
      case llvm::ELF::R_X86_64_REX_GOTPCRELX:
        Width = WordWidth;
        Relax = true;
        break;
      default:
        return fail(RelocationValue, "unsupported x86_64 relocation type");
      }
    } else if (RelocationValue.Format == ObjectFormat::MachO &&
               RelocationValue.Type == llvm::MachO::X86_64_RELOC_UNSIGNED) {
      Width = DoubleWordWidth;
      Absolute = true;
    } else if (RelocationValue.Format == ObjectFormat::MachO &&
               (RelocationValue.Type == llvm::MachO::X86_64_RELOC_SIGNED ||
                RelocationValue.Type == llvm::MachO::X86_64_RELOC_SIGNED_1 ||
                RelocationValue.Type == llvm::MachO::X86_64_RELOC_SIGNED_2 ||
                RelocationValue.Type == llvm::MachO::X86_64_RELOC_SIGNED_4 ||
                RelocationValue.Type == llvm::MachO::X86_64_RELOC_BRANCH)) {
      Width = WordWidth;
      FormatAdjustment = -static_cast<int64_t>(WordWidth);
      switch (RelocationValue.Type) {
      case llvm::MachO::X86_64_RELOC_SIGNED_1:
        if (!RelocationValue.AddendIsImplicit)
          FormatAdjustment -= 1;
        break;
      case llvm::MachO::X86_64_RELOC_SIGNED_2:
        if (!RelocationValue.AddendIsImplicit)
          FormatAdjustment -= 2;
        break;
      case llvm::MachO::X86_64_RELOC_SIGNED_4:
        if (!RelocationValue.AddendIsImplicit)
          FormatAdjustment -= 4;
        break;
      default:
        break;
      }
    } else if (RelocationValue.Format == ObjectFormat::COFF &&
               RelocationValue.Type == llvm::COFF::IMAGE_REL_AMD64_ADDR64) {
      Width = DoubleWordWidth;
      Absolute = true;
    } else if (RelocationValue.Format == ObjectFormat::COFF &&
               RelocationValue.Type >= llvm::COFF::IMAGE_REL_AMD64_REL32 &&
               RelocationValue.Type <= llvm::COFF::IMAGE_REL_AMD64_REL32_5) {
      Width = WordWidth;
      FormatAdjustment =
          PCRelativeAddendBias -
          static_cast<int64_t>(RelocationValue.Type -
                               llvm::COFF::IMAGE_REL_AMD64_REL32);
    } else if (RelocationValue.Format == ObjectFormat::COFF &&
               RelocationValue.Type == llvm::COFF::IMAGE_REL_AMD64_ADDR32NB) {
      Width = WordWidth;
      ImageRelative = true;
    } else {
      return fail(RelocationValue, "unsupported x86_64 relocation type");
    }
    auto &Bytes = Result.Content[RelocationValue.Section];
    if (RelocationValue.Offset > Bytes.size() ||
        Width > Bytes.size() - RelocationValue.Offset) {
      return fail(RelocationValue, "relocation field exceeds section content");
    }
    const auto &Symbol = Graph.symbols()[RelocationValue.Symbol];
    const auto &SymbolSection = Graph.sections()[Symbol.Section];
    if (Symbol.Offset > UINT64_MAX - SymbolSection.Address) {
      return fail(RelocationValue, "symbol address overflows");
    }
    const uint64_t S = SymbolSection.Address + Symbol.Offset;
    const auto &PatchSection = Graph.sections()[RelocationValue.Section];
    if (RelocationValue.Offset > UINT64_MAX - PatchSection.Address) {
      return fail(RelocationValue, "relocation place overflows");
    }
    const uint64_t P = PatchSection.Address + RelocationValue.Offset;
    int64_t Addend = RelocationValue.Addend;
    if (RelocationValue.AddendIsImplicit) {
      auto Decoded =
          readSigned(Bytes, RelocationValue.Offset, Width, Graph.endianness());
      if (!Decoded) {
        return fail(RelocationValue, "cannot decode implicit addend");
      }
      Addend = *Decoded;
    }
    if ((FormatAdjustment < 0 &&
         Addend < std::numeric_limits<int64_t>::min() - FormatAdjustment) ||
        (FormatAdjustment > 0 &&
         Addend > std::numeric_limits<int64_t>::max() - FormatAdjustment)) {
      return fail(RelocationValue, "relocation addend overflows");
    }
    Addend += FormatAdjustment;
    if (Absolute || ImageRelative) {
      uint64_t Value = 0;
      if (!addUnsigned(S, Addend, Value) ||
          (ImageRelative && Value < PEImageBase)) {
        return fail(RelocationValue, "absolute relocation overflows");
      }
      if (ImageRelative)
        Value -= PEImageBase;
      if (!writeUnsigned(Bytes, RelocationValue.Offset, Width,
                         Graph.endianness(), Value)) {
        return fail(RelocationValue, "absolute relocation overflows");
      }
      if (ImageRelative) {
        continue;
      }
      const auto Overlap = std::find_if(
          Result.Rebases.begin(), Result.Rebases.end(), [&](const auto &Old) {
            if (Old.Section != RelocationValue.Section) {
              return false;
            }
            const uint64_t OldWidth =
                std::max<uint8_t>(Old.Width, MinimumRebaseWidth);
            if (RelocationValue.Offset <= Old.Offset) {
              return Width > Old.Offset - RelocationValue.Offset;
            }
            return OldWidth > RelocationValue.Offset - Old.Offset;
          });
      if (Overlap != Result.Rebases.end()) {
        return fail(RelocationValue, "overlapping generated rebase");
      }
      Result.Rebases.push_back(Rebase{RelocationValue.Section,
                                      RelocationValue.Offset,
                                      RelocationValue.Type, Addend, Width});
      Result.Rebases.back().Format = RelocationValue.Format;
      continue;
    }
    if (Relax) {
      constexpr uint8_t RexPrefixMask = 0xF0;
      constexpr uint8_t LoadModRMMask = 0xC7;
      constexpr uint64_t OpcodeAndModRMSize = 2;
      constexpr uint64_t RexOpcodeAndModRMSize = 3;
      constexpr uint64_t ModRMOffsetFromOpcode = 1;
      constexpr int64_t NextInstructionBias = 1;
      constexpr uint64_t DisplacementFieldBacktrack = 1;
      constexpr uint64_t TrailingNopOffsetFromPatch = 3;
      if (RelocationValue.AddendIsImplicit || Addend != PCRelativeAddendBias ||
          RelocationValue.Offset < OpcodeAndModRMSize) {
        return fail(RelocationValue, "unsupported GOTPCRELX instruction");
      }
      const size_t OpcodeOffset =
          static_cast<size_t>(RelocationValue.Offset - OpcodeAndModRMSize);
      const uint8_t Op = Bytes[OpcodeOffset];
      const uint8_t ModRMByte = Bytes[OpcodeOffset + ModRMOffsetFromOpcode];
      const bool HasRex =
          RelocationValue.Offset >= RexOpcodeAndModRMSize &&
          (Bytes[RelocationValue.Offset - RexOpcodeAndModRMSize] &
           RexPrefixMask) == value(Prefix::Rex);
      if (RelocationValue.Type == llvm::ELF::R_X86_64_REX_GOTPCRELX &&
          !HasRex) {
        return fail(RelocationValue, "unsupported GOTPCRELX instruction");
      }
      if (Op == value(Opcode::Load) &&
          (ModRMByte & LoadModRMMask) == value(ModRM::LoadPCRelative)) {
        Bytes[OpcodeOffset] = value(Opcode::LoadEffectiveAddress);
      } else if (Op == value(Opcode::Group5) &&
                 ModRMByte == value(ModRM::CallPCRelative)) {
        Bytes[OpcodeOffset] = value(Prefix::AddressSizeOverride);
        Bytes[OpcodeOffset + ModRMOffsetFromOpcode] =
            value(Opcode::CallRelative);
      } else if (Op == value(Opcode::Group5) &&
                 ModRMByte == value(ModRM::JumpPCRelative)) {
        int64_t Value = 0;
        if (!delta32(S, Addend + NextInstructionBias, P, Value) ||
            !writeSigned(Bytes,
                         RelocationValue.Offset - DisplacementFieldBacktrack,
                         Width, Graph.endianness(), Value)) {
          return fail(RelocationValue, "PC-relative relocation overflows");
        }
        Bytes[OpcodeOffset] = value(Opcode::JumpRelative);
        Bytes[RelocationValue.Offset + TrailingNopOffsetFromPatch] =
            value(Opcode::Nop);
        continue;
      } else {
        return fail(RelocationValue, "unsupported GOTPCRELX instruction");
      }
    }
    int64_t Value = 0;
    if (!delta32(S, Addend, P, Value) ||
        !writeSigned(Bytes, RelocationValue.Offset, Width, Graph.endianness(),
                     Value)) {
      return fail(RelocationValue, "PC-relative relocation overflows");
    }
  }
  return Result;
}

} // namespace Internal
} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
