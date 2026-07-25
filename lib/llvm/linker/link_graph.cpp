// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/link_graph.h"

#include <llvm/BinaryFormat/COFF.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/BinaryFormat/MachO.h>

#include <algorithm>
#include <utility>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

template <typename T> LinkExpect<T> fail(Diagnostic Value) {
  return Unexpected<Diagnostic>(std::move(Value));
}

bool extendsBeyond(uint64_t Offset, uint64_t Size, uint64_t Limit) noexcept {
  return Offset > Limit || Size > Limit - Offset;
}

bool isRISCVSymbolDifference(const Relocation &Value) noexcept {
  return Value.Format == ObjectFormat::ELF && Value.PatchSize == 4 &&
         (Value.Type == llvm::ELF::R_RISCV_ADD32 ||
          Value.Type == llvm::ELF::R_RISCV_SUB32);
}

bool composeRISCVSymbolDifference(const Relocation &Left,
                                  const Relocation &Right) noexcept {
  return isRISCVSymbolDifference(Left) && isRISCVSymbolDifference(Right) &&
         Left.Section == Right.Section && Left.Offset == Right.Offset &&
         Left.Format == Right.Format && Left.PatchSize == Right.PatchSize &&
         Left.Type != Right.Type;
}

template <typename T, typename Size>
bool overlaps(const T &Left, const T &Right, Size GetSize) noexcept {
  if (Left.Section != Right.Section) {
    return false;
  }
  const uint64_t LeftSize = GetSize(Left);
  const uint64_t RightSize = GetSize(Right);
  if (Left.Offset <= Right.Offset) {
    return LeftSize > Right.Offset - Left.Offset;
  }
  return RightSize > Left.Offset - Right.Offset;
}

LinkExpect<void> relocated() {
  return fail<void>(Diagnostic{"link graph relocations already applied"});
}

} // namespace

std::optional<uint8_t> relocationPatchSize(ObjectFormat Format,
                                           Target TargetValue, uint32_t Type,
                                           uint8_t MetadataSize) noexcept {
  constexpr uint8_t BytePatch = 1;
  constexpr uint8_t HalfPatch = 2;
  constexpr uint8_t WordPatch = 4;
  constexpr uint8_t DoubleWordPatch = 8;
  if (TargetValue == Target::X86_64) {
    if (Format == ObjectFormat::ELF) {
      switch (Type) {
      case llvm::ELF::R_X86_64_64:
        return DoubleWordPatch;
      case llvm::ELF::R_X86_64_PC32:
      case llvm::ELF::R_X86_64_PLT32:
      case llvm::ELF::R_X86_64_GOTPCRELX:
      case llvm::ELF::R_X86_64_REX_GOTPCRELX:
        return WordPatch;
      default:
        return std::nullopt;
      }
    }
    if (Format == ObjectFormat::MachO) {
      switch (Type) {
      case llvm::MachO::X86_64_RELOC_UNSIGNED:
        return DoubleWordPatch;
      case llvm::MachO::X86_64_RELOC_SIGNED:
      case llvm::MachO::X86_64_RELOC_SIGNED_1:
      case llvm::MachO::X86_64_RELOC_SIGNED_2:
      case llvm::MachO::X86_64_RELOC_SIGNED_4:
      case llvm::MachO::X86_64_RELOC_BRANCH:
        return WordPatch;
      default:
        return std::nullopt;
      }
    }
    if (Format == ObjectFormat::COFF) {
      if (Type == llvm::COFF::IMAGE_REL_AMD64_ADDR64)
        return DoubleWordPatch;
      if ((Type >= llvm::COFF::IMAGE_REL_AMD64_REL32 &&
           Type <= llvm::COFF::IMAGE_REL_AMD64_REL32_5) ||
          Type == llvm::COFF::IMAGE_REL_AMD64_ADDR32NB) {
        return WordPatch;
      }
    }
    return std::nullopt;
  }
  if (TargetValue == Target::AArch64 && Format == ObjectFormat::MachO) {
    switch (Type) {
    case llvm::MachO::ARM64_RELOC_UNSIGNED:
      return DoubleWordPatch;
    case llvm::MachO::ARM64_RELOC_BRANCH26:
    case llvm::MachO::ARM64_RELOC_PAGE21:
    case llvm::MachO::ARM64_RELOC_PAGEOFF12:
      return WordPatch;
    default:
      return std::nullopt;
    }
  }
  if (TargetValue == Target::AArch64 && Format == ObjectFormat::COFF) {
    switch (Type) {
    case llvm::COFF::IMAGE_REL_ARM64_ADDR64:
      return DoubleWordPatch;
    case llvm::COFF::IMAGE_REL_ARM64_BRANCH26:
    case llvm::COFF::IMAGE_REL_ARM64_PAGEBASE_REL21:
    case llvm::COFF::IMAGE_REL_ARM64_PAGEOFFSET_12A:
    case llvm::COFF::IMAGE_REL_ARM64_PAGEOFFSET_12L:
    case llvm::COFF::IMAGE_REL_ARM64_ADDR32NB:
      return WordPatch;
    default:
      return std::nullopt;
    }
  }
  if (Format != ObjectFormat::ELF)
    return std::nullopt;
  if (TargetValue == Target::ARM) {
    switch (Type) {
    case llvm::ELF::R_ARM_NONE:
      return NoPatch;
    case llvm::ELF::R_ARM_ABS32:
    case llvm::ELF::R_ARM_REL32:
    case llvm::ELF::R_ARM_THM_CALL:
    case llvm::ELF::R_ARM_CALL:
    case llvm::ELF::R_ARM_JUMP24:
    case llvm::ELF::R_ARM_PREL31:
      return WordPatch;
    default:
      return std::nullopt;
    }
  }
  if (TargetValue == Target::AArch64) {
    switch (Type) {
    case llvm::ELF::R_AARCH64_ABS64:
    case llvm::ELF::R_AARCH64_PREL64:
      return DoubleWordPatch;
    case llvm::ELF::R_AARCH64_PREL32:
    case llvm::ELF::R_AARCH64_ADR_PREL_PG_HI21:
    case llvm::ELF::R_AARCH64_ADD_ABS_LO12_NC:
    case llvm::ELF::R_AARCH64_LDST8_ABS_LO12_NC:
    case llvm::ELF::R_AARCH64_JUMP26:
    case llvm::ELF::R_AARCH64_CALL26:
    case llvm::ELF::R_AARCH64_LDST16_ABS_LO12_NC:
    case llvm::ELF::R_AARCH64_LDST32_ABS_LO12_NC:
    case llvm::ELF::R_AARCH64_LDST64_ABS_LO12_NC:
    case llvm::ELF::R_AARCH64_LDST128_ABS_LO12_NC:
      return WordPatch;
    default:
      return std::nullopt;
    }
  }
  if (TargetValue == Target::RISCV64) {
    switch (Type) {
    case llvm::ELF::R_RISCV_64:
    case llvm::ELF::R_RISCV_CALL:
    case llvm::ELF::R_RISCV_CALL_PLT:
      return DoubleWordPatch;
    case llvm::ELF::R_RISCV_PCREL_HI20:
    case llvm::ELF::R_RISCV_PCREL_LO12_I:
    case llvm::ELF::R_RISCV_PCREL_LO12_S:
    case llvm::ELF::R_RISCV_32_PCREL:
    case llvm::ELF::R_RISCV_ADD32:
    case llvm::ELF::R_RISCV_SUB32:
      return WordPatch;
    case llvm::ELF::R_RISCV_RELAX:
      return NoPatch;
    default:
      return std::nullopt;
    }
  }
  if (TargetValue == Target::S390X) {
    switch (Type) {
    case llvm::ELF::R_390_64:
      return DoubleWordPatch;
    case llvm::ELF::R_390_PC32:
    case llvm::ELF::R_390_PC32DBL:
    case llvm::ELF::R_390_PLT32DBL:
      return WordPatch;
    default:
      return std::nullopt;
    }
  }
  if (MetadataSize == BytePatch || MetadataSize == HalfPatch ||
      MetadataSize == WordPatch || MetadataSize == DoubleWordPatch) {
    return MetadataSize;
  }
  return std::nullopt;
}

bool relocationIsPCRelative(ObjectFormat Format, Target TargetValue,
                            uint32_t Type) noexcept {
  if (Format == ObjectFormat::MachO) {
    if (TargetValue == Target::X86_64) {
      return Type == llvm::MachO::X86_64_RELOC_SIGNED ||
             Type == llvm::MachO::X86_64_RELOC_SIGNED_1 ||
             Type == llvm::MachO::X86_64_RELOC_SIGNED_2 ||
             Type == llvm::MachO::X86_64_RELOC_SIGNED_4 ||
             Type == llvm::MachO::X86_64_RELOC_BRANCH;
    }
    return TargetValue == Target::AArch64 &&
           (Type == llvm::MachO::ARM64_RELOC_BRANCH26 ||
            Type == llvm::MachO::ARM64_RELOC_PAGE21);
  }
  if (Format == ObjectFormat::COFF) {
    if (TargetValue == Target::X86_64) {
      return Type >= llvm::COFF::IMAGE_REL_AMD64_REL32 &&
             Type <= llvm::COFF::IMAGE_REL_AMD64_REL32_5;
    }
    return TargetValue == Target::AArch64 &&
           (Type == llvm::COFF::IMAGE_REL_ARM64_BRANCH26 ||
            Type == llvm::COFF::IMAGE_REL_ARM64_PAGEBASE_REL21);
  }
  switch (TargetValue) {
  case Target::X86_64:
    return Type == llvm::ELF::R_X86_64_PC32 ||
           Type == llvm::ELF::R_X86_64_PLT32 ||
           Type == llvm::ELF::R_X86_64_GOTPCRELX ||
           Type == llvm::ELF::R_X86_64_REX_GOTPCRELX;
  case Target::ARM:
    return Type == llvm::ELF::R_ARM_REL32 ||
           Type == llvm::ELF::R_ARM_THM_CALL || Type == llvm::ELF::R_ARM_CALL ||
           Type == llvm::ELF::R_ARM_JUMP24 || Type == llvm::ELF::R_ARM_PREL31;
  case Target::AArch64:
    return Type == llvm::ELF::R_AARCH64_PREL64 ||
           Type == llvm::ELF::R_AARCH64_PREL32 ||
           Type == llvm::ELF::R_AARCH64_ADR_PREL_PG_HI21 ||
           Type == llvm::ELF::R_AARCH64_JUMP26 ||
           Type == llvm::ELF::R_AARCH64_CALL26;
  case Target::RISCV64:
    return Type == llvm::ELF::R_RISCV_CALL ||
           Type == llvm::ELF::R_RISCV_CALL_PLT ||
           Type == llvm::ELF::R_RISCV_PCREL_HI20 ||
           Type == llvm::ELF::R_RISCV_PCREL_LO12_I ||
           Type == llvm::ELF::R_RISCV_PCREL_LO12_S ||
           Type == llvm::ELF::R_RISCV_32_PCREL;
  case Target::S390X:
    return Type == llvm::ELF::R_390_PC32 || Type == llvm::ELF::R_390_PC32DBL ||
           Type == llvm::ELF::R_390_PLT32DBL;
  }
  return false;
}

LinkExpect<void> LinkGraph::beginInput(std::string_view Name) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (InputName) {
    return fail<void>(
        Diagnostic{"link graph accepts exactly one input object"});
  }
  InputName = std::string(Name);
  return {};
}

LinkExpect<SectionId> LinkGraph::addSection(Section Value) {
  if (RelocationsApplied) {
    return fail<SectionId>(
        Diagnostic{"link graph relocations already applied"});
  }
  if (Value.Alignment == 0 || (Value.Alignment & (Value.Alignment - 1)) != 0) {
    Diagnostic Diag{"section alignment must be a non-zero power of two"};
    Diag.SectionName = Value.Name;
    return fail<SectionId>(std::move(Diag));
  }
  if (Value.Content.size() > Value.VirtualSize) {
    Diagnostic Diag{"section content exceeds section virtual size"};
    Diag.SectionName = Value.Name;
    return fail<SectionId>(std::move(Diag));
  }
  if (Value.LinkedSection && *Value.LinkedSection >= Sections.size()) {
    Diagnostic Diag{"invalid linked section ID"};
    Diag.SectionName = Value.Name;
    return fail<SectionId>(std::move(Diag));
  }
  if (Sections.size() >= InvalidSectionId) {
    return fail<SectionId>(Diagnostic{"too many sections"});
  }
  const SectionId Id{static_cast<uint32_t>(Sections.size())};
  Sections.push_back(std::move(Value));
  return Id;
}

LinkExpect<SymbolId> LinkGraph::addSymbol(Symbol Value) {
  if (RelocationsApplied) {
    return fail<SymbolId>(Diagnostic{"link graph relocations already applied"});
  }
  if (Value.Section == InvalidSectionId) {
    Diagnostic Diag{"undefined symbol"};
    Diag.SymbolName = Value.Name;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  if (Value.Section >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Value.Section;
    Diag.SymbolName = Value.Name;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  if (extendsBeyond(Value.Offset, Value.Size,
                    Sections[Value.Section].VirtualSize)) {
    Diagnostic Diag{"symbol extends beyond section virtual size"};
    Diag.Section = Value.Section;
    Diag.SymbolName = Value.Name;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  const auto Duplicate =
      std::find_if(Symbols.begin(), Symbols.end(), [&](const auto &Defined) {
        return Defined.Name == Value.Name;
      });
  if (Duplicate != Symbols.end()) {
    Diagnostic Diag{"duplicate symbol definition"};
    Diag.SymbolName = Value.Name;
    Diag.Section = Value.Section;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  if (Symbols.size() >= InvalidSymbolId) {
    return fail<SymbolId>(Diagnostic{"too many symbols"});
  }
  const SymbolId Id{static_cast<uint32_t>(Symbols.size())};
  Symbols.push_back(std::move(Value));
  return Id;
}

LinkExpect<void> LinkGraph::addRelocation(Relocation Value) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (Value.Section >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Value.Section;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (Value.Symbol >= Symbols.size()) {
    Diagnostic Diag{"invalid symbol ID"};
    Diag.Section = Value.Section;
    Diag.Symbol = Value.Symbol;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  const auto Canonical = relocationPatchSize(Value.Format, TargetValue,
                                             Value.Type, Value.PatchSize);
  if (!Canonical) {
    Diagnostic Diag{"unsupported relocation patch size"};
    Diag.Section = Value.Section;
    Diag.Symbol = Value.Symbol;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (*Canonical != Value.PatchSize) {
    Diagnostic Diag{"invalid relocation patch size"};
    Diag.Section = Value.Section;
    Diag.Symbol = Value.Symbol;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (extendsBeyond(Value.Offset, Value.PatchSize,
                    Sections[Value.Section].Content.size())) {
    Diagnostic Diag{"relocation offset is outside section content"};
    Diag.Section = Value.Section;
    Diag.Symbol = Value.Symbol;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (Value.PatchSize != NoPatch &&
      std::any_of(Relocations.begin(), Relocations.end(), [&](const auto &Old) {
        if (Old.PatchSize == NoPatch) {
          return false;
        }
        return overlaps(Value, Old,
                        [](const auto &RelocationValue) {
                          return RelocationValue.PatchSize;
                        }) &&
               !composeRISCVSymbolDifference(Value, Old);
      })) {
    Diagnostic Diag{"overlapping relocation patches"};
    Diag.Section = Value.Section;
    Diag.Symbol = Value.Symbol;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  Relocations.push_back(Value);
  return {};
}

void LinkGraph::removeEHFrameRelocations(Span<const uint8_t> Remove) {
  size_t Out = 0;
  for (size_t I = 0; I < Relocations.size(); ++I) {
    if (!Remove[I])
      Relocations[Out++] = Relocations[I];
  }
  Relocations.resize(Out);
}

LinkExpect<void> LinkGraph::addRebase(Rebase Value) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (Value.Section >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Value.Section;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  const uint8_t Width = std::max<uint8_t>(Value.Width, MinimumRebaseWidth);
  if (extendsBeyond(Value.Offset, Width,
                    Sections[Value.Section].Content.size())) {
    Diagnostic Diag{"rebase offset is outside section content"};
    Diag.Section = Value.Section;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (std::any_of(Rebases.begin(), Rebases.end(), [&](const auto &Old) {
        return overlaps(Value, Old, [](const auto &RebaseValue) {
          return std::max<uint8_t>(RebaseValue.Width, MinimumRebaseWidth);
        });
      })) {
    Diagnostic Diag{"overlapping rebase patches"};
    Diag.Section = Value.Section;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  Rebases.push_back(Value);
  return {};
}

LinkExpect<void> LinkGraph::addEHFrameReference(EHFrameReference Value) {
  if (Value.Section >= Sections.size() || Value.Symbol >= Symbols.size() ||
      Sections[Value.Section].Purpose != SectionPurpose::EHFrame ||
      extendsBeyond(Value.Offset, 8, Sections[Value.Section].Content.size()))
    return fail<void>(Diagnostic{"invalid EH frame reference"});
  EHFrameReferences.push_back(Value);
  return {};
}

LinkExpect<void> LinkGraph::validate() const {
  if (!InputName) {
    return fail<void>(Diagnostic{"link graph requires one input object"});
  }
  for (SectionId I = 0; I < Sections.size(); ++I) {
    const auto &Value = Sections[I];
    if (Value.Alignment == 0 ||
        (Value.Alignment & (Value.Alignment - 1)) != 0) {
      Diagnostic Diag{"section alignment must be a non-zero power of two"};
      Diag.Section = I;
      Diag.SectionName = Value.Name;
      return fail<void>(std::move(Diag));
    }
    if (Value.Content.size() > Value.VirtualSize) {
      Diagnostic Diag{"section content exceeds section virtual size"};
      Diag.Section = I;
      Diag.SectionName = Value.Name;
      return fail<void>(std::move(Diag));
    }
    if (Value.LinkedSection && *Value.LinkedSection >= Sections.size()) {
      Diagnostic Diag{"invalid linked section ID"};
      Diag.Section = I;
      Diag.SectionName = Value.Name;
      return fail<void>(std::move(Diag));
    }
  }
  for (size_t I = 0; I < Symbols.size(); ++I) {
    const auto &Value = Symbols[I];
    if (Value.Section >= Sections.size()) {
      Diagnostic Diag{"invalid section ID"};
      Diag.Section = Value.Section;
      Diag.Symbol = static_cast<SymbolId>(I);
      Diag.SymbolName = Value.Name;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (extendsBeyond(Value.Offset, Value.Size,
                      Sections[Value.Section].VirtualSize)) {
      Diagnostic Diag{"symbol extends beyond section virtual size"};
      Diag.Section = Value.Section;
      Diag.Symbol = static_cast<SymbolId>(I);
      Diag.SymbolName = Value.Name;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
  }
  for (const auto &Value : Relocations) {
    if (Value.Section >= Sections.size()) {
      Diagnostic Diag{"invalid section ID"};
      Diag.Section = Value.Section;
      Diag.Symbol = Value.Symbol;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (Value.Symbol >= Symbols.size()) {
      Diagnostic Diag{"invalid symbol ID"};
      Diag.Section = Value.Section;
      Diag.Symbol = Value.Symbol;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    const auto Canonical = relocationPatchSize(Value.Format, TargetValue,
                                               Value.Type, Value.PatchSize);
    if (!Canonical || *Canonical != Value.PatchSize) {
      Diagnostic Diag{Canonical ? "invalid relocation patch size"
                                : "unsupported relocation patch size"};
      Diag.Section = Value.Section;
      Diag.Symbol = Value.Symbol;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (extendsBeyond(Value.Offset, Value.PatchSize,
                      Sections[Value.Section].Content.size())) {
      Diagnostic Diag{"relocation offset is outside section content"};
      Diag.Section = Value.Section;
      Diag.Symbol = Value.Symbol;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
  }
  for (size_t I = 0; I < Relocations.size(); ++I) {
    for (size_t J = I + 1; J < Relocations.size(); ++J) {
      if (Relocations[I].PatchSize != NoPatch &&
          Relocations[J].PatchSize != NoPatch &&
          overlaps(Relocations[I], Relocations[J],
                   [](const auto &Value) { return Value.PatchSize; }) &&
          !composeRISCVSymbolDifference(Relocations[I], Relocations[J])) {
        return fail<void>(Diagnostic{"overlapping relocation patches"});
      }
    }
  }
  for (const auto &Value : Relocations) {
    if (!isRISCVSymbolDifference(Value))
      continue;
    const auto Pair = std::count_if(
        Relocations.begin(), Relocations.end(), [&](const auto &Other) {
          return composeRISCVSymbolDifference(Value, Other);
        });
    if (Pair != 1)
      return fail<void>(Diagnostic{"unpaired RISC-V symbol difference"});
  }
  for (const auto &Value : Rebases) {
    if (Value.Section >= Sections.size()) {
      Diagnostic Diag{"invalid section ID"};
      Diag.Section = Value.Section;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (extendsBeyond(Value.Offset,
                      std::max<uint8_t>(Value.Width, MinimumRebaseWidth),
                      Sections[Value.Section].Content.size())) {
      Diagnostic Diag{"rebase offset is outside section content"};
      Diag.Section = Value.Section;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
  }
  for (size_t I = 0; I < Rebases.size(); ++I) {
    for (size_t J = I + 1; J < Rebases.size(); ++J) {
      if (overlaps(Rebases[I], Rebases[J], [](const auto &Value) {
            return std::max<uint8_t>(Value.Width, MinimumRebaseWidth);
          })) {
        return fail<void>(Diagnostic{"overlapping rebase patches"});
      }
    }
  }
  return {};
}

LinkExpect<void> LinkGraph::setSectionAddress(SectionId Id, uint64_t Address) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (Id >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Id;
    return fail<void>(std::move(Diag));
  }
  Sections[Id].Address = Address;
  return {};
}

LinkExpect<void> LinkGraph::setSectionFileOffset(SectionId Id,
                                                 uint64_t FileOffset) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (Id >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Id;
    return fail<void>(std::move(Diag));
  }
  Sections[Id].FileOffset = FileOffset;
  return {};
}

LinkExpect<void> LinkGraph::setELFFlags(uint32_t Flags) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (FormatValue != ObjectFormat::ELF) {
    return fail<void>(Diagnostic{"ELF flags require an ELF link graph"});
  }
  ELFFlags = Flags;
  return {};
}

LinkExpect<void> LinkGraph::setLinkedSection(SectionId Id, SectionId Linked) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (Id >= Sections.size() || Linked >= Sections.size()) {
    return fail<void>(Diagnostic{"invalid linked section ID"});
  }
  Sections[Id].LinkedSection = Linked;
  return {};
}

LinkExpect<Span<Byte>> LinkGraph::sectionContent(SectionId Id) {
  if (RelocationsApplied) {
    return fail<Span<Byte>>(
        Diagnostic{"link graph relocations already applied"});
  }
  if (Id >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Id;
    return fail<Span<Byte>>(std::move(Diag));
  }
  return Span<Byte>(Sections[Id].Content.data(), Sections[Id].Content.size());
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
