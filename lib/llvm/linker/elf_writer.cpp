// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/elf_writer.h"

#include "linker/relocation.h"

#include <llvm/BinaryFormat/Dwarf.h>
#include <llvm/BinaryFormat/ELF.h>

#include <algorithm>
#include <limits>
#include <numeric>
#include <string>
#include <tuple>
#include <vector>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

constexpr uint64_t PageSize = 4096;
constexpr uint8_t ELFMagic0 = 0x7F;
constexpr uint8_t ELFMagic1 = 'E';
constexpr uint8_t ELFMagic2 = 'L';
constexpr uint8_t ELFMagic3 = 'F';

Expect<void> fail() noexcept { return Unexpect(ErrCode::Value::IllegalPath); }

bool add(uint64_t Left, uint64_t Right, uint64_t &Result) noexcept {
  if (Left > std::numeric_limits<uint64_t>::max() - Right)
    return false;
  Result = Left + Right;
  return true;
}

bool align(uint64_t Value, uint64_t Alignment, uint64_t &Result) noexcept {
  const uint64_t Mask = Alignment - 1;
  return add(Value, Mask, Result) && ((Result &= ~Mask), true);
}

bool is64(Target Value) noexcept { return Value != Target::ARM; }

uint16_t machine(Target Value) noexcept {
  switch (Value) {
  case Target::ARM:
    return llvm::ELF::EM_ARM;
  case Target::X86_64:
    return llvm::ELF::EM_X86_64;
  case Target::AArch64:
    return llvm::ELF::EM_AARCH64;
  case Target::RISCV64:
    return llvm::ELF::EM_RISCV;
  case Target::S390X:
    return llvm::ELF::EM_S390;
  }
  return llvm::ELF::EM_NONE;
}

uint32_t relativeType(Target Value) noexcept {
  switch (Value) {
  case Target::ARM:
    return llvm::ELF::R_ARM_RELATIVE;
  case Target::X86_64:
    return llvm::ELF::R_X86_64_RELATIVE;
  case Target::AArch64:
    return llvm::ELF::R_AARCH64_RELATIVE;
  case Target::RISCV64:
    return llvm::ELF::R_RISCV_RELATIVE;
  case Target::S390X:
    return llvm::ELF::R_390_RELATIVE;
  }
  return 0;
}

bool validRebase(const LinkGraph &Graph, const Rebase &Value) noexcept {
  const uint8_t Width = is64(Graph.target()) ? 8 : 4;
  if (Value.Format != ObjectFormat::ELF || Value.Width != Width)
    return false;
  switch (Graph.target()) {
  case Target::ARM:
    return Value.Type == llvm::ELF::R_ARM_ABS32 ||
           Value.Type == llvm::ELF::R_ARM_RELATIVE;
  case Target::X86_64:
    return Value.Type == llvm::ELF::R_X86_64_64 ||
           Value.Type == llvm::ELF::R_X86_64_RELATIVE;
  case Target::AArch64:
    return Value.Type == llvm::ELF::R_AARCH64_ABS64 ||
           Value.Type == llvm::ELF::R_AARCH64_RELATIVE;
  case Target::RISCV64:
    return Value.Type == llvm::ELF::R_RISCV_64 ||
           Value.Type == llvm::ELF::R_RISCV_RELATIVE;
  case Target::S390X:
    return Value.Type == llvm::ELF::R_390_64 ||
           Value.Type == llvm::ELF::R_390_RELATIVE;
  }
  return false;
}

void put(std::vector<Byte> &Bytes, uint64_t Offset, uint64_t Value,
         uint8_t Width, Endianness Endian) {
  for (uint8_t I = 0; I < Width; ++I) {
    const uint8_t Shift = Endian == Endianness::Little ? I : Width - I - 1;
    Bytes[Offset + I] = static_cast<Byte>(Value >> (Shift * 8));
  }
}

uint64_t get(Span<const Byte> Bytes, uint64_t Offset, uint8_t Width,
             Endianness Endian) {
  uint64_t Result = 0;
  for (uint8_t I = 0; I < Width; ++I) {
    const uint8_t Shift = Endian == Endianness::Little ? I : Width - I - 1;
    Result |= static_cast<uint64_t>(Bytes[Offset + I]) << (Shift * 8);
  }
  return Result;
}

uint32_t hash(std::string_view Name) noexcept {
  uint32_t Result = 0;
  for (const unsigned char Character : Name) {
    Result = (Result << 4) + Character;
    const uint32_t High = Result & UINT32_C(0xF0000000);
    if (High != 0)
      Result ^= High >> 24;
    Result &= ~High;
  }
  return Result;
}

struct OutputSection {
  std::string Name;
  uint32_t Type = llvm::ELF::SHT_PROGBITS;
  uint64_t Flags = 0;
  uint64_t Address = 0;
  uint64_t Offset = 0;
  uint64_t Size = 0;
  uint32_t Link = 0;
  uint32_t Info = 0;
  uint64_t Alignment = 1;
  uint64_t EntrySize = 0;
  std::vector<Byte> Content;
};

uint64_t sectionFlags(SectionKind Kind) noexcept {
  switch (Kind) {
  case SectionKind::Text:
    return llvm::ELF::SHF_ALLOC | llvm::ELF::SHF_EXECINSTR;
  case SectionKind::ReadOnly:
  case SectionKind::Unwind:
    return llvm::ELF::SHF_ALLOC;
  case SectionKind::Data:
  case SectionKind::BSS:
    return llvm::ELF::SHF_ALLOC | llvm::ELF::SHF_WRITE;
  }
  return 0;
}

std::vector<SectionId> order(const LinkGraph &Graph, SectionKind Kind) {
  std::vector<SectionId> Result;
  for (SectionId I = 0; I < Graph.sections().size(); ++I)
    if (Graph.sections()[I].Kind == Kind)
      Result.push_back(I);
  std::sort(Result.begin(), Result.end(), [&](SectionId Left, SectionId Right) {
    return std::tie(Graph.sections()[Left].Name, Left) <
           std::tie(Graph.sections()[Right].Name, Right);
  });
  return Result;
}

} // namespace

Expect<void> ELFWriter::layout(LinkGraph &Graph) noexcept {
  try {
    if (Graph.format() != ObjectFormat::ELF || Graph.relocationsApplied() ||
        !Graph.validate() || machine(Graph.target()) == llvm::ELF::EM_NONE ||
        (Graph.target() == Target::S390X
             ? Graph.endianness() != Endianness::Big
             : Graph.endianness() != Endianness::Little))
      return fail();
    const uint64_t HeaderSize = is64(Graph.target()) ? 64 : 52;
    const uint64_t ProgramHeaderSize = is64(Graph.target()) ? 56 : 32;
    constexpr uint64_t MaximumProgramHeaders = 8;
    uint64_t Cursor = 0;
    if (!add(HeaderSize, ProgramHeaderSize * MaximumProgramHeaders, Cursor) ||
        !align(Cursor, PageSize, Cursor))
      return fail();
    const std::array<SectionKind, 5> Kinds{
        SectionKind::Text, SectionKind::ReadOnly, SectionKind::Unwind,
        SectionKind::Data, SectionKind::BSS};
    for (const auto Kind : Kinds) {
      if (Kind != SectionKind::Text && !align(Cursor, PageSize, Cursor))
        return fail();
      for (const SectionId Id : order(Graph, Kind)) {
        const auto &SectionValue = Graph.sections()[Id];
        if (!align(Cursor, SectionValue.Alignment, Cursor) ||
            !Graph.setSectionAddress(Id, Cursor) ||
            !Graph.setSectionFileOffset(
                Id, Kind == SectionKind::BSS ? 0 : Cursor) ||
            !add(Cursor, SectionValue.VirtualSize, Cursor))
          return fail();
      }
    }
    return {};
  } catch (...) {
    return fail();
  }
}

Expect<void> ELFWriter::write(const LinkGraph &Graph, Writer &Output) noexcept {
  try {
    if (!Graph.relocationsApplied() || Graph.format() != ObjectFormat::ELF ||
        !Graph.validate())
      return fail();
    for (const auto &RebaseValue : Graph.rebases())
      if (!validRebase(Graph, RebaseValue))
        return fail();
    const bool Wide = is64(Graph.target());
    const uint8_t AddressSize = Wide ? 8 : 4;
    const uint64_t ELFHeaderSize = Wide ? 64 : 52;
    const uint64_t ProgramHeaderSize = Wide ? 56 : 32;
    const uint64_t SectionHeaderSize = Wide ? 64 : 40;
    const uint64_t SymbolSize = Wide ? 24 : 16;
    const uint64_t RelocationSize = Wide ? 24 : 8;
    const uint64_t DynamicSize = Wide ? 16 : 8;
    const auto Endian = Graph.endianness();

    std::vector<OutputSection> Sections(1);
    std::vector<uint32_t> GraphSectionIndices(Graph.sections().size());
    for (SectionId I = 0; I < Graph.sections().size(); ++I) {
      const auto &Input = Graph.sections()[I];
      GraphSectionIndices[I] = static_cast<uint32_t>(Sections.size());
      Sections.push_back(OutputSection{
          Input.Name,
          Input.Kind == SectionKind::BSS ? llvm::ELF::SHT_NOBITS
                                         : llvm::ELF::SHT_PROGBITS,
          sectionFlags(Input.Kind), Input.Address, Input.FileOffset,
          Input.VirtualSize, 0, 0, Input.Alignment, 0, Input.Content});
    }

    uint64_t Cursor = 0;
    for (const auto &SectionValue : Graph.sections())
      if (!add(std::max(Cursor, SectionValue.Address), SectionValue.VirtualSize,
               Cursor))
        return fail();
    if (!align(Cursor, PageSize, Cursor))
      return fail();

    const auto EH =
        std::find_if(Graph.sections().begin(), Graph.sections().end(),
                     [](const auto &Value) {
                       return Value.Purpose == SectionPurpose::EHFrame;
                     });
    uint32_t EHHeaderIndex = 0;
    if (EH != Graph.sections().end()) {
      constexpr uint64_t EHHeaderSize = 12;
      OutputSection Header{".eh_frame_hdr",
                           llvm::ELF::SHT_PROGBITS,
                           llvm::ELF::SHF_ALLOC | llvm::ELF::SHF_WRITE,
                           Cursor,
                           Cursor,
                           EHHeaderSize,
                           0,
                           0,
                           4,
                           0,
                           std::vector<Byte>(EHHeaderSize)};
      Header.Content[0] = 1;
      Header.Content[1] =
          llvm::dwarf::DW_EH_PE_pcrel | llvm::dwarf::DW_EH_PE_sdata4;
      Header.Content[2] = llvm::dwarf::DW_EH_PE_udata4;
      Header.Content[3] = llvm::dwarf::DW_EH_PE_omit;
      const int64_t Delta = static_cast<int64_t>(EH->Address) -
                            static_cast<int64_t>(Header.Address + 4);
      put(Header.Content, 4, static_cast<uint32_t>(Delta), 4, Endian);
      put(Header.Content, 8, 0, 4, Endian);
      EHHeaderIndex = static_cast<uint32_t>(Sections.size());
      Sections.push_back(std::move(Header));
      Cursor += EHHeaderSize;
    }

    std::vector<const Symbol *> Exports;
    for (const auto &SymbolValue : Graph.symbols())
      if (SymbolValue.Exported)
        Exports.push_back(&SymbolValue);
    std::sort(Exports.begin(), Exports.end(),
              [](const auto *Left, const auto *Right) {
                const auto &L =
                    Left->ExportName ? *Left->ExportName : Left->Name;
                const auto &R =
                    Right->ExportName ? *Right->ExportName : Right->Name;
                return L < R;
              });
    for (size_t I = 1; I < Exports.size(); ++I) {
      const auto &Left = Exports[I - 1]->ExportName
                             ? *Exports[I - 1]->ExportName
                             : Exports[I - 1]->Name;
      const auto &Right =
          Exports[I]->ExportName ? *Exports[I]->ExportName : Exports[I]->Name;
      if (Left == Right)
        return fail();
    }

    std::vector<Byte> DynStr(1);
    std::vector<uint32_t> NameOffsets;
    for (const auto *SymbolValue : Exports) {
      NameOffsets.push_back(static_cast<uint32_t>(DynStr.size()));
      const auto &Name = SymbolValue->ExportName ? *SymbolValue->ExportName
                                                 : SymbolValue->Name;
      DynStr.insert(DynStr.end(), Name.begin(), Name.end());
      DynStr.push_back(0);
    }
    if (!align(Cursor, AddressSize, Cursor))
      return fail();
    const uint32_t DynStrIndex = static_cast<uint32_t>(Sections.size());
    Sections.push_back(
        OutputSection{".dynstr", llvm::ELF::SHT_STRTAB,
                      llvm::ELF::SHF_ALLOC | llvm::ELF::SHF_WRITE, Cursor,
                      Cursor, DynStr.size(), 0, 0, 1, 0, std::move(DynStr)});
    Cursor += Sections.back().Size;

    if (!align(Cursor, AddressSize, Cursor))
      return fail();
    std::vector<Byte> DynSym((Exports.size() + 1) * SymbolSize);
    for (size_t I = 0; I < Exports.size(); ++I) {
      const auto &SymbolValue = *Exports[I];
      const uint64_t Offset = (I + 1) * SymbolSize;
      const uint8_t Type =
          Graph.sections()[SymbolValue.Section].Kind == SectionKind::Text
              ? llvm::ELF::STT_FUNC
              : llvm::ELF::STT_OBJECT;
      if (Wide) {
        put(DynSym, Offset, NameOffsets[I], 4, Endian);
        DynSym[Offset + 4] = llvm::ELF::STB_GLOBAL << 4 | Type;
        DynSym[Offset + 5] = llvm::ELF::STV_DEFAULT;
        put(DynSym, Offset + 6, GraphSectionIndices[SymbolValue.Section], 2,
            Endian);
        put(DynSym, Offset + 8,
            Graph.sections()[SymbolValue.Section].Address + SymbolValue.Offset,
            8, Endian);
        put(DynSym, Offset + 16, SymbolValue.Size, 8, Endian);
      } else {
        put(DynSym, Offset, NameOffsets[I], 4, Endian);
        put(DynSym, Offset + 4,
            Graph.sections()[SymbolValue.Section].Address + SymbolValue.Offset,
            4, Endian);
        put(DynSym, Offset + 8, SymbolValue.Size, 4, Endian);
        DynSym[Offset + 12] = llvm::ELF::STB_GLOBAL << 4 | Type;
        DynSym[Offset + 13] = llvm::ELF::STV_DEFAULT;
        put(DynSym, Offset + 14, GraphSectionIndices[SymbolValue.Section], 2,
            Endian);
      }
    }
    const uint32_t DynSymIndex = static_cast<uint32_t>(Sections.size());
    Sections.push_back(
        OutputSection{".dynsym", llvm::ELF::SHT_DYNSYM,
                      llvm::ELF::SHF_ALLOC | llvm::ELF::SHF_WRITE, Cursor,
                      Cursor, DynSym.size(), DynStrIndex, 1, AddressSize,
                      SymbolSize, std::move(DynSym)});
    Cursor += Sections.back().Size;

    if (!align(Cursor, 4, Cursor))
      return fail();
    const uint32_t BucketCount =
        std::max<uint32_t>(1, static_cast<uint32_t>(Exports.size()));
    std::vector<Byte> Hash((2 + BucketCount + Exports.size() + 1) * 4);
    put(Hash, 0, BucketCount, 4, Endian);
    put(Hash, 4, Exports.size() + 1, 4, Endian);
    for (size_t I = 0; I < Exports.size(); ++I) {
      const auto &Name =
          Exports[I]->ExportName ? *Exports[I]->ExportName : Exports[I]->Name;
      const uint32_t Index = static_cast<uint32_t>(I + 1);
      const uint32_t Bucket = hash(Name) % BucketCount;
      const uint64_t BucketOffset = (2 + Bucket) * 4;
      const uint32_t Previous =
          static_cast<uint32_t>(get(Hash, BucketOffset, 4, Endian));
      put(Hash, BucketOffset, Index, 4, Endian);
      if (Previous != 0)
        put(Hash, (2 + BucketCount + Index) * 4, Previous, 4, Endian);
    }
    const uint32_t HashIndex = static_cast<uint32_t>(Sections.size());
    Sections.push_back(OutputSection{
        ".hash", llvm::ELF::SHT_HASH,
        llvm::ELF::SHF_ALLOC | llvm::ELF::SHF_WRITE, Cursor, Cursor,
        Hash.size(), DynSymIndex, 0, 4, 4, std::move(Hash)});
    Cursor += Sections.back().Size;

    if (!align(Cursor, AddressSize, Cursor))
      return fail();
    std::vector<Byte> Relocations(Graph.rebases().size() * RelocationSize);
    for (size_t I = 0; I < Graph.rebases().size(); ++I) {
      const auto &RebaseValue = Graph.rebases()[I];
      const auto &TargetSection = Graph.sections()[RebaseValue.Section];
      const uint64_t Address = TargetSection.Address + RebaseValue.Offset;
      const uint64_t EntryOffset = I * RelocationSize;
      put(Relocations, EntryOffset, Address, AddressSize, Endian);
      if (Wide) {
        put(Relocations, EntryOffset + 8, relativeType(Graph.target()), 8,
            Endian);
        put(Relocations, EntryOffset + 16,
            get(TargetSection.Content, RebaseValue.Offset, AddressSize, Endian),
            8, Endian);
      } else {
        put(Relocations, EntryOffset + 4, relativeType(Graph.target()), 4,
            Endian);
      }
    }
    const uint32_t RelocationIndex = static_cast<uint32_t>(Sections.size());
    Sections.push_back(
        OutputSection{Wide ? ".rela.dyn" : ".rel.dyn",
                      Wide ? llvm::ELF::SHT_RELA : llvm::ELF::SHT_REL,
                      llvm::ELF::SHF_ALLOC | llvm::ELF::SHF_WRITE, Cursor,
                      Cursor, Relocations.size(), DynSymIndex, 0, AddressSize,
                      RelocationSize, std::move(Relocations)});
    Cursor += Sections.back().Size;

    if (!align(Cursor, PageSize, Cursor))
      return fail();
    const uint64_t DynamicAddress = Cursor;
    constexpr size_t DynamicTagCount = 10;
    std::vector<Byte> Dynamic(DynamicTagCount * DynamicSize);
    size_t DynamicIndex = 0;
    auto AddDynamic = [&](int64_t Tag, uint64_t Value) {
      const uint64_t Offset = DynamicIndex++ * DynamicSize;
      put(Dynamic, Offset, static_cast<uint64_t>(Tag), AddressSize, Endian);
      put(Dynamic, Offset + AddressSize, Value, AddressSize, Endian);
    };
    AddDynamic(llvm::ELF::DT_HASH, Sections[HashIndex].Address);
    AddDynamic(llvm::ELF::DT_STRTAB, Sections[DynStrIndex].Address);
    AddDynamic(llvm::ELF::DT_STRSZ, Sections[DynStrIndex].Size);
    AddDynamic(llvm::ELF::DT_SYMTAB, Sections[DynSymIndex].Address);
    AddDynamic(llvm::ELF::DT_SYMENT, SymbolSize);
    AddDynamic(Wide ? llvm::ELF::DT_RELA : llvm::ELF::DT_REL,
               Sections[RelocationIndex].Address);
    AddDynamic(Wide ? llvm::ELF::DT_RELASZ : llvm::ELF::DT_RELSZ,
               Sections[RelocationIndex].Size);
    AddDynamic(Wide ? llvm::ELF::DT_RELAENT : llvm::ELF::DT_RELENT,
               RelocationSize);
    AddDynamic(llvm::ELF::DT_NULL, 0);
    const uint32_t DynamicSectionIndex = static_cast<uint32_t>(Sections.size());
    Sections.push_back(
        OutputSection{".dynamic", llvm::ELF::SHT_DYNAMIC,
                      llvm::ELF::SHF_ALLOC | llvm::ELF::SHF_WRITE, Cursor,
                      Cursor, Dynamic.size(), DynStrIndex, 0, AddressSize,
                      DynamicSize, std::move(Dynamic)});
    Cursor += Sections.back().Size;

    std::vector<Byte> SectionNames(1);
    std::vector<uint32_t> SectionNameOffsets(Sections.size());
    for (size_t I = 1; I < Sections.size(); ++I) {
      SectionNameOffsets[I] = static_cast<uint32_t>(SectionNames.size());
      SectionNames.insert(SectionNames.end(), Sections[I].Name.begin(),
                          Sections[I].Name.end());
      SectionNames.push_back(0);
    }
    const uint32_t SectionNameIndex = static_cast<uint32_t>(Sections.size());
    SectionNameOffsets.push_back(static_cast<uint32_t>(SectionNames.size()));
    constexpr std::string_view SectionName = ".shstrtab";
    SectionNames.insert(SectionNames.end(), SectionName.begin(),
                        SectionName.end());
    SectionNames.push_back(0);
    if (!align(Cursor, 1, Cursor))
      return fail();
    Sections.push_back(OutputSection{".shstrtab", llvm::ELF::SHT_STRTAB, 0, 0,
                                     Cursor, SectionNames.size(), 0, 0, 1, 0,
                                     std::move(SectionNames)});
    Cursor += Sections.back().Size;
    uint64_t SectionHeaderOffset = 0;
    if (!align(Cursor, AddressSize, SectionHeaderOffset))
      return fail();
    uint64_t FileSize = 0;
    if (!add(SectionHeaderOffset, Sections.size() * SectionHeaderSize,
             FileSize) ||
        FileSize > std::numeric_limits<size_t>::max())
      return fail();

    struct Segment {
      uint32_t Type;
      uint32_t Flags;
      uint64_t Offset;
      uint64_t Address;
      uint64_t FileSize;
      uint64_t MemorySize;
      uint64_t Alignment;
    };
    std::vector<Segment> Segments;
    Segments.push_back({llvm::ELF::PT_LOAD, llvm::ELF::PF_R, 0, 0,
                        ELFHeaderSize + ProgramHeaderSize * 8,
                        ELFHeaderSize + ProgramHeaderSize * 8, PageSize});
    auto AddLoad = [&](uint32_t Flags, auto Predicate) {
      uint64_t First = UINT64_MAX;
      uint64_t FileEnd = 0;
      uint64_t MemoryEnd = 0;
      for (const auto &SectionValue : Sections) {
        if (!Predicate(SectionValue) || SectionValue.Size == 0)
          continue;
        First = std::min(First, SectionValue.Address);
        MemoryEnd =
            std::max(MemoryEnd, SectionValue.Address + SectionValue.Size);
        if (SectionValue.Type != llvm::ELF::SHT_NOBITS)
          FileEnd = std::max(FileEnd, SectionValue.Offset + SectionValue.Size);
      }
      if (First != UINT64_MAX) {
        const uint64_t Start = First & ~(PageSize - 1);
        Segments.push_back({llvm::ELF::PT_LOAD, Flags, Start, Start,
                            FileEnd > Start ? FileEnd - Start : 0,
                            MemoryEnd - Start, PageSize});
      }
    };
    AddLoad(llvm::ELF::PF_R | llvm::ELF::PF_X, [](const auto &Value) {
      return (Value.Flags & llvm::ELF::SHF_EXECINSTR) != 0;
    });
    AddLoad(llvm::ELF::PF_R, [](const auto &Value) {
      return (Value.Flags & llvm::ELF::SHF_ALLOC) != 0 &&
             (Value.Flags &
              (llvm::ELF::SHF_EXECINSTR | llvm::ELF::SHF_WRITE)) == 0;
    });
    AddLoad(llvm::ELF::PF_R | llvm::ELF::PF_W, [](const auto &Value) {
      return (Value.Flags & llvm::ELF::SHF_WRITE) != 0;
    });
    Segments.push_back({llvm::ELF::PT_DYNAMIC,
                        llvm::ELF::PF_R | llvm::ELF::PF_W, DynamicAddress,
                        DynamicAddress, Sections[DynamicSectionIndex].Size,
                        Sections[DynamicSectionIndex].Size, AddressSize});
    if (EHHeaderIndex != 0)
      Segments.push_back(
          {llvm::ELF::PT_GNU_EH_FRAME, llvm::ELF::PF_R,
           Sections[EHHeaderIndex].Offset, Sections[EHHeaderIndex].Address,
           Sections[EHHeaderIndex].Size, Sections[EHHeaderIndex].Size, 4});
    Segments.push_back({llvm::ELF::PT_GNU_STACK,
                        llvm::ELF::PF_R | llvm::ELF::PF_W, 0, 0, 0, 0,
                        AddressSize});
    if (Segments.size() > 8)
      return fail();

    std::vector<Byte> Bytes(static_cast<size_t>(FileSize));
    Bytes[0] = ELFMagic0;
    Bytes[1] = ELFMagic1;
    Bytes[2] = ELFMagic2;
    Bytes[3] = ELFMagic3;
    Bytes[llvm::ELF::EI_CLASS] =
        Wide ? llvm::ELF::ELFCLASS64 : llvm::ELF::ELFCLASS32;
    Bytes[llvm::ELF::EI_DATA] = Endian == Endianness::Little
                                    ? llvm::ELF::ELFDATA2LSB
                                    : llvm::ELF::ELFDATA2MSB;
    Bytes[llvm::ELF::EI_VERSION] = llvm::ELF::EV_CURRENT;
    Bytes[llvm::ELF::EI_OSABI] = llvm::ELF::ELFOSABI_NONE;
    put(Bytes, 16, llvm::ELF::ET_DYN, 2, Endian);
    put(Bytes, 18, machine(Graph.target()), 2, Endian);
    put(Bytes, 20, llvm::ELF::EV_CURRENT, 4, Endian);
    if (Wide) {
      put(Bytes, 32, ELFHeaderSize, 8, Endian);
      put(Bytes, 40, SectionHeaderOffset, 8, Endian);
      put(Bytes, 52, ELFHeaderSize, 2, Endian);
      put(Bytes, 54, ProgramHeaderSize, 2, Endian);
      put(Bytes, 56, Segments.size(), 2, Endian);
      put(Bytes, 58, SectionHeaderSize, 2, Endian);
      put(Bytes, 60, Sections.size(), 2, Endian);
      put(Bytes, 62, SectionNameIndex, 2, Endian);
    } else {
      put(Bytes, 28, ELFHeaderSize, 4, Endian);
      put(Bytes, 32, SectionHeaderOffset, 4, Endian);
      put(Bytes, 40, ELFHeaderSize, 2, Endian);
      put(Bytes, 42, ProgramHeaderSize, 2, Endian);
      put(Bytes, 44, Segments.size(), 2, Endian);
      put(Bytes, 46, SectionHeaderSize, 2, Endian);
      put(Bytes, 48, Sections.size(), 2, Endian);
      put(Bytes, 50, SectionNameIndex, 2, Endian);
    }
    for (size_t I = 0; I < Segments.size(); ++I) {
      const auto &SegmentValue = Segments[I];
      const uint64_t Offset = ELFHeaderSize + I * ProgramHeaderSize;
      put(Bytes, Offset, SegmentValue.Type, 4, Endian);
      if (Wide) {
        put(Bytes, Offset + 4, SegmentValue.Flags, 4, Endian);
        put(Bytes, Offset + 8, SegmentValue.Offset, 8, Endian);
        put(Bytes, Offset + 16, SegmentValue.Address, 8, Endian);
        put(Bytes, Offset + 24, SegmentValue.Address, 8, Endian);
        put(Bytes, Offset + 32, SegmentValue.FileSize, 8, Endian);
        put(Bytes, Offset + 40, SegmentValue.MemorySize, 8, Endian);
        put(Bytes, Offset + 48, SegmentValue.Alignment, 8, Endian);
      } else {
        put(Bytes, Offset + 4, SegmentValue.Offset, 4, Endian);
        put(Bytes, Offset + 8, SegmentValue.Address, 4, Endian);
        put(Bytes, Offset + 12, SegmentValue.Address, 4, Endian);
        put(Bytes, Offset + 16, SegmentValue.FileSize, 4, Endian);
        put(Bytes, Offset + 20, SegmentValue.MemorySize, 4, Endian);
        put(Bytes, Offset + 24, SegmentValue.Flags, 4, Endian);
        put(Bytes, Offset + 28, SegmentValue.Alignment, 4, Endian);
      }
    }
    for (size_t I = 1; I < Sections.size(); ++I) {
      const auto &SectionValue = Sections[I];
      if (SectionValue.Type != llvm::ELF::SHT_NOBITS &&
          !SectionValue.Content.empty())
        std::copy(SectionValue.Content.begin(), SectionValue.Content.end(),
                  Bytes.begin() + SectionValue.Offset);
      const uint64_t Offset = SectionHeaderOffset + I * SectionHeaderSize;
      put(Bytes, Offset, SectionNameOffsets[I], 4, Endian);
      put(Bytes, Offset + 4, SectionValue.Type, 4, Endian);
      if (Wide) {
        put(Bytes, Offset + 8, SectionValue.Flags, 8, Endian);
        put(Bytes, Offset + 16, SectionValue.Address, 8, Endian);
        put(Bytes, Offset + 24, SectionValue.Offset, 8, Endian);
        put(Bytes, Offset + 32, SectionValue.Size, 8, Endian);
        put(Bytes, Offset + 40, SectionValue.Link, 4, Endian);
        put(Bytes, Offset + 44, SectionValue.Info, 4, Endian);
        put(Bytes, Offset + 48, SectionValue.Alignment, 8, Endian);
        put(Bytes, Offset + 56, SectionValue.EntrySize, 8, Endian);
      } else {
        put(Bytes, Offset + 8, SectionValue.Flags, 4, Endian);
        put(Bytes, Offset + 12, SectionValue.Address, 4, Endian);
        put(Bytes, Offset + 16, SectionValue.Offset, 4, Endian);
        put(Bytes, Offset + 20, SectionValue.Size, 4, Endian);
        put(Bytes, Offset + 24, SectionValue.Link, 4, Endian);
        put(Bytes, Offset + 28, SectionValue.Info, 4, Endian);
        put(Bytes, Offset + 32, SectionValue.Alignment, 4, Endian);
        put(Bytes, Offset + 36, SectionValue.EntrySize, 4, Endian);
      }
    }
    EXPECTED_TRY(Output.write(Bytes));
    return Output.close();
  } catch (...) {
    return fail();
  }
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
