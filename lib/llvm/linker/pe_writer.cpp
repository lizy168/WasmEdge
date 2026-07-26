// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/pe_writer.h"

#include <llvm/BinaryFormat/COFF.h>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

constexpr uint64_t ImageBase = UINT64_C(0x180000000);
constexpr uint32_t SectionAlignment = 4096;
constexpr uint32_t FileAlignment = 512;
constexpr uint32_t PEOffset = 0x80;
constexpr uint32_t OptionalHeaderSize = 240;
constexpr uint32_t SectionHeaderSize = 40;
constexpr uint32_t FixedHeaderSize = PEOffset + 4 + 20 + OptionalHeaderSize;

Expect<void> fail() noexcept { return Unexpect(ErrCode::Value::IllegalPath); }

bool add(uint64_t Left, uint64_t Right, uint64_t &Result) noexcept {
  if (Left > UINT64_MAX - Right)
    return false;
  Result = Left + Right;
  return true;
}

bool multiply(uint64_t Left, uint64_t Right, uint64_t &Result) noexcept {
  if (Left != 0 && Right > UINT64_MAX / Left)
    return false;
  Result = Left * Right;
  return true;
}

bool align(uint64_t Value, uint64_t Alignment, uint64_t &Result) noexcept {
  uint64_t Sum = 0;
  if (!add(Value, Alignment - 1, Sum))
    return false;
  Result = Sum & ~(Alignment - 1);
  return true;
}

void put(std::vector<Byte> &Bytes, uint64_t Offset, uint64_t Value,
         uint8_t Width) {
  for (uint8_t I = 0; I < Width; ++I)
    Bytes[Offset + I] = static_cast<Byte>(Value >> (I * 8));
}

uint32_t get32(Span<const Byte> Bytes, size_t Offset) noexcept {
  uint32_t Result = 0;
  for (uint8_t I = 0; I < 4; ++I)
    Result |= static_cast<uint32_t>(Bytes[Offset + I]) << (I * 8);
  return Result;
}

std::string outputName(const Section &Value) {
  if (Value.Purpose == SectionPurpose::PData)
    return ".pdata";
  if (Value.Purpose == SectionPurpose::XData)
    return ".xdata";
  switch (Value.Kind) {
  case SectionKind::Text:
    return ".text";
  case SectionKind::ReadOnly:
    return ".rdata";
  case SectionKind::Data:
    return ".data";
  case SectionKind::BSS:
    return ".bss";
  case SectionKind::Unwind:
    return ".rdata";
  }
  return {};
}

uint32_t characteristics(std::string_view Name) noexcept {
  if (Name == ".text")
    return llvm::COFF::IMAGE_SCN_CNT_CODE | llvm::COFF::IMAGE_SCN_MEM_EXECUTE |
           llvm::COFF::IMAGE_SCN_MEM_READ;
  if (Name == ".data")
    return llvm::COFF::IMAGE_SCN_CNT_INITIALIZED_DATA |
           llvm::COFF::IMAGE_SCN_MEM_READ | llvm::COFF::IMAGE_SCN_MEM_WRITE;
  if (Name == ".bss")
    return llvm::COFF::IMAGE_SCN_CNT_UNINITIALIZED_DATA |
           llvm::COFF::IMAGE_SCN_MEM_READ | llvm::COFF::IMAGE_SCN_MEM_WRITE;
  return llvm::COFF::IMAGE_SCN_CNT_INITIALIZED_DATA |
         llvm::COFF::IMAGE_SCN_MEM_READ;
}

struct OutputSection {
  std::string Name;
  uint32_t RVA = 0;
  uint32_t VirtualSize = 0;
  uint32_t FileOffset = 0;
  uint32_t FileSize = 0;
  uint32_t Characteristics = 0;
  std::vector<Byte> Content;
};

bool containsRVA(const LinkGraph &Graph, SectionKind Kind, uint32_t RVA,
                 bool AllowEnd = false) noexcept {
  for (const auto &Section : Graph.sections()) {
    if (Section.Kind != Kind || Section.Address < ImageBase)
      continue;
    const uint64_t Start = Section.Address - ImageBase;
    const uint64_t End = Start + Section.VirtualSize;
    if (RVA >= Start && (AllowEnd ? RVA <= End : RVA < End))
      return true;
  }
  return false;
}

bool containsXDataRVA(const LinkGraph &Graph, uint32_t RVA) noexcept {
  for (const auto &Section : Graph.sections()) {
    if (Section.Purpose != SectionPurpose::XData || Section.Address < ImageBase)
      continue;
    const uint64_t Start = Section.Address - ImageBase;
    if (RVA >= Start && RVA - Start < Section.VirtualSize)
      return true;
  }
  return false;
}

std::optional<uint32_t> arm64UnwindLength(const LinkGraph &Graph,
                                          uint32_t RVA) noexcept {
  for (const auto &Section : Graph.sections()) {
    if (Section.Purpose != SectionPurpose::XData || Section.Address < ImageBase)
      continue;
    const uint64_t Start = Section.Address - ImageBase;
    if (RVA < Start || RVA - Start > Section.Content.size() ||
        4 > Section.Content.size() - (RVA - Start))
      continue;
    const Span<const Byte> Header(Section.Content.data() + (RVA - Start), 4);
    return get32(Header, 0) & UINT32_C(0x3FFFF);
  }
  return std::nullopt;
}

bool normalizePData(const LinkGraph &Graph, OutputSection &PData) {
  const size_t EntrySize = Graph.target() == Target::X86_64 ? 12 : 8;
  std::vector<SectionId> PDataSections;
  for (SectionId I = 0; I < Graph.sections().size(); ++I)
    if (Graph.sections()[I].Purpose == SectionPurpose::PData) {
      if (Graph.sections()[I].VirtualSize % EntrySize != 0)
        return false;
      if (Graph.sections()[I].Content.size() != Graph.sections()[I].VirtualSize)
        return false;
      PDataSections.push_back(I);
    }
  for (const auto &Symbol : Graph.symbols())
    if (std::find(PDataSections.begin(), PDataSections.end(), Symbol.Section) !=
            PDataSections.end() &&
        (Symbol.Exported || Symbol.Size != 0))
      return false;
  for (const auto &Relocation : Graph.relocations())
    if (std::find(PDataSections.begin(), PDataSections.end(),
                  Graph.symbols()[Relocation.Symbol].Section) !=
        PDataSections.end())
      return false;
  struct Entry {
    uint32_t Begin;
    uint32_t End;
    bool HasEnd;
    std::vector<Byte> Bytes;
  };
  std::vector<Entry> Entries;
  for (const SectionId Id : PDataSections) {
    const auto &Section = Graph.sections()[Id];
    for (size_t Offset = 0; Offset < Section.Content.size();
         Offset += EntrySize) {
      const Span<const Byte> Bytes(Section.Content.data() + Offset, EntrySize);
      const uint32_t Begin = get32(Bytes, 0);
      uint32_t End = Begin;
      bool HasEnd = false;
      if (!containsRVA(Graph, SectionKind::Text, Begin))
        return false;
      if (Graph.target() == Target::X86_64) {
        End = get32(Bytes, 4);
        const uint32_t Unwind = get32(Bytes, 8);
        if (End <= Begin || !containsRVA(Graph, SectionKind::Text, End, true) ||
            !containsXDataRVA(Graph, Unwind))
          return false;
        HasEnd = true;
      } else {
        const uint32_t Unwind = get32(Bytes, 4);
        if ((Unwind & 3) == 0) {
          const auto FunctionLength = arm64UnwindLength(Graph, Unwind);
          if (!FunctionLength || *FunctionLength == 0 ||
              Begin > UINT32_MAX - *FunctionLength * 4)
            return false;
          End = Begin + *FunctionLength * 4;
          if (!containsRVA(Graph, SectionKind::Text, End, true))
            return false;
          HasEnd = true;
        } else {
          if ((Unwind & 3) == 3)
            return false;
          const uint32_t FunctionLength = (Unwind >> 2) & 0x7FF;
          if (FunctionLength == 0 || Begin > UINT32_MAX - FunctionLength * 4)
            return false;
          End = Begin + FunctionLength * 4;
          if (!containsRVA(Graph, SectionKind::Text, End, true))
            return false;
          HasEnd = true;
        }
      }
      Entries.push_back(Entry{Begin, End, HasEnd,
                              std::vector<Byte>(Bytes.begin(), Bytes.end())});
    }
  }
  std::sort(Entries.begin(), Entries.end(),
            [](const auto &Left, const auto &Right) {
              return Left.Begin < Right.Begin;
            });
  for (size_t I = 1; I < Entries.size(); ++I)
    if (Entries[I - 1].Begin == Entries[I].Begin ||
        (Entries[I - 1].HasEnd && Entries[I - 1].End > Entries[I].Begin))
      return false;
  PData.Content.resize(Entries.size() * EntrySize);
  PData.VirtualSize = static_cast<uint32_t>(PData.Content.size());
  size_t Offset = 0;
  for (const auto &Entry : Entries) {
    std::copy(Entry.Bytes.begin(), Entry.Bytes.end(),
              PData.Content.begin() +
                  static_cast<std::vector<Byte>::difference_type>(Offset));
    Offset += EntrySize;
  }
  return true;
}

bool appendSection(std::vector<OutputSection> &Sections, std::string Name,
                   uint64_t &RVA, uint64_t &FileOffset,
                   std::vector<Byte> Content, uint64_t VirtualSize) {
  uint64_t RawSize = 0;
  uint64_t NextRVA = 0;
  uint64_t NextFile = 0;
  if (!align(Content.size(), FileAlignment, RawSize) ||
      !add(RVA, VirtualSize, NextRVA) ||
      !align(NextRVA, SectionAlignment, NextRVA) ||
      !add(FileOffset, RawSize, NextFile) || RVA > UINT32_MAX ||
      FileOffset > UINT32_MAX || VirtualSize > UINT32_MAX ||
      RawSize > UINT32_MAX || NextRVA > UINT32_MAX || NextFile > UINT32_MAX)
    return false;
  Sections.push_back(OutputSection{
      std::move(Name), static_cast<uint32_t>(RVA),
      static_cast<uint32_t>(VirtualSize), static_cast<uint32_t>(FileOffset),
      static_cast<uint32_t>(RawSize), 0, std::move(Content)});
  Sections.back().Characteristics = characteristics(Sections.back().Name);
  RVA = NextRVA;
  FileOffset = NextFile;
  return true;
}

bool fitsSize(uint64_t Value) noexcept {
#if SIZE_MAX < UINT64_MAX
  return Value <= SIZE_MAX;
#else
  (void)Value;
  return true;
#endif
}

} // namespace

bool Internal::validPEExportCount(size_t Count) noexcept {
  constexpr size_t MaximumExportCount = UINT16_MAX + size_t{1};
  return Count <= MaximumExportCount;
}

Expect<void> PEWriter::layout(LinkGraph &Graph) noexcept {
  try {
    if (Graph.format() != ObjectFormat::COFF || Graph.relocationsApplied() ||
        !Graph.validate() || Graph.endianness() != Endianness::Little ||
        (Graph.target() != Target::X86_64 && Graph.target() != Target::AArch64))
      return fail();
    std::map<std::string, std::vector<SectionId>> Groups;
    for (SectionId I = 0; I < Graph.sections().size(); ++I)
      Groups[outputName(Graph.sections()[I])].push_back(I);
    constexpr std::array<std::string_view, 6> Order{
        ".text", ".rdata", ".data", ".bss", ".pdata", ".xdata"};
    uint64_t HeaderBytes = 0;
    if (!add(FixedHeaderSize,
             (Groups.size() + 2) * static_cast<uint64_t>(SectionHeaderSize),
             HeaderBytes) ||
        !align(HeaderBytes, FileAlignment, HeaderBytes) ||
        HeaderBytes > UINT32_MAX)
      return fail();
    uint64_t RVA = SectionAlignment;
    uint64_t FileOffset = HeaderBytes;
    std::vector<std::pair<uint64_t, uint64_t>> Placement(
        Graph.sections().size());
    for (const auto Name : Order) {
      auto Group = Groups.find(std::string(Name));
      if (Group == Groups.end())
        continue;
      uint64_t GroupAlignment = SectionAlignment;
      for (const SectionId Id : Group->second)
        GroupAlignment =
            std::max(GroupAlignment, Graph.sections()[Id].Alignment);
      if (!align(RVA, GroupAlignment, RVA))
        return fail();
      uint64_t GroupOffset = 0;
      for (const SectionId Id : Group->second) {
        const auto &Input = Graph.sections()[Id];
        if (!align(GroupOffset, Input.Alignment, GroupOffset))
          return fail();
        uint64_t Address = 0;
        uint64_t End = 0;
        if (!add(ImageBase, RVA, Address) ||
            !add(Address, GroupOffset, Address) ||
            !add(GroupOffset, Input.VirtualSize, End) || End > UINT32_MAX)
          return fail();
        Placement[Id] = {Address, Input.Kind == SectionKind::BSS
                                      ? 0
                                      : FileOffset + GroupOffset};
        GroupOffset = End;
      }
      if (!add(RVA, GroupOffset, RVA) || !align(RVA, SectionAlignment, RVA) ||
          RVA > UINT32_MAX)
        return fail();
      if (Name != ".bss") {
        uint64_t RawSize = 0;
        if (!align(GroupOffset, FileAlignment, RawSize) ||
            !add(FileOffset, RawSize, FileOffset) || FileOffset > UINT32_MAX)
          return fail();
      }
    }
    for (SectionId I = 0; I < Placement.size(); ++I)
      if (!Graph.setSectionAddress(I, Placement[I].first) ||
          !Graph.setSectionFileOffset(I, Placement[I].second))
        return fail();
    return {};
  } catch (...) {
    return fail();
  }
}

Expect<void> PEWriter::write(const LinkGraph &Graph, std::string_view DLLName,
                             Writer &Output) noexcept {
  try {
    if (!Graph.relocationsApplied() || Graph.format() != ObjectFormat::COFF ||
        !Graph.validate() || DLLName.empty() ||
        DLLName.find('\0') != DLLName.npos)
      return fail();
    std::map<std::string, OutputSection> Inputs;
    for (const auto &Input : Graph.sections()) {
      const std::string Name = outputName(Input);
      const uint64_t InputRVA64 = Input.Address - ImageBase;
      if (Input.Address < ImageBase || InputRVA64 > UINT32_MAX ||
          Input.VirtualSize > UINT32_MAX)
        return fail();
      auto &Section = Inputs[Name];
      Section.Name = Name;
      if (Section.RVA == 0) {
        Section.RVA = static_cast<uint32_t>(InputRVA64);
        Section.FileOffset = static_cast<uint32_t>(Input.FileOffset);
      }
      const uint64_t Offset = InputRVA64 - Section.RVA;
      uint64_t End = 0;
      if (InputRVA64 < Section.RVA || !add(Offset, Input.VirtualSize, End) ||
          End > UINT32_MAX || !fitsSize(End))
        return fail();
      Section.VirtualSize =
          std::max(Section.VirtualSize, static_cast<uint32_t>(End));
      if (Input.Kind != SectionKind::BSS) {
        Section.Content.resize(static_cast<size_t>(End));
        std::copy(Input.Content.begin(), Input.Content.end(),
                  Section.Content.begin() +
                      static_cast<std::vector<Byte>::difference_type>(Offset));
      }
      Section.Characteristics = characteristics(Name);
    }
    if (auto PData = Inputs.find(".pdata");
        PData != Inputs.end() && !normalizePData(Graph, PData->second))
      return fail();
    constexpr std::array<std::string_view, 6> Order{
        ".text", ".rdata", ".data", ".bss", ".pdata", ".xdata"};
    std::vector<OutputSection> Sections;
    uint64_t RVA = SectionAlignment;
    uint64_t FileOffset = 0;
    for (const auto Name : Order) {
      auto Found = Inputs.find(std::string(Name));
      if (Found == Inputs.end())
        continue;
      auto Section = std::move(Found->second);
      uint64_t RawSize = 0;
      if (!align(Section.Content.size(), FileAlignment, RawSize) ||
          RawSize > UINT32_MAX)
        return fail();
      Section.FileSize = static_cast<uint32_t>(RawSize);
      Sections.push_back(std::move(Section));
      RVA = std::max<uint64_t>(RVA, Sections.back().RVA +
                                        Sections.back().VirtualSize);
      FileOffset = std::max<uint64_t>(FileOffset, Sections.back().FileOffset +
                                                      Sections.back().FileSize);
    }
    if (!align(RVA, SectionAlignment, RVA) ||
        !align(FileOffset, FileAlignment, FileOffset))
      return fail();

    std::vector<const Symbol *> Exports;
    for (const auto &Symbol : Graph.symbols())
      if (Symbol.Exported)
        Exports.push_back(&Symbol);
    std::sort(Exports.begin(), Exports.end(),
              [](const auto *Left, const auto *Right) {
                const auto &L =
                    Left->ExportName ? *Left->ExportName : Left->Name;
                const auto &R =
                    Right->ExportName ? *Right->ExportName : Right->Name;
                return std::tie(L, Left->Name) < std::tie(R, Right->Name);
              });
    if (!Internal::validPEExportCount(Exports.size()))
      return fail();
    for (size_t I = 1; I < Exports.size(); ++I) {
      const auto &L = Exports[I - 1]->ExportName ? *Exports[I - 1]->ExportName
                                                 : Exports[I - 1]->Name;
      const auto &R =
          Exports[I]->ExportName ? *Exports[I]->ExportName : Exports[I]->Name;
      if (L == R)
        return fail();
    }
    uint64_t ExportTableSize = 0;
    uint64_t ExportSize = 0;
    if (!multiply(Exports.size(), 10, ExportTableSize) ||
        !add(40, ExportTableSize, ExportSize) ||
        !add(ExportSize, DLLName.size(), ExportSize) ||
        !add(ExportSize, 1, ExportSize))
      return fail();
    for (const auto *Symbol : Exports) {
      const auto &Name =
          Symbol->ExportName ? *Symbol->ExportName : Symbol->Name;
      if (!add(ExportSize, Name.size() + 1, ExportSize))
        return fail();
    }
    if (ExportSize > UINT32_MAX || !fitsSize(ExportSize))
      return fail();
    std::vector<Byte> EData(static_cast<size_t>(ExportSize));
    if (RVA > UINT32_MAX)
      return fail();
    const uint32_t ExportRVA = static_cast<uint32_t>(RVA);
    uint64_t Cursor64 = 0;
    uint64_t DLLNameRVA64 = 0;
    if (!add(40, ExportTableSize, Cursor64) || Cursor64 > UINT32_MAX ||
        !add(ExportRVA, Cursor64, DLLNameRVA64) || DLLNameRVA64 > UINT32_MAX)
      return fail();
    uint32_t Cursor = static_cast<uint32_t>(Cursor64);
    const uint32_t DLLNameRVA = static_cast<uint32_t>(DLLNameRVA64);
    std::copy(DLLName.begin(), DLLName.end(), EData.begin() + Cursor);
    Cursor += static_cast<uint32_t>(DLLName.size()) + 1;
    put(EData, 12, DLLNameRVA, 4);
    put(EData, 16, 1, 4);
    put(EData, 20, Exports.size(), 4);
    put(EData, 24, Exports.size(), 4);
    put(EData, 28, ExportRVA + 40, 4);
    uint64_t NameTableRVA = 0;
    uint64_t OrdinalTableRVA = 0;
    uint64_t TableBytes = 0;
    uint64_t AddressTableRVA = 0;
    if (!add(ExportRVA, 40, AddressTableRVA) ||
        !multiply(Exports.size(), 4, TableBytes) ||
        !add(AddressTableRVA, TableBytes, NameTableRVA) ||
        !add(NameTableRVA, TableBytes, OrdinalTableRVA) ||
        OrdinalTableRVA > UINT32_MAX)
      return fail();
    put(EData, 32, NameTableRVA, 4);
    put(EData, 36, OrdinalTableRVA, 4);
    for (size_t I = 0; I < Exports.size(); ++I) {
      const auto &Symbol = *Exports[I];
      const uint64_t Address =
          Graph.sections()[Symbol.Section].Address + Symbol.Offset;
      if (Address < ImageBase || Address - ImageBase > UINT32_MAX)
        return fail();
      uint64_t NameRVA = 0;
      if (!add(ExportRVA, Cursor, NameRVA) || NameRVA > UINT32_MAX)
        return fail();
      put(EData, 40 + I * 4, Address - ImageBase, 4);
      put(EData, 40 + Exports.size() * 4 + I * 4, NameRVA, 4);
      put(EData, 40 + Exports.size() * 8 + I * 2, I, 2);
      const auto &Name = Symbol.ExportName ? *Symbol.ExportName : Symbol.Name;
      std::copy(Name.begin(), Name.end(), EData.begin() + Cursor);
      Cursor += static_cast<uint32_t>(Name.size()) + 1;
    }
    if (!appendSection(Sections, ".edata", RVA, FileOffset, std::move(EData),
                       ExportSize))
      return fail();

    std::map<uint32_t, std::vector<uint16_t>> RelocationPages;
    for (const auto &Rebase : Graph.rebases()) {
      const uint32_t Required =
          Graph.target() == Target::X86_64
              ? static_cast<uint32_t>(llvm::COFF::IMAGE_REL_AMD64_ADDR64)
              : static_cast<uint32_t>(llvm::COFF::IMAGE_REL_ARM64_ADDR64);
      if (Rebase.Format != ObjectFormat::COFF || Rebase.Type != Required ||
          Rebase.Width != 8 || Rebase.Section >= Graph.sections().size() ||
          Rebase.Offset > Graph.sections()[Rebase.Section].Content.size() ||
          8 > Graph.sections()[Rebase.Section].Content.size() - Rebase.Offset)
        return fail();
      const uint64_t Address =
          Graph.sections()[Rebase.Section].Address + Rebase.Offset;
      if (Address < ImageBase || Address - ImageBase > UINT32_MAX)
        return fail();
      const uint32_t Slot = static_cast<uint32_t>(Address - ImageBase);
      RelocationPages[Slot & ~UINT32_C(0xFFF)].push_back(static_cast<uint16_t>(
          (llvm::COFF::IMAGE_REL_BASED_DIR64 << 12) | (Slot & 0xFFF)));
    }
    std::vector<Byte> Reloc;
    for (auto &[Page, Entries] : RelocationPages) {
      std::sort(Entries.begin(), Entries.end());
      if (Entries.size() % 2 != 0)
        Entries.push_back(llvm::COFF::IMAGE_REL_BASED_ABSOLUTE << 12);
      const size_t Start = Reloc.size();
      Reloc.resize(Start + 8 + Entries.size() * 2);
      put(Reloc, Start, Page, 4);
      put(Reloc, Start + 4, 8 + Entries.size() * 2, 4);
      for (size_t I = 0; I < Entries.size(); ++I)
        put(Reloc, Start + 8 + I * 2, Entries[I], 2);
    }
    const uint32_t RelocRVA = static_cast<uint32_t>(RVA);
    const uint32_t RelocSize = static_cast<uint32_t>(Reloc.size());
    if (!appendSection(Sections, ".reloc", RVA, FileOffset, std::move(Reloc),
                       RelocSize))
      return fail();
    if (Sections.size() > UINT16_MAX || RVA > UINT32_MAX ||
        !fitsSize(FileOffset))
      return fail();

    const uint32_t HeaderSize = Sections.front().FileOffset;
    if (HeaderSize < FixedHeaderSize + Sections.size() * SectionHeaderSize ||
        HeaderSize % FileAlignment != 0)
      return fail();
    std::vector<Byte> Bytes(static_cast<size_t>(FileOffset));
    Bytes[0] = 'M';
    Bytes[1] = 'Z';
    put(Bytes, 0x3C, PEOffset, 4);
    Bytes[0x40] = 0x0E;
    Bytes[0x41] = 0x1F;
    Bytes[0x42] = 0xBA;
    put(Bytes, PEOffset, UINT32_C(0x00004550), 4);
    const size_t COFF = PEOffset + 4;
    put(Bytes, COFF,
        Graph.target() == Target::X86_64 ? llvm::COFF::IMAGE_FILE_MACHINE_AMD64
                                         : llvm::COFF::IMAGE_FILE_MACHINE_ARM64,
        2);
    put(Bytes, COFF + 2, Sections.size(), 2);
    put(Bytes, COFF + 16, OptionalHeaderSize, 2);
    put(Bytes, COFF + 18,
        llvm::COFF::IMAGE_FILE_EXECUTABLE_IMAGE |
            llvm::COFF::IMAGE_FILE_LARGE_ADDRESS_AWARE |
            llvm::COFF::IMAGE_FILE_DLL,
        2);
    const size_t Optional = COFF + 20;
    put(Bytes, Optional, 0x20B, 2);
    uint64_t CodeSize = 0;
    uint64_t InitializedSize = 0;
    uint64_t UninitializedSize = 0;
    uint32_t CodeRVA = 0;
    for (const auto &Section : Sections) {
      if (Section.Name == ".text") {
        CodeSize += Section.FileSize;
        CodeRVA = Section.RVA;
      } else if (Section.Name == ".bss") {
        UninitializedSize += Section.VirtualSize;
      } else {
        InitializedSize += Section.FileSize;
      }
    }
    if (CodeSize > UINT32_MAX || InitializedSize > UINT32_MAX ||
        UninitializedSize > UINT32_MAX)
      return fail();
    put(Bytes, Optional + 4, CodeSize, 4);
    put(Bytes, Optional + 8, InitializedSize, 4);
    put(Bytes, Optional + 12, UninitializedSize, 4);
    put(Bytes, Optional + 20, CodeRVA, 4);
    put(Bytes, Optional + 24, ImageBase, 8);
    put(Bytes, Optional + 32, SectionAlignment, 4);
    put(Bytes, Optional + 36, FileAlignment, 4);
    put(Bytes, Optional + 40, 6, 2);
    put(Bytes, Optional + 48, 6, 2);
    put(Bytes, Optional + 56, RVA, 4);
    put(Bytes, Optional + 60, HeaderSize, 4);
    put(Bytes, Optional + 68, llvm::COFF::IMAGE_SUBSYSTEM_WINDOWS_CUI, 2);
    put(Bytes, Optional + 70,
        llvm::COFF::IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA |
            llvm::COFF::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE |
            llvm::COFF::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT,
        2);
    put(Bytes, Optional + 72, UINT64_C(0x100000), 8);
    put(Bytes, Optional + 80, UINT64_C(0x1000), 8);
    put(Bytes, Optional + 88, UINT64_C(0x100000), 8);
    put(Bytes, Optional + 96, UINT64_C(0x1000), 8);
    put(Bytes, Optional + 108, 16, 4);
    put(Bytes, Optional + 112, ExportRVA, 4);
    put(Bytes, Optional + 116, ExportSize, 4);
    const auto PData =
        std::find_if(Sections.begin(), Sections.end(), [](const auto &Section) {
          return Section.Name == ".pdata";
        });
    if (PData != Sections.end()) {
      const uint32_t EntrySize = Graph.target() == Target::X86_64 ? 12 : 8;
      if (PData->VirtualSize % EntrySize != 0)
        return fail();
      put(Bytes, Optional + 112 + 3 * 8, PData->RVA, 4);
      put(Bytes, Optional + 116 + 3 * 8, PData->VirtualSize, 4);
    }
    if (RelocSize != 0) {
      put(Bytes, Optional + 112 + 5 * 8, RelocRVA, 4);
      put(Bytes, Optional + 116 + 5 * 8, RelocSize, 4);
    }
    for (size_t I = 0; I < Sections.size(); ++I) {
      const auto &Section = Sections[I];
      const size_t Header =
          Optional + OptionalHeaderSize + I * SectionHeaderSize;
      std::copy(Section.Name.begin(), Section.Name.end(),
                Bytes.begin() +
                    static_cast<std::vector<Byte>::difference_type>(Header));
      put(Bytes, Header + 8, Section.VirtualSize, 4);
      put(Bytes, Header + 12, Section.RVA, 4);
      put(Bytes, Header + 16, Section.FileSize, 4);
      put(Bytes, Header + 20, Section.FileSize == 0 ? 0 : Section.FileOffset,
          4);
      put(Bytes, Header + 36, Section.Characteristics, 4);
      if (!Section.Content.empty())
        std::copy(Section.Content.begin(), Section.Content.end(),
                  Bytes.begin() + Section.FileOffset);
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
