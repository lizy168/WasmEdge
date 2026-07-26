// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/macho_writer.h"

#include <llvm/BinaryFormat/MachO.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <numeric>
#include <tuple>
#include <vector>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

constexpr uint64_t X86PageSize = 4096;
constexpr uint64_t ARMPageSize = 16384;
constexpr uint64_t HeaderSize = 32;
constexpr uint64_t SegmentCommandSize = 72;
constexpr uint64_t SectionCommandSize = 80;
constexpr uint64_t DyldInfoCommandSize = 48;
constexpr uint64_t SymtabCommandSize = 24;
constexpr uint64_t DysymtabCommandSize = 80;
constexpr uint64_t BuildVersionCommandSize = 24;
constexpr uint64_t DylibCommandPrefixSize = 24;
constexpr uint64_t CodeSignatureCommandSize = 16;
constexpr std::string_view InstallName = "@rpath/libwasmedge-aot.dylib";

Expect<void> fail() noexcept { return Unexpect(ErrCode::Value::IllegalPath); }

bool add(uint64_t A, uint64_t B, uint64_t &Result) noexcept {
  if (A > UINT64_MAX - B)
    return false;
  Result = A + B;
  return true;
}

bool align(uint64_t Value, uint64_t Alignment, uint64_t &Result) noexcept {
  const uint64_t Mask = Alignment - 1;
  return add(Value, Mask, Result) && ((Result &= ~Mask), true);
}

uint64_t pageSize(Target Architecture) noexcept {
  return Architecture == Target::AArch64 ? ARMPageSize : X86PageSize;
}

bool supported(const LinkGraph &Graph) noexcept {
  const bool HasEH = std::any_of(
      Graph.sections().begin(), Graph.sections().end(), [](const auto &Value) {
        return Value.Purpose == SectionPurpose::EHFrame;
      });
  const bool HasCompact = std::any_of(
      Graph.sections().begin(), Graph.sections().end(), [](const auto &Value) {
        return Value.Purpose == SectionPurpose::CompactUnwind;
      });
  return Graph.format() == ObjectFormat::MachO &&
         Graph.endianness() == Endianness::Little &&
         (Graph.target() == Target::X86_64 ||
          Graph.target() == Target::AArch64) &&
         HasEH && !HasCompact;
}

uint64_t dylibCommandSize() noexcept {
  uint64_t Result = DylibCommandPrefixSize + InstallName.size() + 1;
  return (Result + 7) & ~UINT64_C(7);
}

uint64_t loadCommandSize(const LinkGraph &Graph) noexcept {
  return SegmentCommandSize * 4 + SectionCommandSize * Graph.sections().size() +
         DyldInfoCommandSize + SymtabCommandSize + DysymtabCommandSize +
         BuildVersionCommandSize + dylibCommandSize();
}

void put(std::vector<Byte> &Bytes, uint64_t Offset, uint64_t Value,
         uint8_t Width) {
  for (uint8_t I = 0; I < Width; ++I)
    Bytes[Offset + I] = static_cast<Byte>(Value >> (I * 8));
}

void putName(std::vector<Byte> &Bytes, uint64_t Offset, std::string_view Name) {
  std::copy_n(Name.begin(), std::min<size_t>(Name.size(), 16),
              Bytes.begin() + Offset);
}

void appendULEB(std::vector<Byte> &Bytes, uint64_t Value) {
  do {
    uint8_t Current = static_cast<uint8_t>(Value & 0x7F);
    Value >>= 7;
    if (Value != 0)
      Current |= 0x80;
    Bytes.push_back(Current);
  } while (Value != 0);
}

size_t ulebSize(uint64_t Value) noexcept {
  size_t Result = 1;
  while ((Value >>= 7) != 0)
    ++Result;
  return Result;
}

struct Export {
  std::string Name;
  uint64_t Address;
};

std::optional<std::vector<Byte>> exportTrie(const LinkGraph &Graph) {
  std::vector<Export> Exports;
  for (const auto &SymbolValue : Graph.symbols()) {
    if (!SymbolValue.Exported)
      continue;
    const auto &Name =
        SymbolValue.ExportName ? *SymbolValue.ExportName : SymbolValue.Name;
    Exports.push_back({Name, Graph.sections()[SymbolValue.Section].Address +
                                 SymbolValue.Offset});
  }
  std::sort(Exports.begin(), Exports.end(),
            [](const auto &L, const auto &R) { return L.Name < R.Name; });
  for (size_t I = 1; I < Exports.size(); ++I)
    if (Exports[I - 1].Name == Exports[I].Name)
      return std::nullopt;
  if (Exports.size() > UINT8_MAX)
    return std::nullopt;
  size_t RootSize = 2;
  for (const auto &Value : Exports)
    RootSize += Value.Name.size() + 1 + 1;
  for (;;) {
    size_t Cursor = RootSize;
    size_t NewRootSize = 2;
    for (const auto &Value : Exports) {
      NewRootSize += Value.Name.size() + 1 + ulebSize(Cursor);
      Cursor += 3 + ulebSize(Value.Address);
    }
    if (NewRootSize == RootSize)
      break;
    RootSize = NewRootSize;
  }
  std::vector<Byte> Result{0, static_cast<Byte>(Exports.size())};
  size_t Cursor = RootSize;
  for (const auto &Value : Exports) {
    Result.insert(Result.end(), Value.Name.begin(), Value.Name.end());
    Result.push_back(0);
    appendULEB(Result, Cursor);
    Cursor += 3 + ulebSize(Value.Address);
  }
  for (const auto &Value : Exports) {
    Result.push_back(static_cast<Byte>(1 + ulebSize(Value.Address)));
    Result.push_back(llvm::MachO::EXPORT_SYMBOL_FLAGS_KIND_REGULAR);
    appendULEB(Result, Value.Address);
    Result.push_back(0);
  }
  return Result;
}

struct Segment {
  std::string_view Name;
  uint64_t Address;
  uint64_t Size;
  uint64_t FileOffset;
  uint64_t FileSize;
  uint32_t MaxProtection;
  uint32_t InitialProtection;
  std::vector<SectionId> Sections;
};

std::optional<std::vector<Segment>> segments(const LinkGraph &Graph,
                                             uint64_t LinkEditOffset,
                                             uint64_t LinkEditSize) {
  std::vector<SectionId> Text;
  std::vector<SectionId> Constant;
  std::vector<SectionId> Data;
  for (SectionId I = 0; I < Graph.sections().size(); ++I) {
    const auto Kind = Graph.sections()[I].Kind;
    if (Kind == SectionKind::Data || Kind == SectionKind::BSS)
      Data.push_back(I);
    else if (Kind == SectionKind::ReadOnly)
      Constant.push_back(I);
    else
      Text.push_back(I);
  }
  const uint64_t Page = pageSize(Graph.target());
  uint64_t TextEnd = HeaderSize + loadCommandSize(Graph);
  uint64_t DataStart = LinkEditOffset;
  uint64_t DataEnd = 0;
  uint64_t DataFileEnd = 0;
  for (const auto Id : Text) {
    const auto &SectionValue = Graph.sections()[Id];
    TextEnd =
        std::max(TextEnd, SectionValue.Address + SectionValue.VirtualSize);
  }
  uint64_t ConstantStart = LinkEditOffset;
  uint64_t ConstantEnd = 0;
  for (const auto Id : Constant) {
    const auto &SectionValue = Graph.sections()[Id];
    ConstantStart = std::min(ConstantStart, SectionValue.Address);
    ConstantEnd =
        std::max(ConstantEnd, SectionValue.Address + SectionValue.VirtualSize);
  }
  uint64_t ConstantFileEnd = ConstantStart;
  for (const auto Id : Constant)
    ConstantFileEnd =
        std::max(ConstantFileEnd, Graph.sections()[Id].FileOffset +
                                      Graph.sections()[Id].Content.size());
  for (const auto Id : Data) {
    const auto &SectionValue = Graph.sections()[Id];
    DataStart = std::min(DataStart, SectionValue.Address);
    DataEnd =
        std::max(DataEnd, SectionValue.Address + SectionValue.VirtualSize);
    if (SectionValue.Kind != SectionKind::BSS)
      DataFileEnd = std::max(DataFileEnd, SectionValue.FileOffset +
                                              SectionValue.Content.size());
  }
  uint64_t TextSize = 0;
  if (!align(TextEnd, Page, TextSize))
    return std::nullopt;
  if (Data.empty())
    DataStart = TextSize;
  return std::vector<Segment>{
      {"__TEXT", 0, TextSize, 0, TextSize,
       llvm::MachO::VM_PROT_READ | llvm::MachO::VM_PROT_EXECUTE,
       llvm::MachO::VM_PROT_READ | llvm::MachO::VM_PROT_EXECUTE,
       std::move(Text)},
      {"__DATA_CONST", ConstantStart,
       Constant.empty() ? 0 : ConstantEnd - ConstantStart, ConstantStart,
       Constant.empty() ? 0 : ConstantFileEnd - ConstantStart,
       llvm::MachO::VM_PROT_READ | llvm::MachO::VM_PROT_WRITE,
       llvm::MachO::VM_PROT_READ, std::move(Constant)},
      {"__DATA", DataStart, Data.empty() ? 0 : DataEnd - DataStart, DataStart,
       Data.empty() || DataFileEnd <= DataStart ? 0 : DataFileEnd - DataStart,
       llvm::MachO::VM_PROT_READ | llvm::MachO::VM_PROT_WRITE,
       llvm::MachO::VM_PROT_READ | llvm::MachO::VM_PROT_WRITE, std::move(Data)},
      {"__LINKEDIT",
       LinkEditOffset,
       LinkEditSize,
       LinkEditOffset,
       LinkEditSize,
       llvm::MachO::VM_PROT_READ,
       llvm::MachO::VM_PROT_READ,
       {}}};
}

uint32_t sectionFlags(const Section &SectionValue) noexcept {
  if (SectionValue.Kind == SectionKind::BSS)
    return llvm::MachO::S_ZEROFILL;
  if (SectionValue.Kind == SectionKind::Text)
    return llvm::MachO::S_REGULAR | llvm::MachO::S_ATTR_PURE_INSTRUCTIONS |
           llvm::MachO::S_ATTR_SOME_INSTRUCTIONS;
  return llvm::MachO::S_REGULAR;
}

uint32_t alignmentPower(uint64_t Alignment) noexcept {
  uint32_t Result = 0;
  while (Alignment > 1) {
    Alignment >>= 1;
    ++Result;
  }
  return Result;
}

} // namespace

Expect<void> MachOWriter::layout(LinkGraph &Graph) noexcept {
  try {
    if (!supported(Graph) || Graph.relocationsApplied() || !Graph.validate())
      return fail();
    uint64_t Cursor = 0;
    if (!add(HeaderSize, loadCommandSize(Graph), Cursor) ||
        !add(Cursor, CodeSignatureCommandSize, Cursor) ||
        !align(Cursor, 16, Cursor))
      return fail();
    std::vector<std::pair<uint64_t, uint64_t>> Placements(
        Graph.sections().size());
    const std::array<SectionKind, 5> Kinds{
        SectionKind::Text, SectionKind::Unwind, SectionKind::ReadOnly,
        SectionKind::Data, SectionKind::BSS};
    for (const auto Kind : Kinds) {
      if ((Kind == SectionKind::ReadOnly || Kind == SectionKind::Data) &&
          !align(Cursor, pageSize(Graph.target()), Cursor))
        return fail();
      std::vector<SectionId> Order;
      for (SectionId I = 0; I < Graph.sections().size(); ++I)
        if (Graph.sections()[I].Kind == Kind)
          Order.push_back(I);
      std::sort(Order.begin(), Order.end(), [&](auto L, auto R) {
        return std::tie(Graph.sections()[L].Name, L) <
               std::tie(Graph.sections()[R].Name, R);
      });
      for (const auto Id : Order) {
        const auto &SectionValue = Graph.sections()[Id];
        if (!align(Cursor, SectionValue.Alignment, Cursor))
          return fail();
        Placements[Id] = {Cursor,
                          Kind == SectionKind::BSS ? uint64_t{0} : Cursor};
        if (!add(Cursor, SectionValue.VirtualSize, Cursor))
          return fail();
      }
    }
    for (SectionId I = 0; I < Placements.size(); ++I)
      if (!Graph.setSectionAddress(I, Placements[I].first) ||
          !Graph.setSectionFileOffset(I, Placements[I].second))
        return fail();
    return {};
  } catch (...) {
    return fail();
  }
}

Expect<void> MachOWriter::write(const LinkGraph &Graph,
                                Writer &Output) noexcept {
  try {
    if (!supported(Graph) || !Graph.relocationsApplied() || !Graph.validate())
      return fail();
    if (Graph.sections().size() > UINT8_MAX ||
        Graph.symbols().size() > UINT32_MAX ||
        loadCommandSize(Graph) > UINT32_MAX)
      return fail();
    for (const auto &Value : Graph.rebases())
      if (Value.Format != ObjectFormat::MachO || Value.Width != 8 ||
          Value.Type !=
              static_cast<uint32_t>(Graph.target() == Target::X86_64
                                        ? llvm::MachO::X86_64_RELOC_UNSIGNED
                                        : llvm::MachO::ARM64_RELOC_UNSIGNED))
        return fail();

    auto Exports = exportTrie(Graph);
    if (!Exports)
      return fail();
    std::vector<const Symbol *> Symbols;
    for (const auto &Value : Graph.symbols())
      Symbols.push_back(&Value);
    std::stable_sort(Symbols.begin(), Symbols.end(),
                     [](const auto *L, const auto *R) {
                       return std::tuple(L->Global, L->Name) <
                              std::tuple(R->Global, R->Name);
                     });
    std::vector<Byte> Strings(1);
    std::vector<uint32_t> StringOffsets;
    for (const auto *Value : Symbols) {
      if (Strings.size() + Value->Name.size() + 1 > UINT32_MAX)
        return fail();
      StringOffsets.push_back(static_cast<uint32_t>(Strings.size()));
      Strings.insert(Strings.end(), Value->Name.begin(), Value->Name.end());
      Strings.push_back(0);
    }
    std::vector<Byte> RebaseStream;
    if (!Graph.rebases().empty()) {
      RebaseStream.push_back(llvm::MachO::REBASE_OPCODE_SET_TYPE_IMM |
                             llvm::MachO::REBASE_TYPE_POINTER);
      std::vector<const Linker::Rebase *> Ordered;
      for (const auto &Value : Graph.rebases())
        Ordered.push_back(&Value);
      std::sort(
          Ordered.begin(), Ordered.end(), [&](const auto *L, const auto *R) {
            return std::tie(Graph.sections()[L->Section].Address, L->Offset) <
                   std::tie(Graph.sections()[R->Section].Address, R->Offset);
          });
      for (const auto *Value : Ordered) {
        const auto Kind = Graph.sections()[Value->Section].Kind;
        const uint8_t SegmentIndex = Kind == SectionKind::ReadOnly ? 1 : 2;
        uint64_t SegmentAddress = UINT64_MAX;
        for (const auto &SectionValue : Graph.sections())
          if ((SegmentIndex == 1 &&
               SectionValue.Kind == SectionKind::ReadOnly) ||
              (SegmentIndex == 2 && (SectionValue.Kind == SectionKind::Data ||
                                     SectionValue.Kind == SectionKind::BSS)))
            SegmentAddress = std::min(SegmentAddress, SectionValue.Address);
        if (SegmentAddress == UINT64_MAX)
          return fail();
        RebaseStream.push_back(
            llvm::MachO::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB |
            SegmentIndex);
        const uint64_t Address =
            Graph.sections()[Value->Section].Address + Value->Offset;
        if (Address < SegmentAddress)
          return fail();
        appendULEB(RebaseStream, Address - SegmentAddress);
        RebaseStream.push_back(llvm::MachO::REBASE_OPCODE_DO_REBASE_IMM_TIMES |
                               1);
      }
      RebaseStream.push_back(llvm::MachO::REBASE_OPCODE_DONE);
    }

    uint64_t GraphEnd = HeaderSize + loadCommandSize(Graph);
    for (const auto &SectionValue : Graph.sections())
      GraphEnd =
          std::max(GraphEnd, SectionValue.Address + SectionValue.VirtualSize);
    uint64_t LinkEditOffset = 0;
    if (!align(GraphEnd, pageSize(Graph.target()), LinkEditOffset))
      return fail();
    uint64_t RebaseOffset = LinkEditOffset;
    uint64_t ExportOffset = RebaseOffset + RebaseStream.size();
    uint64_t SymbolOffset = 0;
    if (!align(ExportOffset + Exports->size(), 8, SymbolOffset))
      return fail();
    uint64_t StringOffset = SymbolOffset + Symbols.size() * 16;
    uint64_t FileSize = StringOffset + Strings.size();
    if (FileSize > std::numeric_limits<size_t>::max() || FileSize > UINT32_MAX)
      return fail();
    auto Segments = segments(Graph, LinkEditOffset, FileSize - LinkEditOffset);
    if (!Segments)
      return fail();
    for (const auto &SegmentValue : *Segments) {
      if (SegmentValue.Sections.size() > UINT32_MAX ||
          SegmentValue.Sections.size() >
              (UINT32_MAX - SegmentCommandSize) / SectionCommandSize)
        return fail();
    }
    std::vector<Byte> Bytes(static_cast<size_t>(FileSize));
    put(Bytes, 0, llvm::MachO::MH_MAGIC_64, 4);
    put(Bytes, 4,
        Graph.target() == Target::X86_64 ? llvm::MachO::CPU_TYPE_X86_64
                                         : llvm::MachO::CPU_TYPE_ARM64,
        4);
    put(Bytes, 8,
        Graph.target() == Target::X86_64
            ? static_cast<uint32_t>(llvm::MachO::CPU_SUBTYPE_X86_64_ALL)
            : static_cast<uint32_t>(llvm::MachO::CPU_SUBTYPE_ARM64_ALL),
        4);
    put(Bytes, 12, llvm::MachO::MH_DYLIB, 4);
    constexpr uint32_t CommandCount = 9;
    put(Bytes, 16, CommandCount, 4);
    put(Bytes, 20, loadCommandSize(Graph), 4);
    put(Bytes, 24,
        llvm::MachO::MH_NOUNDEFS | llvm::MachO::MH_DYLDLINK |
            llvm::MachO::MH_TWOLEVEL,
        4);

    uint64_t Command = HeaderSize;
    std::vector<uint8_t> SectionOrdinals(Graph.sections().size());
    uint32_t Ordinal = 1;
    for (const auto &SegmentValue : *Segments) {
      put(Bytes, Command, llvm::MachO::LC_SEGMENT_64, 4);
      put(Bytes, Command + 4,
          SegmentCommandSize +
              SectionCommandSize * SegmentValue.Sections.size(),
          4);
      putName(Bytes, Command + 8, SegmentValue.Name);
      put(Bytes, Command + 24, SegmentValue.Address, 8);
      put(Bytes, Command + 32, SegmentValue.Size, 8);
      put(Bytes, Command + 40, SegmentValue.FileOffset, 8);
      put(Bytes, Command + 48, SegmentValue.FileSize, 8);
      put(Bytes, Command + 56, SegmentValue.MaxProtection, 4);
      put(Bytes, Command + 60, SegmentValue.InitialProtection, 4);
      put(Bytes, Command + 64, SegmentValue.Sections.size(), 4);
      uint64_t SectionCommand = Command + SegmentCommandSize;
      for (const auto Id : SegmentValue.Sections) {
        const auto &SectionValue = Graph.sections()[Id];
        putName(Bytes, SectionCommand, SectionValue.Name);
        putName(Bytes, SectionCommand + 16, SegmentValue.Name);
        put(Bytes, SectionCommand + 32, SectionValue.Address, 8);
        put(Bytes, SectionCommand + 40, SectionValue.VirtualSize, 8);
        put(Bytes, SectionCommand + 48, SectionValue.FileOffset, 4);
        put(Bytes, SectionCommand + 52, alignmentPower(SectionValue.Alignment),
            4);
        put(Bytes, SectionCommand + 64, sectionFlags(SectionValue), 4);
        SectionOrdinals[Id] = static_cast<uint8_t>(Ordinal++);
        SectionCommand += SectionCommandSize;
      }
      Command += SegmentCommandSize +
                 SectionCommandSize * SegmentValue.Sections.size();
    }
    put(Bytes, Command, llvm::MachO::LC_DYLD_INFO_ONLY, 4);
    put(Bytes, Command + 4, DyldInfoCommandSize, 4);
    put(Bytes, Command + 8, RebaseOffset, 4);
    put(Bytes, Command + 12, RebaseStream.size(), 4);
    put(Bytes, Command + 40, ExportOffset, 4);
    put(Bytes, Command + 44, Exports->size(), 4);
    Command += DyldInfoCommandSize;
    put(Bytes, Command, llvm::MachO::LC_SYMTAB, 4);
    put(Bytes, Command + 4, SymtabCommandSize, 4);
    put(Bytes, Command + 8, SymbolOffset, 4);
    put(Bytes, Command + 12, Symbols.size(), 4);
    put(Bytes, Command + 16, StringOffset, 4);
    put(Bytes, Command + 20, Strings.size(), 4);
    Command += SymtabCommandSize;
    put(Bytes, Command, llvm::MachO::LC_DYSYMTAB, 4);
    put(Bytes, Command + 4, DysymtabCommandSize, 4);
    const auto FirstExternal = static_cast<uint32_t>(
        std::count_if(Symbols.begin(), Symbols.end(),
                      [](const auto *V) { return !V->Global; }));
    put(Bytes, Command + 8, 0, 4);
    put(Bytes, Command + 12, FirstExternal, 4);
    put(Bytes, Command + 16, FirstExternal, 4);
    put(Bytes, Command + 20, Symbols.size() - FirstExternal, 4);
    Command += DysymtabCommandSize;
    put(Bytes, Command, llvm::MachO::LC_ID_DYLIB, 4);
    put(Bytes, Command + 4, dylibCommandSize(), 4);
    put(Bytes, Command + 8, DylibCommandPrefixSize, 4);
    put(Bytes, Command + 16, UINT32_C(0x10000), 4);
    put(Bytes, Command + 20, UINT32_C(0x10000), 4);
    std::copy(InstallName.begin(), InstallName.end(),
              Bytes.begin() + Command + DylibCommandPrefixSize);
    Command += dylibCommandSize();
    put(Bytes, Command, llvm::MachO::LC_BUILD_VERSION, 4);
    put(Bytes, Command + 4, BuildVersionCommandSize, 4);
    put(Bytes, Command + 8, llvm::MachO::PLATFORM_MACOS, 4);
    put(Bytes, Command + 12, UINT32_C(0x000B0000), 4);
    put(Bytes, Command + 16, UINT32_C(0x000B0000), 4);

    for (const auto &SectionValue : Graph.sections())
      if (SectionValue.Kind != SectionKind::BSS)
        std::copy(SectionValue.Content.begin(), SectionValue.Content.end(),
                  Bytes.begin() + SectionValue.FileOffset);
    std::copy(RebaseStream.begin(), RebaseStream.end(),
              Bytes.begin() + RebaseOffset);
    std::copy(Exports->begin(), Exports->end(), Bytes.begin() + ExportOffset);
    for (size_t I = 0; I < Symbols.size(); ++I) {
      const auto &Value = *Symbols[I];
      const uint64_t Offset = SymbolOffset + I * 16;
      put(Bytes, Offset, StringOffsets[I], 4);
      Bytes[Offset + 4] =
          llvm::MachO::N_SECT | (Value.Global ? llvm::MachO::N_EXT : 0);
      Bytes[Offset + 5] = SectionOrdinals[Value.Section];
      put(Bytes, Offset + 8,
          Graph.sections()[Value.Section].Address + Value.Offset, 8);
    }
    std::copy(Strings.begin(), Strings.end(), Bytes.begin() + StringOffset);
    EXPECTED_TRY(Output.write(Bytes));
    return Output.close();
  } catch (...) {
    return fail();
  }
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
