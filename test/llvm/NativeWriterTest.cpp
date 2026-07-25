// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/elf_writer.h"
#include "linker/macho_writer.h"
#include "linker/native_linker.h"
#include "linker/pe_writer.h"
#include "linker/relocation.h"

#include <gtest/gtest.h>

#include <llvm/BinaryFormat/COFF.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/BinaryFormat/MachO.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBufferRef.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>
#if !WASMEDGE_OS_WINDOWS
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

using namespace WasmEdge::LLVM::Linker;

LinkGraph makePEGraph(Target Architecture) {
  LinkGraph Graph(Architecture, Endianness::Little, ObjectFormat::COFF);
  EXPECT_TRUE(Graph.beginInput("writer.obj"));
  auto Text = Graph.addSection(
      Section{".text$f", SectionKind::Text, 16, 4, 0, 0,
              Architecture == Target::X86_64
                  ? std::vector<WasmEdge::Byte>{0xC3, 0, 0, 0}
                  : std::vector<WasmEdge::Byte>{0xC0, 0x03, 0x5F, 0xD6}});
  auto RData = Graph.addSection(
      Section{".rdata", SectionKind::ReadOnly, 8, 4, 0, 0, {1, 2, 3, 4}});
  auto Data = Graph.addSection(Section{".data", SectionKind::Data, 8, 8, 0, 0,
                                       std::vector<WasmEdge::Byte>(8)});
  auto BSS = Graph.addSection(Section{".bss", SectionKind::BSS, 8, 16});
  const size_t PDataSize = Architecture == Target::X86_64 ? 12 : 8;
  auto PData = Graph.addSection(
      Section{".pdata", SectionKind::Unwind, 4, PDataSize, 0, 0,
              std::vector<WasmEdge::Byte>(PDataSize), SectionPurpose::PData});
  auto XData = Graph.addSection(Section{".xdata",
                                        SectionKind::Unwind,
                                        4,
                                        4,
                                        0,
                                        0,
                                        {1, 0, 0, 0},
                                        SectionPurpose::XData});
  EXPECT_TRUE(Text && RData && Data && BSS && PData && XData);
  EXPECT_TRUE(
      Graph.addSymbol(Symbol{"z_impl", *Text, 0, 4, true, "alias", true}));
  EXPECT_TRUE(
      Graph.addSymbol(Symbol{"alpha", *Text, 0, 4, true, std::nullopt, true}));
  EXPECT_TRUE(Graph.addRebase(
      Rebase{*Data, 0,
             Architecture == Target::X86_64
                 ? static_cast<uint32_t>(llvm::COFF::IMAGE_REL_AMD64_ADDR64)
                 : static_cast<uint32_t>(llvm::COFF::IMAGE_REL_ARM64_ADDR64),
             0, 8, ObjectFormat::COFF}));
  return Graph;
}

struct ELFCase {
  Target Architecture;
  Endianness Endian;
  uint16_t Machine;
  uint32_t RelativeType;
  bool Is64;
};

void writeInteger(std::vector<WasmEdge::Byte> &Bytes, size_t Offset,
                  uint64_t Value, uint8_t Width, Endianness Endian) {
  for (uint8_t I = 0; I < Width; ++I) {
    const uint8_t Shift = Endian == Endianness::Little ? I : Width - I - 1;
    Bytes[Offset + I] = static_cast<WasmEdge::Byte>(Value >> (Shift * 8));
  }
}

std::vector<WasmEdge::Byte> makeEHFrame(Endianness Endian) {
  constexpr size_t CIERecordSize = 17;
  constexpr size_t FDERecordSize = 17;
  constexpr size_t TerminatorSize = 4;
  std::vector<WasmEdge::Byte> Bytes(CIERecordSize + FDERecordSize * 2 +
                                    TerminatorSize);
  writeInteger(Bytes, 0, 13, 4, Endian);
  Bytes[8] = 1;
  Bytes[9] = 'z';
  Bytes[10] = 'R';
  Bytes[12] = 1;
  Bytes[13] = 0x78;
  Bytes[14] = 16;
  Bytes[15] = 1;
  Bytes[16] = 0x1B;
  for (size_t I = 0; I < 2; ++I) {
    const size_t Offset = CIERecordSize + I * FDERecordSize;
    writeInteger(Bytes, Offset, 13, 4, Endian);
    writeInteger(Bytes, Offset + 4, Offset + 4, 4, Endian);
    writeInteger(Bytes, Offset + 12, 2, 4, Endian);
  }
  return Bytes;
}

std::vector<WasmEdge::Byte> makePersonalityEHFrame(Endianness Endian,
                                                   uint8_t Encoding) {
  constexpr size_t CIERecordSize = 23;
  constexpr size_t FDERecordSize = 17;
  constexpr size_t TerminatorSize = 4;
  std::vector<WasmEdge::Byte> Bytes(CIERecordSize + FDERecordSize +
                                    TerminatorSize);
  writeInteger(Bytes, 0, 19, 4, Endian);
  Bytes[8] = 1;
  Bytes[9] = 'z';
  Bytes[10] = 'P';
  Bytes[11] = 'R';
  Bytes[13] = 1;
  Bytes[14] = 0x78;
  Bytes[15] = 16;
  Bytes[16] = 6;
  Bytes[17] = Encoding;
  Bytes[22] = 0x1B;
  writeInteger(Bytes, CIERecordSize, 13, 4, Endian);
  writeInteger(Bytes, CIERecordSize + 4, CIERecordSize + 4, 4, Endian);
  writeInteger(Bytes, CIERecordSize + 12, 2, 4, Endian);
  return Bytes;
}

LinkGraph makeELFGraph(const ELFCase &Test) {
  LinkGraph Graph(Test.Architecture, Test.Endian);
  EXPECT_TRUE(Graph.beginInput("writer.o"));
  if (Test.Architecture == Target::ARM) {
    EXPECT_TRUE(Graph.setELFFlags(llvm::ELF::EF_ARM_EABI_VER5 |
                                  llvm::ELF::EF_ARM_ABI_FLOAT_HARD));
  }
  const uint8_t PointerSize = Test.Is64 ? 8 : 4;
  auto Text = Graph.addSection(
      Section{".text", SectionKind::Text, 16, 4, 0, 0, {0xC3, 0, 0, 0}});
  auto Rodata = Graph.addSection(
      Section{".rodata", SectionKind::ReadOnly, 8, 4, 0, 0, {1, 2, 3, 4}});
  auto EHFrame = Graph.addSection(Section{
      ".eh_frame", SectionKind::Unwind, 8, makeEHFrame(Test.Endian).size(), 0,
      0, makeEHFrame(Test.Endian), SectionPurpose::EHFrame});
  auto Data = Graph.addSection(
      Section{".data", SectionKind::Data, PointerSize, PointerSize, 0, 0,
              std::vector<WasmEdge::Byte>(PointerSize)});
  auto BSS = Graph.addSection(
      Section{".bss", SectionKind::BSS, PointerSize, PointerSize});
  EXPECT_TRUE(Text && Rodata && EHFrame && Data && BSS);
  EXPECT_TRUE(
      Graph.addSymbol(Symbol{"f0", *Text, 0, 4, true, std::nullopt, true}));
  EXPECT_TRUE(
      Graph.addSymbol(Symbol{"f1", *Text, 2, 2, true, std::nullopt, true}));
  EXPECT_TRUE(Graph.addSymbol(
      Symbol{"value", *Data, 0, PointerSize, true, std::nullopt, true}));
  EXPECT_TRUE(Graph.addRebase(
      Rebase{*Data, 0, Test.RelativeType, 0, PointerSize, ObjectFormat::ELF}));
  return Graph;
}

uint64_t readInteger(const std::vector<WasmEdge::Byte> &Bytes, size_t Offset,
                     uint8_t Width, Endianness Endian) {
  uint64_t Result = 0;
  for (uint8_t I = 0; I < Width; ++I) {
    const uint8_t Shift = Endian == Endianness::Little ? I : Width - I - 1;
    Result |= static_cast<uint64_t>(Bytes[Offset + I]) << (Shift * 8);
  }
  return Result;
}

uint64_t readULEB(const std::vector<WasmEdge::Byte> &Bytes, size_t &Offset,
                  size_t End) {
  uint64_t Result = 0;
  for (uint8_t Shift = 0; Shift < 64 && Offset < End; Shift += 7) {
    const uint8_t Value = Bytes[Offset++];
    Result |= static_cast<uint64_t>(Value & 0x7F) << Shift;
    if ((Value & 0x80) == 0)
      return Result;
  }
  ADD_FAILURE() << "malformed ULEB";
  return 0;
}

void readExportNode(const std::vector<WasmEdge::Byte> &Bytes, size_t Base,
                    size_t Start, size_t End, const std::string &Prefix,
                    std::map<std::string, uint64_t> &Exports,
                    std::set<size_t> &Visited) {
  ASSERT_LT(Start, End);
  ASSERT_TRUE(Visited.insert(Start).second);
  size_t Offset = Start;
  const uint64_t TerminalSize = readULEB(Bytes, Offset, End);
  ASSERT_LE(TerminalSize, End - Offset);
  const size_t TerminalEnd = Offset + TerminalSize;
  if (TerminalSize != 0) {
    const uint64_t Flags = readULEB(Bytes, Offset, TerminalEnd);
    EXPECT_EQ(Flags, llvm::MachO::EXPORT_SYMBOL_FLAGS_KIND_REGULAR);
    const uint64_t Address = readULEB(Bytes, Offset, TerminalEnd);
    EXPECT_EQ(Offset, TerminalEnd);
    Exports.emplace(Prefix, Address);
  }
  Offset = TerminalEnd;
  ASSERT_LT(Offset, End);
  const uint8_t ChildCount = Bytes[Offset++];
  for (uint8_t I = 0; I < ChildCount; ++I) {
    std::string Suffix;
    while (Offset < End && Bytes[Offset] != 0)
      Suffix.push_back(static_cast<char>(Bytes[Offset++]));
    ASSERT_LT(Offset, End);
    ++Offset;
    const uint64_t Child = readULEB(Bytes, Offset, End);
    ASSERT_LT(Child, End - Base);
    readExportNode(Bytes, Base, Base + Child, End, Prefix + Suffix, Exports,
                   Visited);
  }
}

const llvm::object::SectionRef *
findSection(const llvm::object::ObjectFile &Object, std::string_view Wanted,
            llvm::object::SectionRef &Storage) {
  for (const auto &Section : Object.sections()) {
    auto Name = Section.getName();
    EXPECT_TRUE(static_cast<bool>(Name));
    if (Name && *Name == llvm::StringRef(Wanted.data(), Wanted.size())) {
      Storage = Section;
      return &Storage;
    }
  }
  return nullptr;
}

uint32_t elfHash(std::string_view Name) {
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

TEST(PEWriterTest, WritesDeterministicPE32PlusDLLs) {
  constexpr uint64_t ImageBase = UINT64_C(0x180000000);
  for (const auto Architecture : {Target::X86_64, Target::AArch64}) {
    auto Graph = makePEGraph(Architecture);
    ASSERT_TRUE(PEWriter::layout(Graph));
    auto Data = Graph.sectionContent(2);
    auto PData = Graph.sectionContent(4);
    ASSERT_TRUE(Data && PData);
    for (uint8_t I = 0; I < 8; ++I)
      (*Data)[I] =
          static_cast<WasmEdge::Byte>(Graph.sections()[0].Address >> (I * 8));
    auto WritePData = [&](size_t Offset, uint64_t Value) {
      for (uint8_t I = 0; I < 4; ++I)
        (*PData)[Offset + I] = static_cast<WasmEdge::Byte>(Value >> (I * 8));
    };
    WritePData(0, Graph.sections()[0].Address - ImageBase);
    WritePData(4,
               (Architecture == Target::X86_64 ? Graph.sections()[0].Address + 4
                                               : Graph.sections()[5].Address) -
                   ImageBase);
    if (Architecture == Target::X86_64)
      WritePData(8, Graph.sections()[5].Address - ImageBase);
    ASSERT_TRUE(applyRelocations(Graph));

    std::vector<WasmEdge::Byte> Bytes;
    Writer Output(Bytes);
    ASSERT_TRUE(PEWriter::write(Graph, "writer.dll", Output));
    std::vector<WasmEdge::Byte> Again;
    Writer Second(Again);
    ASSERT_TRUE(PEWriter::write(Graph, "writer.dll", Second));
    EXPECT_EQ(Bytes, Again);
    ASSERT_GE(Bytes.size(), 512U);
    EXPECT_EQ(Bytes[0], 'M');
    EXPECT_EQ(Bytes[1], 'Z');
    const uint32_t PEOffset =
        static_cast<uint32_t>(readInteger(Bytes, 0x3C, 4, Endianness::Little));
    EXPECT_GE(PEOffset, 0x40U);
    EXPECT_EQ(readInteger(Bytes, PEOffset, 4, Endianness::Little),
              UINT32_C(0x00004550));
    const size_t COFF = PEOffset + 4;
    EXPECT_EQ(readInteger(Bytes, COFF, 2, Endianness::Little),
              Architecture == Target::X86_64
                  ? llvm::COFF::IMAGE_FILE_MACHINE_AMD64
                  : llvm::COFF::IMAGE_FILE_MACHINE_ARM64);
    EXPECT_EQ(readInteger(Bytes, COFF + 16, 2, Endianness::Little), 240U);
    const uint16_t Characteristics = static_cast<uint16_t>(
        readInteger(Bytes, COFF + 18, 2, Endianness::Little));
    EXPECT_EQ(Characteristics & (llvm::COFF::IMAGE_FILE_DLL |
                                 llvm::COFF::IMAGE_FILE_EXECUTABLE_IMAGE |
                                 llvm::COFF::IMAGE_FILE_LARGE_ADDRESS_AWARE),
              llvm::COFF::IMAGE_FILE_DLL |
                  llvm::COFF::IMAGE_FILE_EXECUTABLE_IMAGE |
                  llvm::COFF::IMAGE_FILE_LARGE_ADDRESS_AWARE);
    const size_t Optional = COFF + 20;
    EXPECT_EQ(readInteger(Bytes, Optional, 2, Endianness::Little), 0x20BU);
    EXPECT_NE(readInteger(Bytes, Optional + 4, 4, Endianness::Little), 0U);
    EXPECT_NE(readInteger(Bytes, Optional + 8, 4, Endianness::Little), 0U);
    EXPECT_EQ(readInteger(Bytes, Optional + 12, 4, Endianness::Little), 16U);
    EXPECT_EQ(readInteger(Bytes, Optional + 16, 4, Endianness::Little), 0U);
    EXPECT_EQ(readInteger(Bytes, Optional + 20, 4, Endianness::Little),
              Graph.sections()[0].Address - ImageBase);
    EXPECT_EQ(readInteger(Bytes, Optional + 24, 8, Endianness::Little),
              ImageBase);
    EXPECT_EQ(readInteger(Bytes, Optional + 32, 4, Endianness::Little), 4096U);
    EXPECT_EQ(readInteger(Bytes, Optional + 36, 4, Endianness::Little), 512U);
    EXPECT_EQ(readInteger(Bytes, Optional + 64, 4, Endianness::Little), 0U);
    EXPECT_EQ(readInteger(Bytes, Optional + 56, 4, Endianness::Little) % 4096,
              0U);
    EXPECT_EQ(readInteger(Bytes, Optional + 60, 4, Endianness::Little) % 512,
              0U);
    EXPECT_EQ(readInteger(Bytes, Optional + 68, 2, Endianness::Little),
              llvm::COFF::IMAGE_SUBSYSTEM_WINDOWS_CUI);
    const uint16_t DLLCharacteristics = static_cast<uint16_t>(
        readInteger(Bytes, Optional + 70, 2, Endianness::Little));
    EXPECT_EQ(DLLCharacteristics &
                  (llvm::COFF::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE |
                   llvm::COFF::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT |
                   llvm::COFF::IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA),
              llvm::COFF::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE |
                  llvm::COFF::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT |
                  llvm::COFF::IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA);
    EXPECT_EQ(readInteger(Bytes, Optional + 108, 4, Endianness::Little), 16U);

    auto Object =
        llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
            llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                            Bytes.size()),
            "writer.dll"));
    ASSERT_TRUE(static_cast<bool>(Object))
        << llvm::toString(Object.takeError());
    const auto *PE = llvm::dyn_cast<llvm::object::COFFObjectFile>(&**Object);
    ASSERT_NE(PE, nullptr);
    std::map<std::string, uint32_t> Exports;
    for (const auto &Export : PE->export_directories()) {
      llvm::StringRef Name;
      llvm::StringRef DLL;
      uint32_t RVA = 0;
      uint32_t Base = 0;
      uint32_t Ordinal = 0;
      bool Forwarder = true;
      ASSERT_FALSE(Export.getSymbolName(Name));
      ASSERT_FALSE(Export.getDllName(DLL));
      ASSERT_FALSE(Export.getExportRVA(RVA));
      ASSERT_FALSE(Export.getOrdinalBase(Base));
      ASSERT_FALSE(Export.getOrdinal(Ordinal));
      ASSERT_FALSE(Export.isForwarder(Forwarder));
      EXPECT_EQ(DLL, "writer.dll");
      EXPECT_EQ(Base, 1U);
      EXPECT_FALSE(Forwarder);
      Exports.emplace(Name.str(), RVA);
    }
    EXPECT_EQ(Exports,
              (std::map<std::string, uint32_t>{
                  {"alias", static_cast<uint32_t>(Graph.sections()[0].Address -
                                                  ImageBase)},
                  {"alpha", static_cast<uint32_t>(Graph.sections()[0].Address -
                                                  ImageBase)}}));
    std::map<std::string, uint32_t> Sections;
    for (const auto &Section : PE->sections()) {
      auto Name = Section.getName();
      ASSERT_TRUE(static_cast<bool>(Name));
      const auto *Header = PE->getCOFFSection(Section);
      Sections.emplace(Name->str(), Header->Characteristics);
      EXPECT_FALSE(
          (Header->Characteristics & llvm::COFF::IMAGE_SCN_MEM_WRITE) != 0 &&
          (Header->Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE) != 0);
    }
    EXPECT_EQ(Sections[".text"], llvm::COFF::IMAGE_SCN_CNT_CODE |
                                     llvm::COFF::IMAGE_SCN_MEM_EXECUTE |
                                     llvm::COFF::IMAGE_SCN_MEM_READ);
    EXPECT_NE(Sections[".data"] & llvm::COFF::IMAGE_SCN_MEM_WRITE, 0U);
    EXPECT_NE(Sections[".bss"] & llvm::COFF::IMAGE_SCN_CNT_UNINITIALIZED_DATA,
              0U);
    for (const char *Name : {".rdata", ".pdata", ".xdata", ".edata", ".reloc"})
      EXPECT_NE(Sections.count(Name), 0U) << Name;

    const std::array<size_t, 8> EmptyDirectories{1, 6, 9, 10, 11, 12, 13, 14};
    for (const size_t Index : EmptyDirectories) {
      const size_t Directory = Optional + 112 + Index * 8;
      EXPECT_EQ(readInteger(Bytes, Directory, 8, Endianness::Little), 0U)
          << Index;
    }
    const size_t ExportDirectory = Optional + 112;
    const size_t ExceptionDirectory = Optional + 112 + 3 * 8;
    const size_t RelocDirectory = Optional + 112 + 5 * 8;
    EXPECT_NE(readInteger(Bytes, ExportDirectory, 4, Endianness::Little), 0U);
    EXPECT_NE(readInteger(Bytes, RelocDirectory, 4, Endianness::Little), 0U);
    EXPECT_EQ(readInteger(Bytes, ExceptionDirectory + 4, 4, Endianness::Little),
              Architecture == Target::X86_64 ? 12U : 8U);
    llvm::object::SectionRef RelocStorage;
    const auto *RelocSection = findSection(*PE, ".reloc", RelocStorage);
    ASSERT_NE(RelocSection, nullptr);
    auto RelocContent = RelocSection->getContents();
    ASSERT_TRUE(static_cast<bool>(RelocContent));
    const std::vector<WasmEdge::Byte> RelocBytes(RelocContent->bytes_begin(),
                                                 RelocContent->bytes_end());
    ASSERT_GE(RelocBytes.size(), 12U);
    const uint32_t DataRVA =
        static_cast<uint32_t>(Graph.sections()[2].Address - ImageBase);
    EXPECT_EQ(readInteger(RelocBytes, 0, 4, Endianness::Little),
              DataRVA & ~UINT32_C(0xFFF));
    EXPECT_EQ(readInteger(RelocBytes, 4, 4, Endianness::Little), 12U);
    EXPECT_EQ(readInteger(RelocBytes, 8, 2, Endianness::Little),
              (llvm::COFF::IMAGE_REL_BASED_DIR64 << 12) | (DataRVA & 0xFFF));
    EXPECT_EQ(readInteger(RelocBytes, 10, 2, Endianness::Little), 0U);
  }
}

TEST(PEWriterTest, RejectsInvalidRebasesAndOverflowAtomically) {
  auto Graph = makePEGraph(Target::X86_64);
  ASSERT_TRUE(PEWriter::layout(Graph));
  ASSERT_TRUE(applyRelocations(Graph));
  auto &RebaseValue = const_cast<std::vector<Rebase> &>(Graph.rebases())[0];
  RebaseValue.Width = 4;
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  EXPECT_FALSE(PEWriter::write(Graph, "invalid.dll", Output));
  EXPECT_TRUE(Bytes.empty());

  LinkGraph Overflow(Target::X86_64, Endianness::Little, ObjectFormat::COFF);
  ASSERT_TRUE(Overflow.beginInput("overflow.obj"));
  ASSERT_TRUE(Overflow.addSection(
      Section{".text", SectionKind::Text, 1, UINT64_C(1) << 32, 0, 0, {0}}));
  EXPECT_FALSE(PEWriter::layout(Overflow));
  EXPECT_EQ(Overflow.sections()[0].Address, 0U);
  EXPECT_EQ(Overflow.sections()[0].FileOffset, 0U);
}

TEST(PEWriterTest, HonorsInputAlignmentAboveSectionAlignment) {
  LinkGraph Graph(Target::X86_64, Endianness::Little, ObjectFormat::COFF);
  ASSERT_TRUE(Graph.beginInput("aligned.obj"));
  ASSERT_TRUE(Graph.addSection(
      Section{".text$a", SectionKind::Text, 16, 1, 0, 0, {0xC3}}));
  ASSERT_TRUE(Graph.addSection(
      Section{".text$b", SectionKind::Text, 8192, 1, 0, 0, {0xC3}}));
  ASSERT_TRUE(PEWriter::layout(Graph));
  EXPECT_EQ(Graph.sections()[1].Address % 8192, 0U);
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  ASSERT_TRUE(PEWriter::write(Graph, "aligned.dll", Output));
  auto Object =
      llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
          llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                          Bytes.size()),
          "aligned.dll"));
  ASSERT_TRUE(static_cast<bool>(Object)) << llvm::toString(Object.takeError());
  llvm::object::SectionRef Storage;
  const auto *Text = findSection(**Object, ".text", Storage);
  ASSERT_NE(Text, nullptr);
  EXPECT_EQ(Text->getAddress() % 8192, 0U);
}

TEST(PEWriterTest, ValidatesExportOrdinalCapacity) {
  EXPECT_TRUE(Internal::validPEExportCount(65536));
  EXPECT_FALSE(Internal::validPEExportCount(65537));
  EXPECT_FALSE(Internal::validPEExportCount(SIZE_MAX));
}

TEST(PEWriterTest, SortsRuntimeFunctionTables) {
  constexpr uint64_t ImageBase = UINT64_C(0x180000000);
  for (const auto Architecture : {Target::X86_64, Target::AArch64}) {
    LinkGraph Graph(Architecture, Endianness::Little, ObjectFormat::COFF);
    ASSERT_TRUE(Graph.beginInput("unwind.obj"));
    auto Text = Graph.addSection(
        Section{".text", SectionKind::Text, 4, 64, 0, 0,
                std::vector<WasmEdge::Byte>(64, Architecture == Target::X86_64
                                                    ? WasmEdge::Byte{0x90}
                                                    : WasmEdge::Byte{0})});
    auto XData = Graph.addSection(Section{".xdata", SectionKind::Unwind, 4, 8,
                                          0, 0, std::vector<WasmEdge::Byte>(8),
                                          SectionPurpose::XData});
    const size_t EntrySize = Architecture == Target::X86_64 ? 12 : 8;
    auto PDataA = Graph.addSection(
        Section{".pdata$a", SectionKind::Unwind, 4, EntrySize, 0, 0,
                std::vector<WasmEdge::Byte>(EntrySize), SectionPurpose::PData});
    auto PDataB = Graph.addSection(
        Section{".pdata$b", SectionKind::Unwind, 16, EntrySize, 0, 0,
                std::vector<WasmEdge::Byte>(EntrySize), SectionPurpose::PData});
    ASSERT_TRUE(Text && XData && PDataA && PDataB);
    ASSERT_TRUE(PEWriter::layout(Graph));
    auto Write32 = [&](SectionId Section, size_t Offset, uint32_t Value) {
      auto Content = Graph.sectionContent(Section);
      ASSERT_TRUE(Content);
      for (uint8_t I = 0; I < 4; ++I)
        (*Content)[Offset + I] = static_cast<WasmEdge::Byte>(Value >> (I * 8));
    };
    const uint32_t TextRVA =
        static_cast<uint32_t>(Graph.sections()[*Text].Address - ImageBase);
    const uint32_t XDataRVA =
        static_cast<uint32_t>(Graph.sections()[*XData].Address - ImageBase);
    if (Architecture == Target::X86_64) {
      Write32(*PDataA, 0, TextRVA + 32);
      Write32(*PDataA, 4, TextRVA + 48);
      Write32(*PDataA, 8, XDataRVA + 4);
      Write32(*PDataB, 0, TextRVA);
      Write32(*PDataB, 4, TextRVA + 16);
      Write32(*PDataB, 8, XDataRVA);
    } else {
      Write32(*XData, 0, 4);
      Write32(*PDataA, 0, TextRVA + 32);
      Write32(*PDataA, 4, (4U << 2) | 1U);
      Write32(*PDataB, 0, TextRVA);
      Write32(*PDataB, 4, XDataRVA);
    }
    ASSERT_TRUE(applyRelocations(Graph));
    std::vector<WasmEdge::Byte> Bytes;
    Writer Output(Bytes);
    ASSERT_TRUE(PEWriter::write(Graph, "sorted.dll", Output));
    auto Object =
        llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
            llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                            Bytes.size()),
            "sorted.dll"));
    ASSERT_TRUE(static_cast<bool>(Object));
    llvm::object::SectionRef Storage;
    const auto *PData = findSection(**Object, ".pdata", Storage);
    ASSERT_NE(PData, nullptr);
    const uint32_t PEOffset =
        static_cast<uint32_t>(readInteger(Bytes, 0x3C, 4, Endianness::Little));
    const size_t ExceptionDirectory = PEOffset + 24 + 112 + 3 * 8;
    EXPECT_EQ(readInteger(Bytes, ExceptionDirectory, 4, Endianness::Little),
              PData->getAddress() - ImageBase);
    EXPECT_EQ(readInteger(Bytes, ExceptionDirectory + 4, 4, Endianness::Little),
              EntrySize * 2);
    auto Content = PData->getContents();
    ASSERT_TRUE(static_cast<bool>(Content));
    std::vector<WasmEdge::Byte> PDataBytes(Content->bytes_begin(),
                                           Content->bytes_end());
    EXPECT_EQ(readInteger(PDataBytes, 0, 4, Endianness::Little), TextRVA);
    EXPECT_EQ(readInteger(PDataBytes, EntrySize, 4, Endianness::Little),
              TextRVA + 32);
  }
}

TEST(PEWriterTest, RejectsSymbolsReferencingSortedRuntimeFunctions) {
  auto Graph = makePEGraph(Target::X86_64);
  ASSERT_TRUE(
      Graph.addSymbol(Symbol{"bad_pdata", 4, 0, 12, true, std::nullopt, true}));
  ASSERT_TRUE(PEWriter::layout(Graph));
  auto PData = Graph.sectionContent(4);
  ASSERT_TRUE(PData);
  constexpr uint64_t ImageBase = UINT64_C(0x180000000);
  const uint32_t TextRVA =
      static_cast<uint32_t>(Graph.sections()[0].Address - ImageBase);
  const uint32_t XDataRVA =
      static_cast<uint32_t>(Graph.sections()[5].Address - ImageBase);
  for (const auto [Offset, Value] : std::array<std::pair<size_t, uint32_t>, 3>{
           {{0, TextRVA}, {4, TextRVA + 4}, {8, XDataRVA}}})
    for (uint8_t I = 0; I < 4; ++I)
      (*PData)[Offset + I] = static_cast<WasmEdge::Byte>(Value >> (I * 8));
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  EXPECT_FALSE(PEWriter::write(Graph, "bad-symbol.dll", Output));
  EXPECT_TRUE(Bytes.empty());
}

TEST(PEWriterTest, RejectsInvalidRuntimeFunctionTables) {
  constexpr uint64_t ImageBase = UINT64_C(0x180000000);
  for (const auto Architecture : {Target::X86_64, Target::AArch64}) {
    auto Graph = makePEGraph(Architecture);
    ASSERT_TRUE(PEWriter::layout(Graph));
    auto PData = Graph.sectionContent(4);
    ASSERT_TRUE(PData);
    const uint32_t TextRVA =
        static_cast<uint32_t>(Graph.sections()[0].Address - ImageBase);
    const uint32_t XDataRVA =
        static_cast<uint32_t>(Graph.sections()[5].Address - ImageBase);
    auto Write = [&](size_t Offset, uint32_t Value) {
      for (uint8_t I = 0; I < 4; ++I)
        (*PData)[Offset + I] = static_cast<WasmEdge::Byte>(Value >> (I * 8));
    };
    Write(0, TextRVA);
    if (Architecture == Target::X86_64) {
      Write(4, TextRVA);
      Write(8, XDataRVA + 8);
    } else {
      Write(4, XDataRVA + 8);
    }
    ASSERT_TRUE(applyRelocations(Graph));
    std::vector<WasmEdge::Byte> Bytes;
    Writer Output(Bytes);
    EXPECT_FALSE(PEWriter::write(Graph, "invalid-unwind.dll", Output));
    EXPECT_TRUE(Bytes.empty());
  }
}

TEST(PEWriterTest, RejectsDuplicateAndOverlappingRuntimeFunctions) {
  constexpr uint64_t ImageBase = UINT64_C(0x180000000);
  for (const bool Duplicate : {true, false}) {
    LinkGraph Graph(Target::X86_64, Endianness::Little, ObjectFormat::COFF);
    ASSERT_TRUE(Graph.beginInput("overlap.obj"));
    auto Text = Graph.addSection(Section{".text", SectionKind::Text, 4, 64, 0,
                                         0, std::vector<WasmEdge::Byte>(64)});
    auto XData = Graph.addSection(Section{".xdata",
                                          SectionKind::Unwind,
                                          4,
                                          4,
                                          0,
                                          0,
                                          {1, 0, 0, 0},
                                          SectionPurpose::XData});
    auto PData = Graph.addSection(Section{".pdata", SectionKind::Unwind, 4, 24,
                                          0, 0, std::vector<WasmEdge::Byte>(24),
                                          SectionPurpose::PData});
    ASSERT_TRUE(Text && XData && PData);
    ASSERT_TRUE(PEWriter::layout(Graph));
    auto Content = Graph.sectionContent(*PData);
    ASSERT_TRUE(Content);
    const uint32_t TextRVA =
        static_cast<uint32_t>(Graph.sections()[*Text].Address - ImageBase);
    const uint32_t XDataRVA =
        static_cast<uint32_t>(Graph.sections()[*XData].Address - ImageBase);
    auto Write = [&](size_t Offset, uint32_t Value) {
      for (uint8_t I = 0; I < 4; ++I)
        (*Content)[Offset + I] = static_cast<WasmEdge::Byte>(Value >> (I * 8));
    };
    Write(0, TextRVA);
    Write(4, TextRVA + 32);
    Write(8, XDataRVA);
    Write(12, TextRVA + (Duplicate ? 0 : 16));
    Write(16, TextRVA + 48);
    Write(20, XDataRVA);
    ASSERT_TRUE(applyRelocations(Graph));
    std::vector<WasmEdge::Byte> Bytes;
    Writer Output(Bytes);
    EXPECT_FALSE(PEWriter::write(Graph, "overlap.dll", Output));
    EXPECT_TRUE(Bytes.empty());
  }

  LinkGraph MisSized(Target::AArch64, Endianness::Little, ObjectFormat::COFF);
  ASSERT_TRUE(MisSized.beginInput("mis-sized.obj"));
  ASSERT_TRUE(MisSized.addSection(Section{".text", SectionKind::Text, 4, 16, 0,
                                          0, std::vector<WasmEdge::Byte>(16)}));
  ASSERT_TRUE(MisSized.addSection(Section{".pdata", SectionKind::Unwind, 4, 9,
                                          0, 0, std::vector<WasmEdge::Byte>(9),
                                          SectionPurpose::PData}));
  ASSERT_TRUE(PEWriter::layout(MisSized));
  ASSERT_TRUE(applyRelocations(MisSized));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  EXPECT_FALSE(PEWriter::write(MisSized, "mis-sized.dll", Output));
  EXPECT_TRUE(Bytes.empty());
}

TEST(ELFWriterTest, WritesLoadableImagesForEveryLinuxTarget) {
  const std::array<ELFCase, 5> Cases{{
      {Target::ARM, Endianness::Little, llvm::ELF::EM_ARM,
       llvm::ELF::R_ARM_RELATIVE, false},
      {Target::X86_64, Endianness::Little, llvm::ELF::EM_X86_64,
       llvm::ELF::R_X86_64_RELATIVE, true},
      {Target::AArch64, Endianness::Little, llvm::ELF::EM_AARCH64,
       llvm::ELF::R_AARCH64_RELATIVE, true},
      {Target::RISCV64, Endianness::Little, llvm::ELF::EM_RISCV,
       llvm::ELF::R_RISCV_RELATIVE, true},
      {Target::S390X, Endianness::Big, llvm::ELF::EM_S390,
       llvm::ELF::R_390_RELATIVE, true},
  }};
  for (const auto &Test : Cases) {
    auto Graph = makeELFGraph(Test);
    ASSERT_TRUE(ELFWriter::layout(Graph));
    auto EHContent = Graph.sectionContent(2);
    ASSERT_TRUE(EHContent);
    for (size_t I = 0; I < 2; ++I) {
      const size_t FieldOffset = 17 + I * 17 + 8;
      const uint64_t FieldAddress = Graph.sections()[2].Address + FieldOffset;
      const uint64_t FunctionAddress = Graph.sections()[0].Address + I * 2;
      const int64_t Delta = static_cast<int64_t>(FunctionAddress) -
                            static_cast<int64_t>(FieldAddress);
      for (uint8_t Byte = 0; Byte < 4; ++Byte) {
        const uint8_t Shift =
            Test.Endian == Endianness::Little ? Byte : 3 - Byte;
        (*EHContent)[FieldOffset + Byte] = static_cast<WasmEdge::Byte>(
            static_cast<uint32_t>(Delta) >> (Shift * 8));
      }
    }
    auto Data = Graph.sectionContent(3);
    ASSERT_TRUE(Data);
    for (uint8_t I = 0; I < (Test.Is64 ? 8 : 4); ++I) {
      const uint8_t Shift =
          Test.Endian == Endianness::Little ? I : (Test.Is64 ? 7 - I : 3 - I);
      (*Data)[I] = static_cast<WasmEdge::Byte>(Graph.sections()[3].Address >>
                                               (Shift * 8));
    }
    ASSERT_TRUE(applyRelocations(Graph));
    std::vector<WasmEdge::Byte> Bytes;
    Writer Output(Bytes);
    ASSERT_TRUE(ELFWriter::write(Graph, Output));
    std::vector<WasmEdge::Byte> SecondBytes;
    Writer SecondOutput(SecondBytes);
    ASSERT_TRUE(ELFWriter::write(Graph, SecondOutput));
    EXPECT_EQ(Bytes, SecondBytes);

    auto Object =
        llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
            llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                            Bytes.size()),
            "writer.so"));
    ASSERT_TRUE(static_cast<bool>(Object))
        << llvm::toString(Object.takeError());
    EXPECT_TRUE((*Object)->isELF());
    EXPECT_EQ(readInteger(Bytes, 16, 2, Test.Endian), llvm::ELF::ET_DYN);
    EXPECT_EQ((*Object)->getArch(),
              Test.Architecture == Target::ARM       ? llvm::Triple::arm
              : Test.Architecture == Target::X86_64  ? llvm::Triple::x86_64
              : Test.Architecture == Target::AArch64 ? llvm::Triple::aarch64
              : Test.Architecture == Target::RISCV64 ? llvm::Triple::riscv64
                                                     : llvm::Triple::systemz);
    std::set<std::string> Sections;
    for (const auto &Section : (*Object)->sections()) {
      auto Name = Section.getName();
      ASSERT_TRUE(static_cast<bool>(Name));
      Sections.emplace(Name->str());
    }
    for (const char *Name :
         {".text", ".rodata", ".eh_frame", ".eh_frame_hdr", ".data", ".bss",
          ".dynsym", ".dynstr", ".hash", ".dynamic", ".shstrtab"}) {
      EXPECT_TRUE(Sections.count(Name)) << Name;
    }
    EXPECT_TRUE(Sections.count(Test.Is64 ? ".rela.dyn" : ".rel.dyn"));
    std::set<std::string> Symbols;
    const auto *ELF =
        llvm::dyn_cast<llvm::object::ELFObjectFileBase>(&**Object);
    ASSERT_NE(ELF, nullptr);
    for (const auto &Symbol : ELF->getDynamicSymbolIterators()) {
      auto Name = Symbol.getName();
      ASSERT_TRUE(static_cast<bool>(Name));
      if (!Name->empty())
        Symbols.emplace(Name->str());
    }
    EXPECT_EQ(Symbols, (std::set<std::string>{"f0", "f1", "value"}));

    const uint64_t ProgramHeaderOffset =
        readInteger(Bytes, Test.Is64 ? 32 : 28, Test.Is64 ? 8 : 4, Test.Endian);
    const uint16_t ProgramHeaderSize = static_cast<uint16_t>(
        readInteger(Bytes, Test.Is64 ? 54 : 42, 2, Test.Endian));
    const uint16_t ProgramHeaderCount = static_cast<uint16_t>(
        readInteger(Bytes, Test.Is64 ? 56 : 44, 2, Test.Endian));
    bool HasDynamic = false;
    bool HasEHFrame = false;
    bool HasNonExecutableStack = false;
    bool HasInterpreter = false;
    bool HasRXLoad = false;
    bool HasReadOnlyLoad = false;
    bool HasRWLoad = false;
    for (uint16_t I = 0; I < ProgramHeaderCount; ++I) {
      const uint64_t Offset = ProgramHeaderOffset + I * ProgramHeaderSize;
      const uint32_t Type =
          static_cast<uint32_t>(readInteger(Bytes, Offset, 4, Test.Endian));
      const uint32_t Flags = static_cast<uint32_t>(
          readInteger(Bytes, Offset + (Test.Is64 ? 4 : 24), 4, Test.Endian));
      HasDynamic |= Type == llvm::ELF::PT_DYNAMIC;
      HasEHFrame |= Type == llvm::ELF::PT_GNU_EH_FRAME;
      HasNonExecutableStack |=
          Type == llvm::ELF::PT_GNU_STACK && (Flags & llvm::ELF::PF_X) == 0;
      HasInterpreter |= Type == llvm::ELF::PT_INTERP;
      if (Type == llvm::ELF::PT_LOAD) {
        const uint64_t FileOffset =
            readInteger(Bytes, Offset + (Test.Is64 ? 8 : 4), Test.Is64 ? 8 : 4,
                        Test.Endian);
        const uint64_t Address =
            readInteger(Bytes, Offset + (Test.Is64 ? 16 : 8), Test.Is64 ? 8 : 4,
                        Test.Endian);
        EXPECT_EQ(FileOffset % 4096, Address % 4096);
        EXPECT_NE(Flags & llvm::ELF::PF_R, 0U);
        EXPECT_FALSE((Flags & llvm::ELF::PF_X) != 0 &&
                     (Flags & llvm::ELF::PF_W) != 0);
        HasRXLoad |= Flags == (llvm::ELF::PF_R | llvm::ELF::PF_X);
        HasReadOnlyLoad |= Flags == llvm::ELF::PF_R;
        HasRWLoad |= Flags == (llvm::ELF::PF_R | llvm::ELF::PF_W);
      }
    }
    EXPECT_TRUE(HasDynamic);
    EXPECT_TRUE(HasEHFrame);
    EXPECT_TRUE(HasNonExecutableStack);
    EXPECT_FALSE(HasInterpreter);
    EXPECT_TRUE(HasRXLoad);
    EXPECT_TRUE(HasReadOnlyLoad);
    EXPECT_TRUE(HasRWLoad);

    llvm::object::SectionRef DynamicStorage;
    const auto *DynamicSection =
        findSection(**Object, ".dynamic", DynamicStorage);
    ASSERT_NE(DynamicSection, nullptr);
    auto DynamicContent = DynamicSection->getContents();
    ASSERT_TRUE(static_cast<bool>(DynamicContent));
    std::map<uint64_t, uint64_t> DynamicTags;
    const uint8_t AddressSize = Test.Is64 ? 8 : 4;
    const uint8_t DynamicEntrySize = AddressSize * 2;
    const std::vector<WasmEdge::Byte> DynamicBytes(
        DynamicContent->bytes_begin(), DynamicContent->bytes_end());
    for (size_t Offset = 0; Offset < DynamicBytes.size();
         Offset += DynamicEntrySize) {
      const uint64_t Tag =
          readInteger(DynamicBytes, Offset, AddressSize, Test.Endian);
      const uint64_t Value = readInteger(DynamicBytes, Offset + AddressSize,
                                         AddressSize, Test.Endian);
      if (Tag == llvm::ELF::DT_NULL)
        break;
      EXPECT_NE(Tag, llvm::ELF::DT_NEEDED);
      DynamicTags.emplace(Tag, Value);
    }
    struct DynamicSectionCase {
      uint64_t AddressTag;
      uint64_t SizeTag;
      uint64_t EntryTag;
      const char *Name;
      uint64_t EntrySize;
    };
    const std::array<DynamicSectionCase, 4> DynamicSections{{
        {llvm::ELF::DT_HASH, 0, 0, ".hash", 4},
        {llvm::ELF::DT_STRTAB, llvm::ELF::DT_STRSZ, 0, ".dynstr", 1},
        {llvm::ELF::DT_SYMTAB, 0, llvm::ELF::DT_SYMENT, ".dynsym",
         Test.Is64 ? 24U : 16U},
        {Test.Is64 ? llvm::ELF::DT_RELA : llvm::ELF::DT_REL,
         Test.Is64 ? llvm::ELF::DT_RELASZ : llvm::ELF::DT_RELSZ,
         Test.Is64 ? llvm::ELF::DT_RELAENT : llvm::ELF::DT_RELENT,
         Test.Is64 ? ".rela.dyn" : ".rel.dyn", Test.Is64 ? 24U : 8U},
    }};
    for (const auto &Expected : DynamicSections) {
      llvm::object::SectionRef Storage;
      const auto *Section = findSection(**Object, Expected.Name, Storage);
      ASSERT_NE(Section, nullptr);
      EXPECT_EQ(DynamicTags[Expected.AddressTag], Section->getAddress());
      if (Expected.SizeTag != 0) {
        EXPECT_EQ(DynamicTags[Expected.SizeTag], Section->getSize());
      }
      if (Expected.EntryTag != 0) {
        EXPECT_EQ(DynamicTags[Expected.EntryTag], Expected.EntrySize);
      }
    }

    llvm::object::SectionRef HashStorage;
    const auto *HashSection = findSection(**Object, ".hash", HashStorage);
    ASSERT_NE(HashSection, nullptr);
    auto HashContent = HashSection->getContents();
    ASSERT_TRUE(static_cast<bool>(HashContent));
    const std::vector<WasmEdge::Byte> HashBytes(HashContent->bytes_begin(),
                                                HashContent->bytes_end());
    const uint32_t BucketCount =
        static_cast<uint32_t>(readInteger(HashBytes, 0, 4, Test.Endian));
    const uint32_t ChainCount =
        static_cast<uint32_t>(readInteger(HashBytes, 4, 4, Test.Endian));
    ASSERT_EQ(ChainCount, Symbols.size() + 1);
    std::vector<std::string> SymbolNames(ChainCount);
    uint32_t SymbolIndex = 1;
    for (const auto &Symbol : ELF->getDynamicSymbolIterators()) {
      auto Name = Symbol.getName();
      ASSERT_TRUE(static_cast<bool>(Name));
      if (!Name->empty())
        SymbolNames[SymbolIndex] = Name->str();
      ++SymbolIndex;
    }
    ASSERT_EQ(SymbolIndex, ChainCount);
    for (uint32_t Wanted = 1; Wanted < ChainCount; ++Wanted) {
      uint32_t Index = static_cast<uint32_t>(readInteger(
          HashBytes, (2 + elfHash(SymbolNames[Wanted]) % BucketCount) * 4, 4,
          Test.Endian));
      std::set<uint32_t> Visited;
      while (Index != 0 && Index != Wanted) {
        ASSERT_LT(Index, ChainCount);
        ASSERT_TRUE(Visited.insert(Index).second);
        Index = static_cast<uint32_t>(readInteger(
            HashBytes, (2 + BucketCount + Index) * 4, 4, Test.Endian));
      }
      EXPECT_EQ(Index, Wanted) << SymbolNames[Wanted];
    }

    bool CheckedRelocation = false;
    for (const auto &Section : (*Object)->sections()) {
      auto Name = Section.getName();
      ASSERT_TRUE(static_cast<bool>(Name));
      if (*Name != (Test.Is64 ? ".rela.dyn" : ".rel.dyn"))
        continue;
      auto Content = Section.getContents();
      ASSERT_TRUE(static_cast<bool>(Content));
      ASSERT_EQ(Content->size(), Test.Is64 ? 24U : 8U);
      const auto *RelocationBytes =
          reinterpret_cast<const WasmEdge::Byte *>(Content->data());
      const uint64_t Info =
          readInteger(std::vector<WasmEdge::Byte>(
                          RelocationBytes, RelocationBytes + Content->size()),
                      Test.Is64 ? 8 : 4, Test.Is64 ? 8 : 4, Test.Endian);
      EXPECT_EQ(Test.Is64 ? static_cast<uint32_t>(Info)
                          : static_cast<uint32_t>(Info & 0xFF),
                Test.RelativeType);
      EXPECT_EQ(Test.Is64 ? Info >> 32 : Info >> 8, 0U);
      EXPECT_EQ(
          readInteger(std::vector<WasmEdge::Byte>(
                          RelocationBytes, RelocationBytes + Content->size()),
                      0, AddressSize, Test.Endian),
          Graph.sections()[3].Address);
      if (Test.Is64) {
        EXPECT_EQ(
            readInteger(std::vector<WasmEdge::Byte>(
                            RelocationBytes, RelocationBytes + Content->size()),
                        16, 8, Test.Endian),
            Graph.sections()[3].Address);
      }
      if (!Test.Is64) {
        EXPECT_EQ(
            readInteger(Bytes, Graph.sections()[3].FileOffset, 4, Test.Endian),
            Graph.sections()[3].Address);
      }
      CheckedRelocation = true;
    }
    EXPECT_TRUE(CheckedRelocation);

    llvm::object::SectionRef HeaderStorage;
    const auto *HeaderSection =
        findSection(**Object, ".eh_frame_hdr", HeaderStorage);
    ASSERT_NE(HeaderSection, nullptr);
    EXPECT_EQ(llvm::object::ELFSectionRef(*HeaderSection).getFlags() &
                  llvm::ELF::SHF_WRITE,
              0U);
    auto HeaderContent = HeaderSection->getContents();
    ASSERT_TRUE(static_cast<bool>(HeaderContent));
    const std::vector<WasmEdge::Byte> HeaderBytes(HeaderContent->bytes_begin(),
                                                  HeaderContent->bytes_end());
    ASSERT_EQ(HeaderBytes.size(), 12U + 2U * 8U);
    EXPECT_EQ(HeaderBytes[0], 1);
    EXPECT_EQ(HeaderBytes[1], 0x1B);
    EXPECT_EQ(HeaderBytes[2], 0x03);
    EXPECT_EQ(HeaderBytes[3], 0x3B);
    EXPECT_EQ(readInteger(HeaderBytes, 8, 4, Test.Endian), 2U);
    uint64_t Previous = 0;
    for (size_t I = 0; I < 2; ++I) {
      const uint64_t FunctionAddress =
          HeaderSection->getAddress() +
          static_cast<int32_t>(
              readInteger(HeaderBytes, 12 + I * 8, 4, Test.Endian));
      const uint64_t FDEAddress = HeaderSection->getAddress() +
                                  static_cast<int32_t>(readInteger(
                                      HeaderBytes, 16 + I * 8, 4, Test.Endian));
      EXPECT_EQ(FunctionAddress, Graph.sections()[0].Address + I * 2);
      EXPECT_EQ(FDEAddress, Graph.sections()[2].Address + 17 + I * 17);
      if (I != 0) {
        EXPECT_LT(Previous, FunctionAddress);
      }
      Previous = FunctionAddress;
    }
  }
}

TEST(ELFWriterTest, OmitsEHFrameHeaderWithoutEHFrame) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("no-eh.o"));
  ASSERT_TRUE(Graph.addSection(
      Section{".text", SectionKind::Text, 16, 1, 0, 0, {0xC3}}));
  ASSERT_TRUE(ELFWriter::layout(Graph));
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  ASSERT_TRUE(ELFWriter::write(Graph, Output));
  auto Object =
      llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
          llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                          Bytes.size()),
          "no-eh.so"));
  ASSERT_TRUE(static_cast<bool>(Object));
  llvm::object::SectionRef Storage;
  EXPECT_EQ(findSection(**Object, ".eh_frame_hdr", Storage), nullptr);
  const uint64_t ProgramHeaderOffset =
      readInteger(Bytes, 32, 8, Endianness::Little);
  const uint16_t ProgramHeaderSize =
      static_cast<uint16_t>(readInteger(Bytes, 54, 2, Endianness::Little));
  const uint16_t ProgramHeaderCount =
      static_cast<uint16_t>(readInteger(Bytes, 56, 2, Endianness::Little));
  for (uint16_t I = 0; I < ProgramHeaderCount; ++I)
    EXPECT_NE(readInteger(Bytes, ProgramHeaderOffset + I * ProgramHeaderSize, 4,
                          Endianness::Little),
              llvm::ELF::PT_GNU_EH_FRAME);
}

TEST(ELFWriterTest, WritesARMExidxAndHardFloatABI) {
  LinkGraph Graph(Target::ARM, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("arm.o"));
  ASSERT_TRUE(Graph.setELFFlags(llvm::ELF::EF_ARM_EABI_VER5 |
                                llvm::ELF::EF_ARM_ABI_FLOAT_HARD));
  auto Text = Graph.addSection(
      Section{".text", SectionKind::Text, 4, 4, 0, 0, {0, 0, 0, 0}});
  auto Exidx = Graph.addSection(Section{".ARM.exidx",
                                        SectionKind::Unwind,
                                        4,
                                        8,
                                        0,
                                        0,
                                        {0, 0, 0, 0, 1, 0, 0, 0},
                                        SectionPurpose::ARMExidx,
                                        0,
                                        *Text});
  ASSERT_TRUE(Text && Exidx);
  ASSERT_TRUE(ELFWriter::layout(Graph));
  ASSERT_TRUE(applyRelocations(Graph));
  const auto ExidxContent = Graph.sections()[*Exidx].Content;
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  ASSERT_TRUE(ELFWriter::write(Graph, Output));
  if (const char *Fixture = std::getenv("WASMEDGE_ARM_ELF_FIXTURE")) {
    std::ofstream File(Fixture, std::ios_base::binary);
    File.write(reinterpret_cast<const char *>(Bytes.data()), Bytes.size());
    ASSERT_TRUE(File);
  }
  EXPECT_EQ(readInteger(Bytes, 36, 4, Endianness::Little),
            llvm::ELF::EF_ARM_EABI_VER5 | llvm::ELF::EF_ARM_ABI_FLOAT_HARD);

  auto Object =
      llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
          llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                          Bytes.size()),
          "arm.so"));
  ASSERT_TRUE(static_cast<bool>(Object));
  llvm::object::SectionRef ExidxStorage;
  const auto *ExidxSection = findSection(**Object, ".ARM.exidx", ExidxStorage);
  ASSERT_NE(ExidxSection, nullptr);
  const llvm::object::ELFSectionRef ELFExidx(*ExidxSection);
  EXPECT_EQ(ELFExidx.getType(), llvm::ELF::SHT_ARM_EXIDX);
  EXPECT_EQ(ELFExidx.getFlags(),
            llvm::ELF::SHF_ALLOC | llvm::ELF::SHF_LINK_ORDER);
  const uint64_t SectionHeaderOffset =
      readInteger(Bytes, 32, 4, Endianness::Little);
  const uint64_t ExidxHeader =
      SectionHeaderOffset + ExidxSection->getIndex() * 40;
  EXPECT_EQ(readInteger(Bytes, ExidxHeader + 24, 4, Endianness::Little), 1U);
  auto Content = ExidxSection->getContents();
  ASSERT_TRUE(static_cast<bool>(Content));
  EXPECT_EQ(
      std::vector<WasmEdge::Byte>(Content->bytes_begin(), Content->bytes_end()),
      ExidxContent);
  const uint64_t ProgramHeaderOffset =
      readInteger(Bytes, 28, 4, Endianness::Little);
  const uint16_t ProgramHeaderSize =
      static_cast<uint16_t>(readInteger(Bytes, 42, 2, Endianness::Little));
  const uint16_t ProgramHeaderCount =
      static_cast<uint16_t>(readInteger(Bytes, 44, 2, Endianness::Little));
  bool HasExidx = false;
  for (uint16_t I = 0; I < ProgramHeaderCount; ++I) {
    const uint64_t Offset = ProgramHeaderOffset + I * ProgramHeaderSize;
    if (readInteger(Bytes, Offset, 4, Endianness::Little) ==
        llvm::ELF::PT_ARM_EXIDX) {
      HasExidx = true;
      EXPECT_EQ(readInteger(Bytes, Offset + 8, 4, Endianness::Little),
                ExidxSection->getAddress());
      EXPECT_EQ(readInteger(Bytes, Offset + 16, 4, Endianness::Little),
                ExidxSection->getSize());
    }
  }
  EXPECT_TRUE(HasExidx);
  llvm::object::SectionRef HeaderStorage;
  EXPECT_EQ(findSection(**Object, ".eh_frame_hdr", HeaderStorage), nullptr);
}

TEST(ELFWriterTest, PreservesARMExidxAssociationsAndUsesOneSegment) {
  LinkGraph Graph(Target::ARM, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("many-arm.o"));
  ASSERT_TRUE(Graph.setELFFlags(llvm::ELF::EF_ARM_EABI_VER5 |
                                llvm::ELF::EF_ARM_ABI_FLOAT_HARD));
  constexpr size_t SectionCount = 10;
  std::array<SectionId, SectionCount> Texts{};
  std::array<SectionId, SectionCount> Exidxs{};
  for (size_t I = 0; I < SectionCount; ++I) {
    const size_t NameOrdinal = SectionCount - I - 1;
    auto Text =
        Graph.addSection(Section{".text." + std::to_string(NameOrdinal),
                                 SectionKind::Text,
                                 4,
                                 4,
                                 0,
                                 0,
                                 {static_cast<WasmEdge::Byte>(I), 0, 0, 0}});
    ASSERT_TRUE(Text);
    Texts[I] = *Text;
    auto Exidx = Graph.addSection(
        Section{".ARM.exidx." + std::to_string(I),
                SectionKind::Unwind,
                4,
                8,
                0,
                0,
                {static_cast<WasmEdge::Byte>(I), 0, 0, 0, 1, 0, 0, 0},
                SectionPurpose::ARMExidx,
                0,
                *Text});
    ASSERT_TRUE(Exidx);
    Exidxs[I] = *Exidx;
  }
  ASSERT_TRUE(ELFWriter::layout(Graph));
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  ASSERT_TRUE(ELFWriter::write(Graph, Output));
  auto Object =
      llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
          llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                          Bytes.size()),
          "many-arm.so"));
  ASSERT_TRUE(static_cast<bool>(Object));

  const uint64_t SectionHeaderOffset =
      readInteger(Bytes, 32, 4, Endianness::Little);
  uint64_t FirstAddress = UINT64_MAX;
  uint64_t LastEnd = 0;
  std::vector<std::pair<uint64_t, uint64_t>> ExidxOrder;
  for (size_t I = 0; I < SectionCount; ++I) {
    llvm::object::SectionRef Storage;
    const auto *Exidx =
        findSection(**Object, ".ARM.exidx." + std::to_string(I), Storage);
    ASSERT_NE(Exidx, nullptr);
    const uint64_t Header = SectionHeaderOffset + Exidx->getIndex() * 40;
    EXPECT_EQ(readInteger(Bytes, Header + 24, 4, Endianness::Little),
              Texts[I] + 1);
    FirstAddress = std::min(FirstAddress, Exidx->getAddress());
    LastEnd = std::max(LastEnd, Exidx->getAddress() + Exidx->getSize());
    ExidxOrder.emplace_back(Exidx->getAddress(),
                            Graph.sections()[Texts[I]].Address);
  }
  std::sort(ExidxOrder.begin(), ExidxOrder.end());
  for (size_t I = 1; I < ExidxOrder.size(); ++I)
    EXPECT_LT(ExidxOrder[I - 1].second, ExidxOrder[I].second);
  const uint64_t ProgramHeaderOffset =
      readInteger(Bytes, 28, 4, Endianness::Little);
  const uint16_t ProgramHeaderSize =
      static_cast<uint16_t>(readInteger(Bytes, 42, 2, Endianness::Little));
  const uint16_t ProgramHeaderCount =
      static_cast<uint16_t>(readInteger(Bytes, 44, 2, Endianness::Little));
  size_t ExidxSegmentCount = 0;
  for (uint16_t I = 0; I < ProgramHeaderCount; ++I) {
    const uint64_t Offset = ProgramHeaderOffset + I * ProgramHeaderSize;
    if (readInteger(Bytes, Offset, 4, Endianness::Little) !=
        llvm::ELF::PT_ARM_EXIDX)
      continue;
    ++ExidxSegmentCount;
    EXPECT_EQ(readInteger(Bytes, Offset + 8, 4, Endianness::Little),
              FirstAddress);
    EXPECT_EQ(readInteger(Bytes, Offset + 16, 4, Endianness::Little),
              LastEnd - FirstAddress);
  }
  EXPECT_EQ(ExidxSegmentCount, 1U);
}

TEST(ELFWriterTest, RejectsConflictingARMABIFlags) {
  LinkGraph Graph(Target::ARM, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("arm.o"));
  ASSERT_TRUE(Graph.setELFFlags(llvm::ELF::EF_ARM_EABI_VER5 |
                                llvm::ELF::EF_ARM_ABI_FLOAT_HARD |
                                llvm::ELF::EF_ARM_ABI_FLOAT_SOFT));
  ASSERT_TRUE(Graph.addSection(
      Section{".text", SectionKind::Text, 4, 4, 0, 0, {0, 0, 0, 0}}));
  ASSERT_TRUE(ELFWriter::layout(Graph));
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  EXPECT_FALSE(ELFWriter::write(Graph, Output));
  EXPECT_TRUE(Bytes.empty());
}

TEST(ELFWriterTest, AcceptsDefinedPCRelativePersonality) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("personality.o"));
  auto Text = Graph.addSection(
      Section{".text", SectionKind::Text, 16, 4, 0, 0, {0xC3, 0, 0xC3, 0}});
  auto EH = Graph.addSection(
      Section{".eh_frame", SectionKind::Unwind, 8,
              makePersonalityEHFrame(Endianness::Little, 0x1B).size(), 0, 0,
              makePersonalityEHFrame(Endianness::Little, 0x1B),
              SectionPurpose::EHFrame});
  ASSERT_TRUE(Text && EH);
  ASSERT_TRUE(
      Graph.addSymbol(Symbol{"f0", *Text, 0, 1, true, std::nullopt, true}));
  ASSERT_TRUE(Graph.addSymbol(
      Symbol{"personality", *Text, 2, 1, false, std::nullopt, false}));
  ASSERT_TRUE(ELFWriter::layout(Graph));
  auto Content = Graph.sectionContent(*EH);
  ASSERT_TRUE(Content);
  const uint64_t PersonalityField = Graph.sections()[*EH].Address + 18;
  const int64_t PersonalityDelta =
      static_cast<int64_t>(Graph.sections()[*Text].Address + 2) -
      static_cast<int64_t>(PersonalityField);
  const uint64_t FunctionField = Graph.sections()[*EH].Address + 31;
  const int64_t FunctionDelta =
      static_cast<int64_t>(Graph.sections()[*Text].Address) -
      static_cast<int64_t>(FunctionField);
  for (uint8_t I = 0; I < 4; ++I) {
    (*Content)[18 + I] = static_cast<WasmEdge::Byte>(
        static_cast<uint32_t>(PersonalityDelta) >> (I * 8));
    (*Content)[31 + I] = static_cast<WasmEdge::Byte>(
        static_cast<uint32_t>(FunctionDelta) >> (I * 8));
  }
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  EXPECT_TRUE(ELFWriter::write(Graph, Output));
}

TEST(ELFWriterTest, RejectsUnsupportedPersonalityEncodings) {
  for (const uint8_t Encoding : {uint8_t{0x9B}, uint8_t{0x03}}) {
    LinkGraph Graph(Target::X86_64, Endianness::Little);
    ASSERT_TRUE(Graph.beginInput("personality.o"));
    ASSERT_TRUE(Graph.addSection(
        Section{".text", SectionKind::Text, 16, 4, 0, 0, {0xC3, 0, 0xC3, 0}}));
    ASSERT_TRUE(Graph.addSection(
        Section{".eh_frame", SectionKind::Unwind, 8,
                makePersonalityEHFrame(Endianness::Little, Encoding).size(), 0,
                0, makePersonalityEHFrame(Endianness::Little, Encoding),
                SectionPurpose::EHFrame}));
    ASSERT_TRUE(ELFWriter::layout(Graph));
    ASSERT_TRUE(applyRelocations(Graph));
    std::vector<WasmEdge::Byte> Bytes;
    Writer Output(Bytes);
    EXPECT_FALSE(ELFWriter::write(Graph, Output));
    EXPECT_TRUE(Bytes.empty());
  }
}

TEST(ELFWriterTest, AcceptsIndirectPersonalityWithRelativeSlot) {
  for (const bool HasRebase : {false, true}) {
    LinkGraph Graph(Target::X86_64, Endianness::Little);
    ASSERT_TRUE(Graph.beginInput("indirect-personality.o"));
    auto Text = Graph.addSection(
        Section{".text", SectionKind::Text, 16, 4, 0, 0, {0xC3, 0, 0xC3, 0}});
    auto Data = Graph.addSection(Section{".data", SectionKind::Data, 8, 8, 0, 0,
                                         std::vector<WasmEdge::Byte>(8)});
    auto EH = Graph.addSection(
        Section{".eh_frame", SectionKind::Unwind, 8,
                makePersonalityEHFrame(Endianness::Little, 0x9B).size(), 0, 0,
                makePersonalityEHFrame(Endianness::Little, 0x9B),
                SectionPurpose::EHFrame});
    ASSERT_TRUE(Text && Data && EH);
    ASSERT_TRUE(
        Graph.addSymbol(Symbol{"f0", *Text, 0, 1, true, std::nullopt, true}));
    ASSERT_TRUE(Graph.addSymbol(
        Symbol{"personality", *Text, 2, 1, false, std::nullopt, false}));
    ASSERT_TRUE(ELFWriter::layout(Graph));
    auto DataContent = Graph.sectionContent(*Data);
    auto EHContent = Graph.sectionContent(*EH);
    ASSERT_TRUE(DataContent && EHContent);
    for (uint8_t I = 0; I < 8; ++I)
      (*DataContent)[I] = static_cast<WasmEdge::Byte>(
          (Graph.sections()[*Text].Address + 2) >> (I * 8));
    const int64_t SlotDelta =
        static_cast<int64_t>(Graph.sections()[*Data].Address) -
        static_cast<int64_t>(Graph.sections()[*EH].Address + 18);
    const int64_t FunctionDelta =
        static_cast<int64_t>(Graph.sections()[*Text].Address) -
        static_cast<int64_t>(Graph.sections()[*EH].Address + 31);
    for (uint8_t I = 0; I < 4; ++I) {
      (*EHContent)[18 + I] = static_cast<WasmEdge::Byte>(
          static_cast<uint32_t>(SlotDelta) >> (I * 8));
      (*EHContent)[31 + I] = static_cast<WasmEdge::Byte>(
          static_cast<uint32_t>(FunctionDelta) >> (I * 8));
    }
    if (HasRebase) {
      ASSERT_TRUE(
          Graph.addRebase(Rebase{*Data, 0, llvm::ELF::R_X86_64_64, 0, 8}));
    }
    ASSERT_TRUE(applyRelocations(Graph));
    std::vector<WasmEdge::Byte> Bytes;
    Writer Output(Bytes);
    EXPECT_EQ(static_cast<bool>(ELFWriter::write(Graph, Output)), HasRebase);
    if (HasRebase) {
      auto Object =
          llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
              llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                              Bytes.size()),
              "indirect.so"));
      ASSERT_TRUE(static_cast<bool>(Object));
      llvm::object::SectionRef Storage;
      const auto *Relocations = findSection(**Object, ".rela.dyn", Storage);
      ASSERT_NE(Relocations, nullptr);
      EXPECT_EQ(Relocations->getSize(), 24U);
    }
  }
}

TEST(ELFWriterTest, RejectsCIEFieldsCrossingRecordBoundary) {
  auto Bytes = makeEHFrame(Endianness::Little);
  Bytes[12] = 0x80;
  Bytes[13] = 0x80;
  Bytes[14] = 0x80;
  Bytes[15] = 0x80;
  Bytes[16] = 0x80;
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("bounded-eh.o"));
  ASSERT_TRUE(Graph.addSection(
      Section{".text", SectionKind::Text, 16, 4, 0, 0, {0xC3, 0, 0, 0}}));
  ASSERT_TRUE(Graph.addSection(Section{".eh_frame", SectionKind::Unwind, 8,
                                       Bytes.size(), 0, 0, std::move(Bytes),
                                       SectionPurpose::EHFrame}));
  ASSERT_TRUE(ELFWriter::layout(Graph));
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> OutputBytes;
  Writer Output(OutputBytes);
  EXPECT_FALSE(ELFWriter::write(Graph, Output));
  EXPECT_TRUE(OutputBytes.empty());
}

TEST(ELFWriterTest, AggregatesMultipleEHFrameSections) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("multiple-eh.o"));
  auto Text = Graph.addSection(Section{".text",
                                       SectionKind::Text,
                                       16,
                                       8,
                                       0,
                                       0,
                                       {0xC3, 0, 0xC3, 0, 0xC3, 0, 0xC3}});
  ASSERT_TRUE(Text);
  std::array<SectionId, 2> EHSections{};
  for (size_t I = 0; I < EHSections.size(); ++I) {
    auto EH = Graph.addSection(
        Section{".eh_frame." + std::to_string(I), SectionKind::Unwind, 8,
                makeEHFrame(Endianness::Little).size(), 0, 0,
                makeEHFrame(Endianness::Little), SectionPurpose::EHFrame});
    ASSERT_TRUE(EH);
    EHSections[I] = *EH;
  }
  ASSERT_TRUE(ELFWriter::layout(Graph));
  for (size_t SectionIndex = 0; SectionIndex < EHSections.size();
       ++SectionIndex) {
    auto Content = Graph.sectionContent(EHSections[SectionIndex]);
    ASSERT_TRUE(Content);
    for (size_t I = 0; I < 2; ++I) {
      const size_t FieldOffset = 17 + I * 17 + 8;
      const uint64_t FieldAddress =
          Graph.sections()[EHSections[SectionIndex]].Address + FieldOffset;
      const uint64_t FunctionAddress =
          Graph.sections()[*Text].Address + (SectionIndex * 2 + I) * 2;
      const int64_t Delta = static_cast<int64_t>(FunctionAddress) -
                            static_cast<int64_t>(FieldAddress);
      for (uint8_t Byte = 0; Byte < 4; ++Byte)
        (*Content)[FieldOffset + Byte] = static_cast<WasmEdge::Byte>(
            static_cast<uint32_t>(Delta) >> (Byte * 8));
    }
  }
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  ASSERT_TRUE(ELFWriter::write(Graph, Output));
  auto Object =
      llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
          llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                          Bytes.size()),
          "multiple-eh.so"));
  ASSERT_TRUE(static_cast<bool>(Object));
  llvm::object::SectionRef Storage;
  const auto *Header = findSection(**Object, ".eh_frame_hdr", Storage);
  ASSERT_NE(Header, nullptr);
  auto Content = Header->getContents();
  ASSERT_TRUE(static_cast<bool>(Content));
  const std::vector<WasmEdge::Byte> HeaderBytes(Content->bytes_begin(),
                                                Content->bytes_end());
  EXPECT_EQ(readInteger(HeaderBytes, 8, 4, Endianness::Little), 4U);
  EXPECT_EQ(HeaderBytes.size(), 12U + 4U * 8U);
}

TEST(ELFWriterTest, RejectsELF32LayoutOverflowAtomically) {
  LinkGraph Graph(Target::ARM, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("overflow.o"));
  ASSERT_TRUE(Graph.setELFFlags(llvm::ELF::EF_ARM_EABI_VER5 |
                                llvm::ELF::EF_ARM_ABI_FLOAT_HARD));
  ASSERT_TRUE(Graph.addSection(
      Section{".text", SectionKind::Text, 1, UINT64_C(1) << 32, 0, 0, {0}}));
  EXPECT_FALSE(ELFWriter::layout(Graph));
  EXPECT_EQ(Graph.sections()[0].Address, 0U);
  EXPECT_EQ(Graph.sections()[0].FileOffset, 0U);
}

TEST(ELFWriterTest, RejectsELF32GeneratedMetadataOverflowAtomically) {
  LinkGraph Graph(Target::ARM, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("metadata-overflow.o"));
  ASSERT_TRUE(Graph.setELFFlags(llvm::ELF::EF_ARM_EABI_VER5 |
                                llvm::ELF::EF_ARM_ABI_FLOAT_HARD));
  auto Text =
      Graph.addSection(Section{".text", SectionKind::Text, 1, 1, 0, 0, {0}});
  ASSERT_TRUE(Text);
  ASSERT_TRUE(Graph.setSectionAddress(*Text, UINT32_MAX - 2047));
  ASSERT_TRUE(Graph.setSectionFileOffset(*Text, UINT32_MAX - 2047));
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  EXPECT_FALSE(ELFWriter::write(Graph, Output));
  EXPECT_TRUE(Bytes.empty());
}

TEST(ELFWriterTest, RejectsUnsupportedRebasesAndInvalidState) {
  const ELFCase Test{Target::X86_64, Endianness::Little, llvm::ELF::EM_X86_64,
                     llvm::ELF::R_X86_64_RELATIVE, true};
  auto Graph = makeELFGraph(Test);
  ASSERT_TRUE(ELFWriter::layout(Graph));
  ASSERT_TRUE(applyRelocations(Graph));
  auto &RebaseValue = const_cast<std::vector<Rebase> &>(Graph.rebases())[0];
  RebaseValue.Width = 4;
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  EXPECT_FALSE(ELFWriter::write(Graph, Output));
  EXPECT_TRUE(Bytes.empty());

  LinkGraph WrongEndian(Target::X86_64, Endianness::Big);
  ASSERT_TRUE(WrongEndian.beginInput("wrong.o"));
  ASSERT_TRUE(WrongEndian.addSection(
      Section{".text", SectionKind::Text, 1, 1, 0, 0, {0}}));
  EXPECT_FALSE(ELFWriter::layout(WrongEndian));
}

LinkGraph makeMachOGraph(Target Architecture) {
  LinkGraph Graph(Architecture, Endianness::Little, ObjectFormat::MachO);
  EXPECT_TRUE(Graph.beginInput("writer.o"));
  auto Text = Graph.addSection(
      Section{"__text", SectionKind::Text, 16, 4, 0, 0,
              Architecture == Target::X86_64
                  ? std::vector<WasmEdge::Byte>{0xC3, 0, 0, 0}
                  : std::vector<WasmEdge::Byte>{0xC0, 0x03, 0x5F, 0xD6}});
  auto Constant = Graph.addSection(
      Section{"__const", SectionKind::ReadOnly, 8, 4, 0, 0, {1, 2, 3, 4}});
  auto EHFrame = Graph.addSection(Section{"__eh_frame",
                                          SectionKind::Unwind,
                                          8,
                                          4,
                                          0,
                                          0,
                                          {0, 0, 0, 0},
                                          SectionPurpose::EHFrame});
  auto Data = Graph.addSection(Section{"__data", SectionKind::Data, 8, 8, 0, 0,
                                       std::vector<WasmEdge::Byte>(8)});
  auto Pointer =
      Graph.addSection(Section{"__pointer", SectionKind::Data, 8, 8, 0, 0,
                               std::vector<WasmEdge::Byte>(8)});
  auto BSS =
      Graph.addSection(Section{"__bss", SectionKind::BSS, 8, 8, 0, 0, {}});
  EXPECT_TRUE(Text && Constant && EHFrame && Data && Pointer && BSS);
  EXPECT_TRUE(
      Graph.addSymbol(Symbol{"_f0", *Text, 0, 4, true, std::nullopt, true}));
  EXPECT_TRUE(
      Graph.addSymbol(Symbol{"_value", *Data, 0, 8, true, std::nullopt, true}));
  EXPECT_TRUE(Graph.addRebase(Rebase{*Data, 0,
                                     Architecture == Target::X86_64
                                         ? llvm::MachO::X86_64_RELOC_UNSIGNED
                                         : llvm::MachO::ARM64_RELOC_UNSIGNED,
                                     0, 8, ObjectFormat::MachO}));
  EXPECT_TRUE(Graph.addRebase(Rebase{*Pointer, 0,
                                     Architecture == Target::X86_64
                                         ? llvm::MachO::X86_64_RELOC_UNSIGNED
                                         : llvm::MachO::ARM64_RELOC_UNSIGNED,
                                     0, 8, ObjectFormat::MachO}));
  return Graph;
}

TEST(MachOWriterTest, WritesDeterministicDylibsForMacOSTargets) {
  for (const auto Architecture : {Target::X86_64, Target::AArch64}) {
    auto Graph = makeMachOGraph(Architecture);
    ASSERT_TRUE(MachOWriter::layout(Graph));
    auto Data = Graph.sectionContent(3);
    auto Pointer = Graph.sectionContent(4);
    ASSERT_TRUE(Data && Pointer);
    for (uint8_t I = 0; I < 8; ++I)
      (*Data)[I] =
          static_cast<WasmEdge::Byte>(Graph.sections()[3].Address >> (I * 8));
    for (uint8_t I = 0; I < 8; ++I)
      (*Pointer)[I] =
          static_cast<WasmEdge::Byte>(Graph.sections()[4].Address >> (I * 8));
    ASSERT_TRUE(applyRelocations(Graph));
    std::vector<WasmEdge::Byte> Bytes;
    Writer Output(Bytes);
    ASSERT_TRUE(MachOWriter::write(Graph, Output));
    std::vector<WasmEdge::Byte> Again;
    Writer Second(Again);
    ASSERT_TRUE(MachOWriter::write(Graph, Second));
    EXPECT_EQ(Bytes, Again);

    auto Object =
        llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
            llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                            Bytes.size()),
            "writer.dylib"));
    ASSERT_TRUE(static_cast<bool>(Object))
        << llvm::toString(Object.takeError());
    EXPECT_TRUE((*Object)->isMachO());
    EXPECT_EQ(readInteger(Bytes, 0, 4, Endianness::Little),
              llvm::MachO::MH_MAGIC_64);
    EXPECT_EQ(readInteger(Bytes, 12, 4, Endianness::Little),
              llvm::MachO::MH_DYLIB);
    EXPECT_EQ(readInteger(Bytes, 24, 4, Endianness::Little),
              llvm::MachO::MH_NOUNDEFS | llvm::MachO::MH_DYLDLINK |
                  llvm::MachO::MH_TWOLEVEL);

    size_t Command = 32;
    uint64_t FirstSectionOffset = UINT64_MAX;
    size_t DyldInfo = 0;
    std::set<uint32_t> Commands;
    std::set<std::string> SegmentNames;
    for (uint32_t I = 0; I < readInteger(Bytes, 16, 4, Endianness::Little);
         ++I) {
      const uint32_t Type = static_cast<uint32_t>(
          readInteger(Bytes, Command, 4, Endianness::Little));
      const uint32_t Size = static_cast<uint32_t>(
          readInteger(Bytes, Command + 4, 4, Endianness::Little));
      ASSERT_GE(Size, 8U);
      ASSERT_LE(Command + Size, Bytes.size());
      Commands.insert(Type);
      if (Type == llvm::MachO::LC_DYLD_INFO_ONLY)
        DyldInfo = Command;
      if (Type == llvm::MachO::LC_SEGMENT_64) {
        const char *Name =
            reinterpret_cast<const char *>(Bytes.data() + Command + 8);
        SegmentNames.emplace(Name, strnlen(Name, 16));
        const uint32_t MaxProtection = static_cast<uint32_t>(
            readInteger(Bytes, Command + 56, 4, Endianness::Little));
        const uint32_t InitialProtection = static_cast<uint32_t>(
            readInteger(Bytes, Command + 60, 4, Endianness::Little));
        EXPECT_EQ(InitialProtection & ~MaxProtection, 0U);
        EXPECT_FALSE((InitialProtection & llvm::MachO::VM_PROT_WRITE) != 0 &&
                     (InitialProtection & llvm::MachO::VM_PROT_EXECUTE) != 0);
        const uint32_t SectionCount = static_cast<uint32_t>(
            readInteger(Bytes, Command + 64, 4, Endianness::Little));
        for (uint32_t Section = 0; Section < SectionCount; ++Section) {
          const uint64_t Offset = readInteger(
              Bytes, Command + 72 + Section * 80 + 48, 4, Endianness::Little);
          if (Offset != 0)
            FirstSectionOffset = std::min(FirstSectionOffset, Offset);
        }
      }
      Command += Size;
    }
    EXPECT_EQ(Command, 32U + readInteger(Bytes, 20, 4, Endianness::Little));
    ASSERT_NE(FirstSectionOffset, UINT64_MAX);
    EXPECT_GE(FirstSectionOffset - Command, 16U);
    EXPECT_EQ(SegmentNames, (std::set<std::string>{"__TEXT", "__DATA_CONST",
                                                   "__DATA", "__LINKEDIT"}));
    for (const uint32_t Required :
         {llvm::MachO::LC_DYLD_INFO_ONLY, llvm::MachO::LC_SYMTAB,
          llvm::MachO::LC_DYSYMTAB, llvm::MachO::LC_ID_DYLIB,
          llvm::MachO::LC_BUILD_VERSION})
      EXPECT_TRUE(Commands.count(Required)) << Required;
    EXPECT_FALSE(Commands.count(llvm::MachO::LC_UUID));
    ASSERT_NE(DyldInfo, 0U);
    EXPECT_EQ(readInteger(Bytes, DyldInfo + 16, 4, Endianness::Little), 0U);
    EXPECT_EQ(readInteger(Bytes, DyldInfo + 20, 4, Endianness::Little), 0U);
    EXPECT_EQ(readInteger(Bytes, DyldInfo + 24, 4, Endianness::Little), 0U);
    EXPECT_EQ(readInteger(Bytes, DyldInfo + 28, 4, Endianness::Little), 0U);
    EXPECT_EQ(readInteger(Bytes, DyldInfo + 32, 4, Endianness::Little), 0U);
    EXPECT_EQ(readInteger(Bytes, DyldInfo + 36, 4, Endianness::Little), 0U);

    const size_t ExportOffset = static_cast<size_t>(
        readInteger(Bytes, DyldInfo + 40, 4, Endianness::Little));
    const size_t ExportEnd =
        ExportOffset + static_cast<size_t>(readInteger(Bytes, DyldInfo + 44, 4,
                                                       Endianness::Little));
    std::map<std::string, uint64_t> TrieExports;
    std::set<size_t> Visited;
    readExportNode(Bytes, ExportOffset, ExportOffset, ExportEnd, "",
                   TrieExports, Visited);
    EXPECT_EQ(TrieExports, (std::map<std::string, uint64_t>{
                               {"_f0", Graph.sections()[0].Address},
                               {"_value", Graph.sections()[3].Address}}));

    const size_t RebaseOffset = static_cast<size_t>(
        readInteger(Bytes, DyldInfo + 8, 4, Endianness::Little));
    const size_t RebaseEnd =
        RebaseOffset + static_cast<size_t>(readInteger(Bytes, DyldInfo + 12, 4,
                                                       Endianness::Little));
    size_t RebaseCursor = RebaseOffset;
    ASSERT_LT(RebaseCursor, RebaseEnd);
    EXPECT_EQ(Bytes[RebaseCursor++], llvm::MachO::REBASE_OPCODE_SET_TYPE_IMM |
                                         llvm::MachO::REBASE_TYPE_POINTER);
    std::set<uint64_t> RebasedAddresses;
    while (RebaseCursor < RebaseEnd &&
           Bytes[RebaseCursor] != llvm::MachO::REBASE_OPCODE_DONE) {
      const uint8_t SegmentOpcode = Bytes[RebaseCursor++];
      EXPECT_EQ(SegmentOpcode & llvm::MachO::REBASE_OPCODE_MASK,
                llvm::MachO::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB);
      const uint8_t SegmentIndex =
          SegmentOpcode & llvm::MachO::REBASE_IMMEDIATE_MASK;
      ASSERT_LT(SegmentIndex, 4U);
      const uint64_t SegmentOffset = readULEB(Bytes, RebaseCursor, RebaseEnd);
      ASSERT_LT(RebaseCursor, RebaseEnd);
      EXPECT_EQ(Bytes[RebaseCursor++],
                llvm::MachO::REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1);
      const uint64_t SegmentAddress =
          SegmentIndex == 1 ? Graph.sections()[1].Address & ~UINT64_C(0xFFF)
                            : Graph.sections()[3].Address;
      RebasedAddresses.insert(SegmentAddress + SegmentOffset);
    }
    ASSERT_LT(RebaseCursor, RebaseEnd);
    EXPECT_EQ(Bytes[RebaseCursor++], llvm::MachO::REBASE_OPCODE_DONE);
    EXPECT_EQ(RebaseCursor, RebaseEnd);
    std::set<uint64_t> ExpectedRebases;
    for (const auto &Rebase : Graph.rebases()) {
      EXPECT_EQ(Rebase.Width, 8U);
      EXPECT_EQ(Rebase.Format, ObjectFormat::MachO);
      EXPECT_TRUE(Graph.sections()[Rebase.Section].Kind == SectionKind::Data ||
                  Graph.sections()[Rebase.Section].Kind == SectionKind::BSS);
      ExpectedRebases.insert(Graph.sections()[Rebase.Section].Address +
                             Rebase.Offset);
    }
    EXPECT_EQ(RebasedAddresses, ExpectedRebases);

    std::set<std::string> Names;
    for (const auto &Symbol : (*Object)->symbols()) {
      auto Name = Symbol.getName();
      ASSERT_TRUE(static_cast<bool>(Name));
      Names.emplace(Name->str());
      auto Flags = Symbol.getFlags();
      ASSERT_TRUE(static_cast<bool>(Flags));
      EXPECT_EQ(*Flags & llvm::object::SymbolRef::SF_Undefined, 0U);
    }
    EXPECT_EQ(Names, (std::set<std::string>{"_f0", "_value"}));
  }
}

TEST(MachOWriterTest, RejectsRawCompactUnwind) {
  LinkGraph Graph(Target::AArch64, Endianness::Little, ObjectFormat::MachO);
  ASSERT_TRUE(Graph.beginInput("compact.o"));
  ASSERT_TRUE(Graph.addSection(
      Section{"__compact_unwind", SectionKind::Unwind, 8, 32, 0, 0,
              std::vector<WasmEdge::Byte>(32), SectionPurpose::CompactUnwind}));
  EXPECT_FALSE(MachOWriter::layout(Graph));
}

TEST(MachOWriterTest, RejectsResidualCompactUnwindWithEHFrame) {
  LinkGraph Graph(Target::AArch64, Endianness::Little, ObjectFormat::MachO);
  ASSERT_TRUE(Graph.beginInput("mixed-unwind.o"));
  ASSERT_TRUE(Graph.addSection(Section{"__eh_frame",
                                       SectionKind::Unwind,
                                       8,
                                       4,
                                       0,
                                       0,
                                       {0, 0, 0, 0},
                                       SectionPurpose::EHFrame}));
  ASSERT_TRUE(Graph.addSection(
      Section{"__compact_unwind", SectionKind::Unwind, 8, 32, 0, 0,
              std::vector<WasmEdge::Byte>(32), SectionPurpose::CompactUnwind}));
  EXPECT_FALSE(MachOWriter::layout(Graph));
}

TEST(MachOWriterTest, RejectsMissingEHFrame) {
  LinkGraph Graph(Target::X86_64, Endianness::Little, ObjectFormat::MachO);
  ASSERT_TRUE(Graph.beginInput("no-eh.o"));
  ASSERT_TRUE(Graph.addSection(
      Section{"__text", SectionKind::Text, 1, 1, 0, 0, {0xC3}}));
  EXPECT_FALSE(MachOWriter::layout(Graph));
}

TEST(MachOWriterTest, WritesBSSOnlyDataSegment) {
  LinkGraph Graph(Target::X86_64, Endianness::Little, ObjectFormat::MachO);
  ASSERT_TRUE(Graph.beginInput("bss.o"));
  ASSERT_TRUE(Graph.addSection(
      Section{"__text", SectionKind::Text, 1, 1, 0, 0, {0xC3}}));
  ASSERT_TRUE(Graph.addSection(Section{"__eh_frame",
                                       SectionKind::Unwind,
                                       8,
                                       4,
                                       0,
                                       0,
                                       {0, 0, 0, 0},
                                       SectionPurpose::EHFrame}));
  ASSERT_TRUE(
      Graph.addSection(Section{"__bss", SectionKind::BSS, 8, 8, 0, 0, {}}));
  ASSERT_TRUE(MachOWriter::layout(Graph));
  ASSERT_TRUE(applyRelocations(Graph));
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  ASSERT_TRUE(MachOWriter::write(Graph, Output));
  auto Object =
      llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
          llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                          Bytes.size()),
          "bss.dylib"));
  ASSERT_TRUE(static_cast<bool>(Object)) << llvm::toString(Object.takeError());
}

TEST(MachOWriterTest, AppliesMachOAbsolutePointersAsRebases) {
  for (const auto Architecture : {Target::X86_64, Target::AArch64}) {
    LinkGraph Graph(Architecture, Endianness::Little, ObjectFormat::MachO);
    ASSERT_TRUE(Graph.beginInput("absolute.o"));
    auto Text = Graph.addSection(
        Section{"__text", SectionKind::Text, 4, 4, 0, 0,
                Architecture == Target::X86_64
                    ? std::vector<WasmEdge::Byte>{0xC3, 0, 0, 0}
                    : std::vector<WasmEdge::Byte>{0xC0, 0x03, 0x5F, 0xD6}});
    auto Data = Graph.addSection(Section{"__data", SectionKind::Data, 8, 8, 0,
                                         0, std::vector<WasmEdge::Byte>(8)});
    auto EHFrame = Graph.addSection(Section{"__eh_frame",
                                            SectionKind::Unwind,
                                            8,
                                            4,
                                            0,
                                            0,
                                            {0, 0, 0, 0},
                                            SectionPurpose::EHFrame});
    ASSERT_TRUE(Text && Data && EHFrame);
    auto Function =
        Graph.addSymbol(Symbol{"_f0", *Text, 0, 4, true, std::nullopt, true});
    ASSERT_TRUE(Function);
    const uint32_t Type = Architecture == Target::X86_64
                              ? llvm::MachO::X86_64_RELOC_UNSIGNED
                              : llvm::MachO::ARM64_RELOC_UNSIGNED;
    ASSERT_TRUE(Graph.addRelocation(Relocation{*Data, 0, Type, *Function, 0,
                                               true, ObjectFormat::MachO, 8,
                                               false, false, false}));
    ASSERT_TRUE(MachOWriter::layout(Graph));
    ASSERT_TRUE(applyRelocations(Graph));
    ASSERT_EQ(Graph.rebases().size(), 1U);
    EXPECT_EQ(
        readInteger(Graph.sections()[*Data].Content, 0, 8, Endianness::Little),
        Graph.sections()[*Text].Address);
  }
}

TEST(MachOWriterTest, BoundsSectionOrdinalsAtomically) {
  auto MakeGraph = [](size_t Count) {
    LinkGraph Graph(Target::X86_64, Endianness::Little, ObjectFormat::MachO);
    EXPECT_TRUE(Graph.beginInput("many-sections.o"));
    EXPECT_TRUE(Graph.addSection(Section{"__eh_frame",
                                         SectionKind::Unwind,
                                         8,
                                         4,
                                         0,
                                         0,
                                         {0, 0, 0, 0},
                                         SectionPurpose::EHFrame}));
    for (size_t I = 1; I < Count; ++I)
      EXPECT_TRUE(Graph.addSection(Section{"__text" + std::to_string(I),
                                           SectionKind::Text,
                                           1,
                                           1,
                                           0,
                                           0,
                                           {0xC3}}));
    return Graph;
  };

  auto Boundary = MakeGraph(UINT8_MAX);
  ASSERT_TRUE(MachOWriter::layout(Boundary));
  ASSERT_TRUE(applyRelocations(Boundary));
  std::vector<WasmEdge::Byte> BoundaryBytes;
  Writer BoundaryOutput(BoundaryBytes);
  EXPECT_TRUE(MachOWriter::write(Boundary, BoundaryOutput));

  auto Overflow = MakeGraph(static_cast<size_t>(UINT8_MAX) + 1);
  ASSERT_TRUE(MachOWriter::layout(Overflow));
  ASSERT_TRUE(applyRelocations(Overflow));
  const std::vector<WasmEdge::Byte> Existing{1, 2, 3};
  auto Bytes = Existing;
  Writer Output(Bytes);
  EXPECT_FALSE(MachOWriter::write(Overflow, Output));
  EXPECT_EQ(Bytes, Existing);
  auto SecondBytes = Existing;
  Writer SecondOutput(SecondBytes);
  EXPECT_FALSE(MachOWriter::write(Overflow, SecondOutput));
  EXPECT_EQ(SecondBytes, Existing);
}

#if !WASMEDGE_OS_WINDOWS
TEST(NativeWriterTest, PublishFailurePreservesDestination) {
  llvm::SmallString<128> UniqueRoot;
  ASSERT_FALSE(llvm::sys::fs::createUniqueDirectory("wasmedge-publish-failure",
                                                    UniqueRoot));
  const auto Root = std::filesystem::u8path(UniqueRoot.str().str());
  struct Cleanup {
    std::filesystem::path Root;
    ~Cleanup() {
      std::error_code Error;
      std::filesystem::remove_all(Root, Error);
    }
  } CleanupGuard{Root};
  const auto Destination = Root / "library.so";
  const auto Temporary = Root / "library.so.tmp-test";
  const std::vector<WasmEdge::Byte> Existing{1, 2, 3};
  const std::vector<WasmEdge::Byte> Replacement{4, 5, 6};
  auto Write = [](const std::filesystem::path &Path,
                  const std::vector<WasmEdge::Byte> &Bytes) {
    std::ofstream File(Path, std::ios_base::binary);
    File.write(reinterpret_cast<const char *>(Bytes.data()), Bytes.size());
  };
  auto Read = [](const std::filesystem::path &Path) {
    std::ifstream File(Path, std::ios_base::binary);
    return std::vector<WasmEdge::Byte>(std::istreambuf_iterator<char>(File),
                                       std::istreambuf_iterator<char>());
  };
  Write(Destination, Existing);
  Write(Temporary, Replacement);
  ASSERT_EQ(::chmod(Destination.c_str(), 0751), 0);

  bool Called = false;
  EXPECT_FALSE(Internal::publishAtomically(
      Temporary, Destination,
      [&](const std::filesystem::path &Path) -> WasmEdge::Expect<void> {
        Called = true;
        EXPECT_EQ(Read(Path), Replacement);
        return WasmEdge::Unexpect(WasmEdge::ErrCode::Value::IllegalPath);
      }));
  EXPECT_TRUE(Called);
  EXPECT_EQ(Read(Destination), Existing);
  struct stat DestinationStat{};
  ASSERT_EQ(::stat(Destination.c_str(), &DestinationStat), 0);
  EXPECT_EQ(DestinationStat.st_mode & 0777, 0751);
  EXPECT_FALSE(std::filesystem::exists(Temporary));
  size_t Entries = 0;
  for (const auto &Entry : std::filesystem::directory_iterator(Root)) {
    static_cast<void>(Entry);
    ++Entries;
  }
  EXPECT_EQ(Entries, 1U);
}

TEST(MachOWriterTest, PublishesOnlyAfterSigningAndVerification) {
  llvm::SmallString<128> UniqueRoot;
  ASSERT_FALSE(
      llvm::sys::fs::createUniqueDirectory("wasmedge-macho-sign", UniqueRoot));
  const auto Root = std::filesystem::u8path(UniqueRoot.str().str());
  struct Cleanup {
    std::filesystem::path Root;
    ~Cleanup() {
      std::error_code Error;
      std::filesystem::remove_all(Root, Error);
    }
  } CleanupGuard{Root};
  const auto Log = Root / "order.log";
  auto MakeHelper = [&](std::string_view Name, std::string_view Action) {
    const auto Path = Root / Name;
    std::ofstream Script(Path);
    Script << "#!/bin/sh\n"
              "printf '%s\\n' \"$1\" >> \""
           << Log.string() << "\"\n"
           << Action << "\n";
    Script.close();
    EXPECT_TRUE(Script);
    EXPECT_EQ(::chmod(Path.c_str(), 0700), 0);
    return Path;
  };
  const auto Success = MakeHelper("success helper", "exit 0");
  const auto Signaled = MakeHelper("signal helper", "kill -TERM $$");
  const auto Failed = MakeHelper("failure helper", "exit 7");

  const auto Destination = Root / "library.dylib";
  const std::vector<WasmEdge::Byte> Existing{1, 2, 3};
  const std::vector<WasmEdge::Byte> Replacement{4, 5, 6};
  auto Write = [](const std::filesystem::path &Path,
                  const std::vector<WasmEdge::Byte> &Bytes) {
    std::ofstream File(Path, std::ios_base::binary);
    File.write(reinterpret_cast<const char *>(Bytes.data()), Bytes.size());
  };
  auto Read = [](const std::filesystem::path &Path) {
    std::ifstream File(Path, std::ios_base::binary);
    return std::vector<WasmEdge::Byte>(std::istreambuf_iterator<char>(File),
                                       std::istreambuf_iterator<char>());
  };
  Write(Destination, Existing);

  struct Case {
    std::filesystem::path Sign;
    std::filesystem::path Verify;
    const char *LogValue;
  };
  const std::array<Case, 5> Failures{{
      {Root / "missing", Success, ""},
      {Signaled, Success, "--force\n"},
      {Failed, Success, "--force\n"},
      {"/bin/false", Success, ""},
      {Success, Failed, "--force\n--verify\n"},
  }};
  for (size_t I = 0; I < Failures.size(); ++I) {
    const auto Temporary = Root / ("temporary-" + std::to_string(I));
    Write(Temporary, Replacement);
    std::filesystem::remove(Log);
    EXPECT_FALSE(Internal::publishMachO(Temporary, Destination,
                                        Failures[I].Sign, Failures[I].Verify));
    EXPECT_EQ(Read(Destination), Existing);
    EXPECT_FALSE(std::filesystem::exists(Temporary));
    std::string LogValue;
    if (std::filesystem::exists(Log)) {
      const auto LogBytes = Read(Log);
      LogValue.assign(LogBytes.begin(), LogBytes.end());
    }
    EXPECT_EQ(LogValue, Failures[I].LogValue);
  }

  const auto Temporary = Root / "temporary-success";
  Write(Temporary, Replacement);
  std::filesystem::remove(Log);
  EXPECT_TRUE(Internal::publishMachO(Temporary, Destination, Success, Success));
  EXPECT_EQ(Read(Destination), Replacement);
  EXPECT_FALSE(std::filesystem::exists(Temporary));
  const auto LogBytes = Read(Log);
  EXPECT_EQ(std::string(LogBytes.begin(), LogBytes.end()),
            "--force\n--verify\n");
}
#endif

} // namespace
