// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/elf_writer.h"
#include "linker/relocation.h"

#include <gtest/gtest.h>

#include <llvm/BinaryFormat/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBufferRef.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

using namespace WasmEdge::LLVM::Linker;

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
    auto Text =
        Graph.addSection(Section{".text." + std::to_string(I),
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
  }
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

} // namespace
